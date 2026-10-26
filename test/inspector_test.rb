# frozen_string_literal: true

require_relative "test_helper"
require "socket"
require "securerandom"
require "uri"
require "net/http"
require "open3"
require "rbconfig"

# Minimal Chrome DevTools Protocol client: just enough WebSocket to talk to
# MiniRacer::Inspector the way DevTools does.
class CdpClient
  def initialize(url, headers: {})
    uri = URI(url)
    @sock = TCPSocket.new(uri.host, uri.port)
    extra = headers.map { |k, v| "#{k}: #{v}\r\n" }.join
    @sock.write(
      "GET #{uri.path} HTTP/1.1\r\nHost: #{uri.host}:#{uri.port}\r\n" \
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" \
        "Sec-WebSocket-Key: #{SecureRandom.base64(16)}\r\n" \
        "Sec-WebSocket-Version: 13\r\n#{extra}\r\n"
    )
    status = @sock.gets
    raise "handshake failed: #{status}" unless status.to_s.include?(" 101 ")
    nil while @sock.gets != "\r\n"
    @next_id = 0
    @events = []
  end

  def command(method, **params)
    timeout = 5
    id = (@next_id += 1)
    send_text(JSON.generate(id: id, method: method, params: params))
    loop do
      msg = read_message(timeout)
      raise "timed out waiting for #{method}" unless msg
      if msg["id"] == id
        raise "#{method}: #{msg["error"]["message"]}" if msg["error"]
        return msg["result"]
      end
      @events << msg
    end
  end

  def wait_event(name, timeout: 5)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      if (i = @events.index { |e| e["method"] == name })
        return @events.delete_at(i)["params"]
      end
      left = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      raise "timed out waiting for #{name}" if left <= 0
      msg = read_message(left)
      @events << msg if msg
    end
  end

  def close
    @sock.close unless @sock.closed?
  end

  # reads (and discards) whatever is still in flight until the server
  # closes the connection, or |timeout| passes
  def closed_by_peer?(timeout: 5)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      left = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      return false if left <= 0 || !@sock.wait_readable(left)
      return true if @sock.read_nonblock(65_536, exception: false).nil?
    end
  rescue Errno::ECONNRESET
    true
  end

  attr_reader :events

  def send_text(text)
    send_frame(0x1, text)
  end

  # the next frame of any kind, as [opcode, payload]
  def read_frame(timeout = 5)
    return nil unless @sock.wait_readable(timeout)
    b0, b1 = @sock.read(2).bytes
    len = b1 & 0x7f
    len = @sock.read(2).unpack1("n") if len == 126
    len = @sock.read(8).unpack1("Q>") if len == 127
    [b0 & 0x0f, len.zero? ? "".b : @sock.read(len)]
  end

  def write_raw(bytes)
    @sock.write(bytes)
  end

  # a frame with |b0| as its first byte (FIN, RSV and opcode bits), masked
  def send_frame_bits(b0, payload)
    payload = payload.b
    mask = SecureRandom.random_bytes(4).bytes
    n = payload.bytesize
    header = [b0].pack("C") + (n < 126 ? [0x80 | n].pack("C") : [0x80 | 126, n].pack("Cn"))
    masked = payload.bytes.each_with_index.map { |b, i| b ^ mask[i % 4] }
    @sock.write(header + mask.pack("C*") + masked.pack("C*"))
  end

  def wait_response(id, timeout: 5)
    wait_message(id, timeout: timeout)["result"]
  end

  # the whole reply, "error" included
  def wait_message(id, timeout: 5)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      left = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      raise "timed out waiting for response #{id}" if left <= 0
      msg = read_message(left)
      return msg if msg && msg["id"] == id
      @events << msg if msg
    end
  end

  def send_frame(opcode, payload)
    @sock.write(frame_bytes(opcode, payload))
  end

  # several text messages in one write, so they're queued together
  def send_texts(*texts)
    @sock.write(texts.map { |t| frame_bytes(0x1, t) }.join)
  end

  def frame_bytes(opcode, payload)
    payload = payload.b
    mask = SecureRandom.random_bytes(4).bytes
    header = [0x80 | opcode].pack("C")
    n = payload.bytesize
    header <<
      if n < 126
        [0x80 | n].pack("C")
      elsif n < 65_536
        [0x80 | 126, n].pack("Cn")
      else
        [0x80 | 127, n].pack("CQ>")
      end
    masked = payload.bytes.each_with_index.map { |b, i| b ^ mask[i % 4] }
    header + mask.pack("C*") + masked.pack("C*")
  end

  private

  def read_message(timeout)
    return nil unless @sock.wait_readable(timeout)
    b0, b1 = @sock.read(2).bytes
    len = b1 & 0x7f
    len = @sock.read(2).unpack1("n") if len == 126
    len = @sock.read(8).unpack1("Q>") if len == 127
    payload = len.zero? ? "" : @sock.read(len)
    raise "unexpected opcode #{b0 & 0x0f}" unless (b0 & 0x0f) == 1
    JSON.parse(payload.force_encoding("UTF-8"))
  end
end

class MiniRacerInspectorTest < Minitest::Test
  def setup
    skip "no inspector on truffleruby" if RUBY_ENGINE == "truffleruby"
    @port = MiniRacer::Inspector.start(port: 0)
    @contexts = []
    @clients = []
  end

  def teardown
    @clients.each(&:close)
    @contexts.each(&:dispose)
  end

  def new_context(**opts)
    ctx = MiniRacer::Context.new(**opts)
    @contexts << ctx
    ctx
  end

  def targets(host: "127.0.0.1:#{@port}")
    http_get("/json/list", host: host)
  end

  def http_get(path, host: "127.0.0.1:#{@port}")
    Net::HTTP.start("127.0.0.1", @port) do |http|
      res = http.get(path, "Host" => host)
      [res.code.to_i, res.body.empty? ? nil : JSON.parse(res.body)]
    end
  end

  def target_for(title)
    _, list = targets
    list.find { |t| t["title"] == title } or flunk "no target #{title}: #{list}"
  end

  def connect(title, headers: {})
    client = CdpClient.new(target_for(title)["webSocketDebuggerUrl"], headers: headers)
    @clients << client
    client
  end

  # What DevTools sends on attach.
  def attach_like_devtools(title)
    client = connect(title)
    client.command("Runtime.enable")
    client.command("Debugger.enable")
    client.command("Runtime.runIfWaitingForDebugger")
    client
  end

  def test_start_is_idempotent
    assert_equal @port, MiniRacer::Inspector.start(port: 0)
    assert_equal @port, MiniRacer::Inspector.port
    assert MiniRacer::Inspector.started?
  end

  def test_lists_only_inspectable_contexts
    new_context(inspector: "listed")
    new_context
    code, list = targets
    assert_equal 200, code
    titles = list.map { |t| t["title"] }
    assert_includes titles, "listed"
    t = target_for("listed")
    assert_equal "node", t["type"]
    assert_equal "ws://127.0.0.1:#{@port}/#{t["id"]}", t["webSocketDebuggerUrl"]
    assert_includes t["devtoolsFrontendUrl"], "ws=127.0.0.1:#{@port}/#{t["id"]}"
  end

  def test_default_title_and_unicode_title
    new_context(inspector: true)
    new_context(inspector: "transform é\u{1F600} \"quoted\"")
    titles = targets[1].map { |t| t["title"] }
    assert_includes titles, "mini_racer"
    assert_includes titles, "transform é\u{1F600} \"quoted\""
  end

  def test_disposed_context_is_unlisted
    ctx = new_context(inspector: "short-lived")
    ctx.dispose
    # dispose wakes the V8 thread, which unregisters the target on its way out
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
    titles = nil
    loop do
      titles = targets[1].map { |t| t["title"] }
      break unless titles.include?("short-lived")
      break if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.01
    end
    refute_includes titles, "short-lived"
  end

  def test_version_endpoint
    code, body = http_get("/json/version")
    assert_equal 200, code
    assert_equal "1.1", body["Protocol-Version"]
  end

  def test_rejects_foreign_host_header
    code, _ = http_get("/json/list", host: "attacker.example:#{@port}")
    assert_equal 403, code
    assert_equal 200, http_get("/json/list", host: "localhost:#{@port}")[0]
  end

  def test_second_frontend_is_refused
    new_context(inspector: "single")
    connect("single")
    assert_raises(RuntimeError) { connect("single") }
  end

  def test_evaluate_while_idle
    ctx = new_context(inspector: "idle")
    ctx.eval("var answer = 41")
    client = attach_like_devtools("idle")
    result = client.command("Runtime.evaluate", expression: "answer + 1")
    assert_equal 42, result["result"]["value"]
    assert ctx.debugger_attached?
  end

  def test_ruby_callback_from_idle_console_errors_instead_of_hanging
    ctx = new_context(inspector: "idle-callback")
    ctx.attach("rubyAdd", proc { |a, b| a + b })
    client = attach_like_devtools("idle-callback")
    result = client.command("Runtime.evaluate", expression: "rubyAdd(1, 2)")
    assert_match(/pause at a breakpoint first/, result.dig("exceptionDetails", "exception", "description"))
    # and the context still works normally afterwards
    assert_equal 3, ctx.eval("rubyAdd(1, 2)")
  end

  def test_scripts_are_reported_with_their_filename
    ctx = new_context(inspector: "scripts")
    client = attach_like_devtools("scripts")
    ctx.eval("1 + 1", filename: "transforms/EBS Lines Compare.js")
    parsed = client.wait_event("Debugger.scriptParsed") while parsed.nil? || parsed["url"] != "transforms/EBS Lines Compare.js"
    assert_equal "transforms/EBS Lines Compare.js", parsed["url"]
  end

  def test_debugger_statement_pauses_and_inspects_locals
    ctx = new_context(inspector: "debugger-stmt")
    client = attach_like_devtools("debugger-stmt")
    th = Thread.new { ctx.eval("(function(){ let row = {code: 'P1~~T~~7'}; debugger; return row.code.split('~~').length })()") }
    paused = client.wait_event("Debugger.paused")
    frame = paused["callFrames"].first
    r = client.command("Debugger.evaluateOnCallFrame", callFrameId: frame["callFrameId"], expression: "row.code")
    assert_equal "P1~~T~~7", r["result"]["value"]
    client.command("Debugger.resume")
    assert_equal 3, th.value
  end

  def test_pause_on_uncaught_exceptions_stops_on_errors_escaping_to_ruby
    ctx = new_context(inspector: "uncaught")
    client = attach_like_devtools("uncaught")
    client.command("Debugger.setPauseOnExceptions", state: "uncaught")
    # caught in JavaScript: no pause
    assert_equal "caught",
                 ctx.eval("try { throw new Error('x') } catch (e) { 'caught' }")
    th = Thread.new do
      Thread.current.report_on_exception = false
      ctx.eval("(function f() { const row = 7; throw new Error('bad') })()")
    end
    paused = client.wait_event("Debugger.paused")
    assert_equal "exception", paused["reason"]
    frame = paused["callFrames"].first
    r = client.command("Debugger.evaluateOnCallFrame", callFrameId: frame["callFrameId"], expression: "row")
    assert_equal 7, r["result"]["value"]
    client.command("Debugger.resume")
    error = assert_raises(MiniRacer::RuntimeError) { th.value }
    assert_includes error.message, "bad"
    # turned off again: the error goes straight to Ruby
    client.command("Debugger.setPauseOnExceptions", state: "none")
    assert_raises(MiniRacer::RuntimeError) { ctx.eval("throw new Error('quiet')") }
  end

  def test_target_id_matches_the_listing
    ctx = new_context(inspector: "by-id")
    assert_equal target_for("by-id")["id"], ctx.inspector_target_id
    assert_nil new_context.inspector_target_id
    ctx.dispose
    assert_nil ctx.inspector_target_id
  end

  def test_inspector_state_follows_attach_and_pauses
    ctx = new_context(inspector: "state")
    assert_nil new_context.inspector_state
    state = ctx.inspector_state
    refute state[:attached]
    assert_equal 0, state[:pause_generation]
    client = attach_like_devtools("state")
    th = Thread.new { ctx.eval("debugger; debugger; 1") }
    client.wait_event("Debugger.paused")
    sleep 0.05
    state = ctx.inspector_state
    assert state[:attached]
    assert state[:ready]
    assert state[:paused]
    assert_equal 1, state[:pause_generation]
    assert_operator state[:paused_ms], :>=, 40
    client.command("Debugger.resume")
    client.wait_event("Debugger.paused")
    assert_equal 2, ctx.inspector_state[:pause_generation]
    client.command("Debugger.resume")
    assert_equal 1, th.value
    state = ctx.inspector_state
    refute state[:paused]
    assert_equal 0, state[:paused_ms]
    assert_operator state[:total_paused_ms], :>=, 40
  end

  def test_await_debugger_says_how_the_wait_ended
    ctx = new_context(inspector: "await")
    assert_equal :timeout, ctx.await_debugger(timeout: 0.05)
    th = Thread.new { ctx.await_debugger }
    sleep 0.1
    ctx.cancel_debugger_wait
    assert_equal :cancelled, th.value
    th = Thread.new { ctx.await_debugger }
    sleep 0.1
    ctx.stop
    assert_equal :cancelled, th.value
    th = Thread.new { ctx.await_debugger(timeout: 5) }
    sleep 0.1
    attach_like_devtools("await")
    assert_equal :ready, th.value
    other = new_context(inspector: "await-disposed")
    th = Thread.new { other.await_debugger(timeout: 5) }
    sleep 0.1
    other.dispose
    assert_equal :disposed, th.value
    assert_raises(MiniRacer::ContextDisposedError) { other.wait_for_debugger(timeout: 0) }
  end

  def test_inspector_detach_terminate_ends_a_paused_script
    ctx = new_context(inspector: "detach-terminate", inspector_detach: :terminate)
    client = attach_like_devtools("detach-terminate")
    th = Thread.new do
      Thread.current.report_on_exception = false
      ctx.eval("debugger; 'ran on'")
    end
    client.wait_event("Debugger.paused")
    client.close
    assert_raises(MiniRacer::ScriptTerminatedError) { th.value }
    # only what was running then: the context is still usable
    assert_equal 2, ctx.eval("1 + 1")
    assert_raises(ArgumentError) { new_context(inspector: "x", inspector_detach: :explode) }
  end

  def test_detach_resumes_by_default
    ctx = new_context(inspector: "detach-resume")
    client = attach_like_devtools("detach-resume")
    th = Thread.new { ctx.eval("debugger; 'ran on'") }
    client.wait_event("Debugger.paused")
    client.close
    assert_equal "ran on", th.value
  end

  def test_disconnect_debugger_revokes_and_terminates
    ctx = new_context(inspector: "revoke")
    client = attach_like_devtools("revoke")
    th = Thread.new do
      Thread.current.report_on_exception = false
      ctx.eval("debugger; 'ran on'")
    end
    client.wait_event("Debugger.paused")
    assert ctx.disconnect_debugger
    assert_raises(MiniRacer::ScriptTerminatedError) { th.value }
    assert client.closed_by_peer?
    refute ctx.debugger_attached?
    assert_equal 2, ctx.eval("1 + 1")
    # without terminate:, the default policy resumes
    client = attach_like_devtools("revoke")
    th = Thread.new { ctx.eval("debugger; 'ran on'") }
    client.wait_event("Debugger.paused")
    ctx.disconnect_debugger(terminate: false)
    assert_equal "ran on", th.value
  end

  def test_ruby_callback_from_breakpoint_console
    ctx = new_context(inspector: "paused-callback")
    ctx.attach("rubyAdd", proc { |a, b| a + b })
    client = attach_like_devtools("paused-callback")
    th = Thread.new { ctx.eval("debugger; 'done'") }
    frame = client.wait_event("Debugger.paused")["callFrames"].first
    r = client.command("Debugger.evaluateOnCallFrame", callFrameId: frame["callFrameId"], expression: "rubyAdd(20, 22)")
    assert_equal 42, r["result"]["value"]
    client.command("Debugger.resume")
    assert_equal "done", th.value
  end

  def test_breakpoint_by_url_and_stepping
    ctx = new_context(inspector: "bp")
    client = attach_like_devtools("bp")
    client.command("Debugger.setBreakpointByUrl", lineNumber: 1, url: "bp.js")
    th = Thread.new { ctx.eval("var a = 1;\nvar b = a + 1;\nvar c = b + 1;\nc", filename: "bp.js") }
    paused = client.wait_event("Debugger.paused")
    assert_equal 1, paused["callFrames"].first["location"]["lineNumber"]
    client.command("Debugger.stepOver")
    client.wait_event("Debugger.resumed")
    paused = client.wait_event("Debugger.paused")
    assert_equal 2, paused["callFrames"].first["location"]["lineNumber"]
    client.command("Debugger.resume")
    assert_equal 3, th.value
  end

  def test_wait_for_debugger_breaks_on_first_statement
    ctx = new_context(inspector: "wait")
    waiter = Thread.new { ctx.wait_for_debugger(timeout: 5) }
    client = attach_like_devtools("wait")
    assert_equal true, waiter.value
    th = Thread.new { ctx.eval("var x = 41;\nx + 1", filename: "wait.js") }
    paused = client.wait_event("Debugger.paused")
    assert_equal 0, paused["callFrames"].first["location"]["lineNumber"]
    client.command("Debugger.resume")
    assert_equal 42, th.value
    # only the first evaluation breaks
    assert_equal 2, ctx.eval("1 + 1")
  end

  def test_wait_for_debugger_times_out
    ctx = new_context(inspector: "nobody")
    assert_equal false, ctx.wait_for_debugger(timeout: 0.2)
  end

  def test_wait_for_debugger_requires_inspector
    assert_raises(ArgumentError) { new_context.wait_for_debugger(timeout: 0) }
  end

  def test_time_paused_does_not_count_against_timeout
    ctx = new_context(inspector: "timeout", timeout: 300)
    client = attach_like_devtools("timeout")
    th = Thread.new { ctx.eval("debugger; 'survived'") }
    client.wait_event("Debugger.paused")
    sleep 0.8
    client.command("Debugger.resume")
    assert_equal "survived", th.value
  end

  def test_timeout_still_applies_to_running_code
    ctx = new_context(inspector: "timeout-running", timeout: 200)
    attach_like_devtools("timeout-running")
    assert_raises(MiniRacer::ScriptTerminatedError) { ctx.eval("for(;;){}") }
  end

  def test_stop_while_paused_terminates
    ctx = new_context(inspector: "stop")
    client = attach_like_devtools("stop")
    th = Thread.new { ctx.eval("debugger; 'unreachable'") }
    client.wait_event("Debugger.paused")
    ctx.stop
    assert_raises(MiniRacer::ScriptTerminatedError) { th.value }
    assert_equal 2, ctx.eval("1 + 1")
  end

  def test_disconnect_while_paused_resumes
    ctx = new_context(inspector: "disconnect")
    client = attach_like_devtools("disconnect")
    th = Thread.new { ctx.eval("debugger; 'resumed'") }
    client.wait_event("Debugger.paused")
    client.close
    assert_equal "resumed", th.value
    refute ctx.debugger_attached?
    # a new frontend can attach afterwards
    client = attach_like_devtools("disconnect")
    assert_equal 2, client.command("Runtime.evaluate", expression: "1 + 1")["result"]["value"]
  end

  def test_dispose_closes_frontend
    ctx = new_context(inspector: "dispose")
    client = attach_like_devtools("dispose")
    ctx.dispose
    assert client.closed_by_peer?
  end

  def test_pause_requested_while_running
    ctx = new_context(inspector: "pause-running")
    client = attach_like_devtools("pause-running")
    th = Thread.new { ctx.eval("var i = 0; while (i < 1e12) i++; i") }
    sleep 0.1
    client.command("Debugger.pause")
    paused = client.wait_event("Debugger.paused")
    frame = paused["callFrames"].first
    r = client.command("Debugger.evaluateOnCallFrame", callFrameId: frame["callFrameId"], expression: "i > 0")
    assert_equal true, r["result"]["value"]
    ctx.stop
    assert_raises(MiniRacer::ScriptTerminatedError) { th.value }
  end

  def test_console_messages_reach_frontend
    ctx = new_context(inspector: "console")
    client = attach_like_devtools("console")
    ctx.eval("console.log('hello', 42)")
    called = client.wait_event("Runtime.consoleAPICalled")
    assert_equal ["hello", 42], called["args"].map { |a| a["value"] }
  end

  def test_contexts_without_inspector_are_unaffected
    ctx = new_context
    assert_equal 0, ctx.send(:__inspector_status)
    refute ctx.debugger_attached?
    assert_equal 3, ctx.eval("1 + 2")
  end

  def test_unicode_round_trip
    ctx = new_context(inspector: "unicode")
    client = attach_like_devtools("unicode")
    ctx.eval("var s = 'café \u{1F600}'")
    r = client.command("Runtime.evaluate", expression: "s + '   ok'")
    assert_equal "café \u{1F600}   ok", r["result"]["value"]
  end

  def test_websocket_from_web_page_origin_is_refused
    new_context(inspector: "origin")
    err = assert_raises(RuntimeError) { connect("origin", headers: { "Origin" => "https://evil.example" }) }
    assert_match(/403/, err.message)
    client = connect("origin", headers: { "Origin" => "devtools://devtools" })
    assert_equal 2, client.command("Runtime.evaluate", expression: "1 + 1")["result"]["value"]
  end

  def test_oversized_control_frame_closes_connection
    new_context(inspector: "big-ping")
    client = connect("big-ping")
    client.send_frame(0x9, "x" * 200)
    assert client.closed_by_peer?
  end

  def test_refuses_non_loopback_host_without_allow_remote
    assert_raises(ArgumentError) { MiniRacer::Inspector.start(host: "0.0.0.0", port: 0) }
    assert_raises(ArgumentError) { MiniRacer::Inspector.start(host: "example.com", port: 0) }
    # already started on 127.0.0.1: another host is refused, not ignored
    assert_raises(ArgumentError) { MiniRacer::Inspector.start(host: "::1", port: 0) }
    assert_raises(ArgumentError) { MiniRacer::Inspector.start(host: "0.0.0.0", port: 0, allow_remote: true) }
    assert_equal "http://127.0.0.1:#{@port}/json/list", MiniRacer::Inspector.url
  end

  def test_max_pause_terminates_a_forgotten_breakpoint
    ctx = new_context(inspector: "max-pause", max_pause: 300)
    client = attach_like_devtools("max-pause")
    th = Thread.new { ctx.eval("debugger; 'unreachable'") }
    client.wait_event("Debugger.paused")
    assert_raises(MiniRacer::ScriptTerminatedError) { th.value }
    assert_equal 2, ctx.eval("1 + 1")
  end

  def test_max_pause_zero_means_no_cap
    ctx = new_context(inspector: "no-cap", max_pause: 0)
    client = attach_like_devtools("no-cap")
    th = Thread.new { ctx.eval("debugger; 'resumed'") }
    client.wait_event("Debugger.paused")
    sleep 0.3
    client.command("Debugger.resume")
    assert_equal "resumed", th.value
  end

  def test_bad_max_pause
    assert_raises(ArgumentError) { MiniRacer::Context.new(max_pause: -1) }
  end

  def test_breakpoint_in_function_compiled_before_attach
    ctx = new_context(inspector: "pre-attach")
    ctx.eval("function twice(x) {\n  return x * 2;\n}", filename: "pre.js")
    client = attach_like_devtools("pre-attach")
    client.command("Debugger.setBreakpointByUrl", lineNumber: 1, url: "pre.js")
    th = Thread.new { ctx.eval("twice(21)") }
    paused = client.wait_event("Debugger.paused")
    assert_equal 1, paused["callFrames"].first["location"]["lineNumber"]
    client.command("Debugger.resume")
    assert_equal 42, th.value
  end

  def test_reattach_after_idle_disconnect
    ctx = new_context(inspector: "reattach")
    3.times do |i|
      client = attach_like_devtools("reattach")
      assert_equal i, client.command("Runtime.evaluate", expression: "#{i}")["result"]["value"]
      client.close
      @clients.delete(client)
      sleep 0.01 while ctx.debugger_attached?
    end
    assert_equal 2, ctx.eval("1 + 1")
  end

  def test_start_refuses_different_settings_and_reports_its_endpoint
    assert_equal @port, MiniRacer::Inspector.start(port: 0)
    assert_raises(ArgumentError) { MiniRacer::Inspector.start(port: 0, max_connections: 5) }
    assert_raises(ArgumentError) { MiniRacer::Inspector.start(port: 0, token: "late") }
    assert_raises(ArgumentError) { MiniRacer::Inspector.start(port: 0, frobnicate: 1) }
    # 0.5 would truncate to 0, which natively means no cap
    assert_raises(ArgumentError) { MiniRacer::Inspector.start(port: 0, max_targets: 0.5) }
    endpoint = MiniRacer::Inspector.endpoint
    assert_equal({ host: "127.0.0.1", port: @port, pid: Process.pid },
                 endpoint.slice(:host, :port, :pid))
    assert_match(/\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/, endpoint[:boot_id])
  end

  def test_stop_drops_frontends_and_a_restart_lists_the_contexts_again
    ctx = new_context(inspector: "survives-stop")
    client = attach_like_devtools("survives-stop")
    th = Thread.new { ctx.eval("debugger; 'resumed'") }
    client.wait_event("Debugger.paused")
    boot_id = MiniRacer::Inspector.endpoint[:boot_id]
    assert MiniRacer::Inspector.stop
    refute MiniRacer::Inspector.started?
    assert_nil MiniRacer::Inspector.endpoint
    assert client.closed_by_peer?
    assert_equal "resumed", th.value # inspector_detach: :resume, the default
    refute MiniRacer::Inspector.stop
    @port = MiniRacer::Inspector.start(port: 0)
    refute_equal boot_id, MiniRacer::Inspector.endpoint[:boot_id]
    assert_includes targets[1].map { |t| t["title"] }, "survives-stop"
  end

  def test_max_targets_and_handshake_timeout
    script = <<~RUBY
      require "mini_racer"
      require "socket"
      port = MiniRacer::Inspector.start(port: 0, max_targets: 2, handshake_timeout: 0.2)
      a = MiniRacer::Context.new(inspector: "a")
      b = MiniRacer::Context.new(inspector: "b")
      checks = []
      checks << (MiniRacer::Inspector.target_count == 2)
      begin
        MiniRacer::Context.new(inspector: "c")
        checks << false
      rescue MiniRacer::RuntimeError => e
        checks << e.message.include?("too many targets")
      end
      checks << (MiniRacer::Context.new.eval("1 + 1") == 2) # not inspectable: not counted
      a.dispose
      c = MiniRacer::Context.new(inspector: "c")
      checks << (c.eval("2 + 2") == 4)
      # a connection that never sends its request is dropped
      sock = TCPSocket.new("127.0.0.1", port)
      t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      checks << (sock.wait_readable(5) && (begin; sock.read_nonblock(1, exception: false); rescue Errno::ECONNRESET; nil; end).nil?) # a reset is closed too
      checks << (Process.clock_gettime(Process::CLOCK_MONOTONIC) - t < 3)
      puts checks.inspect
      exit!(checks.all? ? 0 : 1)
    RUBY
    out, err, status =
      Open3.capture3(RbConfig.ruby, "-I", File.expand_path("../lib", __dir__), "-e", script)
    assert status.success?, "#{out} #{err}"
  end

  def test_events_follow_a_debugging_session
    MiniRacer::Inspector.events(max: 64) while MiniRacer::Inspector.events(max: 64).any?
    ctx = new_context(inspector: "events", inspector_detach: :terminate)
    id = ctx.inspector_target_id
    client = attach_like_devtools("events")
    th = Thread.new do
      Thread.current.report_on_exception = false
      ctx.eval("debugger; debugger; 1")
    end
    client.wait_event("Debugger.paused")
    client.command("Debugger.resume")
    client.wait_event("Debugger.paused")
    client.close
    assert_raises(MiniRacer::ScriptTerminatedError) { th.value }
    ctx.dispose
    seen = []
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
    until seen.any? { |e| e[:event] == :destroyed } ||
            Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      seen.concat(MiniRacer::Inspector.events(timeout: 0.5).select { |e| e[:target_id] == id })
    end
    assert_equal %i[created attached paused resumed paused detached terminated resumed destroyed],
                 seen.map { |e| e[:event] }
    assert_equal [1, 2], seen.select { |e| e[:event] == :paused }.map { |e| e[:pause_generation] }
    assert_equal :detach, seen.find { |e| e[:event] == :terminated }[:reason]
    assert_equal seen.map { |e| e[:seq] }.sort, seen.map { |e| e[:seq] }
    assert_kind_of Float, seen.first[:at]
  end

  def test_ambiguous_requests_are_refused
    t = new_context(inspector: "strict") && target_for("strict")["id"]
    host = "Host: 127.0.0.1:#{@port}\r\n"
    # a second Host, a name with a space, a folded line, HTTP/0.9-ish
    assert_includes raw_request("GET /json/list HTTP/1.1\r\n#{host}Host: evil.example\r\n\r\n"), " 400 "
    assert_includes raw_request("GET /json/list HTTP/1.1\r\nHost : 127.0.0.1\r\n\r\n"), " 400 "
    assert_includes raw_request("GET /json/list HTTP/1.1\r\n#{host}X-A: 1\r\n folded\r\n\r\n"), " 400 "
    assert_includes raw_request("GET /json/list HTTP/2.0\r\n#{host}\r\n"), " 400 "
    assert_includes raw_request("GET /json/list HTTP/1.1\r\n#{host}\r\n"), " 200 "
    # control characters in a value; HTTP/1.1 without Host (1.0 may omit it)
    assert_includes raw_request("GET /json/list HTTP/1.1\r\n#{host}X-A: a\x01b\r\n\r\n"), " 400 "
    assert_includes raw_request("GET /json/list HTTP/1.1\r\n#{host}X-A: a\x7fb\r\n\r\n"), " 400 "
    assert_includes raw_request("GET /json/list HTTP/1.1\r\n#{host}X-A: a\tb\r\n\r\n"), " 200 "
    assert_includes raw_request("GET /json/list HTTP/1.1\r\n\r\n"), " 400 "
    assert_includes raw_request("GET /json/list HTTP/1.0\r\n\r\n"), " 200 "
    # a head over 64 KiB is refused even when the read that ends it is short
    sock = TCPSocket.new("127.0.0.1", @port)
    sock.write("GET /json/list HTTP/1.1\r\n#{host}X-Big: #{"a" * 60_000}")
    sleep 0.2
    sock.write("#{"a" * 6000}\r\n\r\n")
    refute_includes sock.gets.to_s, " 200 "
    sock.close
    # Connection must contain the token "upgrade", the key must be 16 bytes of base64
    head = upgrade_head("/#{t}")
    assert_includes raw_request(head.sub("Connection: Upgrade", "Connection: notupgrade")), " 400 "
    assert_includes raw_request(head.sub("Connection: Upgrade", "Connection: keep-alive, Upgrade")), " 101 "
    bad_key = head.sub(/Sec-WebSocket-Key: \S+/, "Sec-WebSocket-Key: #{"!" * 22}==")
    assert_includes raw_request(bad_key), " 400 "
    assert_includes raw_request(head.sub("HTTP/1.1", "HTTP/1.0")), " 400 "
  end

  def test_malformed_frames_close_the_connection
    new_context(inspector: "frames")
    [
      ->(c) { c.write_raw([0x81, 0x80 | 126, 5].pack("CCn") + "\0\0\0\0{}{}{") }, # 16-bit length for 5 bytes
      ->(c) { c.write_raw([0x81, 0x80 | 127, 5].pack("CCQ>") + "\0\0\0\0{}{}{") }, # 64-bit length for 5 bytes
      ->(c) { c.send_frame_bits(0xC1, "{}") },         # RSV1 set
      ->(c) { c.send_frame_bits(0x80, "{}") },         # continuation of nothing
      ->(c) { c.send_frame_bits(0x01, "{\"id\":1,"); c.send_frame_bits(0x81, "{}") }, # new message mid-fragment
      ->(c) { c.send_frame(0x1, "\xff\xfe".b) }        # not UTF-8
    ].each do |send_bad|
      client = connect("frames")
      send_bad.(client)
      assert client.closed_by_peer?
      @clients.delete(client)
    end
    # a correctly fragmented message is fine
    client = connect("frames")
    msg = JSON.generate(id: 1, method: "Runtime.evaluate", params: { expression: "6 * 7" })
    client.send_frame_bits(0x01, msg[0, 10])
    client.send_frame_bits(0x80, msg[10..])
    assert_equal 42, client.wait_response(1)["result"]["value"]
  end

  def test_close_frames_are_answered_with_a_valid_code
    new_context(inspector: "close")
    { [1000].pack("n") + "bye" => [1000].pack("n"),
      "" => "",
      [1012].pack("n") => [1012].pack("n"),             # registered: service restart
      [1013].pack("n") => [1013].pack("n"),             # try again later
      [1014].pack("n") => [1014].pack("n"),             # bad gateway
      [1015].pack("n") => [1002].pack("n"),             # reserved for TLS failures
      [1001].pack("n") + "\xff".b => [1002].pack("n"), # reason not UTF-8
      [999].pack("n") => [1002].pack("n"),              # not a code to send
      [1005].pack("n") => [1002].pack("n"),             # reserved
      "\x03" => [1002].pack("n") }.each do |sent, answer|                # one byte
      client = connect("close")
      client.send_frame(0x8, sent)
      assert_equal [0x8, answer.b], client.read_frame, sent.inspect
      assert client.closed_by_peer?
      @clients.delete(client)
    end
  end

  def test_a_stalled_partial_frame_is_dropped
    script = <<~RUBY
      require "mini_racer"
      require "socket"
      require "securerandom"
      port = MiniRacer::Inspector.start(port: 0, handshake_timeout: 0.3)
      ctx = MiniRacer::Context.new(inspector: "stall")
      id = ctx.inspector_target_id
      sock = TCPSocket.new("127.0.0.1", port)
      sock.write("GET /\#{id} HTTP/1.1\\r\\nHost: 127.0.0.1:\#{port}\\r\\nUpgrade: websocket\\r\\n" \\
                 "Connection: Upgrade\\r\\nSec-WebSocket-Key: \#{SecureRandom.base64(16)}\\r\\n" \\
                 "Sec-WebSocket-Version: 13\\r\\n\\r\\n")
      nil while sock.gets != "\\r\\n"
      sock.write([0x81, 0x80 | 100].pack("CC") + "mask" + "x" * 10) # 10 of 100 bytes
      t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      closed = sock.wait_readable(5) && (begin; sock.read_nonblock(1, exception: false); rescue Errno::ECONNRESET; nil; end).nil? # a reset is closed too
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t
      exit!(closed && elapsed < 3 ? 0 : 1)
    RUBY
    _, err, status =
      Open3.capture3(RbConfig.ruby, "-I", File.expand_path("../lib", __dir__), "-e", script)
    assert status.success?, err
  end

  def test_back_to_back_messages_each_get_the_partial_frame_timeout
    script = <<~RUBY
      require "mini_racer"
      require "socket"
      require "securerandom"
      port = MiniRacer::Inspector.start(port: 0, handshake_timeout: 0.5)
      ctx = MiniRacer::Context.new(inspector: "steady")
      id = ctx.inspector_target_id
      sock = TCPSocket.new("127.0.0.1", port)
      sock.write("GET /\#{id} HTTP/1.1\\r\\nHost: 127.0.0.1:\#{port}\\r\\nUpgrade: websocket\\r\\n" \\
                 "Connection: Upgrade\\r\\nSec-WebSocket-Key: \#{SecureRandom.base64(16)}\\r\\n" \\
                 "Sec-WebSocket-Version: 13\\r\\n\\r\\n")
      nil while sock.gets != "\\r\\n"
      ping = [0x89, 0x80 | 4].pack("CC") + "\\0\\0\\0\\0ping" # masked with zeros
      # each write ends one ping and starts the next, for 3x handshake_timeout
      sock.write(ping[0, 3])
      10.times { sleep 0.15; sock.write(ping[3..] + ping[0, 3]) }
      sock.write(ping[3..])
      pongs = 0
      while sock.wait_readable(1) && (head = sock.read(2))
        pongs += 1 if head.getbyte(0) == 0x8A
        sock.read(head.getbyte(1) & 0x7f)
        break if pongs == 11
      end
      exit!(pongs == 11 ? 0 : 1)
    RUBY
    _, err, status =
      Open3.capture3(RbConfig.ruby, "-I", File.expand_path("../lib", __dir__), "-e", script)
    assert status.success?, err
  end

  def test_a_backlog_of_debugger_commands_does_not_hold_up_an_eval
    ctx = new_context(inspector: "fair", timeout: 5000)
    client = connect("fair")
    # about 6 s of work queued at once, 30 ms a command
    client.send_texts(*Array.new(200) { |i|
      JSON.generate(id: 100 + i, method: "Runtime.evaluate",
                    params: { expression: "for (const t = Date.now(); Date.now() - t < 30;); #{i}" })
    })
    client.wait_response(100) # the V8 thread has started on them
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_equal 2, ctx.eval("1 + 1")
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 1.5,
                    "the eval went ahead of the queued commands"
    # and the commands still run after it
    assert_equal 199, client.wait_response(299, timeout: 15)["result"]["value"]
  end

  def test_two_endless_commands_in_a_pause_both_end
    ctx = new_context(inspector: "nested-two", timeout: 1000, max_pause: 1500)
    client = attach_like_devtools("nested-two")
    th = Thread.new do
      ctx.eval("debugger; 'after'")
    rescue MiniRacer::Error => e
      e
    end
    frame = client.wait_event("Debugger.paused")["callFrames"][0]["callFrameId"]
    endless = { callFrameId: frame, expression: "for (;;) {}" }
    client.send_texts(JSON.generate(id: 20, method: "Debugger.evaluateOnCallFrame", params: endless),
                      JSON.generate(id: 21, method: "Debugger.evaluateOnCallFrame", params: endless))
    # max_pause ends the pause and what runs in it, the second command too:
    # both answer, and the eval returns
    replies = [20, 21].map { |id| client.wait_message(id, timeout: 8) }
    assert_equal [20, 21], replies.map { _1["id"] }
    # the first is terminated by max_pause; V8 refuses the second (-32603),
    # with no result: it never ran
    assert_equal "Execution was terminated", replies[0].dig("error", "message"), replies[0]
    assert_equal [-32603, "Internal error"], [replies[1].dig("error", "code"), replies[1].dig("error", "message")], replies[1]
    assert_nil replies[1]["result"]
    assert th.join(8), "the eval never returned: a nested command ran unwatched"
    assert_equal 2, ctx.eval("1 + 1")
  end

  def test_commands_left_queued_when_a_pause_ends_are_answered_while_the_script_runs
    ctx = new_context(inspector: "resume-backlog", timeout: 10_000)
    client = attach_like_devtools("resume-backlog")
    th = Thread.new { ctx.eval("debugger; for (const t = Date.now(); Date.now() - t < 2000;); 'done'") }
    frame = client.wait_event("Debugger.paused")["callFrames"][0]["callFrameId"]
    # A nested evaluation runs JavaScript in the pause, which spends the
    # interrupt the frontend's wake asked for (it does nothing while
    # paused). Then the resume, and more than a pause batch (64) behind it:
    # the rest are still queued when the pause ends, with no interrupt left.
    nested = JSON.generate(id: 998, method: "Debugger.evaluateOnCallFrame",
                           params: { callFrameId: frame, expression: "for (let i = 0; i < 1e6; i++); 1" })
    commands = Array.new(100) { |i| JSON.generate(id: 1000 + i, method: "Runtime.evaluate", params: { expression: i.to_s }) }
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    client.send_texts(nested, JSON.generate(id: 999, method: "Debugger.resume", params: {}), *commands)
    assert_equal 99, client.wait_response(1099, timeout: 5)["result"]["value"]
    # answered while the resumed script runs, not after its 2 s
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 1.5
    assert_equal "done", th.value
  end

  def test_reconnecting_while_the_context_is_busy_is_refused_at_the_queue_cap
    script = <<~'RUBY'
      require "mini_racer"
      require "socket"
      require "securerandom"
      port = MiniRacer::Inspector.start(port: 0, max_queued_messages: 4)
      ctx = MiniRacer::Context.new(inspector: "cap")
      ctx.attach("nap", -> { sleep 1.5; 1 })
      id = ctx.inspector_target_id
      upgrade = lambda do
        sock = TCPSocket.new("127.0.0.1", port)
        sock.write("GET /#{id} HTTP/1.1\r\nHost: 127.0.0.1:#{port}\r\nUpgrade: websocket\r\n" \
                   "Connection: Upgrade\r\nSec-WebSocket-Key: #{SecureRandom.base64(16)}\r\n" \
                   "Sec-WebSocket-Version: 13\r\n\r\n")
        status = sock.gets.to_s
        [sock, status]
      end
      th = Thread.new { ctx.eval("nap()") }
      sleep 0.2 # V8 is in the Ruby callback: nothing queued is handled
      statuses = []
      8.times do
        sock, status = upgrade.call
        statuses << status[/ (\d{3}) /, 1]
        sock.close
        sleep 0.05 # let the server see the close before the next try
      end
      th.join
      sleep 0.2
      # the queue drained once V8 was free: attaching works again
      sock, status = upgrade.call
      sock.close
      ok = statuses.include?("503") && statuses.count("101") <= 3 && status.include?(" 101 ")
      warn statuses.inspect, status unless ok
      exit!(ok ? 0 : 1)
    RUBY
    _, err, status =
      Open3.capture3(RbConfig.ruby, "-I", File.expand_path("../lib", __dir__), "-e", script)
    assert status.success?, err
  end

  def test_pings_inside_a_stalled_fragmented_message_do_not_keep_it_alive
    script = <<~RUBY
      require "mini_racer"
      require "socket"
      require "securerandom"
      port = MiniRacer::Inspector.start(port: 0, handshake_timeout: 0.5)
      ctx = MiniRacer::Context.new(inspector: "fragments")
      id = ctx.inspector_target_id
      sock = TCPSocket.new("127.0.0.1", port)
      sock.write("GET /\#{id} HTTP/1.1\\r\\nHost: 127.0.0.1:\#{port}\\r\\nUpgrade: websocket\\r\\n" \\
                 "Connection: Upgrade\\r\\nSec-WebSocket-Key: \#{SecureRandom.base64(16)}\\r\\n" \\
                 "Sec-WebSocket-Version: 13\\r\\n\\r\\n")
      nil while sock.gets != "\\r\\n"
      # the first fragment of a text message (no FIN), then only pings
      sock.write([0x01, 0x80 | 2].pack("CC") + "\\0\\0\\0\\0{a")
      ping = [0x89, 0x80 | 4].pack("CC") + "\\0\\0\\0\\0ping"
      t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      closed = false
      20.times do
        sleep 0.1
        begin
          sock.write(ping)
        rescue Errno::EPIPE, Errno::ECONNRESET
          closed = true
          break
        end
        while sock.wait_readable(0)
          head = begin
            sock.read_nonblock(2, exception: false)
          rescue Errno::ECONNRESET
            nil # dropped: as good as EOF here
          end
          if head.nil? || head == :wait_readable
            closed = head.nil?
            break
          end
          sock.read(head.getbyte(1) & 0x7f)
        end
        break if closed
      end
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t
      exit!(closed && elapsed < 1.5 ? 0 : 1)
    RUBY
    _, err, status =
      Open3.capture3(RbConfig.ruby, "-I", File.expand_path("../lib", __dir__), "-e", script)
    assert status.success?, err
  end

  def test_a_frontend_that_stops_reading_cannot_stall_the_script
    script = <<~RUBY
      require "mini_racer"
      require "socket"
      require "securerandom"
      require "json"
      port = MiniRacer::Inspector.start(port: 0, max_queued_bytes: 1 << 20, send_idle_timeout: 1)
      ctx = MiniRacer::Context.new(inspector: "slow")
      id = ctx.inspector_target_id
      sock = TCPSocket.new("127.0.0.1", port)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 4096)
      sock.write("GET /\#{id} HTTP/1.1\\r\\nHost: 127.0.0.1:\#{port}\\r\\nUpgrade: websocket\\r\\n" \\
                 "Connection: Upgrade\\r\\nSec-WebSocket-Key: \#{SecureRandom.base64(16)}\\r\\n" \\
                 "Sec-WebSocket-Version: 13\\r\\n\\r\\n")
      nil while sock.gets != "\\r\\n"
      msg = JSON.generate(id: 1, method: "Runtime.enable")
      sock.write([0x81, 0x80 | msg.bytesize].pack("CC") + "\\0\\0\\0\\0" + msg)
      sleep 0.2 # then never read again
      t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      n = ctx.eval("for (let i = 0; i < 20000; i++) console.log('x'.repeat(500)); 20000")
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t
      sleep 0.5
      exit!(n == 20000 && elapsed < 5 && !ctx.debugger_attached? ? 0 : 1)
    RUBY
    _, err, status =
      Open3.capture3(RbConfig.ruby, "-I", File.expand_path("../lib", __dir__), "-e", script)
    assert status.success?, err
  end

  def test_the_next_frontend_does_not_see_the_last_ones_console
    ctx = new_context(inspector: "console-discard")
    first = attach_like_devtools("console-discard")
    ctx.eval("console.log('session one secret')")
    first.wait_event("Runtime.consoleAPICalled")
    first.close
    @clients.delete(first)
    sleep 0.01 while ctx.debugger_attached?
    second = connect("console-discard")
    second.command("Runtime.enable")
    ctx.eval("console.log('session two')")
    seen = second.wait_event("Runtime.consoleAPICalled")
    assert_equal "session two", seen["args"][0]["value"]
  end

  def test_a_quick_reconnect_sees_nothing_of_the_last_frontends_queued_commands
    ctx = new_context(inspector: "quick-reconnect")
    ctx.attach("nap", -> { sleep 1; 1 })
    ctx.eval("console.log('left by session one')")
    first = connect("quick-reconnect")
    th = Thread.new { ctx.eval("nap()") }
    sleep 0.2 # inside the Ruby callback: what the first frontend sends now waits
    first.send_text(JSON.generate(id: 777, method: "Runtime.enable", params: {}))
    first.close
    @clients.delete(first)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
    begin
      second = connect("quick-reconnect")
    rescue RuntimeError # 409 until the server has seen the close
      raise if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.01
      retry
    end
    assert_equal 1, th.value # the queued enable, disconnect and connect run now
    second.command("Runtime.enable")
    ctx.eval("console.log('session two')")
    assert_equal "session two", second.wait_event("Runtime.consoleAPICalled")["args"][0]["value"]
    # neither the reply to the first frontend's enable nor what it replayed,
    # nor the reply to the discardConsoleEntries sent when it left
    assert_empty second.events.select { |m| [777, -1].include?(m["id"]) }
    assert_empty(second.events.select { |m| m.to_s.include?("left by session one") })
  end

  def test_a_frontend_that_attaches_during_the_last_ones_paused_command_gets_none_of_its_replies
    ctx = new_context(inspector: "paused-handover")
    first = attach_like_devtools("paused-handover")
    # a command that pauses: its reply comes only once the pause ends
    first.send_text(JSON.generate(id: 4242, method: "Runtime.evaluate", params: { expression: "debugger; 'done'" }))
    frame = first.wait_event("Debugger.paused")["callFrames"][0]["callFrameId"]
    # keep V8 busy inside the pause while the frontends change over, so it
    # finds the old one's Disconnect and the new one's Connect together
    first.send_text(JSON.generate(id: 4243, method: "Debugger.evaluateOnCallFrame",
                                  params: { callFrameId: frame, expression: "for (const t = Date.now(); Date.now() - t < 800;); 1" }))
    sleep 0.1
    first.close
    @clients.delete(first)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
    begin
      second = connect("paused-handover")
    rescue RuntimeError # 409 until the server has seen the close
      raise if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.01
      retry
    end
    assert_equal 42, second.command("Runtime.evaluate", expression: "6 * 7")["result"]["value"]
    second.command("Runtime.enable")
    assert_empty second.events.select { |m| [4242, 4243, -1].include?(m["id"]) }
    refute ctx.eval("1; false") # the context carries on
  end

  def test_a_second_breakpoint_in_the_last_frontends_command_does_not_lock_out_the_next
    ctx = new_context(inspector: "second-pause")
    first = attach_like_devtools("second-pause")
    first.send_text(JSON.generate(id: 4242, method: "Runtime.evaluate",
                                  params: { expression: "debugger; debugger; 'done'" }))
    frame = first.wait_event("Debugger.paused")["callFrames"][0]["callFrameId"]
    first.send_text(JSON.generate(id: 4243, method: "Debugger.evaluateOnCallFrame",
                                  params: { callFrameId: frame, expression: "for (const t = Date.now(); Date.now() - t < 800;); 1" }))
    sleep 0.1
    first.close
    @clients.delete(first)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
    begin
      second = connect("second-pause")
    rescue RuntimeError
      raise if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.01
      retry
    end
    # the resumed command passes its second debugger statement without
    # pausing for nobody, so the next frontend gets in
    assert_equal 42, second.command("Runtime.evaluate", expression: "6 * 7")["result"]["value"]
    assert_equal 2, ctx.eval("1 + 1")
  end

  def test_a_debugger_command_while_idle_is_held_to_the_timeout
    ctx = new_context(inspector: "idle-timeout", timeout: 300)
    client = connect("idle-timeout")
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    # queued together, both endless: each is stopped at its own 300 ms, so
    # the second can't have run unwatched (it would never answer), and the
    # pair takes at least two timeouts
    endless = JSON.generate(method: "Runtime.evaluate", params: { expression: "for (;;) {}" })
    client.send_texts(endless.sub("{", '{"id":9,'), endless.sub("{", '{"id":10,'))
    assert_equal "Execution was terminated", client.wait_message(9)["error"]["message"]
    assert_equal "Execution was terminated", client.wait_message(10)["error"]["message"]
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    assert_operator elapsed, :>=, 0.55
    assert_operator elapsed, :<, 4
    assert_equal 2, ctx.eval("1 + 1") # and the termination doesn't leak into the next eval
  end

  def test_stop_during_a_blocked_callback_and_a_pause
    ctx = new_context(inspector: "stop-under-load")
    ctx.attach("slowRuby", -> { sleep 1; 7 })
    client = attach_like_devtools("stop-under-load")
    th = Thread.new { ctx.eval("slowRuby() + 1") }
    sleep 0.2 # inside the Ruby callback
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert MiniRacer::Inspector.stop
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 3
    assert_equal 8, th.value
    assert client.closed_by_peer?
    @clients.delete(client)
    # and while paused: the default detach policy resumes
    @port = MiniRacer::Inspector.start(port: 0)
    client = attach_like_devtools("stop-under-load")
    th = Thread.new { ctx.eval("debugger; 'resumed'") }
    client.wait_event("Debugger.paused")
    assert MiniRacer::Inspector.stop
    assert_equal "resumed", th.value
    @port = MiniRacer::Inspector.start(port: 0)
  end

  def test_fork_child_starts_without_parent_targets
    skip "no fork" unless Process.respond_to?(:fork)
    new_context(inspector: "parent-only")
    pid = fork do
      ok = MiniRacer::Inspector.port.nil?
      port = MiniRacer::Inspector.start(port: 0)
      list = Net::HTTP.start("127.0.0.1", port) { |h| JSON.parse(h.get("/json/list").body) }
      exit!(ok && list.empty? ? 0 : 1)
    end
    _, status = Process.wait2(pid)
    assert status.success?, "child saw parent state"
    assert_includes targets[1].map { |t| t["title"] }, "parent-only"
  end

  def raw_request(head)
    sock = TCPSocket.new("127.0.0.1", @port)
    sock.write(head)
    sock.gets.to_s
  ensure
    sock&.close
  end

  def upgrade_head(path, method: "GET", extra: "", version: "13")
    "#{method} #{path} HTTP/1.1\r\nHost: 127.0.0.1:#{@port}\r\n" \
      "Upgrade: websocket\r\nConnection: Upgrade\r\n" \
      "Sec-WebSocket-Key: #{SecureRandom.base64(16)}\r\n" \
      "Sec-WebSocket-Version: #{version}\r\n#{extra}\r\n"
  end

  def test_upgrade_requires_a_real_websocket_handshake
    new_context(inspector: "strict")
    path = URI(target_for("strict")["webSocketDebuggerUrl"]).path
    assert_includes raw_request(upgrade_head(path, method: "POST")), " 400 "
    assert_includes raw_request(upgrade_head(path, version: "8")), " 400 "
    # an HTTP client smuggling frames after the request head
    assert_includes raw_request(upgrade_head(path) + "\x81\x85abcdefghi"), " 400 "
    assert_includes raw_request(upgrade_head(path)), " 101 "
  end

  def test_upgrade_with_a_body_is_refused
    new_context(inspector: "no-body")
    path = URI(target_for("no-body")["webSocketDebuggerUrl"]).path
    # the body could arrive in a later packet and be read as frames
    assert_includes raw_request(upgrade_head(path, extra: "Content-Length: 9\r\n")), " 400 "
    assert_includes raw_request(upgrade_head(path, extra: "Transfer-Encoding: chunked\r\n")), " 400 "
  end

  def test_max_pause_ends_a_debugger_expression_that_never_returns
    ctx = new_context(inspector: "eval-forever", timeout: 100, max_pause: 300)
    client = attach_like_devtools("eval-forever")
    th = Thread.new { ctx.eval("debugger; 'unreachable'") }
    frame = client.wait_event("Debugger.paused")["callFrames"].first
    client.send_text(JSON.generate(id: 99, method: "Debugger.evaluateOnCallFrame",
                                   params: { callFrameId: frame["callFrameId"], expression: "while (true) {}" }))
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_raises(MiniRacer::ScriptTerminatedError) { th.value }
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 3
    assert_equal 2, ctx.eval("1 + 1")
  end

  def test_debugger_message_reaches_a_context_waiting_in_await
    ctx = new_context(inspector: "await")
    client = connect("await")
    th = Thread.new { ctx.eval_await("new Promise(r => globalThis.finish = r)") }
    sleep 0.3 # the context admits one Ruby thread at a time; don't poll it
    client.command("Runtime.evaluate", expression: "finish(42)")
    assert_equal 42, th.join(5)&.value
  end

  def test_frontend_that_floods_a_busy_context_is_dropped
    ctx = new_context(inspector: "flood")
    client = connect("flood")
    release = Queue.new
    ctx.attach("block", proc { release.pop })
    th = Thread.new { ctx.eval("block(); 1") }
    sleep 0.1
    msg = JSON.generate(id: 1, method: "Runtime.evaluate", params: { expression: "1" })
    begin
      5000.times { client.send_text(msg) }
    rescue Errno::EPIPE, Errno::ECONNRESET
      # dropped while still sending
    end
    assert client.closed_by_peer?
    release << :go
    assert_equal 1, th.value
  end

  def test_idle_connections_expire
    skip "takes 10 s; set MINI_RACER_SLOW_TESTS=1" unless ENV["MINI_RACER_SLOW_TESTS"]
    idle = Array.new(32) { TCPSocket.new("127.0.0.1", @port) }
    sleep 0.2
    assert_raises(EOFError, Errno::ECONNRESET, Errno::EPIPE) { targets }
    sleep 11
    assert_equal 200, targets.first
  ensure
    idle&.each(&:close)
  end

  def test_origin_matching_host_is_allowed
    new_context(inspector: "same-origin")
    client = connect("same-origin", headers: { "Origin" => "http://127.0.0.1:#{@port}" })
    assert_equal 2, client.command("Runtime.evaluate", expression: "1 + 1")["result"]["value"]
  end

  def test_token_guards_every_url
    script = <<~RUBY
      require "mini_racer"
      require "net/http"
      require "json"
      require "socket"
      port = MiniRacer::Inspector.start(port: 0, token: "s3cret")
      ctx = MiniRacer::Context.new(inspector: "tokened")
      get = ->(path) { Net::HTTP.start("127.0.0.1", port) { |h| h.get(path) } }
      checks = []
      checks << (get.("/json/list").code == "404")
      checks << (get.("/s3cretx/json/list").code == "404")
      res = get.("/s3cret/json/list")
      checks << (res.code == "200")
      ws = JSON.parse(res.body).first["webSocketDebuggerUrl"]
      checks << ws.start_with?("ws://127.0.0.1:\#{port}/s3cret/")
      checks << (MiniRacer::Inspector.url == "http://127.0.0.1:\#{port}/s3cret/json/list")
      sock = TCPSocket.new("127.0.0.1", port)
      sock.write("GET \#{URI(ws).path} HTTP/1.1\\r\\nHost: 127.0.0.1:\#{port}\\r\\n" \\
        "Upgrade: websocket\\r\\nConnection: Upgrade\\r\\n" \\
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\\r\\nSec-WebSocket-Version: 13\\r\\n\\r\\n")
      checks << sock.gets.include?(" 101 ")
      sock.close
      ctx.dispose
      exit(checks.all? ? 0 : 1)
    RUBY
    out = IO.popen([RbConfig.ruby, "-I", File.expand_path("../lib", __dir__),
                    "-I", File.expand_path("../ext", __dir__), "-e", script], err: [:child, :out], &:read)
    assert $?.success?, "token checks failed: #{out}"
  end
end
