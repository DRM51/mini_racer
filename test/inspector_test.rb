# frozen_string_literal: true

require_relative "test_helper"
require "socket"
require "securerandom"
require "uri"
require "net/http"

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

  def closed_by_peer?(timeout: 5)
    return false unless @sock.wait_readable(timeout)
    @sock.read_nonblock(65_536, exception: false).nil?
  rescue Errno::ECONNRESET
    true
  end

  def send_text(text)
    send_frame(0x1, text)
  end

  def send_frame(opcode, payload)
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
    @sock.write(header + mask.pack("C*") + masked.pack("C*"))
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
    refute_includes targets[1].map { |t| t["title"] }, "short-lived"
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
    # already started, so these return the running server's port
    assert_equal @port, MiniRacer::Inspector.start(host: "::1", port: 0)
    assert_equal @port, MiniRacer::Inspector.start(host: "localhost", port: 0)
    assert_equal @port, MiniRacer::Inspector.start(host: "0.0.0.0", port: 0, allow_remote: true)
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
