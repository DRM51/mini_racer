require "mini_racer/version"
require "pathname"

module MiniRacer
  class Binary
    attr_reader :data

    def initialize(data)
      unless data.is_a?(String)
        raise TypeError, "wrong argument type #{data.class} (expected String)"
      end
      @data = data
    end
  end
end

if RUBY_ENGINE == "truffleruby"
  require "mini_racer/truffleruby"
else
  if ENV["LD_PRELOAD"].to_s.include?("malloc")
    require "mini_racer_extension"
  else
    require "mini_racer_loader"
    ext_filename = "mini_racer_extension.#{RbConfig::CONFIG["DLEXT"]}"
    ext_path =
      Gem.loaded_specs["mini_racer"].require_paths.map do |p|
        (p = Pathname.new(p)).absolute? ? p : Pathname.new(__dir__).parent + p
      end
    ext_found = ext_path.map { |p| p + ext_filename }.find { |p| p.file? }

    unless ext_found
      raise LoadError,
            "Could not find #{ext_filename} in #{ext_path.map(&:to_s)}"
    end
    MiniRacer::Loader.load(ext_found.to_s)
  end
end

require "json"
require "io/wait"

module MiniRacer
  class Error < ::StandardError
  end

  class ContextDisposedError < Error
  end
  class PlatformAlreadyInitialized < Error
  end

  class EvalError < Error
  end
  class ParseError < EvalError
  end
  class ScriptTerminatedError < EvalError
  end
  class V8OutOfMemoryError < EvalError
  end

  class RuntimeError < EvalError
    # With Context.new(capture_on_throw: true): where the uncaught exception
    # was thrown and the local variables of each frame, as
    #   {"reason" => "exception", "frames" => [{"function" => "f",
    #    "url" => "transform.js", "line" => 3, "column" => 9,
    #    "scopes" => [{"type" => "local", "variables" => {"x" => 1}}]}]}
    # Values are copies, cut off at a few levels deep and a few hundred
    # characters; getters and proxies show as "[Getter]" and "[Proxy]".
    # "truncated" => true when recording ran out of room or time.
    attr_reader :capture

    def initialize(message, stack = "")
      @frames = stack.split("\n").map { "JavaScript #{_1.strip}" }
      super(message)
    end

    def backtrace
      frames = super
      @frames + frames unless frames.nil?
    end
  end

  class ScriptError < EvalError
    def initialize(message)
      message, *@frames = message.split("\n")
      @frames.map! { "JavaScript #{_1.strip}" }
      super(message)
    end

    def backtrace
      frames = super || []
      @frames + frames
    end
  end

  class SnapshotError < Error
    def initialize(message)
      message, *@frames = message.split("\n")
      @frames.map! { "JavaScript #{_1.strip}" }
      super(message)
    end

    def backtrace
      frames = super
      @frames + frames unless frames.nil?
    end
  end

  class Context
    def load(filename)
      # Discard the completion value without serializing objects or invoking getters.
      eval(File.read(filename) + "\n;void 0;")
    end

    def write_heap_snapshot(file_or_io)
      f = nil
      implicit = false

      if String === file_or_io
        f = File.open(file_or_io, "w")
        implicit = true
      else
        f = file_or_io
      end

      raise ArgumentError, "file_or_io" unless File === f

      f.write(heap_snapshot())
    ensure
      f.close if implicit
    end

    # True while a DevTools frontend is connected to this context.
    # Requires Context.new(inspector: ...).
    def debugger_attached?
      __inspector_status & INSPECTOR_ATTACHED != 0
    end

    # Blocks until a DevTools frontend has attached and is ready, then pauses
    # on the first statement of the next eval or call so breakpoints can be
    # set before any code runs. Returns false if |timeout| (seconds) passes
    # first or the wait is cancelled, true otherwise. See #await_debugger.
    def wait_for_debugger(timeout: nil)
      case await_debugger(timeout: timeout)
      when :ready
        true
      when :disposed
        raise ContextDisposedError, "disposed context"
      else
        false
      end
    end

    # Like #wait_for_debugger, but says how the wait ended: :ready (the next
    # eval or call will pause on its first statement), :timeout,
    # :cancelled (#cancel_debugger_wait or #stop, from another thread) or
    # :disposed.
    def await_debugger(timeout: nil)
      if __inspector_status & INSPECTOR_ENABLED == 0
        raise ArgumentError, "context was not created with inspector:"
      end
      @debugger_wait_cancelled = false
      deadline =
        timeout && Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
      loop do
        status =
          begin
            __inspector_status
          rescue ContextDisposedError
            return :disposed
          end
        if status & INSPECTOR_READY != 0
          __inspector_break_next
          return :ready
        end
        return :cancelled if @debugger_wait_cancelled
        if deadline &&
             Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
          return :timeout
        end
        sleep 0.02
      end
    end

    # Ends a #wait_for_debugger or #await_debugger in progress on another
    # thread; it returns :cancelled within about 20 ms.
    def cancel_debugger_wait
      @debugger_wait_cancelled = true
      nil
    end

    # Context#stop also ends a wait for the debugger.
    alias_method :__stop_execution, :stop
    private :__stop_execution
    def stop
      @debugger_wait_cancelled = true
      __stop_execution
    end

    # The inspector's view of this context, for a supervisor deciding when
    # to end a debugging session; nil without inspector:.
    #
    #   attached:         a frontend is connected
    #   ready:            it sent Runtime.runIfWaitingForDebugger
    #   paused:           stopped at a breakpoint or a debugger statement
    #   pause_generation: pauses so far; anything a frontend got during a
    #                     pause (a call frame id) is stale once it changes
    #   paused_ms:        how long the current pause has lasted
    #   total_paused_ms:  all pauses so far, the current one excluded
    def inspector_state
      bits, generation, total_ms, current_ms = __inspector_state || return
      {
        attached: bits & INSPECTOR_ATTACHED != 0,
        ready: bits & INSPECTOR_READY != 0,
        paused: bits & INSPECTOR_PAUSED != 0,
        pause_generation: generation,
        paused_ms: current_ms,
        total_paused_ms: total_ms
      }
    end

    # Drops the attached DevTools frontend, if any, for revoking access.
    # With terminate: true (the default) whatever is running or paused is
    # ended first (as by #stop, raising ScriptTerminatedError in the eval or
    # call), so revoking never lets the script run on unobserved. With
    # terminate: false, Context.new's inspector_detach: decides, as for any
    # disconnect (:resume, the default, lets it continue).
    def disconnect_debugger(terminate: true)
      stop if terminate
      __inspector_disconnect
    end

    INSPECTOR_ENABLED = 1
    INSPECTOR_ATTACHED = 2
    INSPECTOR_READY = 4
    INSPECTOR_PAUSED = 8
    private_constant :INSPECTOR_ENABLED,
                     :INSPECTOR_ATTACHED,
                     :INSPECTOR_READY,
                     :INSPECTOR_PAUSED
  end

  # Chrome DevTools Protocol server, one per process. Contexts created with
  # inspector: true (or inspector: "name") show up as targets under
  # chrome://inspect once it is started. Anyone who can reach the port can
  # run arbitrary code in those contexts: keep the default loopback host and
  # tunnel (e.g. ssh -L 9229:localhost:9229) to debug a remote machine.
  module Inspector
    DEFAULT_PORT = 9229

    # Limits the server applies, with their defaults. Times are seconds.
    #
    #   max_connections:   open sockets at once (32)
    #   max_message_bytes: largest WebSocket message from a frontend (16 MiB)
    #   max_queued_messages / max_queued_bytes: messages waiting for a busy
    #                      context before its frontend is dropped (4096, 64 MiB)
    #   handshake_timeout: to finish the HTTP request or WebSocket handshake (10)
    #   send_idle_timeout / send_timeout: a frontend that stops reading is
    #                      dropped after this long without progress on one
    #                      message, or this long for it in all (10, 30)
    #   max_targets:       inspectable contexts in the process; Context.new
    #                      raises past it (nil: no cap). Counts contexts made
    #                      before the server started too.
    DEFAULT_SETTINGS = {
      max_connections: 32,
      max_message_bytes: 16 << 20,
      max_queued_messages: 4096,
      max_queued_bytes: 64 << 20,
      handshake_timeout: 10,
      send_idle_timeout: 10,
      send_timeout: 30,
      max_targets: nil
    }.freeze

    # Starts the server and returns the bound port (pass port: 0 for any
    # free port). Calling it again in the same process returns that port,
    # as long as the call asks for the same thing; a different host, token,
    # explicit port or setting raises ArgumentError rather than being
    # silently ignored (Inspector.stop first to change them). A forked child
    # starts afresh, without the parent's contexts.
    #
    # Binding anything but a loopback address exposes code execution to the
    # network and needs allow_remote: true.
    #
    # token: true (or a string of letters, digits, - and _) makes the token
    # the first path segment of every URL, /json/list included, so only
    # someone told the URL can find or attach to a context. chrome://inspect
    # can't discover such targets; open the devtoolsFrontendUrl from
    # Inspector.url instead.
    #
    # Other keywords: see DEFAULT_SETTINGS.
    def self.start(
      host: "127.0.0.1",
      port: DEFAULT_PORT,
      allow_remote: false,
      token: nil,
      **settings
    )
      host = host.to_s
      if !allow_remote && !loopback?(host)
        raise ArgumentError,
              "refusing to expose the inspector on #{host}: anyone who can " \
                "connect can run code in your contexts; bind 127.0.0.1 and " \
                "tunnel, or pass allow_remote: true"
      end
      unless token == true || token.to_s.match?(/\A[A-Za-z0-9_-]*\z/)
        raise ArgumentError, "token may only contain letters, digits, - and _"
      end
      settings = settings_for(settings)
      port = Integer(port)
      if started?
        check_same!(host, port, token, settings)
        return self.port
      end
      if token == true
        require "securerandom"
        token = SecureRandom.hex(16)
      end
      token = token.to_s
      bound = __start(host, port, token, native_settings(settings))
      require "securerandom"
      @host = host
      @token = token.empty? ? nil : token
      @settings = settings
      @boot_id = SecureRandom.uuid
      @pid = Process.pid
      bound
    end

    # Stops listening, drops every attached frontend (each context then
    # behaves as on any disconnect: see Context.new's inspector_detach:) and
    # waits for the server thread. Contexts stay inspectable and reappear
    # if the server starts again. Returns whether it was running.
    def self.stop
      stopped = __stop
      @host = @token = @settings = @boot_id = @pid = nil
      stopped
    end

    # Where the server is, for a supervisor to route debugging sessions
    # without parsing URLs: {host:, port:, pid:, boot_id:}, or nil when not
    # started. boot_id is new on every start, so a recycled pid or port
    # can't be mistaken for an older server. It leaves the token out: hand
    # that out separately, if at all.
    def self.endpoint
      p = port or return nil
      return nil unless @pid == Process.pid
      { host: @host, port: p, pid: @pid, boot_id: @boot_id }
    end

    # What happened to inspectable contexts, oldest first, for auditing a
    # debugging session or reacting to one (a supervisor ending a session
    # whose frontend detached, say). Waits up to |timeout| seconds for the
    # first event (nil: until there is one; 0: don't wait) and returns at
    # most |max| (up to 64). Each is a Hash:
    #
    #   seq:              increasing; a gap means events were dropped
    #   event:            :created, :destroyed, :attached, :detached,
    #                     :paused, :resumed or :terminated
    #   target_id:        Context#inspector_target_id
    #   pause_generation: the context's, when it happened
    #   at:               Process.clock_gettime(Process::CLOCK_MONOTONIC)
    #                     seconds, when it happened
    #   reason:           for :terminated, :max_pause or :detach
    #                     (inspector_detach: :terminate); else nil
    #
    # The process keeps the last 1024 unread events; older ones are dropped
    # and counted in events_dropped. Events are consumed by whoever reads
    # them: have one reader.
    def self.events(timeout: 0, max: 64)
      timeout_ms = timeout.nil? ? -1 : (Float(timeout) * 1000).ceil
      raise ArgumentError, "bad timeout" if timeout_ms < -1
      __events(timeout_ms, Integer(max)).map do |seq, event, at_ms, generation, target, reason|
        {
          seq: seq,
          event: event.to_sym,
          target_id: target,
          pause_generation: generation,
          at: at_ms / 1000.0,
          reason: reason.empty? ? nil : reason.to_sym
        }
      end
    end

    def self.settings_for(given)
      unknown = given.keys - DEFAULT_SETTINGS.keys
      unless unknown.empty?
        raise ArgumentError, "unknown inspector setting: #{unknown.join(", ")}"
      end
      settings = DEFAULT_SETTINGS.merge(given)
      settings.each do |k, v|
        next if k == :max_targets && v.nil?
        unless v.is_a?(Numeric) && v.positive? && v <= (k.end_with?("timeout") ? 86_400 : 1 << 40)
          raise ArgumentError, "bad inspector setting #{k}: #{v.inspect}"
        end
      end
      settings.freeze
    end
    private_class_method :settings_for

    def self.native_settings(s)
      ms = ->(seconds) { (seconds * 1000).ceil }
      [
        Integer(s[:max_message_bytes]),
        Integer(s[:max_connections]),
        ms.(s[:send_idle_timeout]),
        ms.(s[:send_timeout]),
        ms.(s[:handshake_timeout]),
        Integer(s[:max_queued_messages]),
        Integer(s[:max_queued_bytes]),
        s[:max_targets] ? Integer(s[:max_targets]) : 0
      ]
    end
    private_class_method :native_settings

    def self.check_same!(host, port, token, settings)
      differs = []
      differs << "host" if host != @host
      differs << "port" if port != 0 && port != self.port
      differs << "token" if token == true ? @token.nil? : token.to_s != @token.to_s
      differs << "settings" if settings != @settings
      return if differs.empty?
      raise ArgumentError,
            "inspector already started with a different #{differs.join(", ")}; " \
              "Inspector.stop first to change it"
    end
    private_class_method :check_same!

    def self.loopback?(host)
      return true if host == "localhost"
      require "ipaddr"
      IPAddr.new(host.delete_prefix("[").delete_suffix("]")).loopback?
    rescue IPAddr::InvalidAddressError
      false
    end
    private_class_method :loopback?

    # The target discovery URL, token included, for logging which port (and
    # token) a process got. nil until started.
    def self.url
      p = port or return nil
      h = @host.to_s.delete_prefix("[").delete_suffix("]")
      h = "127.0.0.1" if h.empty? || h == "0.0.0.0"
      h = "::1" if h == "::"
      h = "[#{h}]" if h.include?(":")
      "http://#{h}:#{p}#{"/#{@token}" if @token}/json/list"
    end

    def self.started?
      !port.nil?
    end
  end
end
