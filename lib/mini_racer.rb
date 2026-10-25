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
    # first, true otherwise.
    def wait_for_debugger(timeout: nil)
      if __inspector_status & INSPECTOR_ENABLED == 0
        raise ArgumentError, "context was not created with inspector:"
      end
      deadline =
        timeout && Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
      until __inspector_status & INSPECTOR_READY != 0
        if deadline &&
             Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
          return false
        end
        sleep 0.05
      end
      __inspector_break_next
      true
    end

    INSPECTOR_ENABLED = 1
    INSPECTOR_ATTACHED = 2
    INSPECTOR_READY = 4
    private_constant :INSPECTOR_ENABLED, :INSPECTOR_ATTACHED, :INSPECTOR_READY
  end

  # Chrome DevTools Protocol server, one per process. Contexts created with
  # inspector: true (or inspector: "name") show up as targets under
  # chrome://inspect once it is started. Anyone who can reach the port can
  # run arbitrary code in those contexts: keep the default loopback host and
  # tunnel (e.g. ssh -L 9229:localhost:9229) to debug a remote machine.
  module Inspector
    DEFAULT_PORT = 9229

    # Starts the server and returns the bound port (pass port: 0 for any
    # free port). Calling it again in the same process returns that port;
    # a forked child starts afresh, without the parent's contexts.
    #
    # Binding anything but a loopback address exposes code execution to the
    # network and needs allow_remote: true.
    #
    # token: true (or a string of letters, digits, - and _) makes the token
    # the first path segment of every URL, /json/list included, so only
    # someone told the URL can find or attach to a context. chrome://inspect
    # can't discover such targets; open the devtoolsFrontendUrl from
    # Inspector.url instead.
    def self.start(
      host: "127.0.0.1",
      port: DEFAULT_PORT,
      allow_remote: false,
      token: nil
    )
      host = host.to_s
      if !allow_remote && !loopback?(host)
        raise ArgumentError,
              "refusing to expose the inspector on #{host}: anyone who can " \
                "connect can run code in your contexts; bind 127.0.0.1 and " \
                "tunnel, or pass allow_remote: true"
      end
      if token == true
        require "securerandom"
        token = SecureRandom.hex(16)
      end
      token = token.to_s
      unless token.match?(/\A[A-Za-z0-9_-]*\z/)
        raise ArgumentError, "token may only contain letters, digits, - and _"
      end
      return self.port if started? # the method, not the port: keyword
      bound = __start(host, Integer(port), token)
      @host = host
      @token = token.empty? ? nil : token
      bound
    end

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
