# frozen_string_literal: true

require_relative "test_helper"
require "open3"
require "rbconfig"

class MiniRacerCaptureTest < Minitest::Test
  def setup
    skip "no capture_on_throw on truffleruby" if RUBY_ENGINE == "truffleruby"
    @contexts = []
  end

  def teardown
    @contexts.each(&:dispose)
  end

  def new_context(**opts)
    ctx = MiniRacer::Context.new(capture_on_throw: true, **opts)
    @contexts << ctx
    ctx
  end

  def capture_of
    yield
    flunk "expected a MiniRacer::RuntimeError"
  rescue MiniRacer::RuntimeError => e
    e.capture
  end

  def variables(frame, type = "local")
    frame["scopes"].find { |s| s["type"] == type }&.fetch("variables")
  end

  def test_records_frames_and_their_variables
    ctx = new_context
    ctx.eval(<<~JS, filename: "lib.js")
      const SETTINGS = { currency: "USD" };
      function label(row) {
        const prefix = "#";
        return prefix + row.customer.name;
      }
    JS
    ctx.eval(<<~JS, filename: "transform.js")
      function transform(rows) {
        const out = [];
        for (let i = 0; i < rows.length; i++) out.push(label(rows[i]));
        return out;
      }
    JS
    rows = [{ "customer" => { "name" => "a" } }, { "customer" => nil }]
    capture = capture_of { ctx.call("transform", rows) }

    assert_equal "exception", capture["reason"]
    top, caller = capture["frames"]
    assert_equal ["label", "lib.js", 4],
                 top.values_at("function", "url", "line")
    assert_equal(
      { "row" => { "customer" => nil }, "prefix" => "#" },
      variables(top)
    )
    assert_equal(
      { "SETTINGS" => { "currency" => "USD" } },
      variables(top, "script")
    )
    assert_equal ["transform", "transform.js", 3],
                 caller.values_at("function", "url", "line")
    assert_equal({ "i" => 1 }, variables(caller, "block"))
    assert_equal ["#a"], variables(caller)["out"]
    refute(
      capture["frames"]
        .flat_map { |f| f["scopes"] }
        .any? { |s| s["type"] == "global" }
    )
  end

  def test_line_and_column_match_the_stack_trace
    ctx = new_context
    error =
      begin
        ctx.eval("(function f() {\n  return null.x;\n})()", filename: "f.js")
      rescue MiniRacer::RuntimeError => e
        e
      end
    frame = error.capture["frames"].first
    assert_includes error.backtrace.first,
                    "f.js:#{frame["line"]}:#{frame["column"]}"
  end

  def test_no_capture_without_the_option
    ctx = MiniRacer::Context.new
    @contexts << ctx
    assert_nil(capture_of { ctx.eval("null.x") })
  end

  def test_thrown_primitives_and_async_rejections
    ctx = new_context
    capture =
      capture_of { ctx.eval("(function f() { let a = 1; throw 'nope' })()") }
    assert_equal({ "a" => 1 }, variables(capture["frames"].first))

    capture =
      capture_of do
        ctx.eval_await(
          "(async function h() { let z = 3; await null; throw new Error('late') })()"
        )
      end
    assert_equal "promiseRejection", capture["reason"]
    assert_equal ["h", { "z" => 3 }],
                 [
                   capture["frames"].first["function"],
                   variables(capture["frames"].first)
                 ]
  end

  def test_exceptions_caught_in_javascript_leave_nothing_behind
    ctx = new_context
    ctx.eval(<<~JS)
      function quiet() { try { let hidden = 1; throw new Error("inner") } catch (e) {} return 1 }
      function loud() { let shown = 2; quiet(); throw new Error("outer") }
    JS
    assert_equal 1, ctx.call("quiet")
    capture = capture_of { ctx.call("loud") }
    assert_equal(["loud"], capture["frames"].map { |f| f["function"] })
    assert_equal({ "shown" => 2 }, variables(capture["frames"].first))
  end

  def test_recording_runs_no_javascript
    ctx = new_context
    ctx.eval(<<~JS)
      globalThis.calls = 0;
      function fail() {
        const withGetter = { get secret() { calls++; return 1 }, plain: 2 };
        const proxy = new Proxy({}, { ownKeys() { calls++; return [] }, get() { calls++ } });
        const custom = { toString() { calls++; return "x" }, toJSON() { calls++ } };
        throw new Error("boom");
      }
    JS
    capture = capture_of { ctx.call("fail") }
    assert_equal 0, ctx.eval("calls")
    vars = variables(capture["frames"].first)
    assert_equal({ "secret" => "[Getter]", "plain" => 2 }, vars["withGetter"])
    assert_equal "[Proxy]", vars["proxy"]
    assert_equal "[Function: toString]", vars["custom"]["toString"]
  end

  def test_values_are_bounded
    ctx = new_context
    capture = capture_of { ctx.eval(<<~JS) }
          (function f() {
            const long = "x".repeat(10000);
            const deep = { a: { b: { c: { d: 1 } } } };
            const many = Array.from({ length: 120 }, (_, i) => i);
            const wide = Object.fromEntries(Array.from({ length: 80 }, (_, i) => ["k" + i, i]));
            const loop = { name: "loop" }; loop.self = loop;
            const map = new Map([["k", { v: 1 }]]);
            const when = new Date(0);
            const err = new TypeError("bad");
            const fn = function named() {};
            throw new Error("boom");
          })()
        JS
    vars = variables(capture["frames"].first)
    assert_operator vars["long"].length, :<, 600
    assert vars["long"].end_with?("(10000 chars)")
    assert_equal({ "a" => { "b" => { "c" => "[Object]" } } }, vars["deep"])
    assert_equal 51, vars["many"].length
    assert_equal "… 70 more", vars["many"].last
    assert_equal 51, vars["wide"].size
    assert_equal({ "name" => "loop", "self" => "[Circular]" }, vars["loop"])
    assert_equal [["k", { "v" => 1 }]], vars["map"]
    assert_equal Time.at(0), vars["when"]
    assert_equal "TypeError: bad", vars["err"]
    assert_equal "[Function: named]", vars["fn"]
  end

  def test_ruby_exceptions_still_propagate
    ctx = new_context
    ctx.attach("rubyRaise", -> { raise ArgumentError, "from ruby" })
    error =
      assert_raises(ArgumentError) do
        ctx.eval("(function g() { return rubyRaise() })()")
      end
    assert_equal "from ruby", error.message
    capture =
      capture_of { ctx.eval("(function h() { let after = 1; null.x })()") }
    assert_equal(["h", ""], capture["frames"].map { |f| f["function"] })
  end

  def test_nested_evaluation_errors_get_their_own_capture
    ctx = new_context
    inner = nil
    ctx.attach(
      "nested",
      lambda do
        inner =
          capture_of do
            ctx.eval("(function inner() { let deep = 1; null.x })()")
          end
        "rescued"
      end
    )
    assert_equal "rescued", ctx.eval("(function outer() { return nested() })()")
    assert_equal "inner", inner["frames"].first["function"]
    capture = capture_of { ctx.eval("(function later() { null.y })()") }
    assert_equal(["later", ""], capture["frames"].map { |f| f["function"] })
  end

  def test_timeouts_and_console_still_work
    ctx = new_context(timeout: 100)
    ctx.eval("console.log('a', {b: 1}); console.error('c')")
    assert_raises(MiniRacer::ScriptTerminatedError) { ctx.eval("for (;;) {}") }
    assert_equal 2, ctx.eval("1 + 1")
  end

  def test_large_and_shared_values_are_recorded_once_and_cheaply
    ctx = new_context(timeout: 5000)
    ctx.eval(<<~JS)
      const TABLE = {};
      for (let i = 0; i < 200000; i++) TABLE["k" + i] = i;
      const BIG = new Map(Array.from({ length: 20000 }, (_, i) => [i, i]));
      function recurse(n) {
        const refs = [TABLE, TABLE, TABLE, BIG];
        const text = new String("x".repeat(1000000));
        if (n === 0) throw new Error("bottom");
        return recurse(n - 1);
      }
    JS
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    capture = capture_of { ctx.call("recurse", 9) }
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    assert_operator elapsed, :<, 2, "recording took #{elapsed}s"
    vars = variables(capture["frames"].first)
    assert_equal "[Map(20000)]", vars["refs"][3]
    assert vars["text"].end_with?("(1000000 chars)")
    # the table appears once per reference but is the same record
    assert_same vars["refs"][0], vars["refs"][1]
    assert_equal ["script"],
                 capture["frames"]
                   .flat_map { |f| f["scopes"] }
                   .map { |s| s["type"] }
                   .grep("script")
  end

  def test_running_out_of_room_is_marked
    ctx = new_context
    capture = capture_of { ctx.eval(<<~JS) }
          (function f() {
            const grid = Array.from({ length: 50 }, () =>
              Array.from({ length: 50 }, () => Array.from({ length: 50 }, (_, i) => i)));
            throw new Error("big");
          })()
        JS
    assert_equal true, capture["truncated"]
    assert_includes capture.to_s, "[…]"
  end

  def test_each_error_gets_the_record_of_its_own_exception
    ctx = new_context
    # the other rejection pauses after the awaited one: it must not replace it
    capture = capture_of { ctx.eval_await(<<~JS) }
          const p = (async function real() { let a = 1; await null; throw new Error("real") })();
          (async function other() { let b = 2; await null; await null; throw new Error("other") })();
          p
        JS
    assert_equal "real", capture["frames"].first["function"]

    # a rejection while a result is being converted belongs to no error
    capture = capture_of { ctx.eval(<<~JS) }
          ({ get x() {
            (function unrelated() { let s = 1; Promise.reject(NaN) })();
            throw "the real error";
          } })
        JS
    assert_nil capture
  end

  def test_unusual_values
    ctx = new_context
    capture = capture_of { ctx.eval(<<~JS) }
          (function f() {
            const parsed = JSON.parse('{"__proto__": {"admin": true}, "y": 2}');
            const bound = function g() {}.bind(null);
            const re = /a+b/gi;
            const big = 2n ** 2000n;
            const small = 12n;
            throw new Error("x");
          })()
        JS
    vars = variables(capture["frames"].first)
    assert_equal(
      { "__proto__" => { "admin" => true }, "y" => 2 },
      vars["parsed"]
    )
    assert_equal "[Function: bound g]", vars["bound"]
    assert_equal "/a+b/gi", vars["re"]
    assert_equal "[BigInt: 2048 bits]", vars["big"]
    assert_equal 12, vars["small"]
  end

  def test_debugger_statements_do_not_pause
    ctx = new_context
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    ctx.eval("for (let i = 0; i < 20000; i++) { debugger; }")
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started,
                    :<,
                    0.3
    capture = capture_of { ctx.eval("(function f() { debugger; null.x })()") }
    assert_equal "f", capture["frames"].first["function"]
  end

  def test_cannot_be_combined_with_the_inspector
    assert_raises(ArgumentError) do
      MiniRacer::Context.new(capture_on_throw: true, inspector: "x")
    end
  end

  def test_uncaught_exceptions_are_not_printed
    script = <<~RUBY
      require "mini_racer"
      ctx = MiniRacer::Context.new(capture_on_throw: true)
      begin
        ctx.eval("null.x")
      rescue MiniRacer::RuntimeError => e
        abort "no capture" unless e.capture
      end
    RUBY
    lib = File.expand_path("../lib", __dir__)
    _, err, status = Open3.capture3(RbConfig.ruby, "-I", lib, "-e", script)
    assert status.success?, err
    assert_equal "", err
  end
end
