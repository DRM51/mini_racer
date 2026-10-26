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

  def new_context_with(**capture_opts)
    ctx = MiniRacer::Context.new(capture_on_throw: capture_opts)
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
      for (let i = 0; i < 20000; i++) TABLE["k" + i] = i;
      const BIG = new Map(Array.from({ length: 20000 }, (_, i) => [i, i]));
      function recurse(n) {
        const refs = [BIG, TABLE, TABLE, TABLE];
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
    assert_equal "[Map(20000)]", vars["refs"][0]
    assert vars["text"].end_with?("(1000000 chars)")
    # the table appears once per reference but is the same record
    assert_same vars["refs"][1], vars["refs"][2]
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

  def test_long_bind_chains_and_labels_are_bounded
    ctx = new_context
    ctx.eval(<<~JS)
      var target = function named() {};
      for (let i = 0; i < 20000; i++) target = target.bind(null);
      function fail() { const f = target; const s = Symbol("x".repeat(10000)); throw new Error("x") }
    JS
    vars = variables(capture_of { ctx.call("fail") }["frames"].first)
    assert_equal "[Function: bound bound bound bound \u2026]", vars["f"]
    assert_operator vars["s"].length, :<, 600
  end

  def test_equal_thrown_primitives_in_one_evaluation_get_no_record
    ctx = new_context
    # a stray rejection and the real throw share the value: ambiguous
    capture = capture_of { ctx.eval(<<~JS) }
          (function unrelated() { let wrong = 1; Promise.reject("same") })();
          (function real() { let right = 2; throw "same" })();
        JS
    assert_nil capture
  end

  def test_thrown_bigints_are_captured
    ctx = new_context
    capture =
      capture_of { ctx.eval("(function big() { let x = 1; throw 12n })()") }
    assert_equal({ "x" => 1 }, variables(capture["frames"].first))
  end

  def test_nested_evaluations_leave_the_outer_record_alone
    ctx = new_context
    ctx.attach("nested", -> { ctx.eval("1") })
    capture = capture_of { ctx.eval_await(<<~JS) }
          const p = (async function real() { let a = 1; await null; throw new Error("real") })();
          nested();
          p
        JS
    assert_equal "real", capture["frames"].first["function"]

    # a nested eval run by a getter while the result is converted keeps its own
    inner = nil
    ctx.attach(
      "inner",
      lambda do
        inner =
          capture_of { ctx.eval("(function deep() { let d = 1; null.x })()") }
        1
      end
    )
    assert_equal({ "x" => 1 }, ctx.eval("({ get x() { return inner() } })"))
    assert_equal "deep", inner["frames"].first["function"]
  end

  def test_limits_hold_for_getters_dates_and_shared_objects
    ctx = new_context
    capture = capture_of { ctx.eval_await(<<~JS) }
          var date = new Date(0);
          const a0 = {}, a1 = { x: a0 }, a2 = { x: a1 }, a3 = { x: a2 }, a4 = { x: a3 };
          const getters = Array.from({ length: 50 }, () =>
            Array.from({ length: 50 }, () => {
              const o = {};
              for (let i = 0; i < 50; i++) Object.defineProperty(o, "g" + i, { enumerable: true, get() { return 1 } });
              return o;
            }));
          const p = (async function real() { let when = date, chain = a4, g = getters; throw new Error("x") })();
          date.setTime(123000);
          p
        JS
    vars = variables(capture["frames"].first)
    assert_equal Time.at(0), vars["when"]
    assert_equal({ "x" => { "x" => { "x" => "[Object]" } } }, vars["chain"])
    assert_equal true, capture["truncated"]
  end

  def test_values_ruby_cannot_take_and_long_names
    ctx = new_context
    capture = capture_of { ctx.eval(<<~JS) }
          (function f() {
            const bad = new Date(NaN);
            const keyed = { ["k".repeat(5000)]: 1 };
            throw new Error("x");
          })()
        JS
    vars = variables(capture["frames"].first)
    assert_equal "Invalid Date", vars["bad"]
    assert_operator vars["keyed"].keys.first.length, :<, 600
  end

  def test_ambiguous_records_are_left_out
    ctx = new_context
    # two rejections with an equal value in one evaluation: either could be
    # the one awaited, so neither is attached
    capture = capture_of { ctx.eval_await(<<~JS) }
          const p = (async function wanted() { const right = 1; throw 404 })();
          (async function unrelated() { const wrong = 2; throw 404 })();
          p
        JS
    assert_nil capture
  end

  def test_a_nested_evaluation_cannot_take_its_callers_record
    ctx = new_context
    ctx.attach(
      "nested",
      lambda do
        ctx.eval("throw 7")
      rescue MiniRacer::RuntimeError
        nil
      end
    )
    capture = capture_of { ctx.eval_await(<<~JS) }
          const p = (function outer() { let o = 1; return Promise.reject(7) })();
          try { nested() } catch (e) {}
          p
        JS
    assert_equal "outer", capture["frames"].first["function"]
  end

  def test_long_names_that_shorten_alike_both_stay
    ctx = new_context
    capture = capture_of { ctx.eval(<<~JS) }
          (function f() {
            const o = { ["k".repeat(600) + "a"]: 1, ["k".repeat(600) + "b"]: 2 };
            throw new Error("x");
          })()
        JS
    assert_equal [1, 2], variables(capture["frames"].first)["o"].values.sort
  end

  def test_expressions_are_evaluated_in_the_failing_frame
    ctx =
      new_context_with(
        expressions: [
          "row.id",
          "row.items.map(i => i.qty).reduce((a, b) => a + b, 0)",
          "label",
          "nowhere.x"
        ]
      )
    ctx.eval(<<~JS)
      function helper(c) { return c.name }
      function transform(row) { const label = "#" + row.id; return helper(row.customer) }
    JS
    capture =
      capture_of do
        ctx.call(
          "transform",
          {
            "id" => 7,
            "customer" => nil,
            "items" => [{ "qty" => 2 }, { "qty" => 3 }]
          }
        )
      end
    results = capture["expressions"].to_h { |x| [x["expression"], x] }
    # helper's frame has no row; the next frame out does
    assert_equal(
      { "expression" => "row.id", "frame" => 1, "value" => 7 },
      results["row.id"]
    )
    assert_equal 5, results.values[1]["value"]
    assert_equal "#7", results["label"]["value"]
    assert_equal "ReferenceError: nowhere is not defined",
                 results["nowhere.x"]["error"]
    refute results["nowhere.x"].key?("frame")
  end

  def test_expressions_cannot_change_anything
    calls = 0
    ctx =
      new_context_with(
        expressions: [
          "row.secret",
          "row.id = 99",
          "rubyFn()",
          "row.tags.push(1)",
          "while (true) {}"
        ]
      )
    ctx.attach("rubyFn", -> { calls += 1 })
    ctx.eval(<<~JS)
      globalThis.hits = 0;
      function fail(row) {
        Object.defineProperty(row, "secret", { get() { hits++; return 1 } });
        throw new Error("x");
      }
    JS
    capture = capture_of { ctx.call("fail", { "id" => 1, "tags" => [] }) }
    errors = capture["expressions"].map { |x| x["error"] }
    assert_equal 4, errors.grep(/side-effect/).size, errors.inspect
    assert_equal "Execution was terminated", errors.last
    assert_equal 0, ctx.eval("hits")
    assert_equal 0, calls
    assert_equal 2, ctx.eval("1 + 1")
  end

  def test_expressions_report_runtime_errors_where_they_happen
    ctx = new_context_with(expressions: %w[row.id compute() big huge])
    ctx.eval(<<~JS)
      function inner(row) {
        Object.defineProperty(row, "id", { get() { throw new ReferenceError("from a getter") } });
        const compute = () => { throw new ReferenceError("runtime") };
        const big = 7n, huge = 2n ** 5000n;
        throw new Error("x");
      }
      function outer() { const row = { id: 99 }; const compute = () => 88; return inner({}) }
    JS
    results = capture_of { ctx.call("outer") }["expressions"]
    # a ReferenceError the code threw is the answer, not a reason to try the
    # outer frame's row and compute
    assert_equal(
      {
        "expression" => "row.id",
        "frame" => 0,
        "error" => "ReferenceError: from a getter"
      },
      results[0]
    )
    assert_equal(
      {
        "expression" => "compute()",
        "frame" => 0,
        "error" => "ReferenceError: runtime"
      },
      results[1]
    )
    assert_equal 7, results[2]["value"] # a BigInt, as a local would be
    assert_match(/\A\[BigInt: \d+ digits\]\z/, results[3]["value"])
  end

  def test_expressions_must_be_valid_text
    ["\xff".b, "\xff".dup.force_encoding("UTF-8")].each do |bad|
      assert_raises(ArgumentError, bad.inspect) do
        MiniRacer::Context.new(capture_on_throw: { expressions: [bad] })
      end
    end
    ctx = new_context_with(expressions: ["\"\u00e9\"".encode("ISO-8859-1")])
    capture = capture_of { ctx.eval("(function f() { null.x })()") }
    assert_equal "\u00e9", capture["expressions"].first["value"]
  end

  def test_expression_options_are_checked
    [
      { expressions: "row.id" },
      { expressions: [1] },
      { expressions: [""] },
      { expressions: ["x" * 1001] },
      { expressions: ["a"] * 21 },
      { other: true }
    ].each do |opts|
      assert_raises(ArgumentError, opts.inspect) do
        MiniRacer::Context.new(capture_on_throw: opts)
      end
    end
    ctx = MiniRacer::Context.new(capture_on_throw: {})
    @contexts << ctx
    capture = capture_of { ctx.eval("(function f() { let a = 1; null.x })()") }
    assert_equal({ "a" => 1 }, variables(capture["frames"].first))
    refute capture.key?("expressions")
  end

  def test_cannot_be_combined_with_the_inspector
    assert_raises(ArgumentError) do
      MiniRacer::Context.new(capture_on_throw: true, inspector: "x")
    end
  end

  def test_the_heap_limit_stays_where_it_was
    # V8's debugger would raise it fourfold near the limit; the fatal
    # out-of-memory error must come at about the same point as without
    # capture (it came at four to five times as many objects without the fix)
    reached =
      [false, true].map do |capture|
        script = <<~RUBY
          require "mini_racer"
          MiniRacer::Platform.set_flags!(max_old_space_size: 64)
          ctx = MiniRacer::Context.new(capture_on_throw: #{capture})
          ctx.attach("report", ->(n) { puts n; $stdout.flush; nil })
          ctx.eval("const keep = []; for (let i = 0; ; i++) { keep.push({ i, s: 'x'.repeat(64) + i }); if (i % 50000 === 0) report(i) }")
        RUBY
        lib = File.expand_path("../lib", __dir__)
        out, err, status =
          Open3.capture3(RbConfig.ruby, "-I", lib, "-e", script)
        refute status.success?
        assert_includes err, "out of memory" # V8's fatal error, not an exception
        out.split.map(&:to_i).max
      end
    assert_operator reached[1],
                    :<=,
                    2 * reached[0],
                    "capture off/on: #{reached}"
  end

  def test_running_out_of_memory_with_capture_on_ends_gracefully
    # max_memory's termination, not V8's fatal out-of-memory error
    script = <<~RUBY
      require "mini_racer"
      ctx = MiniRacer::Context.new(capture_on_throw: true, max_memory: 64 << 20)
      begin
        ctx.eval("const keep = []; for (let i = 0; ; i++) keep.push({ i, s: 'x'.repeat(64) + i })")
      rescue MiniRacer::V8OutOfMemoryError
        puts "out of memory"
      end
      puts ctx.eval("1 + 1")
    RUBY
    lib = File.expand_path("../lib", __dir__)
    out, err, status = Open3.capture3(RbConfig.ruby, "-I", lib, "-e", script)
    assert status.success?, "child failed (#{status}): #{err}"
    assert_equal ["out of memory", "2"], out.lines.map(&:chomp)
  end

  def test_large_sparse_and_hidden_keys
    ctx = new_context
    capture =
      capture_of do
        ctx.eval(<<~JS)
          const big = { name: "rows" }
          for (let i = 0; i < 1e6; i++) big[i] = i
          throw new Error("x")
        JS
      end
    big = variables(capture["frames"][0], "script")["big"]
    assert_equal (0...50).map(&:to_s) + ["\u2026"], big.keys
    assert_equal "999951 more", big["\u2026"]
    # integer keys anywhere, in order and before names; non-enumerable ones
    # stay hidden (a fresh context: walking `big` again could use up the
    # recording deadline on a loaded machine)
    sparse =
      capture_of do
        new_context.eval(<<~JS)
          const o = { name: "c", 1000: "far", 0: "a" }
          Object.defineProperty(o, 5, { value: "hidden", enumerable: false })
          throw o
        JS
      end
    assert_equal({ "0" => "a", "1000" => "far", "name" => "c" },
                 variables(sparse["frames"][0], "script")["o"])
  end

  def test_scopes_per_frame_are_bounded
    ctx = new_context
    depth = 60
    source = (1..depth).map { |i| "(function f#{i}() { const v#{i} = #{i};" }.join
    # using every outer variable keeps all 60 closure scopes in the chain
    sum = (1..depth).map { |i| "v#{i}" }.join(" + ")
    source += "throw new Error(String(#{sum}));" + ("})()" * depth)
    capture = capture_of { ctx.eval(source) }
    assert_equal 20, capture["frames"][0]["scopes"].size
  end

  # Codex's review of the expressions (0.22.2.13): wrapping a result or an
  # exception must not run the script's getters, outside the side-effect check
  def test_expressions_run_no_getters_when_their_results_are_wrapped
    ctx = new_context(capture_on_throw: { expressions: ["errLike", "(() => { throw errLike })()", "errLike.message"] })
    ctx.eval(<<~JS)
      globalThis.hits = []
      var errLike = { __proto__: Error.prototype,
        get message() { hits.push("message"); return "m" },
        get name() { hits.push("name"); return "N" },
        get stack() { hits.push("stack"); return "s" } }
    JS
    capture = capture_of { ctx.eval("function f() { throw new Error('plain') } f()") }
    results = capture["expressions"].to_h { |x| [x["expression"], x] }
    assert_equal "[Getter]", results["errLike"]["value"]["message"]
    assert_includes results["errLike.message"]["error"], "side-effect"
    assert_equal [], ctx.eval("hits")
  end

  def test_a_thrown_look_alike_reference_error_does_not_move_to_an_outer_frame
    ctx = new_context(capture_on_throw: { expressions: ["fake()"] })
    ctx.eval("var fake = () => { throw { message: 'fake is not defined' } }")
    capture = capture_of { ctx.eval("function inner() { throw new Error('x') } function outer() { inner() } outer()") }
    assert_equal 0, capture["expressions"].first["frame"]
  end

  def test_a_reference_error_thrown_by_a_function_in_the_frame_stays_there
    ctx = new_context(capture_on_throw: { expressions: ["fake()"] })
    capture = capture_of do
      ctx.eval(<<~JS)
        function outer() { const fake = () => "outer's"; inner(); return fake() }
        function inner() {
          const fake = () => { throw new ReferenceError("fake is not defined") }
          throw new Error(typeof fake)
        }
        outer()
      JS
    end
    entry = capture["expressions"].first
    assert_equal 0, entry["frame"], entry
    assert_equal "ReferenceError: fake is not defined", entry["error"]
  end

  def test_a_reference_error_naming_a_call_is_not_probed
    # 20 of them: probing "typeof f()" would call f again and again, and
    # use up the recording's 100 ms before the last ones were reached
    expressions = Array.new(20) { |i| "f()#{" " * i}" }
    ctx = new_context(capture_on_throw: { expressions: expressions })
    capture = capture_of do
      ctx.eval(<<~JS)
        function inner() {
          const f = () => { throw new ReferenceError("f() is not defined") }
          throw new Error(typeof f)
        }
        inner()
      JS
    end
    capture["expressions"].each do |entry|
      assert_equal 0, entry["frame"], entry
      assert_equal "ReferenceError: f() is not defined", entry["error"]
    end
  end

  def test_a_reference_error_naming_more_than_an_identifier_is_not_probed
    # "new\u00a0F" is a call to F, and so is a name with a reserved word
    expressions = Array.new(20) { |i| "new\u00a0F#{" " * i}" }
    ctx = new_context(capture_on_throw: { expressions: expressions })
    capture = capture_of do
      ctx.eval(<<~JS)
        function inner() {
          function F() { throw new ReferenceError("new\u00a0F is not defined") }
          throw new Error(typeof F)
        }
        inner()
      JS
    end
    capture["expressions"].each do |entry|
      assert_equal 0, entry["frame"], entry
      assert_equal "ReferenceError: new\u00a0F is not defined", entry["error"]
    end
  end

  def test_the_identifier_check_ignores_the_locale
    skip "no ru_RU.CP1251 locale" unless `locale -a 2>/dev/null`.include?("ru_RU.CP1251")
    # there, the bytes of U+2000 (E2 80 80) are letters to isalnum. A guard,
    # not a proof: before the explicit ASCII ranges the probe called F just
    # once more (the recursion guard stops the rest), which a side-effect-free
    # evaluation can't count
    script = <<~'RUBY'
      require "mini_racer"
      expressions = Array.new(20) { |i| "new\u2000F#{" " * i}" }
      ctx = MiniRacer::Context.new(capture_on_throw: { expressions: expressions })
      begin
        ctx.eval(<<~JS)
          function inner() {
            function F() { throw new ReferenceError("new\u2000F is not defined") }
            throw new Error(typeof F)
          }
          inner()
        JS
      rescue MiniRacer::RuntimeError => e
        errors = e.capture["expressions"].map { _1["error"] }.uniq
        warn errors.inspect unless errors == ["ReferenceError: new\u2000F is not defined"]
        exit!(errors == ["ReferenceError: new\u2000F is not defined"] ? 0 : 1)
      end
      exit!(1)
    RUBY
    env = { "LC_ALL" => "ru_RU.CP1251" }
    _, err, status = Open3.capture3(env, RbConfig.ruby, "-I", File.expand_path("../lib", __dir__), "-e", script)
    assert status.success?, err
  end

  def test_a_binding_not_yet_declared_says_so_rather_than_showing_a_stale_value
    ctx = new_context(capture_on_throw: true)
    # V8 drops the TDZ check here, so in the second iteration the debugger
    # still sees the first one's tags: the throw is inside tags' own
    # initializer, so it isn't declared yet
    capture = capture_of do
      ctx.eval(<<~JS)
        let rows = [{ id: 1, details: { tags: ["rail"] } }, { id: 2 }];
        for (let i = 0; i < rows.length; i++) {
          const row = rows[i];
          const tags = row.details.tags;
        }
      JS
    end
    block = capture["frames"].first["scopes"].first["variables"]
    assert_equal "[Not yet declared]", block["tags"]
    assert_equal({ "id" => 2 }, block["row"])
  end

  def test_declarations_after_the_throw_are_not_yet_declared_and_earlier_ones_keep_their_values
    ctx = new_context(capture_on_throw: true)
    capture = capture_of do
      ctx.eval(<<~JS)
        function f(p) {
          var v = 2
          let x = 1
          const { id, name: label } = { id: 7, name: "seven" }
          null.boom
          let later = 3
          const { lateKey } = {}
          class Later {}
          return [later, lateKey, Later]
        }
        f(9)
      JS
    end
    local = variables(capture["frames"].first)
    assert_equal [9, 2, 1, 7, "seven"], local.values_at("p", "v", "x", "id", "label")
    # V8 holds these as holes, which the walker leaves out; either way they
    # never show a value
    local.values_at("later", "lateKey", "Later").each do |value|
      assert_includes [nil, "[Not yet declared]"], value
    end
  end

  def test_marking_declarations_scans_a_big_script_once
    # a pasted library: many top-level lets in a few MB. Searched per name
    # it took ~10 s here (21 s at 4 MB), far past the recording's 100 ms
    script = (1..400).map { |i| "let v#{i} = #{i};" }.join("\n") + "\n" +
             ("// #{"x" * 200}\n" * 10_000) + "null.boom\n"
    ctx = new_context(capture_on_throw: true)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    capture = capture_of { ctx.eval(script) }
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 3
    shown = variables(capture["frames"].first, "script")
    assert_operator shown.size, :>=, 50 # the first 50 keys, then "… N more"
    assert_empty shown.values.grep("[Not yet declared]"), "all 400 were declared before the throw"
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
