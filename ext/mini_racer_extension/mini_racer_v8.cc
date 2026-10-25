#include "v8.h"
#include "v8-profiler.h"
#include "v8-inspector.h"
#include "libplatform/libplatform.h"
#include "mini_racer_v8.h"
#include "mini_racer_inspector.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <iterator>
#include <memory>
#include <string>
#include <vector>
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>

// note: the filter function gets called inside the safe context,
// i.e., the context that has not been tampered with by user JS
// convention: $-prefixed identifiers signify objects from the
// user JS context and should be handled with special care
static const char safe_context_script_source[] = R"js(
;(function($globalThis) {
    const {Map: $Map, Set: $Set} = $globalThis
    const sentinel = {}
    return function filter(v) {
        if (typeof v === "function")
            return sentinel
        if (typeof v !== "object" || v === null)
            return v
        if (v instanceof $Map) {
            const m = new Map()
            for (let [k, t] of Map.prototype.entries.call(v)) {
                t = filter(t)
                if (t !== sentinel)
                    m.set(k, t)
            }
            return m
        } else if (v instanceof $Set) {
            const s = new Set()
            for (let t of Set.prototype.values.call(v)) {
                t = filter(t)
                if (t !== sentinel)
                    s.add(t)
            }
            return s
        } else {
            const o = Array.isArray(v) ? [] : {}
            const pds = Object.getOwnPropertyDescriptors(v)
            for (const [k, d] of Object.entries(pds)) {
                if (!d.enumerable)
                    continue
                let t = d.value
                if (d.get) {
                    // *not* d.get.call(...), may have been tampered with
                    t = Function.prototype.call.call(d.get, v, k)
                }
                t = filter(t)
                if (t !== sentinel)
                    Object.defineProperty(o, k, {value: t, enumerable: true})
            }
            return o
        }
    }
})
)js";

struct Callback
{
    struct State *st;
    int32_t id;
};

enum : unsigned
{
    NON_WATCHDOG_TERMINATION = 1,
    WATCHDOG_TERMINATION = 2,
};

// NOTE: do *not* use thread_locals to store state. In single-threaded
// mode, V8 runs on the same thread as Ruby and the Ruby runtime clobbers
// thread-locals when it context-switches threads. Ruby 3.4.0 has a new
// API rb_thread_lock_native_thread() that pins the thread but I don't
// think we're quite ready yet to drop support for older versions, hence
// this inelegant "everything" struct.
struct Inspector; // defined below, only exists when Context.new(inspector:)
struct Capture;   // defined below, only exists when Context.new(capture_on_throw:)

// what an uncaught exception's pause recorded, and that exception, so the
// failing eval or call can find the record that belongs to its error
struct CapturedError
{
    v8::Global<v8::Value> record;
    v8::Global<v8::Value> exception;
    std::string bigint; // a thrown BigInt, as CDP spells it ("12n")
    uint64_t invocation; // the eval or call running when it was recorded
};

struct State
{
    v8::Isolate *isolate;
    // declaring as Local is safe because we take special care
    // to ensure it's rooted in a HandleScope before being used
    v8::Local<v8::Context> context;
    // extra context for when we need access to built-ins like Array
    // and want to be sure they haven't been tampered with by JS code
    v8::Local<v8::Context> safe_context;
    v8::Local<v8::Function> safe_context_function;
    v8::Persistent<v8::Context> persistent_context;         // single-thread mode only
    v8::Persistent<v8::Context> persistent_safe_context;    // single-thread mode only
    v8::Persistent<v8::Function> persistent_safe_context_function;  // single-thread mode only
    v8::Persistent<v8::Value> ruby_exception;
    Context *ruby_context;
    int64_t max_memory;
    int err_reason;
    // TerminateExecution() while idle doesn't make IsExecutionTerminating() true
    std::atomic<unsigned> terminate_requested;
    // Armed before checking terminate_requested so a concurrent terminator
    // either gets observed or posts a task. Uses sequential consistency.
    std::atomic<bool> waiting_for_task;
    // Tracks reentrant call/eval dispatches so nested await calls can fail
    // instead of deadlocking and nested pumps preserve outer termination.
    int javascript_call_depth;
    bool verbose_exceptions;
    std::vector<Callback*> callbacks;
    std::unique_ptr<v8::ArrayBuffer::Allocator> allocator;
    std::unique_ptr<Inspector> inspector;
    std::unique_ptr<Capture> capture;
    std::vector<CapturedError> captured;
    // ids of the evals and calls in progress, innermost last; a record
    // belongs to the innermost one, and only its error may claim it
    std::vector<uint64_t> invocations;
    uint64_t last_invocation = 0;
    int replying_depth = -1; // javascript_call_depth of a reply() in progress
    // true while the inspector runs frontend messages with no ruby call in
    // progress; js -> ruby callbacks have nobody to answer them then
    bool inspector_idle;
    inline ~State();
};

namespace {

// deliberately leaked on program exit,
// not safe to destroy after main() returns
v8::Platform *platform;

struct Serialized
{
    uint8_t *data = nullptr;
    size_t   size = 0;

    Serialized(State& st, v8::Local<v8::Value> v)
    {
        v8::ValueSerializer ser(st.isolate);
        ser.WriteHeader();
        if (!ser.WriteValue(st.context, v).FromMaybe(false)) return; // exception pending
        auto pair = ser.Release();
        data = pair.first;
        size = pair.second;
    }

    ~Serialized()
    {
        free(data);
    }
};

void append_bytes(std::vector<char>& out, const char *p, size_t n)
{
    out.insert(out.end(), p, p + n);
}

void append_literal(std::vector<char>& out, const char *s)
{
    append_bytes(out, s, strlen(s));
}

bool append_utf8(std::vector<char>& out, const v8::String::Utf8Value& s)
{
    if (!*s) return false;
    append_bytes(out, *s, s.length());
    return true;
}

void append_format(std::vector<char>& out, const char *fmt, ...)
{
    char buf[128];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (static_cast<size_t>(n) < sizeof(buf)) {
        append_bytes(out, buf, n);
        return;
    }

    std::vector<char> tmp(static_cast<size_t>(n) + 1);
    va_start(ap, fmt);
    vsnprintf(tmp.data(), tmp.size(), fmt, ap);
    va_end(ap);
    append_bytes(out, tmp.data(), n);
}

v8::Local<v8::String> string_from_bytes(v8::Isolate *isolate, const std::vector<char>& bytes)
{
    v8::Local<v8::String> s;
    auto type = v8::NewStringType::kNormal;
    if (bytes.size() <= static_cast<size_t>(std::numeric_limits<int>::max()) &&
        v8::String::NewFromUtf8(isolate, bytes.data(), type,
                                static_cast<int>(bytes.size())).ToLocal(&s)) {
        return s;
    }

    char fallback[] = {
        bytes.empty() ? static_cast<char>(INTERNAL_ERROR) : bytes[0],
        'u', 'n', 'e', 'x', 'p', 'e', 'c', 't', 'e', 'd', ' ', 'e', 'r', 'r', 'o', 'r'
    };
    if (v8::String::NewFromUtf8(isolate, fallback, type, static_cast<int>(sizeof(fallback))).ToLocal(&s)) return s;
    return v8::String::Empty(isolate);
}

void set_error_message(std::vector<char>& out, int cause, const char *message)
{
    out.clear();
    out.push_back(static_cast<char>(cause));
    append_literal(out, message);
}

bool set_error_message(std::vector<char>& out, int cause, const v8::String::Utf8Value& message)
{
    out.clear();
    out.push_back(static_cast<char>(cause));
    return append_utf8(out, message);
}

void set_fallback_error(State& st, v8::TryCatch *try_catch, int cause,
                        std::vector<char>& out)
{
    v8::String::Utf8Value s(st.isolate, try_catch->Exception());
    const char *message = *s ? nullptr : "unexpected failure";
    if (cause == MEMORY_ERROR) message = "out of memory";
    if (cause == TERMINATED_ERROR) message = "terminated";
    if (message) {
        set_error_message(out, cause, message);
    } else if (!set_error_message(out, cause, s)) {
        set_error_message(out, cause, "unexpected failure");
    }
}

bool read_path_key(State& st, const char *&p, const char *pe,
                   v8::Local<v8::String> *key, bool *last)
{
    const char *dot;
    size_t n;

    if (p > pe) return false;
    dot = static_cast<const char*>(memchr(p, '.', pe - p));
    *last = (dot == nullptr);
    n = *last ? static_cast<size_t>(pe - p) : static_cast<size_t>(dot - p);
    if (n > static_cast<size_t>(std::numeric_limits<int>::max())) return false;
    auto type = v8::NewStringType::kNormal;
    if (!v8::String::NewFromUtf8(st.isolate, p, type, static_cast<int>(n)).ToLocal(key)) return false;
    p = *last ? pe : dot + 1;
    return true;
}

bool bubble_up_ruby_exception(State& st, v8::TryCatch *try_catch)
{
    auto exception = try_catch->Exception();
    if (exception.IsEmpty()) return false;
    auto ruby_exception = v8::Local<v8::Value>::New(st.isolate, st.ruby_exception);
    if (ruby_exception.IsEmpty()) return false;
    if (!ruby_exception->SameValue(exception)) return false;
    // signal that the ruby thread should reraise the exception
    // that it caught earlier when executing a js->ruby callback
    uint8_t c = 'e';
    v8_reply(st.ruby_context, &c, 1);
    return true;
}

// throws JS exception on serialization error
bool reply(State& st, v8::Local<v8::Value> v)
{
    // pauses for exceptions its getters cause belong to no error, but those
    // of an eval or call nested in a getter (one level deeper) do
    struct Replying {
        int& depth;
        int saved;
        Replying(int& depth, int now) : depth(depth), saved(depth) { depth = now; }
        ~Replying() { depth = saved; }
    } replying(st.replying_depth, st.javascript_call_depth);
    v8::TryCatch try_catch(st.isolate);
    {
        Serialized serialized(st, v);
        if (serialized.data) {
            v8_reply(st.ruby_context, serialized.data, serialized.size);
            return true;
        }
    }
    if (!try_catch.CanContinue()) {
        try_catch.ReThrow();
        return false;
    }
    auto recv = v8::Undefined(st.isolate);
    if (!st.safe_context_function->Call(st.safe_context, recv, 1, &v).ToLocal(&v)) {
        try_catch.ReThrow();
        return false;
    }
    Serialized serialized(st, v);
    if (serialized.data)
        v8_reply(st.ruby_context, serialized.data, serialized.size);
    else
        try_catch.ReThrow();
    return serialized.data != nullptr; // exception pending if false
}

bool reply(State& st, v8::Local<v8::Value> result, v8::Local<v8::Value> err)
{
    v8::TryCatch try_catch(st.isolate);
    try_catch.SetVerbose(st.verbose_exceptions);
    v8::Local<v8::Array> response;
    {
        v8::Context::Scope context_scope(st.safe_context);
        response = v8::Array::New(st.isolate, 2);
    }
    response->Set(st.context, 0, result).Check();
    response->Set(st.context, 1, err).Check();
    if (reply(st, response)) return true;
    if (!try_catch.CanContinue()) { // termination exception?
        try_catch.ReThrow();
        return false;
    }
    v8::String::Utf8Value s(st.isolate, try_catch.Exception());
    const char *message = *s ? *s : "unexpected failure";
    // most serialization errors will be DataCloneErrors but not always
    // DataCloneErrors are not directly detectable so use a heuristic
    if (!strstr(message, "could not be cloned")) {
        try_catch.ReThrow();
        return false;
    }
    // return an {"error": "foo could not be cloned"} object
    v8::Local<v8::Object> error;
    {
        v8::Context::Scope context_scope(st.safe_context);
        error = v8::Object::New(st.isolate);
    }
    auto key = v8::String::NewFromUtf8Literal(st.isolate, "error");
    v8::Local<v8::String> val;
    if (!v8::String::NewFromUtf8(st.isolate, message).ToLocal(&val)) {
        val = v8::String::NewFromUtf8Literal(st.isolate, "unexpected error");
    }
    error->Set(st.context, key, val).Check();
    response->Set(st.context, 0, error).Check();
    if (!reply(st, response)) {
        try_catch.ReThrow();
        return false;
    }
    return true;
}

// for when a reply is not expected to fail because of serialization
// errors but can still fail when preempted by isolate termination;
// temporarily cancels the termination exception so it can send the reply
void reply_retry(State& st, v8::Local<v8::Value> response)
{
    v8::TryCatch try_catch(st.isolate);
    try_catch.SetVerbose(st.verbose_exceptions);
    bool ok = reply(st, response);
    while (!ok) {
        assert(try_catch.HasCaught());
        assert(try_catch.HasTerminated());
        if (!try_catch.HasTerminated()) abort();
        st.isolate->CancelTerminateExecution();
        ok = reply(st, response);
        st.isolate->TerminateExecution();
    }
}

v8::Local<v8::Value> sanitize(State& st, v8::Local<v8::Value> v)
{
    // punch through proxies
    while (v->IsProxy()) v = v8::Proxy::Cast(*v)->GetTarget();
    // V8's serializer doesn't accept symbols
    if (v->IsSymbol()) return v8::Symbol::Cast(*v)->Description(st.isolate);
    // TODO(bnoordhuis) replace this hack with something more principled
    if (v->IsFunction()) {
        auto type = v8::NewStringType::kNormal;
        const size_t size = sizeof(js_function_marker) / sizeof(*js_function_marker);
        return v8::String::NewFromTwoByte(st.isolate, js_function_marker, type, size).ToLocalChecked();
    }
    if (v->IsWeakMap() || v->IsWeakSet() || v->IsMapIterator() || v->IsSetIterator()) {
        bool is_key_value;
        v8::Local<v8::Array> array;
        if (v8::Object::Cast(*v)->PreviewEntries(&is_key_value).ToLocal(&array)) {
            return array;
        }
    }
    return v;
}

v8::Local<v8::Value> to_error(State& st, v8::TryCatch *try_catch, int cause)
{
    std::vector<char> buf;

    if (cause == NO_ERROR) {
        return v8::String::Empty(st.isolate);
    } else if (cause == PARSE_ERROR) {
        auto message = try_catch->Message();
        v8::String::Utf8Value s(st.isolate, message->Get());
        v8::String::Utf8Value name(st.isolate, message->GetScriptResourceName());
        if (*s && *name) {
            buf.push_back(static_cast<char>(cause));
            append_utf8(buf, s);
            append_literal(buf, " at ");
            append_utf8(buf, name);
            auto line = message->GetLineNumber(st.context).FromMaybe(0);
            auto column = message->GetStartColumn(st.context).FromMaybe(0);
            append_format(buf, ":%d:%d", line, column);
        } else {
            set_fallback_error(st, try_catch, cause, buf);
        }
    } else {
        v8::Local<v8::Value> t;
        if (try_catch->StackTrace(st.context).ToLocal(&t)) {
            v8::String::Utf8Value s(st.isolate, t);
            if (*s) {
                if (cause == RUNTIME_ERROR) {
                    auto exception_message = try_catch->Message();
                    auto captured = exception_message.IsEmpty()
                        ? v8::String::Empty(st.isolate) : exception_message->Get();
                    v8::String::Utf8Value message(st.isolate, captured);
                    // Use V8's captured text without calling exception.toString().
                    const char *text = *message;
                    size_t length = text ? message.length() : 0;
                    static const char prefix[] = "Uncaught ";
                    if (length >= sizeof(prefix)-1 &&
                        !memcmp(text, prefix, sizeof(prefix)-1)) {
                        text += sizeof(prefix)-1;
                        length -= sizeof(prefix)-1;
                    }
                    size_t slen = s.length();
                    bool matched = !exception_message.IsEmpty() && text &&
                        slen >= length && !memcmp(*s, text, length) &&
                        (slen == length || (*s)[length] == '\n');
                    if (!matched) {
                        // Custom stack headers may differ from V8's captured
                        // text. Retain their legacy first-line formatting.
                        const char *nl = static_cast<const char*>(memchr(*s, '\n', slen));
                        text = *s;
                        length = nl ? static_cast<size_t>(nl - *s) : slen;
                    }
                    buf.push_back(static_cast<char>(cause));
                    append_bytes(buf, text, length);
                    auto error = string_from_bytes(st.isolate, buf);
                    // A matching header can contain any number of message
                    // newlines; only the remaining stack belongs in backtrace.
                    size_t offset = length < slen ? length + 1 : slen;
                    buf.clear();
                    append_bytes(buf, *s + offset, slen - offset);
                    auto stack = string_from_bytes(st.isolate, buf);
                    v8::Local<v8::Value> fields[] = {error, stack};
                    v8::Context::Scope context_scope(st.safe_context);
                    return v8::Array::New(st.isolate, fields, 2);
                }
                buf.push_back(static_cast<char>(cause));
                append_utf8(buf, s);
            } else {
                set_fallback_error(st, try_catch, cause, buf);
            }
        } else {
            set_fallback_error(st, try_catch, cause, buf);
        }
    }
    return string_from_bytes(st.isolate, buf);
}

extern "C" void v8_global_init(void)
{
    char *p;
    size_t n;

    v8_get_flags(&p, &n);
    if (p) {
        for (char *s = p; s < p+n; s += 1 + strlen(s)) {
            v8::V8::SetFlagsFromString(s);
        }
        free(p);
    }
    v8::V8::InitializeICU();
    if (single_threaded) {
        platform = v8::platform::NewSingleThreadedDefaultPlatform().release();
    } else {
        platform = v8::platform::NewDefaultPlatform().release();
    }
    v8::V8::InitializePlatform(platform);
    v8::V8::Initialize();
}

void v8_gc_callback(v8::Isolate*, v8::GCType, v8::GCCallbackFlags, void *data)
{
    State& st = *static_cast<State*>(data);
    v8::HeapStatistics s;
    st.isolate->GetHeapStatistics(&s);
    int64_t used_heap_size = static_cast<int64_t>(s.used_heap_size());
    if (used_heap_size > st.max_memory) {
        st.err_reason = MEMORY_ERROR;
        st.terminate_requested.fetch_or(NON_WATCHDOG_TERMINATION);
        st.isolate->TerminateExecution();
    }
}

} // namespace anonymous

// --- Chrome DevTools Protocol support ---
//
// All of this runs on the v8 thread except inspector_wake (server thread)
// and the Ruby-facing status accessors, which only touch atomics. Frontend
// messages arrive in three situations, mirroring Node:
//   - idle: v8_thread_main sees inspector_pending and calls
//     v8_inspector_dispatch
//   - running JS: an isolate interrupt drains them
//   - paused at a breakpoint: runMessageLoopOnPause drains them until resumed

namespace mri = mini_racer_inspector;

namespace {

constexpr int kContextGroupId = 1;

void request_termination(State *pst, unsigned request);

std::vector<uint16_t> utf8_to_utf16(const std::string& s)
{
    std::vector<uint16_t> out;
    out.reserve(s.size());
    const unsigned char *p = reinterpret_cast<const unsigned char *>(s.data());
    const unsigned char *pe = p + s.size();
    while (p < pe) {
        uint32_t c = *p++;
        int extra = 0;
        if (c >= 0xF0 && c < 0xF8)      { c &= 0x07; extra = 3; }
        else if (c >= 0xE0)             { c &= 0x0F; extra = 2; }
        else if (c >= 0xC0)             { c &= 0x1F; extra = 1; }
        else if (c >= 0x80)             { out.push_back(0xFFFD); continue; }
        if (c >= 0xF8 || pe - p < extra) { out.push_back(0xFFFD); break; }
        bool ok = true;
        for (int i = 0; i < extra; i++) {
            if ((p[i] & 0xC0) != 0x80) { ok = false; break; }
            c = (c << 6) | (p[i] & 0x3F);
        }
        if (!ok) { out.push_back(0xFFFD); continue; }
        p += extra;
        if (c >= 0x10000) {
            c -= 0x10000;
            out.push_back(static_cast<uint16_t>(0xD800 + (c >> 10)));
            out.push_back(static_cast<uint16_t>(0xDC00 + (c & 0x3FF)));
        } else {
            out.push_back(static_cast<uint16_t>(c));
        }
    }
    return out;
}

void put_utf8(std::string& out, uint32_t c)
{
    if (c < 0x80) {
        out += static_cast<char>(c);
    } else if (c < 0x800) {
        out += static_cast<char>(0xC0 | (c >> 6));
        out += static_cast<char>(0x80 | (c & 0x3F));
    } else if (c < 0x10000) {
        out += static_cast<char>(0xE0 | (c >> 12));
        out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (c & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (c >> 18));
        out += static_cast<char>(0x80 | ((c >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (c & 0x3F));
    }
}

std::string to_utf8(const v8_inspector::StringView& v)
{
    std::string out;
    if (v.is8Bit()) { // latin1
        for (size_t i = 0; i < v.length(); i++)
            put_utf8(out, v.characters8()[i]);
        return out;
    }
    const uint16_t *p = v.characters16();
    for (size_t i = 0, n = v.length(); i < n; i++) {
        uint32_t c = p[i];
        if (c >= 0xD800 && c < 0xDC00 && i+1 < n && p[i+1] >= 0xDC00 && p[i+1] < 0xE000) {
            c = 0x10000 + ((c - 0xD800) << 10) + (p[++i] - 0xDC00);
        } else if (c >= 0xD800 && c < 0xE000) {
            c = 0xFFFD; // lone surrogate
        }
        put_utf8(out, c);
    }
    return out;
}

v8_inspector::StringView latin1_view(const char *s)
{
    return v8_inspector::StringView(reinterpret_cast<const uint8_t *>(s), strlen(s));
}

struct InspectorClient final : public v8_inspector::V8InspectorClient
{
    Inspector& in;
    explicit InspectorClient(Inspector& in) : in(in) {}
    void runMessageLoopOnPause(int) override;
    void quitMessageLoopOnPause() override;
    void runIfWaitingForDebugger(int) override;
    double currentTimeMS() override { return platform->CurrentClockTimeMillis(); }
    v8::Local<v8::Context> ensureDefaultContextInGroup(int) override;
};

struct InspectorChannel final : public v8_inspector::V8Inspector::Channel
{
    Inspector& in;
    explicit InspectorChannel(Inspector& in) : in(in) {}
    void sendResponse(int, std::unique_ptr<v8_inspector::StringBuffer> m) override;
    void sendNotification(std::unique_ptr<v8_inspector::StringBuffer> m) override;
    void flushProtocolNotifications() override {}
};

} // namespace anonymous

struct Inspector
{
    State& st;
    std::string title;
    InspectorClient client{*this};
    InspectorChannel channel{*this};
    // Created with the context, not on first attach: V8 tags each script
    // with its context's inspector id at compile time, so code compiled
    // before contextCreated() could never be debugged. The cost is that V8
    // routes console.* into the inspector's message storage, which keeps the
    // last 1000 calls' arguments alive.
    std::unique_ptr<v8_inspector::V8Inspector> inspector;
    std::unique_ptr<v8_inspector::V8InspectorSession> session;
    std::shared_ptr<mri::Target> target;
    bool paused = false;
    bool quit_pause = false;
    // V8 forbids destroying a session from inside its pause loop or a
    // dispatch; a disconnect then only resumes and the session goes later
    bool disconnect_pending = false;
    int dispatch_depth = 0;
    // read by ruby threads
    std::atomic<bool> attached{false};
    std::atomic<bool> ready{false};
    std::atomic<bool> break_next{false};

    explicit Inspector(State& st) : st(st) {}
};

namespace {

void inspector_send(Inspector& in, const v8_inspector::StringView& v)
{
    mri::send(*in.target, to_utf8(v));
}

void InspectorChannel::sendResponse(int, std::unique_ptr<v8_inspector::StringBuffer> m)
{
    inspector_send(in, m->string());
}

void InspectorChannel::sendNotification(std::unique_ptr<v8_inspector::StringBuffer> m)
{
    inspector_send(in, m->string());
}

v8::Local<v8::Context> InspectorClient::ensureDefaultContextInGroup(int)
{
    return in.st.context;
}

void InspectorClient::runIfWaitingForDebugger(int)
{
    in.ready = true;
}

void InspectorClient::quitMessageLoopOnPause()
{
    in.quit_pause = true;
}

void inspector_drop_session_if_safe(Inspector& in)
{
    if (in.disconnect_pending && !in.paused && in.dispatch_depth == 0) {
        in.session.reset();
        in.disconnect_pending = false;
    }
}

void inspector_create(Inspector& in)
{
    State& st = in.st;
    v8::HandleScope handle_scope(st.isolate);
    in.inspector = v8_inspector::V8Inspector::create(st.isolate, &in.client);
    std::vector<uint16_t> name = utf8_to_utf16(in.title);
    v8_inspector::V8ContextInfo info(st.context, kContextGroupId,
                                     v8_inspector::StringView(name.data(), name.size()));
    info.auxData = latin1_view("{\"isDefault\":true,\"type\":\"default\"}");
    in.inspector->contextCreated(info);
}

// Runs every queued frontend event. Returns whether there were any.
bool inspector_drain(Inspector& in)
{
    bool any = false;
    std::string msg;
    for (;;) {
        mri::Event ev = mri::poll(*in.target, &msg);
        if (ev == mri::Event::None)
            break;
        any = true;
        switch (ev) {
        case mri::Event::Connect:
            if (in.session && in.disconnect_pending) {
                // reconnected before the old session could be dropped;
                // the new frontend re-enables whatever domains it needs
                in.disconnect_pending = false;
            } else {
                in.session = in.inspector->connect(
                    kContextGroupId, &in.channel, v8_inspector::StringView(),
                    v8_inspector::V8Inspector::kFullyTrusted);
            }
            in.attached = true;
            break;
        case mri::Event::Disconnect:
            in.attached = false;
            in.ready = false;
            in.break_next = false;
            if (!in.session)
                break;
            in.disconnect_pending = true;
            if (in.paused) {
                in.session->resume();
                in.quit_pause = true;
            }
            inspector_drop_session_if_safe(in);
            break;
        case mri::Event::Message:
            if (!in.session || in.disconnect_pending)
                break;
            {
                std::vector<uint16_t> u16 = utf8_to_utf16(msg);
                in.dispatch_depth++;
                in.session->dispatchProtocolMessage(
                    v8_inspector::StringView(u16.data(), u16.size()));
                in.dispatch_depth--;
            }
            inspector_drop_session_if_safe(in);
            break;
        case mri::Event::None:
            break;
        }
    }
    return any;
}

void InspectorClient::runMessageLoopOnPause(int)
{
    if (in.paused)
        return;
    State& st = in.st;
    in.paused = true;
    in.quit_pause = false;
    v8_inspector_paused(st.ruby_context, 1); // stops the watchdog clock
    const int64_t max_pause = v8_inspector_max_pause(st.ruby_context);
    const auto start = std::chrono::steady_clock::now();
    while (!in.quit_pause) {
        // a forgotten breakpoint must not hold the calling thread forever
        if (max_pause > 0 && std::chrono::steady_clock::now() - start >=
                                 std::chrono::milliseconds(max_pause)) {
            request_termination(&st, NON_WATCHDOG_TERMINATION);
            break;
        }
        if (inspector_drain(in))
            continue;
        // Context#stop, dispose or a vanished frontend end the pause; V8
        // then resumes and the pending termination, if any, takes over
        if (st.terminate_requested.load() || v8_context_quitting(st.ruby_context) || !in.session)
            break;
        mri::wait(*in.target, 100);
    }
    in.paused = false;
    v8_inspector_paused(st.ruby_context, 0);
}

void inspector_interrupt(v8::Isolate *, void *arg)
{
    State& st = *static_cast<State*>(arg);
    Inspector *in = st.inspector.get();
    // a pause loop or a dispatch further up the stack drains instead
    if (in && !in->paused && in->dispatch_depth == 0)
        inspector_drain(*in);
}

// Runs on the v8 thread when it's blocked in await_promise(), where an
// interrupt can't reach it because no JavaScript is running.
struct InspectorTask : public v8::Task
{
    State *pst;
    explicit InspectorTask(State *pst) : pst(pst) {}
    void Run() final { inspector_interrupt(pst->isolate, pst); }
};

// server thread, with the target's lock held
void inspector_wake(void *arg)
{
    State *pst = static_cast<State*>(arg);
    v8_inspector_wake(pst->ruby_context);
    pst->isolate->RequestInterrupt(inspector_interrupt, pst);
    if (pst->waiting_for_task.exchange(false)) {
        platform->GetForegroundTaskRunner(pst->isolate)
            ->PostTask(std::make_unique<InspectorTask>(pst));
    }
}

void inspector_init(State& st, const char *title)
{
    st.inspector = std::make_unique<Inspector>(st);
    Inspector& in = *st.inspector;
    in.title = title;
    inspector_create(in);
    in.target = mri::register_target(title, inspector_wake, &st);
}

void inspector_teardown(State& st)
{
    Inspector& in = *st.inspector;
    if (!in.target)
        return;
    mri::unregister_target(in.target); // no wakes after this returns
    in.attached = false;
    in.ready = false;
    in.session.reset();
    if (in.inspector) {
        v8::HandleScope handle_scope(st.isolate);
        in.inspector->contextDestroyed(st.context);
        in.inspector.reset();
    }
    in.target.reset();
    // |in| itself lives until ~State; ruby threads may still read its atomics
}

void inspector_maybe_break(State& st)
{
    Inspector *in = st.inspector.get();
    if (in && in->session && in->break_next.exchange(false))
        in->session->schedulePauseOnNextStatement(latin1_view("Break on start"),
                                                  latin1_view("{}"));
}

// --- capture on throw ---
//
// Context.new(capture_on_throw: true) keeps an in-process inspector session
// that pauses on uncaught exceptions. The pause records each frame's
// location and local variables, then lets the exception continue; the
// failing eval or call hands the record to Ruby with the error. Unlike
// inspector: there is no server and nothing waits for a frontend.
//
// Recording runs no JavaScript: no getters, no proxy traps, no toString.

constexpr int kCaptureFrames = 10;       // innermost frames recorded
constexpr int kCaptureDepth = 3;         // nesting below a variable
constexpr uint32_t kCaptureItems = 50;   // properties or elements per object
constexpr uint32_t kCaptureString = 500; // UTF-16 units kept of a string
constexpr int kCaptureValues = 5000;     // values recorded per exception
constexpr int kCaptureMillis = 100;      // time spent recording per exception
constexpr size_t kCaptureCollection = 10000; // larger Maps and Sets: just the size
constexpr size_t kCaptureRecords = 8;    // pauses waiting for their error
constexpr size_t kCapturePauseMessage = 16 << 20; // larger pauses aren't recorded

struct CaptureClient final : public v8_inspector::V8InspectorClient
{
    Capture& cap;
    explicit CaptureClient(Capture& cap) : cap(cap) {}
    void runMessageLoopOnPause(int) override;
    double currentTimeMS() override { return platform->CurrentClockTimeMillis(); }
    v8::Local<v8::Context> ensureDefaultContextInGroup(int) override;
    // the overload without a context id: V8 13 has only this one, and V8
    // 14's other overload calls it
    void consoleAPIMessage(int, v8::Isolate::MessageErrorLevel,
                           const v8_inspector::StringView&,
                           const v8_inspector::StringView&, unsigned, unsigned,
                           v8_inspector::V8StackTrace*) override;
};

struct CaptureChannel final : public v8_inspector::V8Inspector::Channel
{
    Capture& cap;
    explicit CaptureChannel(Capture& cap) : cap(cap) {}
    void sendResponse(int, std::unique_ptr<v8_inspector::StringBuffer>) override {}
    void sendNotification(std::unique_ptr<v8_inspector::StringBuffer> m) override;
    void flushProtocolNotifications() override {}
};

} // namespace anonymous

struct Capture
{
    State& st;
    CaptureClient client{*this};
    CaptureChannel channel{*this};
    std::unique_ptr<v8_inspector::V8Inspector> inspector;
    std::unique_ptr<v8_inspector::V8InspectorSession> session;
    std::string paused;         // the Debugger.paused notification being handled
    bool console_dirty = false; // console.* calls V8 kept for the inspector

    explicit Capture(State& st) : st(st) {}
};

namespace {

bool starts_with(const v8_inspector::StringView& v, const char *prefix)
{
    size_t n = strlen(prefix);
    if (v.length() < n) return false;
    for (size_t i = 0; i < n; i++) {
        uint16_t c = v.is8Bit() ? v.characters8()[i] : v.characters16()[i];
        if (c != static_cast<unsigned char>(prefix[i])) return false;
    }
    return true;
}

void CaptureChannel::sendNotification(std::unique_ptr<v8_inspector::StringBuffer> m)
{
    // the rest (a scriptParsed for each compiled script) is dropped
    // without being converted
    // V8 has already spent the time building a huge one (a long thrown
    // string, thousands of frames); don't spend more parsing it
    auto v = m->string();
    if (v.length() <= kCapturePauseMessage &&
        starts_with(v, "{\"method\":\"Debugger.paused\""))
        cap.paused = to_utf8(v);
}

v8::Local<v8::Context> CaptureClient::ensureDefaultContextInGroup(int)
{
    return cap.st.context;
}

void CaptureClient::consoleAPIMessage(int, v8::Isolate::MessageErrorLevel,
                                      const v8_inspector::StringView&,
                                      const v8_inspector::StringView&, unsigned,
                                      unsigned, v8_inspector::V8StackTrace*)
{
    cap.console_dirty = true;
}

void capture_dispatch(Capture& cap, const char *message)
{
    cap.session->dispatchProtocolMessage(latin1_view(message));
}

// After each outermost eval or call: drop a capture no error claimed (the
// exception was a Ruby one, or a rejection handled later), and the
// arguments of console.* calls, which V8 keeps (up to 1000) for a frontend
// that capture mode never has.
void capture_after_eval(State& st)
{
    Capture *cap = st.capture.get();
    if (!cap)
        return;
    st.captured.clear();
    if (cap->console_dirty) {
        cap->console_dirty = false;
        capture_dispatch(*cap, "{\"id\":3,\"method\":\"Runtime.discardConsoleEntries\"}");
    }
}

// V8's debugger raises the heap limit fourfold when it's nearly reached,
// so a frontend could still inspect the out-of-memory state. Capture mode
// has no frontend: keep the limit, so the context fails where it would have.
// V8 only calls the callback added last.
size_t capture_near_heap_limit(void *, size_t current_heap_limit, size_t)
{
    return current_heap_limit;
}

void capture_init(State& st)
{
    st.capture = std::make_unique<Capture>(st);
    Capture& cap = *st.capture;
    v8::HandleScope handle_scope(st.isolate);
    cap.inspector = v8_inspector::V8Inspector::create(st.isolate, &cap.client);
    v8_inspector::V8ContextInfo info(st.context, kContextGroupId, latin1_view("mini_racer"));
    cap.inspector->contextCreated(info);
    cap.session = cap.inspector->connect(kContextGroupId, &cap.channel,
                                         v8_inspector::StringView(),
                                         v8_inspector::V8Inspector::kFullyTrusted);
    // scripts are only looked up while paused; keep none after they're collected
    capture_dispatch(cap, "{\"id\":1,\"method\":\"Debugger.enable\",\"params\":{\"maxScriptsCacheSize\":0}}");
    capture_dispatch(cap, "{\"id\":2,\"method\":\"Debugger.setPauseOnExceptions\",\"params\":{\"state\":\"uncaught\"}}");
    st.isolate->AddNearHeapLimitCallback(capture_near_heap_limit, nullptr);
    // debugger; statements would pause too, for nothing
    capture_dispatch(cap, "{\"id\":4,\"method\":\"Debugger.setBreakpointsActive\",\"params\":{\"active\":false}}");
}

void capture_teardown(State& st)
{
    Capture& cap = *st.capture;
    cap.session.reset();
    if (cap.inspector) {
        v8::HandleScope handle_scope(st.isolate);
        cap.inspector->contextDestroyed(st.context);
        cap.inspector.reset();
    }
}

// V8 reports a verbose TryCatch's exception to message listeners, and
// prints it when there are none. Capture mode needs verbose TryCatches (see
// verbose_try_catch) but should stay as quiet as before.
void capture_message_listener(v8::Local<v8::Message>, v8::Local<v8::Value>) {}

// The debugger counts an exception as caught when a non-verbose TryCatch,
// mini_racer's default, would catch it, so it would never pause on one
// that escapes to Ruby. A verbose TryCatch doesn't count.
bool verbose_try_catch(const State& st)
{
    return st.verbose_exceptions || st.capture;
}

struct CaptureWalk
{
    State& st;
    v8::Local<v8::Context> context; // where the inspected values live
    int budget = kCaptureValues;
    // each object is recorded once per depth; later references at that depth
    // share the record (sharing across depths would undo the depth limit)
    v8::Local<v8::Map> seen[kCaptureDepth];
    std::vector<v8::Local<v8::Object>> path; // for [Circular]
    std::chrono::steady_clock::time_point deadline;
    bool stopped = false;

    CaptureWalk(State& st, v8::Local<v8::Context> context)
        : st(st), context(context),
          deadline(std::chrono::steady_clock::now() + std::chrono::milliseconds(kCaptureMillis))
    {
        v8::Context::Scope scope(st.safe_context);
        for (auto& m : seen) m = v8::Map::New(st.isolate);
    }

    // out of values or time, or the script is being terminated (timeout,
    // Context#stop): what's left is recorded as [...]
    bool exhausted()
    {
        if (!stopped && (--budget < 0 ||
                         st.terminate_requested.load() ||
                         st.isolate->IsExecutionTerminating() ||
                         std::chrono::steady_clock::now() > deadline))
            stopped = true;
        return stopped;
    }

    // what an accessor property shows as; counts like any value
    v8::Local<v8::Value> getter()
    {
        return str(exhausted() ? "[\xE2\x80\xA6]" : "[Getter]");
    }

    v8::Local<v8::String> str(const std::string& s)
    {
        auto type = v8::NewStringType::kNormal;
        v8::Local<v8::String> r;
        if (s.size() <= static_cast<size_t>(std::numeric_limits<int>::max()) &&
            v8::String::NewFromUtf8(st.isolate, s.data(), type,
                                    static_cast<int>(s.size())).ToLocal(&r))
            return r;
        return v8::String::Empty(st.isolate);
    }

    std::string utf8(v8::Local<v8::Value> v)
    {
        v8::String::Utf8Value s(st.isolate, v);
        return *s ? std::string(*s, s.length()) : std::string();
    }

    v8::Local<v8::Array> new_array()
    {
        v8::Context::Scope scope(st.safe_context);
        return v8::Array::New(st.isolate);
    }

    v8::Local<v8::Object> new_object()
    {
        v8::Context::Scope scope(st.safe_context);
        return v8::Object::New(st.isolate);
    }

    // CreateDataProperty, unlike Set, can't run the safe context's setters
    // (a "__proto__" key would otherwise vanish)
    void put(v8::Local<v8::Object> o, v8::Local<v8::Name> key, v8::Local<v8::Value> v)
    {
        o->CreateDataProperty(st.safe_context, key, v).FromMaybe(false);
    }

    void put(v8::Local<v8::Object> o, uint32_t index, v8::Local<v8::Value> v)
    {
        o->CreateDataProperty(st.safe_context, index, v).FromMaybe(false);
    }

    v8::Local<v8::Value> truncated(v8::Local<v8::String> s)
    {
        uint32_t n = static_cast<uint32_t>(s->Length());
        if (n <= kCaptureString) return s;
        std::vector<uint16_t> buf(kCaptureString);
        s->WriteV2(st.isolate, 0, kCaptureString, buf.data());
        uint32_t keep = kCaptureString;
        if (buf[keep-1] >= 0xD800 && buf[keep-1] < 0xDC00) keep--; // half a pair
        v8::Local<v8::String> head;
        if (!v8::String::NewFromTwoByte(st.isolate, buf.data(), v8::NewStringType::kNormal,
                                        static_cast<int>(keep)).ToLocal(&head))
            return str("[string]");
        return v8::String::Concat(st.isolate, head,
                                  str("\xE2\x80\xA6 (" + std::to_string(n) + " chars)"));
    }

    // an own data property, read without running getters or traps
    bool own_value(v8::Local<v8::Object> o, v8::Local<v8::Name> key,
                   v8::Local<v8::Value> *value, bool *accessor)
    {
        v8::Local<v8::Value> desc_v;
        if (!o->GetOwnPropertyDescriptor(context, key).ToLocal(&desc_v) || !desc_v->IsObject())
            return false;
        auto desc = desc_v.As<v8::Object>();
        auto value_key = str("value");
        // the descriptor is a fresh object; only its own fields are safe to read
        *accessor = !desc->HasOwnProperty(context, value_key).FromMaybe(false);
        if (*accessor) return true;
        return desc->Get(context, value_key).ToLocal(value);
    }

    // a bound function is named after its target; chains of bind() can be
    // arbitrarily long, so only the first few links are followed
    std::string function_name(v8::Local<v8::Function> f)
    {
        std::string prefix;
        for (int i = 0; i < 4; i++) {
            auto name = f->GetDebugName();
            if (name->IsString() && name.As<v8::String>()->Length() > 0)
                return prefix + utf8(truncated(name.As<v8::String>()));
            auto target = f->GetBoundFunction();
            if (!target->IsFunction())
                return prefix;
            prefix += "bound ";
            f = target.As<v8::Function>();
        }
        return prefix + "\xE2\x80\xA6";
    }

    std::string regexp(v8::Local<v8::RegExp> re)
    {
        static const std::pair<v8::RegExp::Flags, char> flags[] = {
            {v8::RegExp::kHasIndices, 'd'}, {v8::RegExp::kGlobal, 'g'},
            {v8::RegExp::kIgnoreCase, 'i'}, {v8::RegExp::kLinear, 'l'},
            {v8::RegExp::kMultiline, 'm'}, {v8::RegExp::kDotAll, 's'},
            {v8::RegExp::kUnicode, 'u'}, {v8::RegExp::kUnicodeSets, 'v'},
            {v8::RegExp::kSticky, 'y'},
        };
        std::string s = "/" + utf8(truncated(re->GetSource())) + "/";
        for (auto& [flag, c] : flags)
            if (re->GetFlags() & flag) s += c;
        return s;
    }

    v8::Local<v8::Value> value(v8::Local<v8::Value> v, int depth)
    {
        if (exhausted()) return str("[\xE2\x80\xA6]");
        if (v->IsUndefined() || v->IsNull() || v->IsBoolean() || v->IsNumber())
            return v;
        if (v->IsDate()) { // a copy: the script may change it after the throw
            double t = v.As<v8::Date>()->ValueOf();
            v8::Local<v8::Value> copy;
            if (std::isnan(t)) return str("Invalid Date"); // Ruby can't take it
            if (v8::Date::New(st.safe_context, t).ToLocal(&copy))
                return copy;
            return str("[Date]");
        }
        if (v->IsBigInt()) {
            int words = v.As<v8::BigInt>()->WordCount();
            if (words <= 16) return v;
            return str("[BigInt: " + std::to_string(64 * words) + " bits]");
        }
        if (v->IsString()) return truncated(v.As<v8::String>());
        if (v->IsSymbol()) {
            auto d = v.As<v8::Symbol>()->Description(st.isolate);
            return str("Symbol(" + (d->IsString() ? utf8(truncated(d.As<v8::String>())) : std::string()) + ")");
        }
        if (v->IsProxy()) return str("[Proxy]");
        if (v->IsFunction()) {
            auto name = function_name(v.As<v8::Function>());
            return truncated(str("[Function" + (name.empty() ? std::string() : ": " + name) + "]"));
        }
        if (v->IsRegExp()) return truncated(str(regexp(v.As<v8::RegExp>())));
        if (v->IsPromise()) {
            static const char *states[] = {"pending", "fulfilled", "rejected"};
            return str(std::string("[Promise ") + states[v.As<v8::Promise>()->State()] + "]");
        }
        // new String("...") etc.: the wrapped primitive, not one key per character
        if (v->IsStringObject()) return truncated(v.As<v8::StringObject>()->ValueOf());
        if (v->IsNumberObject())
            return v8::Number::New(st.isolate, v.As<v8::NumberObject>()->ValueOf());
        if (v->IsBooleanObject())
            return v8::Boolean::New(st.isolate, v.As<v8::BooleanObject>()->ValueOf());
        if (!v->IsObject()) return str("[unknown]");
        auto o = v.As<v8::Object>();
        std::string cls = utf8(truncated(o->GetConstructorName()));
        if (cls.empty()) cls = "Object";
        if (v->IsArrayBufferView() || v->IsArrayBuffer() || v->IsSharedArrayBuffer() ||
            v->IsWeakMap() || v->IsWeakSet() || v->IsWeakRef() || v->IsSymbolObject() ||
            v->IsBigIntObject())
            return str("[" + cls + "]");
        if (v->IsNativeError()) {
            v8::Local<v8::Value> message;
            bool accessor = false;
            std::string text = cls;
            if (own_value(o, str("message"), &message, &accessor) && !accessor && message->IsString())
                text += ": " + utf8(truncated(message.As<v8::String>()));
            return truncated(str(text));
        }
        for (auto& seen_o : path)
            if (seen_o->StrictEquals(o)) return str("[Circular]");
        if (depth >= kCaptureDepth)
            return str(v->IsArray() ? "[Array]" : "[" + cls + "]");
        v8::Local<v8::Value> prior;
        if (seen[depth]->Get(st.safe_context, o).ToLocal(&prior) && !prior->IsUndefined())
            return prior;
        if ((v->IsMap() && v.As<v8::Map>()->Size() > kCaptureCollection) ||
            (v->IsSet() && v.As<v8::Set>()->Size() > kCaptureCollection)) {
            size_t n = v->IsMap() ? v.As<v8::Map>()->Size() : v.As<v8::Set>()->Size();
            return str("[" + cls + "(" + std::to_string(n) + ")]");
        }
        path.push_back(o);
        v8::Local<v8::Value> r;
        if (v->IsMap() || v->IsSet())
            r = collection(o, depth);
        else if (v->IsArray())
            r = array(o.As<v8::Array>(), depth);
        else
            r = object(o, depth);
        path.pop_back();
        if (!stopped)
            seen[depth]->Set(st.safe_context, o, r).IsEmpty();
        return r;
    }

    // a Map as [[key, value], ...], a Set as [value, ...]
    v8::Local<v8::Value> collection(v8::Local<v8::Object> o, int depth)
    {
        v8::EscapableHandleScope scope(st.isolate);
        bool pairs = false;
        v8::Local<v8::Array> entries;
        auto out = new_array();
        if (!o->PreviewEntries(&pairs).ToLocal(&entries)) return scope.Escape(out);
        uint32_t n = entries->Length(), step = pairs ? 2 : 1;
        uint32_t j = 0;
        for (uint32_t i = 0; i + step - 1 < n && j < kCaptureItems; i += step, j++) {
            v8::Local<v8::Value> k, val;
            if (!entries->Get(context, i).ToLocal(&k)) break;
            if (pairs) {
                if (!entries->Get(context, i + 1).ToLocal(&val)) break;
                auto pair = new_array();
                put(pair, 0, value(k, depth + 1));
                put(pair, 1, value(val, depth + 1));
                put(out, j, pair);
            } else {
                put(out, j, value(k, depth + 1));
            }
        }
        if (n / step > j)
            put(out, j, str("\xE2\x80\xA6 " + std::to_string(n / step - j) + " more"));
        return scope.Escape(out);
    }

    v8::Local<v8::Value> array(v8::Local<v8::Array> a, int depth)
    {
        v8::EscapableHandleScope scope(st.isolate);
        uint32_t n = a->Length();
        auto out = new_array();
        uint32_t j = 0;
        for (; j < n && j < kCaptureItems; j++) {
            v8::Local<v8::Value> val;
            v8::Local<v8::String> key;
            bool accessor = false;
            if (!v8::Integer::NewFromUnsigned(st.isolate, j)->ToString(context).ToLocal(&key) ||
                !own_value(a, key, &val, &accessor))
                val = v8::Undefined(st.isolate);
            put(out, j, accessor ? getter() : value(val, depth + 1));
        }
        if (n > j)
            put(out, j, str("\xE2\x80\xA6 " + std::to_string(n - j) + " more"));
        return scope.Escape(out);
    }

    // own enumerable string-keyed properties; a debugger scope object's
    // properties are its variables
    v8::Local<v8::Value> object(v8::Local<v8::Object> o, int depth)
    {
        v8::EscapableHandleScope scope(st.isolate);
        auto out = new_object();
        if (stopped) return scope.Escape(out); // out of room: don't list the keys
        v8::Local<v8::Array> names;
        auto filter = static_cast<v8::PropertyFilter>(v8::ONLY_ENUMERABLE | v8::SKIP_SYMBOLS);
        if (!o->GetOwnPropertyNames(context, filter, v8::KeyConversionMode::kConvertToString).ToLocal(&names))
            return scope.Escape(out);
        uint32_t n = names->Length(), kept = 0;
        for (uint32_t i = 0; i < n; i++) {
            v8::Local<v8::Value> name_v, val;
            if (!names->Get(context, i).ToLocal(&name_v) || !name_v->IsString()) continue;
            if (kept == kCaptureItems) {
                put(out, str("\xE2\x80\xA6"), str(std::to_string(n - i) + " more"));
                break;
            }
            auto name = name_v.As<v8::String>();
            bool accessor = false;
            if (!own_value(o, name, &val, &accessor)) continue;
            auto key = name;
            if (name->Length() > static_cast<int>(kCaptureString)) {
                key = truncated(name).As<v8::String>();
                // two long names can shorten to the same key
                if (out->HasOwnProperty(st.safe_context, key).FromMaybe(false))
                    key = v8::String::Concat(st.isolate, key, str(" #" + std::to_string(i)));
            }
            put(out, key, accessor ? getter() : value(val, depth + 1));
            kept++;
        }
        return scope.Escape(out);
    }
};

v8::Local<v8::Value> get_field(v8::Local<v8::Context> c, v8::Local<v8::Value> o, const char *key)
{
    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    v8::Local<v8::Value> v;
    if (!o->IsObject() ||
        !o.As<v8::Object>()->Get(c, v8::String::NewFromUtf8(isolate, key).ToLocalChecked()).ToLocal(&v))
        return v8::Undefined(isolate);
    return v;
}

bool unwrap(Capture& cap, v8::Local<v8::Value> remote, v8::Local<v8::Value> *out)
{
    v8::Local<v8::Value> id = get_field(cap.st.safe_context, remote, "objectId");
    if (!id->IsString()) return false;
    v8::String::Value id16(cap.st.isolate, id);
    std::unique_ptr<v8_inspector::StringBuffer> error, group;
    v8::Local<v8::Context> context;
    return cap.session->unwrapObject(&error,
        v8_inspector::StringView(reinterpret_cast<const uint16_t*>(*id16), id16.length()),
        out, &context, &group);
}

// The thrown value a Debugger.paused event describes: an object by its id,
// a primitive by value, a BigInt by its digits.
bool thrown_value(Capture& cap, CaptureWalk& walk, v8::Local<v8::Value> data,
                  v8::Local<v8::Value> *out, std::string *bigint)
{
    State& st = cap.st;
    auto sc = st.safe_context;
    if (unwrap(cap, data, out)) return true;
    if (walk.utf8(get_field(sc, data, "type")) == "undefined") {
        *out = v8::Undefined(st.isolate);
        return true;
    }
    if (data->IsObject() &&
        data.As<v8::Object>()->HasOwnProperty(sc, walk.str("value")).FromMaybe(false)) {
        *out = get_field(sc, data, "value");
        return true;
    }
    std::string u = walk.utf8(get_field(sc, data, "unserializableValue"));
    double d;
    if (u == "NaN") d = std::numeric_limits<double>::quiet_NaN();
    else if (u == "Infinity") d = std::numeric_limits<double>::infinity();
    else if (u == "-Infinity") d = -std::numeric_limits<double>::infinity();
    else if (u == "-0") d = -0.0;
    else if (u.size() > 1 && u.back() == 'n') { // a BigInt, matched by its digits
        *bigint = u;
        *out = v8::Undefined(st.isolate);
        return true;
    }
    else return false;
    *out = v8::Number::New(st.isolate, d);
    return true;
}

void capture_record(Capture& cap, const std::string& message)
{
    State& st = cap.st;
    // reply() serializing a result can run getters; an exception they cause
    // belongs to no evaluation's error
    if (st.replying_depth == st.javascript_call_depth)
        return;
    v8::HandleScope handle_scope(st.isolate);
    v8::TryCatch try_catch(st.isolate); // best effort; never disturbs the exception
    // CDP leaves a frame's url empty and names scripts only in scriptParsed
    // events; the pause happens on the throwing stack, which knows them.
    // Taken before entering the safe context: frames of a context the
    // current one can't access are left out
    std::vector<std::pair<int, v8::Local<v8::String>>> script_names;
    auto trace = v8::StackTrace::CurrentStackTrace(st.isolate, 4 * kCaptureFrames);
    for (int i = 0; i < trace->GetFrameCount(); i++) {
        auto f = trace->GetFrame(st.isolate, i);
        auto name = f->GetScriptNameOrSourceURL();
        if (!name.IsEmpty())
            script_names.emplace_back(f->GetScriptId(), name);
    }
    v8::Local<v8::Context> sc = st.safe_context;
    v8::Context::Scope context_scope(sc);
    CaptureWalk walk(st, st.context);
    v8::Local<v8::Value> parsed;
    if (!v8::JSON::Parse(sc, walk.str(message)).ToLocal(&parsed)) return;
    auto params = get_field(sc, parsed, "params");
    auto data = get_field(sc, params, "data");
    if (!get_field(sc, data, "uncaught")->IsTrue()) return;
    v8::Local<v8::Value> exception;
    std::string bigint;
    if (!thrown_value(cap, walk, data, &exception, &bigint)) return;
    auto frames_v = get_field(sc, params, "callFrames");
    if (!frames_v->IsArray()) return;
    auto frames = frames_v.As<v8::Array>();
    auto out_frames = walk.new_array();
    bool script_scope_done = false; // top-level let/const: the same in every frame
    for (uint32_t i = 0, n = frames->Length(); i < n && i < kCaptureFrames; i++) {
        v8::Local<v8::Value> frame;
        if (!frames->Get(sc, i).ToLocal(&frame)) break;
        auto location = get_field(sc, frame, "location");
        auto line = get_field(sc, location, "lineNumber");
        auto column = get_field(sc, location, "columnNumber");
        auto out = walk.new_object();
        auto function = get_field(sc, frame, "functionName");
        walk.put(out, walk.str("function"),
                 function->IsString() ? walk.truncated(function.As<v8::String>()) : function);
        v8::Local<v8::Value> url = v8::String::Empty(st.isolate);
        int script_id = atoi(walk.utf8(get_field(sc, location, "scriptId")).c_str());
        for (auto& [id, name] : script_names)
            if (id == script_id) { url = name; break; }
        walk.put(out, walk.str("url"),
                 url->IsString() ? walk.truncated(url.As<v8::String>()) : url);
        // CDP counts from 0; stack traces and editors from 1
        if (line->IsNumber())
            walk.put(out, walk.str("line"), v8::Number::New(st.isolate, line.As<v8::Number>()->Value() + 1));
        if (column->IsNumber())
            walk.put(out, walk.str("column"), v8::Number::New(st.isolate, column.As<v8::Number>()->Value() + 1));
        auto scopes_v = get_field(sc, frame, "scopeChain");
        auto out_scopes = walk.new_array();
        uint32_t k = 0;
        if (scopes_v->IsArray()) {
            auto scopes = scopes_v.As<v8::Array>();
            for (uint32_t j = 0; j < scopes->Length(); j++) {
                v8::Local<v8::Value> scope, object;
                if (!scopes->Get(sc, j).ToLocal(&scope)) break;
                std::string type = walk.utf8(get_field(sc, scope, "type"));
                if (type == "global") continue; // all of globalThis
                if (type == "script") {
                    if (script_scope_done) continue;
                    script_scope_done = true;
                }
                if (!unwrap(cap, get_field(sc, scope, "object"), &object) || !object->IsObject())
                    continue;
                auto out_scope = walk.new_object();
                walk.put(out_scope, walk.str("type"), walk.str(type));
                auto name = get_field(sc, scope, "name");
                if (name->IsString())
                    walk.put(out_scope, walk.str("name"), walk.truncated(name.As<v8::String>()));
                // a scope's variables count as the first level
                walk.put(out_scope, walk.str("variables"), walk.object(object.As<v8::Object>(), -1));
                walk.put(out_scopes, k++, out_scope);
            }
        }
        walk.put(out, walk.str("scopes"), out_scopes);
        walk.put(out_frames, i, out);
    }
    auto record = walk.new_object();
    walk.put(record, walk.str("reason"), get_field(sc, params, "reason"));
    walk.put(record, walk.str("frames"), out_frames);
    // a single large value can carry recording past the deadline
    if (walk.stopped || std::chrono::steady_clock::now() > walk.deadline)
        walk.put(record, walk.str("truncated"), v8::True(st.isolate));
    // a later pause (another rejection, say) must not push this one out
    // before its error claims it
    if (st.captured.size() == kCaptureRecords)
        st.captured.erase(st.captured.begin());
    st.captured.emplace_back();
    st.captured.back().record.Reset(st.isolate, record);
    st.captured.back().exception.Reset(st.isolate, exception);
    st.captured.back().bigint = bigint;
    st.captured.back().invocation = st.invocations.empty() ? 0 : st.invocations.back();
}

void CaptureClient::runMessageLoopOnPause(int)
{
    std::string message;
    message.swap(cap.paused);
    if (!message.empty())
        capture_record(cap, message);
    // returning resumes; there is no frontend to wait for
}

bool same_exception(State& st, const CapturedError& c, v8::Local<v8::Value> thrown)
{
    if (!c.bigint.empty()) {
        v8::Local<v8::String> digits;
        if (!thrown->IsBigInt() || !thrown->ToString(st.safe_context).ToLocal(&digits))
            return false;
        v8::String::Utf8Value u(st.isolate, digits);
        return *u && std::string(*u, u.length()) + "n" == c.bigint;
    }
    return thrown->SameValue(v8::Local<v8::Value>::New(st.isolate, c.exception));
}

// Appends to a runtime error's [message, stack] the record of the pause for
// this very exception, if exactly one record of this eval or call matches
// it: two throws of an equal value (two rejections with 404, say) can't be
// told apart, and a wrong record is worse than none. Then drops this
// evaluation's records, and if it's the outermost one, all records.
v8::Local<v8::Value> with_capture(State& st, v8::TryCatch *try_catch, int cause,
                                  bool nested, v8::Local<v8::Value> err)
{
    if (st.captured.empty())
        return err;
    uint64_t self = st.invocations.empty() ? 0 : st.invocations.back();
    v8::Local<v8::Value> record;
    int matches = 0;
    auto thrown = try_catch->Exception();
    if (cause == RUNTIME_ERROR && !thrown.IsEmpty()) {
        for (auto& c : st.captured) {
            if (c.invocation == self && same_exception(st, c, thrown)) {
                record = v8::Local<v8::Value>::New(st.isolate, c.record);
                matches++;
            }
        }
    }
    if (nested) {
        st.captured.erase(std::remove_if(st.captured.begin(), st.captured.end(),
                                         [self](const CapturedError& c) { return c.invocation == self; }),
                          st.captured.end());
    } else {
        st.captured.clear();
    }
    if (matches != 1)
        return err;
    if (err->IsArray()) {
        auto fields = err.As<v8::Array>();
        fields->CreateDataProperty(st.safe_context, fields->Length(), record).FromMaybe(false);
        return err;
    }
    // a thrown primitive has no stack, so its error is the bare message
    v8::Local<v8::Value> fields[] = {err, v8::String::Empty(st.isolate), record};
    v8::Context::Scope context_scope(st.safe_context);
    return v8::Array::New(st.isolate, fields, 3);
}

// Marks an eval or call as in progress for the records it makes.
struct InvocationScope
{
    State& st;
    explicit InvocationScope(State& st) : st(st) { st.invocations.push_back(++st.last_invocation); }
    ~InvocationScope() { st.invocations.pop_back(); }
};

extern "C" State *v8_thread_init(Context *c, const uint8_t *snapshot_buf,
                                 size_t snapshot_len, int64_t max_memory,
                                 int verbose_exceptions,
                                 const char *inspector_title,
                                 int capture_on_throw)
{
    State *pst = new State{};
    State& st = *pst;
    st.verbose_exceptions = (verbose_exceptions != 0);
    st.ruby_context = c;
    st.allocator.reset(v8::ArrayBuffer::Allocator::NewDefaultAllocator());
    v8::StartupData blob{nullptr, 0};
    v8::Isolate::CreateParams params;
    params.array_buffer_allocator = st.allocator.get();
    if (snapshot_len) {
        blob.data = reinterpret_cast<const char*>(snapshot_buf);
        blob.raw_size = snapshot_len;
        params.snapshot_blob = &blob;
    }
    st.isolate = v8::Isolate::New(params);
    st.max_memory = max_memory;
    if (st.max_memory > 0)
        st.isolate->AddGCEpilogueCallback(v8_gc_callback, pst);
    {
        v8::Locker locker(st.isolate);
        v8::Isolate::Scope isolate_scope(st.isolate);
        v8::HandleScope handle_scope(st.isolate);
        st.safe_context = v8::Context::New(st.isolate);
        st.context = v8::Context::New(st.isolate);
        v8::Context::Scope context_scope(st.context);
        {
            v8::Context::Scope context_scope(st.safe_context);
            auto source = v8::String::NewFromUtf8Literal(st.isolate, safe_context_script_source);
            auto filename = v8::String::NewFromUtf8Literal(st.isolate, "safe_context_script.js");
            v8::ScriptOrigin origin(filename);
            auto script =
                v8::Script::Compile(st.safe_context, source, &origin)
                .ToLocalChecked();
            auto function_v = script->Run(st.safe_context).ToLocalChecked();
            auto function = v8::Function::Cast(*function_v);
            auto recv = v8::Undefined(st.isolate);
            v8::Local<v8::Value> arg = st.context->Global();
            // grant the safe context access to the user context's globalThis
            st.safe_context->SetSecurityToken(st.context->GetSecurityToken());
            function_v =
                function->Call(st.safe_context, recv, 1, &arg)
                .ToLocalChecked();
            // revoke access again now that the script did its one-time setup
            st.safe_context->UseDefaultSecurityToken();
            st.safe_context_function = v8::Local<v8::Function>::Cast(function_v);
        }
        if (single_threaded) {
            st.persistent_safe_context_function.Reset(st.isolate, st.safe_context_function);
            st.persistent_safe_context.Reset(st.isolate, st.safe_context);
            st.persistent_context.Reset(st.isolate, st.context);
            return pst; // intentionally returning early and keeping alive
        }
        if (inspector_title)
            inspector_init(st, inspector_title);
        if (capture_on_throw) {
            capture_init(st);
            if (!st.verbose_exceptions)
                st.isolate->AddMessageListener(capture_message_listener);
        }
        v8_thread_main(c, pst); // shuts the inspector down on its way out
    }
    delete pst;
    return nullptr;
}

void v8_api_callback(const v8::FunctionCallbackInfo<v8::Value>& info)
{
    auto ext = v8::External::Cast(*info.Data());
    Callback *cb = static_cast<Callback*>(ext->Value());
    State& st = *cb->st;
    if (st.inspector_idle) {
        auto message = v8::String::NewFromUtf8Literal(st.isolate,
            "Ruby callbacks are unavailable from the debugger while no "
            "evaluation is running; pause at a breakpoint first");
        st.isolate->ThrowException(v8::Exception::Error(message));
        return;
    }
    v8::Local<v8::Array> request;
    {
        v8::Context::Scope context_scope(st.safe_context);
        request = v8::Array::New(st.isolate, 1 + info.Length());
    }
    for (int i = 0, n = info.Length(); i < n; i++) {
        request->Set(st.context, i, sanitize(st, info[i])).Check();
    }
    auto id = v8::Int32::New(st.isolate, cb->id);
    request->Set(st.context, info.Length(), id).Check(); // callback id
    {
        Serialized serialized(st, request);
        if (!serialized.data) return; // exception pending
        uint8_t marker = 'c'; // callback marker
        v8_reply(st.ruby_context, &marker, 1);
        v8_reply(st.ruby_context, serialized.data, serialized.size);
    }
    const uint8_t *p;
    size_t n;
    for (;;) {
        v8_roundtrip(st.ruby_context, &p, &n);
        if (*p == 'c') // callback reply
            break;
        if (*p == 'e') { // ruby exception pending
            v8::Local<v8::String> message;
            auto type = v8::NewStringType::kNormal;
            if (!v8::String::NewFromOneByte(st.isolate, p+1, type, n-1).ToLocal(&message)) {
                message = v8::String::NewFromUtf8Literal(st.isolate, "Ruby exception");
            }
            auto exception = v8::Exception::Error(message);
            st.ruby_exception.Reset(st.isolate, exception);
            st.isolate->ThrowException(exception);
            return;
        }
        v8_dispatch(st.ruby_context);
    }
    v8::ValueDeserializer des(st.isolate, p+1, n-1);
    des.ReadHeader(st.context).Check();
    v8::Local<v8::Value> result;
    if (!des.ReadValue(st.context).ToLocal(&result)) return; // exception pending
    info.GetReturnValue().Set(result);
}

// response is err or empty string
extern "C" void v8_attach(State *pst, const uint8_t *p, size_t n)
{
    State& st = *pst;
    v8::TryCatch try_catch(st.isolate);
    try_catch.SetVerbose(st.verbose_exceptions);
    v8::HandleScope handle_scope(st.isolate);
    v8::ValueDeserializer des(st.isolate, p, n);
    des.ReadHeader(st.context).Check();
    int cause = INTERNAL_ERROR;
    {
        v8::Local<v8::Value> request_v;
        if (!des.ReadValue(st.context).ToLocal(&request_v)) goto fail;
        v8::Local<v8::Object> request; // [name, id]
        if (!request_v->ToObject(st.context).ToLocal(&request)) goto fail;
        v8::Local<v8::Value> name_v;
        if (!request->Get(st.context, 0).ToLocal(&name_v)) goto fail;
        v8::Local<v8::Value> id_v;
        if (!request->Get(st.context, 1).ToLocal(&id_v)) goto fail;
        v8::Local<v8::String> name;
        if (!name_v->ToString(st.context).ToLocal(&name)) goto fail;
        int32_t id;
        if (!id_v->IsInt32()) goto fail;
        id = id_v.As<v8::Int32>()->Value();
        // support foo.bar.baz paths
        v8::String::Utf8Value path(st.isolate, name);
        if (!*path) goto fail;
        const char *p = *path;
        const char *pe = p + path.length();
        v8::Local<v8::Object> obj = st.context->Global();
        v8::Local<v8::String> key;
        for (;;) {
            bool last;
            if (!read_path_key(st, p, pe, &key, &last)) goto fail;
            if (last) break;
            v8::Local<v8::Value> val;
            if (!obj->Get(st.context, key).ToLocal(&val)) goto fail;
            if (!val->IsObject() && !val->IsFunction()) {
                val = v8::Object::New(st.isolate);
                if (!obj->Set(st.context, key, val).FromMaybe(false)) goto fail;
            }
            obj = val.As<v8::Object>();
        }
        std::unique_ptr<Callback> cb(new Callback{pst, id});
        v8::Local<v8::External> ext = v8::External::New(st.isolate, cb.get());
        v8::Local<v8::Function> function;
        if (!v8::Function::New(st.context, v8_api_callback, ext).ToLocal(&function)) goto fail;
        st.callbacks.push_back(cb.release());
        if (!obj->Set(st.context, key, function).FromMaybe(false)) goto fail;
    }
    cause = NO_ERROR;
fail:
    if (!cause && try_catch.HasCaught()) cause = RUNTIME_ERROR;
    auto err = to_error(st, &try_catch, cause);
    reply_retry(st, err);
}

struct JavascriptCallScope
{
    int& depth;

    explicit JavascriptCallScope(int& depth) : depth(depth) { depth++; }
    ~JavascriptCallScope() { depth--; }
};

void throw_nested_await_call(State& st)
{
    // V8 does not run microtask checkpoints recursively. A nested await call
    // from an attached Ruby callback can therefore deadlock, so reject it
    // before entering JavaScript.
    auto message = v8::String::NewFromUtf8Literal(
        st.isolate, "nested call_await/eval_await is not supported");
    st.isolate->ThrowException(v8::Exception::Error(message));
}

// awaits |*result| if it's a promise; false means an exception is pending
bool await_promise(State& st, v8::Local<v8::Value> *result)
{
    if (!(*result)->IsPromise()) return true;
    auto promise = result->As<v8::Promise>();
    for (;;) {
        v8::MicrotasksScope::PerformCheckpoint(st.isolate);
        switch (promise->State()) {
        case v8::Promise::kFulfilled:
            *result = promise->Result();
            return true;
        case v8::Promise::kRejected:
            st.isolate->ThrowException(promise->Result());
            return false;
        case v8::Promise::kPending:
            break;
        }
        st.waiting_for_task.store(true);
        if (st.terminate_requested.load() || st.isolate->IsExecutionTerminating()) {
            st.waiting_for_task.store(false);
            return false;
        }
        // a debugger message that arrived before waiting_for_task was set
        // posted no task; handle it now rather than sleep on it
        if (st.inspector) {
            Inspector& in = *st.inspector;
            if (!in.paused && in.dispatch_depth == 0 && inspector_drain(in)) {
                st.waiting_for_task.store(false);
                continue;
            }
        }
        // blocks until the next task; a concurrent v8_terminate_execution
        // or debugger message observes waiting_for_task and posts one
        v8::platform::PumpMessageLoop(
            platform, st.isolate,
            v8::platform::MessageLoopBehavior::kWaitForWork);
        st.waiting_for_task.store(false);
    }
}

// Nested calls report termination but leave it pending for the enclosing call.
// Outermost calls consume it as before.
bool suspend_termination(State& st, bool nested, int& cause)
{
    unsigned requests = nested ? st.terminate_requested.load()
                               : st.terminate_requested.exchange(0);
    if (!requests && !st.isolate->IsExecutionTerminating()) return false;
    st.isolate->CancelTerminateExecution();
    cause = st.err_reason ? st.err_reason : TERMINATED_ERROR;
    if (!nested) st.err_reason = NO_ERROR;
    return nested;
}

void restore_termination(State& st, bool suspended)
{
    if (suspended)
        st.isolate->TerminateExecution();
}

// response is errback [result, err] array
void v8_call_impl(State *pst, const uint8_t *p, size_t n, bool await)
{
    State& st = *pst;
    v8::TryCatch try_catch(st.isolate);
    try_catch.SetVerbose(verbose_try_catch(st));
    v8::HandleScope handle_scope(st.isolate);
    v8::ValueDeserializer des(st.isolate, p, n);
    std::vector<v8::Local<v8::Value>> args;
    des.ReadHeader(st.context).Check();
    v8::Local<v8::Value> result;
    int cause = INTERNAL_ERROR;
    bool preserve_termination = false;
    bool nested = st.javascript_call_depth > 0;
    JavascriptCallScope call_scope(st.javascript_call_depth);
    InvocationScope invocation(st);
    if (!nested) st.captured.clear(); // left by microtasks run while idle
    if (await && nested) {
        throw_nested_await_call(st);
        cause = RUNTIME_ERROR;
        goto fail;
    }
    {
        v8::Local<v8::Value> request_v;
        if (!des.ReadValue(st.context).ToLocal(&request_v)) goto fail;
        v8::Local<v8::Object> request;
        if (!request_v->ToObject(st.context).ToLocal(&request)) goto fail;
        v8::Local<v8::Value> name_v;
        if (!request->Get(st.context, 0).ToLocal(&name_v)) goto fail;
        v8::Local<v8::String> name;
        if (!name_v->ToString(st.context).ToLocal(&name)) goto fail;
        cause = RUNTIME_ERROR;
        // support foo.bar.baz paths
        v8::String::Utf8Value path(st.isolate, name);
        if (!*path) goto fail;
        const char *p = *path;
        const char *pe = p + path.length();
        v8::Local<v8::Object> obj = st.context->Global();
        v8::Local<v8::String> key;
        for (;;) {
            bool last;
            if (!read_path_key(st, p, pe, &key, &last)) goto fail;
            if (last) break;
            v8::Local<v8::Value> val;
            if (!obj->Get(st.context, key).ToLocal(&val)) goto fail;
            if (!val->ToObject(st.context).ToLocal(&obj)) goto fail;
        }
        v8::Local<v8::Value> function_v;
        if (!obj->Get(st.context, key).ToLocal(&function_v)) goto fail;
        if (!function_v->IsFunction()) {
            // XXX it's technically possible for |function_v| to be a callable
            // object but those are effectively extinct; regexp objects used
            // to be callable but not anymore
            auto message = v8::String::NewFromUtf8Literal(st.isolate, "not a function");
            auto exception = v8::Exception::TypeError(message);
            st.isolate->ThrowException(exception);
            goto fail;
        }
        auto function = v8::Function::Cast(*function_v);
        assert(request->IsArray());
        int n = v8::Array::Cast(*request)->Length();
        for (int i = 1; i < n; i++) {
            v8::Local<v8::Value> val;
            if (!request->Get(st.context, i).ToLocal(&val)) goto fail;
            args.push_back(val);
        }
        if (!nested) inspector_maybe_break(st);
        auto maybe_result_v = function->Call(st.context, obj, args.size(), args.data());
        v8::Local<v8::Value> result_v;
        if (!maybe_result_v.ToLocal(&result_v)) goto fail;
        if (await && !await_promise(st, &result_v)) goto fail;
        result = sanitize(st, result_v);
    }
    cause = NO_ERROR;
fail:
    preserve_termination = suspend_termination(st, nested, cause);
    if (bubble_up_ruby_exception(st, &try_catch)) {
        if (!nested) capture_after_eval(st);
        restore_termination(st, preserve_termination);
        return;
    }
    if (!cause && try_catch.HasCaught()) cause = RUNTIME_ERROR;
    if (cause) result = v8::Undefined(st.isolate);
    auto err = to_error(st, &try_catch, cause);
    err = with_capture(st, &try_catch, cause, nested, err);
    // Error formatting can run user JS (for example Error.prepareStackTrace)
    // which may call Context#stop. Do not let that termination leak into the
    // reply or the next evaluation.
    bool terminated_during_error = false;
    if (st.terminate_requested.load() || st.isolate->IsExecutionTerminating()) {
        terminated_during_error = true;
        preserve_termination =
            suspend_termination(st, nested, cause) || preserve_termination;
    }
    if (terminated_during_error) {
        result = v8::Undefined(st.isolate);
        std::vector<char> buf;
        set_error_message(buf, cause,
                          cause == MEMORY_ERROR ? "out of memory" : "terminated");
        err = string_from_bytes(st.isolate, buf);
    }
    if (!reply(st, result, err)) {
        assert(try_catch.HasCaught());
        goto fail; // retry; can be termination exception
    }
    if (!nested) capture_after_eval(st);
    if (!nested &&
        (st.terminate_requested.load() || st.isolate->IsExecutionTerminating())) {
        // A callback invoked by the serializer (for example a getter) can
        // request termination after the last suspend_termination check. Do not
        // leak that request into the next outermost evaluation.
        st.terminate_requested.store(0);
        st.isolate->CancelTerminateExecution();
        st.err_reason = NO_ERROR;
    }
    restore_termination(st, preserve_termination);
}

extern "C" void v8_call(State *pst, const uint8_t *p, size_t n)
{
    v8_call_impl(pst, p, n, false);
}

extern "C" void v8_call_await(State *pst, const uint8_t *p, size_t n)
{
    v8_call_impl(pst, p, n, true);
}

// response is errback [result, err] array
void v8_eval_impl(State *pst, const uint8_t *p, size_t n, bool await)
{
    State& st = *pst;
    v8::TryCatch try_catch(st.isolate);
    try_catch.SetVerbose(verbose_try_catch(st));
    v8::HandleScope handle_scope(st.isolate);
    v8::ValueDeserializer des(st.isolate, p, n);
    des.ReadHeader(st.context).Check();
    v8::Local<v8::Value> result;
    int cause = INTERNAL_ERROR;
    bool preserve_termination = false;
    bool nested = st.javascript_call_depth > 0;
    JavascriptCallScope call_scope(st.javascript_call_depth);
    InvocationScope invocation(st);
    if (!nested) st.captured.clear(); // left by microtasks run while idle
    if (await && nested) {
        throw_nested_await_call(st);
        cause = RUNTIME_ERROR;
        goto fail;
    }
    {
        v8::Local<v8::Value> request_v;
        if (!des.ReadValue(st.context).ToLocal(&request_v)) goto fail;
        v8::Local<v8::Object> request; // [filename, source]
        if (!request_v->ToObject(st.context).ToLocal(&request)) goto fail;
        v8::Local<v8::Value> filename;
        if (!request->Get(st.context, 0).ToLocal(&filename)) goto fail;
        v8::Local<v8::Value> source_v;
        if (!request->Get(st.context, 1).ToLocal(&source_v)) goto fail;
        v8::Local<v8::String> source;
        if (!source_v->ToString(st.context).ToLocal(&source)) goto fail;
        v8::ScriptOrigin origin(filename);
        v8::Local<v8::Script> script;
        cause = PARSE_ERROR;
        if (!v8::Script::Compile(st.context, source, &origin).ToLocal(&script)) goto fail;
        v8::Local<v8::Value> result_v;
        cause = RUNTIME_ERROR;
        if (!nested) inspector_maybe_break(st);
        auto maybe_result_v = script->Run(st.context);
        if (!maybe_result_v.ToLocal(&result_v)) goto fail;
        if (await && !await_promise(st, &result_v)) goto fail;
        result = sanitize(st, result_v);
    }
    cause = NO_ERROR;
fail:
    preserve_termination = suspend_termination(st, nested, cause);
    if (bubble_up_ruby_exception(st, &try_catch)) {
        if (!nested) capture_after_eval(st);
        restore_termination(st, preserve_termination);
        return;
    }
    if (!cause && try_catch.HasCaught()) cause = RUNTIME_ERROR;
    if (cause) result = v8::Undefined(st.isolate);
    auto err = to_error(st, &try_catch, cause);
    err = with_capture(st, &try_catch, cause, nested, err);
    // Error formatting can run user JS (for example Error.prepareStackTrace)
    // which may call Context#stop. Do not let that termination leak into the
    // reply or the next evaluation.
    bool terminated_during_error = false;
    if (st.terminate_requested.load() || st.isolate->IsExecutionTerminating()) {
        terminated_during_error = true;
        preserve_termination =
            suspend_termination(st, nested, cause) || preserve_termination;
    }
    if (terminated_during_error) {
        result = v8::Undefined(st.isolate);
        std::vector<char> buf;
        set_error_message(buf, cause,
                          cause == MEMORY_ERROR ? "out of memory" : "terminated");
        err = string_from_bytes(st.isolate, buf);
    }
    if (!reply(st, result, err)) {
        assert(try_catch.HasCaught());
        goto fail; // retry; can be termination exception
    }
    if (!nested) capture_after_eval(st);
    if (!nested &&
        (st.terminate_requested.load() || st.isolate->IsExecutionTerminating())) {
        // A callback invoked by the serializer (for example a getter) can
        // request termination after the last suspend_termination check. Do not
        // leak that request into the next outermost evaluation.
        st.terminate_requested.store(0);
        st.isolate->CancelTerminateExecution();
        st.err_reason = NO_ERROR;
    }
    restore_termination(st, preserve_termination);
}

extern "C" void v8_eval(State *pst, const uint8_t *p, size_t n)
{
    v8_eval_impl(pst, p, n, false);
}

extern "C" void v8_eval_await(State *pst, const uint8_t *p, size_t n)
{
    v8_eval_impl(pst, p, n, true);
}

extern "C" void v8_heap_stats(State *pst)
{
    State& st = *pst;
    v8::HandleScope handle_scope(st.isolate);
    v8::HeapStatistics s;
    st.isolate->GetHeapStatistics(&s);
    v8::Local<v8::Object> response = v8::Object::New(st.isolate);
#define PROP(name)                                                      \
    do {                                                                \
        auto key = v8::String::NewFromUtf8Literal(st.isolate, #name);   \
        auto val = v8::Number::New(st.isolate, s.name());               \
        response->Set(st.context, key, val).Check();                    \
    } while (0)
    PROP(total_heap_size);
    PROP(total_heap_size);
    PROP(total_heap_size_executable);
    PROP(total_physical_size);
    PROP(total_available_size);
    PROP(total_global_handles_size);
    PROP(used_global_handles_size);
    PROP(used_heap_size);
    PROP(heap_size_limit);
    PROP(malloced_memory);
    PROP(external_memory);
    PROP(peak_malloced_memory);
    PROP(number_of_native_contexts);
    PROP(number_of_detached_contexts);
#undef PROP
    reply_retry(st, response);
}

struct OutputStream : public v8::OutputStream
{
    std::vector<uint8_t> buf;

    void EndOfStream() final {}
    int GetChunkSize() final { return 65536; }

    WriteResult WriteAsciiChunk(char* data, int size)
    {
        const uint8_t *p = reinterpret_cast<uint8_t*>(data);
        buf.insert(buf.end(), p, p+size);
        return WriteResult::kContinue;
    }
};

extern "C" void v8_heap_snapshot(State *pst)
{
    State& st = *pst;
    v8::HandleScope handle_scope(st.isolate);
    auto snapshot = st.isolate->GetHeapProfiler()->TakeHeapSnapshot();
    OutputStream os;
    snapshot->Serialize(&os, v8::HeapSnapshot::kJSON);
    const_cast<v8::HeapSnapshot*>(snapshot)->Delete();
    v8_reply(st.ruby_context, os.buf.data(), os.buf.size()); // not serialized because big
}

extern "C" void v8_perform_microtask_checkpoint(State *pst)
{
    // Leave any termination active so the enclosing v8_call/v8_eval frame
    // surfaces OOM (set by v8_gc_callback) or watchdog termination to Ruby.
    State& st = *pst;
    JavascriptCallScope call_scope(st.javascript_call_depth);
    v8::TryCatch try_catch(st.isolate);
    try_catch.SetVerbose(st.verbose_exceptions);
    v8::HandleScope handle_scope(st.isolate);
    v8::MicrotasksScope::PerformCheckpoint(st.isolate);
    reply_retry(st, v8::Undefined(st.isolate));
}

extern "C" void v8_pump_message_loop(State *pst)
{
    State& st = *pst;
    bool nested = st.javascript_call_depth > 0;
    JavascriptCallScope call_scope(st.javascript_call_depth);
    v8::TryCatch try_catch(st.isolate);
    try_catch.SetVerbose(st.verbose_exceptions);
    v8::HandleScope handle_scope(st.isolate);
    bool ran_task = v8::platform::PumpMessageLoop(platform, st.isolate);
    if (st.isolate->IsExecutionTerminating()) goto fail;
    if (try_catch.HasCaught()) goto fail;
    if (ran_task) v8::MicrotasksScope::PerformCheckpoint(st.isolate);
    if (st.isolate->IsExecutionTerminating()) goto fail;
    if (platform->IdleTasksEnabled(st.isolate)) {
        double idle_time_in_seconds = 1.0 / 50;
        v8::platform::RunIdleTasks(platform, st.isolate, idle_time_in_seconds);
        if (st.isolate->IsExecutionTerminating()) goto fail;
        if (try_catch.HasCaught()) goto fail;
    }
fail:
    // A nested pump must leave termination active for the enclosing call/eval.
    if (!nested &&
        (st.terminate_requested.exchange(0) ||
         st.isolate->IsExecutionTerminating())) {
        st.isolate->CancelTerminateExecution();
        st.err_reason = NO_ERROR;
    }
    auto result = v8::Boolean::New(st.isolate, ran_task);
    reply_retry(st, result);
}

static uint32_t read_le32(const uint8_t *p)
{
    return static_cast<uint32_t>(p[0])
         | static_cast<uint32_t>(p[1]) << 8
         | static_cast<uint32_t>(p[2]) << 16
         | static_cast<uint32_t>(p[3]) << 24;
}

static bool snapshot_checksum_matches(const uint8_t *data, size_t n)
{
    if (n < 13)
        return false;
    uint32_t expected = read_le32(data + 8);

    // V8 uses zlib's adler32 when built with V8_USE_ZLIB, otherwise a
    // Fletcher-32 variant. Accept either so this check remains portable
    // across libv8-node builds. This is a corruption check, not a sandbox:
    // snapshots are still trusted-input-only.
    uint32_t s1 = 0, s2 = 0;
    for (size_t i = 12; i < n; i++) {
        s1 = (s1 + data[i]) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    if ((s2 << 16 | s1) == expected)
        return true;

    s1 = s2 = 0;
    for (size_t i = 12; i < n; i++) {
        s1 = (s1 + data[i]) % 65535;
        s2 = (s2 + s1) % 65535;
    }
    return (s2 << 16 | s1) == expected;
}

// The header/section offsets below mirror V8 13.6's SnapshotImpl. Keep them
// in sync with libv8-node; the fallback is intentionally limited to preventing
// V8's fatal deserializer checks, not to sandboxing untrusted snapshots.
extern "C" int v8_snapshot_validate(const uint8_t *data, size_t n,
                                     char *err, size_t errlen)
{
#define SNAPSHOT_INVALID(msg)                                           \
    do {                                                                \
        if (err && errlen)                                              \
            snprintf(err, errlen, "%s", msg);                           \
        return -1;                                                      \
    } while (0)

    if (n == 0)
        return 0; // Snapshot.load("") means "use V8's built-in snapshot".
    if (n > static_cast<size_t>(std::numeric_limits<int>::max()))
        SNAPSHOT_INVALID("snapshot is too large");
    if (n < 88)
        SNAPSHOT_INVALID("snapshot is too short");

    v8::StartupData blob{reinterpret_cast<const char*>(data),
                         static_cast<int>(n)};
    if (!blob.IsValid())
        SNAPSHOT_INVALID("snapshot version mismatch");

    uint32_t num_contexts = read_le32(data);
    uint32_t rehashability = read_le32(data + 4);
    if (rehashability > 1)
        SNAPSHOT_INVALID("snapshot header is invalid");
    if (num_contexts == 0)
        SNAPSHOT_INVALID("snapshot has no contexts");
    if (num_contexts > (n - 88) / 4)
        SNAPSHOT_INVALID("snapshot context table is invalid");

    const size_t pointer_size = sizeof(void*);
    size_t header_size = 88 + static_cast<size_t>(num_contexts) * 4;
    size_t startup_offset =
        (header_size + pointer_size - 1) & ~(pointer_size - 1);
    if (startup_offset > n)
        SNAPSHOT_INVALID("snapshot context table is invalid");

    uint32_t read_only_offset = read_le32(data + 80);
    uint32_t shared_heap_offset = read_le32(data + 84);
    if (read_only_offset <= startup_offset || read_only_offset > n)
        SNAPSHOT_INVALID("snapshot read-only section is invalid");
    if (shared_heap_offset <= read_only_offset || shared_heap_offset > n)
        SNAPSHOT_INVALID("snapshot shared-heap section is invalid");

    size_t previous_offset = shared_heap_offset;
    for (uint32_t i = 0; i < num_contexts; i++) {
        uint32_t offset = read_le32(data + 88 + static_cast<size_t>(i) * 4);
        if (offset <= previous_offset || offset >= n)
            SNAPSHOT_INVALID("snapshot context section is invalid");
        previous_offset = offset;
    }

    if (!snapshot_checksum_matches(data, n))
        SNAPSHOT_INVALID("snapshot checksum mismatch");

    return 0;
#undef SNAPSHOT_INVALID
}

// Keep all guard state in a JavaScript closure. The setup script returns a
// query function to C++; do not install a native callback or External global,
// because a retained property descriptor would otherwise make CreateBlob fail
// with "Unknown external reference".
static const char snapshot_intl_setup_source[] = R"js(
;(function() {
    const original = globalThis.Intl
    let used = false
    const getter = function() {
        used = true
        return original
    }
    const setter = function(value) {
        used = true
    }
    if (!original) {
        const query = function() { return used }
        query.getter = getter
        return query
    }
    Object.defineProperty(globalThis, "Intl", {
        configurable: true,
        enumerable: false,
        get: getter,
        set: setter
    })
    const query = function() { return used }
    query.getter = getter
    return query
})()
)js";

static const char snapshot_intl_error[] =
    "Intl is not supported in Snapshot.new scripts";

int snapshot(bool is_warmup, bool verbose_exceptions,
             const v8::String::Utf8Value& code,
             v8::StartupData blob, v8::StartupData *result,
             std::vector<char> *errbuf)
{
    // SnapshotCreator takes ownership of isolate
    v8::Isolate *isolate = v8::Isolate::Allocate();
    // An empty loaded snapshot means "start from V8's built-in snapshot", just
    // like Context.new. Passing a non-null StartupData with raw_size == 0 to
    // SnapshotCreator trips CHECK(!artifacts) during warmup.
    v8::StartupData *existing_blob =
        (is_warmup && blob.data && blob.raw_size > 0) ? &blob : nullptr;
    v8::SnapshotCreator snapshot_creator(isolate, nullptr, existing_blob);
    v8::Isolate::Scope isolate_scope(isolate);
    v8::TryCatch try_catch(isolate);
    try_catch.SetVerbose(verbose_exceptions);
    auto mode = is_warmup
        ? v8::SnapshotCreator::FunctionCodeHandling::kKeep
        : v8::SnapshotCreator::FunctionCodeHandling::kClear;
    int cause = INTERNAL_ERROR;
    {
        // Keep script-created values out of the scope that is alive when
        // CreateBlob() runs. V8's own warmup implementation uses separate
        // scopes; sharing one scope leaves Intl foreign handles visible to the
        // snapshot handle checker and aborts with
        // CheckGlobalAndEternalHandles failed.
        v8::HandleScope handle_scope(isolate);
        auto filename = is_warmup
            ? v8::String::NewFromUtf8Literal(isolate, "<warmup>")
            : v8::String::NewFromUtf8Literal(isolate, "<snapshot>");
        auto context = v8::Context::New(isolate);
        v8::Context::Scope context_scope(context);
        auto intl_key = v8::String::NewFromUtf8Literal(isolate, "Intl");
        v8::Local<v8::Value> intl_original;
        v8::Local<v8::Function> intl_state_fn;
        v8::Local<v8::Function> intl_guard_getter;
        bool intl_guarded = false;
        if (!context->Global()->Get(context, intl_key).ToLocal(&intl_original)) {
            set_error_message(*errbuf, INTERNAL_ERROR,
                              "failed to inspect snapshot Intl");
            return INTERNAL_ERROR;
        }
        if (!is_warmup && intl_original->IsObject()) {
            auto intl_setup_source = v8::String::NewFromUtf8Literal(
                isolate, snapshot_intl_setup_source);
            v8::Local<v8::Script> intl_setup_script;
            v8::Local<v8::Value> intl_state;
            if (!v8::Script::Compile(context, intl_setup_source)
                     .ToLocal(&intl_setup_script) ||
                !intl_setup_script->Run(context).ToLocal(&intl_state) ||
                !intl_state->IsFunction()) {
                set_error_message(*errbuf, INTERNAL_ERROR,
                                  "failed to initialize snapshot Intl guard");
                return INTERNAL_ERROR;
            }
            intl_state_fn = intl_state.As<v8::Function>();
            v8::Local<v8::Value> getter;
            auto getter_key =
                v8::String::NewFromUtf8Literal(isolate, "getter");
            if (!intl_state_fn->Get(context, getter_key).ToLocal(&getter) ||
                !getter->IsFunction()) {
                set_error_message(*errbuf, INTERNAL_ERROR,
                                  "failed to initialize snapshot Intl guard");
                return INTERNAL_ERROR;
            }
            intl_guard_getter = getter.As<v8::Function>();
            intl_guarded = true;
        }
        v8::Local<v8::String> source;
        auto type = v8::NewStringType::kNormal;
        if (!v8::String::NewFromUtf8(isolate, *code, type, code.length()).ToLocal(&source)) {
            v8::String::Utf8Value s(isolate, try_catch.Exception());
            if (!set_error_message(*errbuf, cause, s))
                set_error_message(*errbuf, cause, "unexpected failure");
            return cause;
        }
        v8::ScriptOrigin origin(filename);
        v8::Local<v8::Script> script;
        cause = PARSE_ERROR;
        if (!v8::Script::Compile(context, source, &origin).ToLocal(&script)) {
            auto m = try_catch.Message();
            if (m.IsEmpty()) {
                set_error_message(*errbuf, cause, "unexpected failure");
                return cause;
            }
            v8::String::Utf8Value s(isolate, m->Get());
            v8::String::Utf8Value name(isolate, m->GetScriptResourceName());
            auto line = m->GetLineNumber(context).FromMaybe(0);
            auto column = m->GetStartColumn(context).FromMaybe(0);
            if (*s && *name) {
                errbuf->clear();
                errbuf->push_back(static_cast<char>(cause));
                append_utf8(*errbuf, s);
                append_literal(*errbuf, "\n");
                append_utf8(*errbuf, name);
                append_format(*errbuf, ":%d:%d", line, column);
            } else {
                set_error_message(*errbuf, cause, "unexpected failure");
            }
            return cause;
        }
        cause = RUNTIME_ERROR;
        if (script->Run(context).IsEmpty()) {
            auto m = try_catch.Message();
            if (m.IsEmpty()) {
                set_error_message(*errbuf, cause, "unexpected failure");
                return cause;
            }
            v8::String::Utf8Value s(isolate, m->Get());
            v8::String::Utf8Value name(isolate, m->GetScriptResourceName());
            auto line = m->GetLineNumber(context).FromMaybe(0);
            auto column = m->GetStartColumn(context).FromMaybe(0);
            if (*s && *name) {
                errbuf->clear();
                errbuf->push_back(static_cast<char>(cause));
                append_utf8(*errbuf, s);
                append_literal(*errbuf, "\n");
                append_utf8(*errbuf, name);
                append_format(*errbuf, ":%d:%d", line, column);
            } else {
                set_error_message(*errbuf, cause, "unexpected failure");
            }
            return cause;
        }
        if (intl_guarded) {
            v8::Local<v8::Value> used;
            auto recv = v8::Undefined(isolate);
            if (!intl_state_fn->Call(context, recv, 0, nullptr)
                     .ToLocal(&used)) {
                set_error_message(*errbuf, INTERNAL_ERROR,
                                  "failed to inspect snapshot Intl guard");
                return INTERNAL_ERROR;
            }
            if (used->IsTrue()) {
                set_error_message(*errbuf, RUNTIME_ERROR, snapshot_intl_error);
                return RUNTIME_ERROR;
            }
        }
        if (intl_guarded) {
            // Only replace our accessor. If the script deliberately replaced
            // or deleted Intl, leave that change in the snapshot.
            v8::Local<v8::Value> descriptor;
            if (!context->Global()
                     ->GetOwnPropertyDescriptor(context, intl_key)
                     .ToLocal(&descriptor)) {
                set_error_message(*errbuf, INTERNAL_ERROR,
                                  "failed to inspect Intl after snapshot script");
                return INTERNAL_ERROR;
            }
            bool restore_intl = false;
            if (descriptor->IsObject()) {
                auto get_key =
                    v8::String::NewFromUtf8Literal(isolate, "get");
                v8::Local<v8::Value> getter_descriptor;
                if (!descriptor.As<v8::Object>()
                         ->GetOwnPropertyDescriptor(context, get_key)
                         .ToLocal(&getter_descriptor)) {
                    set_error_message(*errbuf, INTERNAL_ERROR,
                                      "failed to inspect Intl after snapshot script");
                    return INTERNAL_ERROR;
                }
                if (getter_descriptor->IsObject()) {
                    v8::Local<v8::Value> getter;
                    auto value_key =
                        v8::String::NewFromUtf8Literal(isolate, "value");
                    if (!getter_descriptor.As<v8::Object>()
                             ->Get(context, value_key)
                             .ToLocal(&getter)) {
                        set_error_message(*errbuf, INTERNAL_ERROR,
                                          "failed to inspect Intl after snapshot script");
                        return INTERNAL_ERROR;
                    }
                    restore_intl =
                        getter->IsFunction() &&
                        getter->SameValue(intl_guard_getter);
                }
            }
            if (restore_intl &&
                !context->Global()
                     ->DefineOwnProperty(
                         context, intl_key, intl_original,
                         v8::PropertyAttribute::DontEnum)
                     .FromMaybe(false)) {
                set_error_message(*errbuf, INTERNAL_ERROR,
                                  "failed to restore Intl after snapshot script");
                return INTERNAL_ERROR;
            }
        }
        if (!is_warmup) snapshot_creator.SetDefaultContext(context);
    }
    if (is_warmup) {
        v8::HandleScope handle_scope(isolate);
        isolate->ContextDisposedNotification(false);
        auto context = v8::Context::New(isolate);
        snapshot_creator.SetDefaultContext(context);
    }
    *result = snapshot_creator.CreateBlob(mode);
    return NO_ERROR;
}

// response is errback [result, err] array
// note: currently needs --stress_snapshot in V8 debug builds
// to work around a buggy check in the snapshot deserializer
extern "C" void v8_snapshot(State *pst, const uint8_t *p, size_t n)
{
    State& st = *pst;
    v8::TryCatch try_catch(st.isolate);
    try_catch.SetVerbose(st.verbose_exceptions);
    v8::HandleScope handle_scope(st.isolate);
    v8::ValueDeserializer des(st.isolate, p, n);
    des.ReadHeader(st.context).Check();
    v8::Local<v8::Value> result;
    v8::StartupData blob{nullptr, 0};
    int cause = INTERNAL_ERROR;
    std::vector<char> errbuf;
    {
        v8::Local<v8::Value> code_v;
        if (!des.ReadValue(st.context).ToLocal(&code_v)) goto fail;
        v8::String::Utf8Value code(st.isolate, code_v);
        if (!*code) goto fail;
        v8::StartupData init{nullptr, 0};
        cause = snapshot(/*is_warmup*/false, st.verbose_exceptions, code, init, &blob, &errbuf);
        if (cause) goto fail;
    }
    if (blob.data) {
        auto data = reinterpret_cast<const uint8_t*>(blob.data);
        auto type = v8::NewStringType::kNormal;
        bool ok = v8::String::NewFromOneByte(st.isolate, data, type,
                                             blob.raw_size).ToLocal(&result);
        delete[] blob.data;
        blob = v8::StartupData{nullptr, 0};
        if (!ok) goto fail;
    }
    cause = NO_ERROR;
fail:
    if (st.terminate_requested.exchange(0) ||
        st.isolate->IsExecutionTerminating()) {
        st.isolate->CancelTerminateExecution();
        cause = st.err_reason ? st.err_reason : TERMINATED_ERROR;
        st.err_reason = NO_ERROR;
    }
    if (!cause && try_catch.HasCaught()) cause = RUNTIME_ERROR;
    if (cause) result = v8::Undefined(st.isolate);
    v8::Local<v8::Value> err;
    if (!errbuf.empty()) {
        err = string_from_bytes(st.isolate, errbuf);
    } else {
        err = to_error(st, &try_catch, cause);
    }
    if (!reply(st, result, err)) {
        assert(try_catch.HasCaught());
        goto fail; // retry; can be termination exception
    }
}

extern "C" void v8_warmup(State *pst, const uint8_t *p, size_t n)
{
    State& st = *pst;
    v8::TryCatch try_catch(st.isolate);
    try_catch.SetVerbose(st.verbose_exceptions);
    v8::HandleScope handle_scope(st.isolate);
    std::vector<uint8_t> storage;
    v8::ValueDeserializer des(st.isolate, p, n);
    des.ReadHeader(st.context).Check();
    v8::Local<v8::Value> result;
    v8::StartupData blob{nullptr, 0};
    int cause = INTERNAL_ERROR;
    std::vector<char> errbuf;
    {
        v8::Local<v8::Value> request_v;
        if (!des.ReadValue(st.context).ToLocal(&request_v)) goto fail;
        v8::Local<v8::Object> request; // [snapshot, warmup_code]
        if (!request_v->ToObject(st.context).ToLocal(&request)) goto fail;
        v8::Local<v8::Value> blob_data_v;
        if (!request->Get(st.context, 0).ToLocal(&blob_data_v)) goto fail;
        v8::Local<v8::String> blob_data;
        if (!blob_data_v->ToString(st.context).ToLocal(&blob_data)) goto fail;
        assert(blob_data->IsOneByte());
        assert(blob_data->ContainsOnlyOneByte());
        if (const uint32_t len = blob_data->Length()) {
            // copies the bytes verbatim, NULs included, without a terminator
            storage.resize(len);
            blob_data->WriteOneByteV2(st.isolate, 0, len, storage.data());
        }
        v8::Local<v8::Value> code_v;
        if (!request->Get(st.context, 1).ToLocal(&code_v)) goto fail;
        v8::String::Utf8Value code(st.isolate, code_v);
        if (!*code) goto fail;
        auto data = reinterpret_cast<const char*>(storage.data());
        auto size = static_cast<int>(storage.size());
        v8::StartupData init{data, size};
        cause = snapshot(/*is_warmup*/true, st.verbose_exceptions, code, init, &blob, &errbuf);
        if (cause) goto fail;
    }
    if (blob.data) {
        auto data = reinterpret_cast<const uint8_t*>(blob.data);
        auto type = v8::NewStringType::kNormal;
        bool ok = v8::String::NewFromOneByte(st.isolate, data, type,
                                             blob.raw_size).ToLocal(&result);
        delete[] blob.data;
        blob = v8::StartupData{nullptr, 0};
        if (!ok) goto fail;
    }
    cause = NO_ERROR;
fail:
    if (st.terminate_requested.exchange(0) ||
        st.isolate->IsExecutionTerminating()) {
        st.isolate->CancelTerminateExecution();
        cause = st.err_reason ? st.err_reason : TERMINATED_ERROR;
        st.err_reason = NO_ERROR;
    }
    if (!cause && try_catch.HasCaught()) cause = RUNTIME_ERROR;
    if (cause) result = v8::Undefined(st.isolate);
    v8::Local<v8::Value> err;
    if (!errbuf.empty()) {
        err = string_from_bytes(st.isolate, errbuf);
    } else {
        err = to_error(st, &try_catch, cause);
    }
    if (!reply(st, result, err)) {
        assert(try_catch.HasCaught());
        goto fail; // retry; can be termination exception
    }
}

extern "C" void v8_low_memory_notification(State *pst)
{
    pst->isolate->LowMemoryNotification();
}

struct WakeupTask : public v8::Task
{
    void Run() final {}
};

// called from ruby or watchdog thread
void request_termination(State *pst, unsigned request)
{
    pst->terminate_requested.fetch_or(request);
    pst->isolate->TerminateExecution();
    // Wake await_promise if it may be blocked. A racing early return can leave
    // one harmless no-op task queued.
    if (pst->waiting_for_task.exchange(false)) {
        platform->GetForegroundTaskRunner(pst->isolate)
            ->PostTask(std::make_unique<WakeupTask>());
    }
}

extern "C" void v8_terminate_execution(State *pst)
{
    request_termination(pst, NON_WATCHDOG_TERMINATION);
}

extern "C" void v8_terminate_watchdog(State *pst)
{
    request_termination(pst, WATCHDOG_TERMINATION);
}

extern "C" void v8_cancel_watchdog_termination(State *pst)
{
    unsigned requests = pst->terminate_requested.fetch_and(~WATCHDOG_TERMINATION);
    if (requests == WATCHDOG_TERMINATION) {
        pst->isolate->CancelTerminateExecution();
        if (pst->terminate_requested.load())
            pst->isolate->TerminateExecution();
    }
}

// called from ruby thread
extern "C" void v8_cancel_terminate_execution(State *pst)
{
    // TerminateExecution can race with V8 completing and queue a termination
    // for the next entry without IsExecutionTerminating() becoming true.
    pst->terminate_requested.store(0);
    pst->isolate->CancelTerminateExecution();
}

extern "C" void v8_inspector_dispatch(State *pst)
{
    State& st = *pst;
    Inspector *in = st.inspector.get();
    if (!in || !in->target)
        return;
    v8::HandleScope handle_scope(st.isolate);
    st.inspector_idle = true;
    inspector_drop_session_if_safe(*in);
    inspector_drain(*in);
    st.inspector_idle = false;
}

extern "C" void v8_inspector_shutdown(State *pst)
{
    if (pst->inspector)
        inspector_teardown(*pst);
    if (pst->capture)
        capture_teardown(*pst);
}

extern "C" int v8_inspector_status(State *pst)
{
    Inspector *in = pst->inspector.get();
    if (!in)
        return 0;
    return INSPECTOR_ENABLED
        | (in->attached.load() ? INSPECTOR_ATTACHED : 0)
        | (in->ready.load() ? INSPECTOR_READY : 0);
}

extern "C" void v8_inspector_break_next(State *pst)
{
    if (Inspector *in = pst->inspector.get())
        in->break_next = true;
}

extern "C" int v8_inspector_start(const char *host, int port, const char *token,
                                  char *err, size_t errlen)
{
    std::string e;
    int r = mri::start_server(host, port, token, &e);
    if (r < 0)
        snprintf(err, errlen, "%s", e.c_str());
    return r;
}

extern "C" int v8_inspector_port(void)
{
    return mri::server_port();
}

extern "C" void v8_single_threaded_enter(State *pst, Context *c, void (*f)(Context *c))
{
    State& st = *pst;
    v8::Locker locker(st.isolate);
    v8::Isolate::Scope isolate_scope(st.isolate);
    v8::HandleScope handle_scope(st.isolate);
    {
        st.safe_context_function = v8::Local<v8::Function>::New(st.isolate, st.persistent_safe_context_function);
        st.safe_context = v8::Local<v8::Context>::New(st.isolate, st.persistent_safe_context);
        st.context = v8::Local<v8::Context>::New(st.isolate, st.persistent_context);
        v8::Context::Scope context_scope(st.context);
        f(c);
        st.context = v8::Local<v8::Context>();
        st.safe_context = v8::Local<v8::Context>();
        st.safe_context_function = v8::Local<v8::Function>();
    }
}

extern "C" void v8_single_threaded_dispose(struct State *pst)
{
    delete pst; // see State::~State() below
}

} // namespace anonymous

State::~State()
{
    {
        v8::Locker locker(isolate);
        v8::Isolate::Scope isolate_scope(isolate);
        persistent_safe_context_function.Reset();
        persistent_safe_context.Reset();
        persistent_context.Reset();
        ruby_exception.Reset();
        captured.clear();
    }
    isolate->Dispose();
    for (Callback *cb : callbacks)
        delete cb;
}
