#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

#if defined(__linux__) && !defined(__GLIBC__)
// musl compatibility for glibc-linked libraries (e.g. libv8-node)
// some versions of libv8-node are accidentally linked against glibc symbols
// or compiled with a toolchain that emits these C23 compatibility symbols
unsigned long long __isoc23_strtoull(const char *nptr, char **endptr, int base) {
    return strtoull(nptr, endptr, base);
}
unsigned long __isoc23_strtoul(const char *nptr, char **endptr, int base) {
    return strtoul(nptr, endptr, base);
}
long long __isoc23_strtoll(const char *nptr, char **endptr, int base) {
    return strtoll(nptr, endptr, base);
}
long __isoc23_strtol(const char *nptr, char **endptr, int base) {
    return strtol(nptr, endptr, base);
}
double __isoc23_strtod(const char *nptr, char **endptr) {
    return strtod(nptr, endptr);
}
float __isoc23_strtof(const char *nptr, char **endptr) {
    return strtof(nptr, endptr);
}
#endif

#include "ruby.h"
#include "ruby/encoding.h"
#include "ruby/version.h"
#include "ruby/thread.h"
#include "serde.c"
#include "mini_racer_v8.h"

// for debugging
#define RB_PUTS(v)                                          \
    do {                                                    \
        fflush(stdout);                                     \
        rb_funcall(rb_mKernel, rb_intern("puts"), 1, v);    \
    } while (0)

#if RUBY_API_VERSION_CODE < 3*10000+4*100 // 3.4.0
static inline void rb_thread_lock_native_thread(void)
{
    // Without rb_thread_lock_native_thread, V8 in single-threaded mode is
    // prone to crash with debug checks like this...
    //
    // # Fatal error in ../deps/v8/src/base/platform/platform-posix.cc, line 1350
    // # Debug check failed: MainThreadIsCurrentThread().
    //
    // ...because the Ruby runtime clobbers thread-local variables when it
    // context-switches threads. You have been warned.
}
#endif

#define countof(x)  (sizeof(x) / sizeof(*(x)))
#define endof(x)    ((x) + countof(x))
#define BIGINT_STACK_WORDS 64
#define BIGINT_MAX_BYTES (16 * 1024 * 1024)
#define SERIALIZE_MAX_DEPTH 512

// mostly RO: assigned once by platform_set_flag1 while holding |flags_mtx|,
// from then on read-only and accessible without holding locks
int single_threaded;

// work around missing pthread_barrier_t on macOS
typedef struct Barrier
{
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    int count, in, out;
} Barrier;

static inline int barrier_init(Barrier *b, int count)
{
    int r;

    if ((r = pthread_mutex_init(&b->mtx, NULL)))
        return r;
    if ((r = pthread_cond_init(&b->cv, NULL))) {
        pthread_mutex_destroy(&b->mtx);
        return r;
    }
    b->count = count;
    b->out = 0;
    b->in = 0;
    return 0;
}

static inline void barrier_destroy(Barrier *b)
{
    pthread_mutex_destroy(&b->mtx);
    pthread_cond_destroy(&b->cv);
}

static inline int barrier_wait(Barrier *b)
{
    int last;

    pthread_mutex_lock(&b->mtx);
    while (b->out)
        pthread_cond_wait(&b->cv, &b->mtx);
    if (++b->in == b->count) {
        b->in = 0;
        b->out = b->count;
        pthread_cond_broadcast(&b->cv);
    } else {
        do
            pthread_cond_wait(&b->cv, &b->mtx);
        while (b->in);
    }
    last = (--b->out == 0);
    if (last)
        pthread_cond_broadcast(&b->cv);
    pthread_mutex_unlock(&b->mtx);
    return last;
}

typedef struct Context
{
    int depth;     // call depth, protected by |rr_mtx|
    // protected by |mtx|; RW for ruby threads, RO for v8 thread;
    // atomic because context_stop (which can be called from other ruby
    // threads) writes it without holding |mtx|, to avoid deadlocking
    // 1=shut down v8, 2=free memory; note that only the v8 thread
    // frees the memory and it intentionally stays around until
    // the ruby object is gc'd, otherwise lifecycle management
    // gets too complicated
    atomic_int quit;
    int verbose_exceptions;
    int ser_opts;      // SER_* flags, set by Context.new(date:, decimal:)
    int64_t idle_gc, max_memory, timeout;
    struct State *pst; // used by v8 thread
    VALUE procs;       // array of js -> ruby callbacks
    VALUE exception;   // pending exception or Qnil
    int pending_jump_tag; // non-exception jump to replay after the roundtrip
    Buf req, res;      // ruby->v8 request/response, mediated by |mtx| and |cv|
    Buf v8_req;        // stable v8-side copy of a request returned by v8_roundtrip
    int res_ready;     // protected by |mtx|; response may be filled before ready
    Buf snapshot;
    Buf capture_expressions; // Context.new(capture_on_throw: {expressions:}), NUL-separated
    pthread_t single_threaded_thr;
    pid_t single_threaded_pid;
    int single_threaded_thr_started;
    // |rr_mtx| stands for "recursive ruby mutex"; it's used to exclude
    // other ruby threads but allow reentrancy from the same ruby thread
    // (think ruby->js->ruby->js calls)
    pthread_mutex_t rr_mtx;
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    struct {
        pthread_mutex_t mtx;
        pthread_cond_t cv;
        int active; // dispatch thread only
        int cancel; // protected by |mtx|
    } wd; // watchdog
    struct {
        pthread_t thr;
        pthread_mutex_t mtx;
        pthread_cond_t cv;
        int active; // v8 thread only
        int cancel; // protected by |mtx|
    } pw; // pause watchdog, enforces |max_pause|
    Barrier early_init, late_init;
    // inspector (Chrome DevTools Protocol); see mini_racer_inspector.h
    int inspector;               // set by Context.new(inspector:)
    int capture_on_throw;        // set by Context.new(capture_on_throw:)
    char inspector_title[256];
    int64_t max_pause;           // ms a breakpoint may hold the caller; 0 = no cap
    int inspector_pending;       // protected by |mtx|
    atomic_int dbg_paused;       // v8 thread is stopped at a breakpoint
    atomic_llong dbg_paused_ms;  // total time spent paused; the watchdog
                                 // does not count it against |timeout|
    atomic_llong dbg_pause_start_ms; // written by the v8 thread
    atomic_uint pause_generation; // pauses so far; a frame handle is only good
                                  // for the pause it came from
    char inspector_target_id[64]; // set by the v8 thread before late_init
    int inspector_detach_terminates; // Context.new(inspector_detach: :terminate)
} Context;

typedef struct Snapshot {
    VALUE blob;
} Snapshot;

static void context_destroy(Context *c);
static void context_abandon(Context *c);
static void context_free(void *arg);
static void context_mark(void *arg);
static size_t context_size(const void *arg);

static const rb_data_type_t context_type = {
    .wrap_struct_name   =  "mini_racer/context",
    .function           = {
        .dfree = context_free,
        .dmark = context_mark,
        .dsize = context_size,
    },
};

static void snapshot_free(void *arg);
static void snapshot_mark(void *arg);
static size_t snapshot_size(const void *arg);

static const rb_data_type_t snapshot_type = {
    .wrap_struct_name   =  "mini_racer/snapshot",
    .function           = {
        .dfree = snapshot_free,
        .dmark = snapshot_mark,
        .dsize = snapshot_size,
    },
};

static VALUE platform_init_error;
static VALUE context_disposed_error;
static VALUE parse_error;
static VALUE memory_error;
static VALUE script_error;
static VALUE runtime_error;
static VALUE internal_error;
static VALUE snapshot_error;
static VALUE terminated_error;
static VALUE context_class;
static VALUE snapshot_class;
static VALUE date_class;
static VALUE date_time_class;
static VALUE binary_class;
static VALUE big_decimal_class;
static VALUE js_function_class;

static pthread_mutex_t flags_mtx = PTHREAD_MUTEX_INITIALIZER;
static Buf flags; // protected by |flags_mtx|

// arg == &(struct rendezvous_nogvl){...}
static void *rendezvous_callback(void *arg);

// note: must be stack-allocated or VALUEs won't be visible to ruby's GC
typedef struct State
{
    VALUE   a, b;
    uint8_t verbatim_keys:1;
} State;

// note: must be stack-allocated or VALUEs won't be visible to ruby's GC
typedef struct DesCtx
{
    State   *tos;
    VALUE   refs; // object refs array
    uint8_t transcode_latin1:1;
    char    err[64];
    State   stack[512];
} DesCtx;

struct rendezvous_nogvl
{
    Context *context;
    Buf *req, *res;
    atomic_int active;
    atomic_int interrupted;
    int started, finished, has_rr_mtx;
};

struct rendezvous_des
{
    DesCtx *d;
    Buf *res;
};

static void DesCtx_init(DesCtx *c)
{
    c->tos  = c->stack;
    c->refs = rb_ary_new();
    *c->tos = (State){Qundef, Qundef, /*verbatim_keys*/0};
    *c->err = '\0';
    c->transcode_latin1 = 1; // convert to utf8
}

static void put(DesCtx *c, VALUE v)
{
    VALUE *a, *b;

    if (*c->err)
        return;
    a = &c->tos->a;
    b = &c->tos->b;
    switch (TYPE(*a)) {
    case T_ARRAY:
        rb_ary_push(*a, v);
        break;
    case T_HASH:
        if (*b == Qundef) {
            *b = v;
        } else {
            if (!c->tos->verbatim_keys) {
                if (RB_TYPE_P(*b, T_STRING))
                    *b = rb_str_to_interned_str(*b);
                else
                    *b = rb_funcall(*b, rb_intern("to_s"), 0);
            }
            rb_hash_aset(*a, *b, v);
            *b = Qundef;
        }
        break;
    case T_UNDEF:
        *a = v;
        break;
    default:
        snprintf(c->err, sizeof(c->err), "bad state");
        return;
    }
}

static void push(DesCtx *c, VALUE v)
{
    if (*c->err)
        return;
    if (c->tos == endof(c->stack) - 1) {
        snprintf(c->err, sizeof(c->err), "stack overflow");
        return;
    }
    *++c->tos = (State){v, Qundef, /*verbatim_keys*/0};
    rb_ary_push(c->refs, v);
}

// see also des_named_props_end
static void pop(DesCtx *c)
{
    if (*c->err)
        return;
    if (c->tos == c->stack) {
        snprintf(c->err, sizeof(c->err), "stack underflow");
        return;
    }
    put(c, (*c->tos--).a);
}

static void des_null(void *arg)
{
    put(arg, Qnil);
}

static void des_undefined(void *arg)
{
    put(arg, Qnil);
}

static void des_bool(void *arg, int v)
{
    put(arg, v ? Qtrue : Qfalse);
}

static void des_int(void *arg, int64_t v)
{
    put(arg, LL2NUM((LONG_LONG)v));
}

static void des_num(void *arg, double v)
{
    if (isfinite(v) && v == trunc(v)) {
        // INT64_MAX is not exactly representable as a double: it rounds up to
        // 2^63, which would let 2^63 through and make the cast undefined.
        if (v >= -0x1p63 && v < 0x1p63) {
            put(arg, LL2NUM((LONG_LONG)v));
        } else {
            put(arg, rb_dbl2big(v));
        }
    } else {
        put(arg, DBL2NUM(v));
    }
}

static void des_date(void *arg, double v)
{
    double sec, usec;

    if (!isfinite(v))
        rb_raise(rb_eRangeError, "invalid Date");
    sec = v/1e3;
    usec = 1e3 * fmod(v, 1e3);
    put(arg, rb_time_new(sec, usec));
}

// note: v8 stores bigints as a sign plus little-endian 64-bit magnitude words
static void des_bigint(void *arg, const void *p, size_t n, int sign)
{
    VALUE v;
    DesCtx *c;
    int flags;

    c = arg;
    if (*c->err)
        return;
    if (n % sizeof(uint64_t)) {
        snprintf(c->err, sizeof(c->err), "bad bigint");
        return;
    }
    if (n > BIGINT_MAX_BYTES) {
        snprintf(c->err, sizeof(c->err), "bigint too big");
        return;
    }
    if (n == 0) {
        v = INT2FIX(0);
    } else {
        flags = INTEGER_PACK_LITTLE_ENDIAN;
        if (sign < 0)
            flags |= INTEGER_PACK_NEGATIVE;
        v = rb_integer_unpack(p, n/sizeof(uint64_t), sizeof(uint64_t), 0, flags);
    }
    put(c, v);
}

static void des_string(void *arg, const char *s, size_t n)
{
    put(arg, rb_utf8_str_new(s, n));
}

static VALUE str_encode_bang(VALUE v)
{
    // TODO cache these? this function can get called often
    return rb_funcall(v, rb_intern("encode!"), 1, rb_str_new_cstr("UTF-8"));
}

static void des_string8(void *arg, const uint8_t *s, size_t n)
{
    size_t i, hi;
    DesCtx *c;
    VALUE v;
    char *d;

    c = arg;
    if (*c->err)
        return;
    if (c->transcode_latin1) {
        // latin1 -> utf8 without a round trip through String#encode!
        for (hi = 0, i = 0; i < n; i++)
            hi += s[i] >> 7;
        if (!hi) {
            v = rb_utf8_str_new((char *)s, n);
        } else {
            // every byte >= 0x80 becomes two bytes
            v = rb_utf8_str_new(NULL, n + hi);
            d = RSTRING_PTR(v);
            for (i = 0; i < n; i++) {
                if (s[i] < 0x80) {
                    *d++ = s[i];
                } else {
                    *d++ = 0xC0 | (s[i] >> 6);
                    *d++ = 0x80 | (s[i] & 0x3F);
                }
            }
        }
    } else {
        v = rb_enc_str_new((char *)s, n, rb_ascii8bit_encoding());
    }
    put(c, v);
}

// des_string16: |s| is not word aligned
// des_string16: |n| is in bytes, not code points
static void des_string16(void *arg, const void *s, size_t n)
{
    rb_encoding *e;
    VALUE v, r;
    DesCtx *c;
    int exc;

    c = arg;
    if (*c->err)
        return;
    // TODO(bnoordhuis) replace this hack with something more principled
    if (n == sizeof(js_function_marker) && !memcmp(js_function_marker, s, n))
        return put(c, rb_funcall(js_function_class, rb_intern("new"), 0));
    e = rb_enc_find("UTF-16LE"); // TODO cache?
    if (!e) {
        snprintf(c->err, sizeof(c->err), "no UTF16-LE encoding");
        return;
    }
    v = rb_enc_str_new((char *)s, n, e);
    // JS strings can contain unmatched or illegal surrogate pairs
    // that Ruby won't decode; return the string as-is in that case
    r = rb_protect(str_encode_bang, v, &exc);
    if (exc) {
        rb_set_errinfo(Qnil);
        r = v;
    }
    put(c, r);
}

// ruby doesn't really have a concept of a byte array so store it as
// an 8-bit string instead; it's either that or a regular array of
// numbers, but the latter is markedly less efficient, storage-wise
static void des_arraybuffer(void *arg, const void *s, size_t n)
{
    put(arg, rb_enc_str_new((char *)s, n, rb_ascii8bit_encoding()));
}

static void des_array_begin(void *arg)
{
    push(arg, rb_ary_new());
}

static void des_array_end(void *arg)
{
    pop(arg);
}

static void des_named_props_begin(void *arg)
{
    push(arg, rb_hash_new());
}

// see also pop
static void des_named_props_end(void *arg)
{
    DesCtx *c;

    c = arg;
    if (*c->err)
        return;
    if (c->tos == c->stack) {
        snprintf(c->err, sizeof(c->err), "stack underflow");
        return;
    }
    c->tos--; // dropped, no way to represent in ruby
}

static void des_object_begin(void *arg)
{
    push(arg, rb_hash_new());
}

static void des_object_end(void *arg)
{
    pop(arg);
}

static void des_map_begin(void *arg)
{
    DesCtx *c;

    c = arg;
    push(c, rb_hash_new());
    c->tos->verbatim_keys = 1; // don't stringify or intern keys
}

static void des_map_end(void *arg)
{
    pop(arg);
}

static void des_object_ref(void *arg, uint32_t id)
{
    DesCtx *c;
    VALUE v;

    c = arg;
    v = rb_ary_entry(c->refs, id);
    put(c, v);
}

static void des_error_begin(void *arg)
{
    push(arg, rb_ary_new());
}

static void des_error_end(void *arg)
{
    VALUE *a, h, message, stack, cause, newline;
    DesCtx *c;

    c = arg;
    if (*c->err)
        return;
    if (c->tos == c->stack) {
        snprintf(c->err, sizeof(c->err), "stack underflow");
        return;
    }
    a = &c->tos->a;
    h = rb_ary_pop(*a);
    message = rb_hash_aref(h, rb_str_new_cstr("message"));
    stack = rb_hash_aref(h, rb_str_new_cstr("stack"));
    cause = rb_hash_aref(h, rb_str_new_cstr("cause"));
    if (NIL_P(message))
        message = rb_str_new_cstr("JS exception");
    if (!NIL_P(stack)) {
        newline = rb_str_new_cstr("\n");
        message = rb_funcall(message, rb_intern("concat"), 2, newline, stack);
    }
    *a = rb_class_new_instance(1, &message, script_error);
    if (!NIL_P(cause))
        rb_iv_set(*a, "@cause", cause);
    pop(c);
}

static int collect(VALUE k, VALUE v, VALUE a)
{
    rb_ary_push(a, k);
    rb_ary_push(a, v);
    return ST_CONTINUE;
}

static void add_string(Ser *s, VALUE v)
{
    rb_encoding *e;
    const void *p;
    size_t n;

    Check_Type(v, T_STRING);
    e = rb_enc_get(v);
    p = RSTRING_PTR(v);
    n = RSTRING_LEN(v);
    if (e) {
        if (!strcmp(e->name, "ISO-8859-1"))
            return ser_string8(s, p, n);
        if (!strcmp(e->name, "UTF-16LE"))
            return ser_string16(s, p, n);
    }
    // ASCII is valid latin1: V8 builds a one-byte string without decoding
    if (e && rb_enc_asciicompat(e) && rb_enc_str_coderange(v) == ENC_CODERANGE_7BIT)
        return ser_string8(s, p, n);
    return ser_string(s, p, n);
}

// Keep small values allocation-free while allowing large values up to a
// deliberate per-value limit that bounds temporary conversion storage.
static int serialize_bigint(Ser *s, VALUE v)
{
    uint64_t stack_words[BIGINT_STACK_WORDS];
    uint64_t *words;
    size_t nwords, nbytes;
    int packed;

    nwords = rb_absint_numwords(v, 64, NULL);
    if (nwords == (size_t)-1 || nwords > BIGINT_MAX_BYTES/sizeof(*words))
        return bail(&s->err, "bigint too big");
    nbytes = nwords * sizeof(*words);
    words = stack_words;
    if (nwords > countof(stack_words)) {
        words = malloc(nbytes);
        if (!words)
            return bail(&s->err, "out of memory");
    }
    packed = rb_integer_pack(v, words, nwords, sizeof(*words), 0,
                             INTEGER_PACK_LITTLE_ENDIAN);
    if (packed < -1 || packed > 1) {
        if (words != stack_words)
            free(words);
        return bail(&s->err, "bigint too big");
    }
    ser_bigint(s, words, nbytes, packed < 0 ? -1 : 1);
    if (words != stack_words)
        free(words);
    return *s->err ? -1 : 0;
}

// how serialize() hands JS the Ruby values that have no exact JS type
enum {
    SER_DATE_ISO      = 1, // Date (not DateTime) as "YYYY-MM-DD", not a JS Date
    SER_DECIMAL_FLOAT = 2, // BigDecimal as a number, not "Undefined Conversion"
};

static int serialize1(Ser *s, VALUE refs, VALUE v, int depth, int opts)
{
    VALUE a, t, id;
    size_t i, n;

    if (*s->err)
        return -1;
    if (depth > SERIALIZE_MAX_DEPTH)
        return bail(&s->err, "max depth exceeded");
    switch (TYPE(v)) {
    case T_ARRAY:
        {
            id = rb_hash_lookup(refs, v);
            if (NIL_P(id)) {
                n = RARRAY_LENINT(v);
                i = rb_hash_size_num(refs);
                rb_hash_aset(refs, v, LONG2FIX(i));
                ser_array_begin(s, n);
                for (i = 0; i < n; i++)
                    if (serialize1(s, refs, rb_ary_entry(v, i), depth + 1, opts))
                        return -1;
                ser_array_end(s, n);
            } else {
                ser_object_ref(s, FIX2LONG(id));
            }
        }
        break;
    case T_HASH:
        {
            id = rb_hash_lookup(refs, v);
            if (NIL_P(id)) {
                a = rb_ary_new();
                i = rb_hash_size_num(refs);
                n = rb_hash_size_num(v);
                rb_hash_aset(refs, v, LONG2FIX(i));
                rb_hash_foreach(v, collect, a);
                for (i = 0; i < 2*n; i += 2) {
                    t = rb_ary_entry(a, i);
                    switch (TYPE(t)) {
                    case T_FIXNUM:
                    case T_STRING:
                    case T_SYMBOL:
                        continue;
                    }
                    break;
                }
                if (i == 2*n) {
                    ser_object_begin(s);
                    for (i = 0; i < 2*n; i += 2) {
                        if (serialize1(s, refs, rb_ary_entry(a, i+0), depth + 1, opts))
                            return -1;
                        if (serialize1(s, refs, rb_ary_entry(a, i+1), depth + 1, opts))
                            return -1;
                    }
                    ser_object_end(s, n);
                } else {
                    return bail(&s->err, "TODO serialize as Map");
                }
            } else {
                ser_object_ref(s, FIX2LONG(id));
            }
        }
        break;
    case T_DATA:
        // Date and DateTime may have been required after context creation.
        if (NIL_P(date_time_class) && rb_const_defined(rb_cObject, rb_intern("DateTime")))
            date_time_class = rb_const_get(rb_cObject, rb_intern("DateTime"));
        if (NIL_P(date_class) && rb_const_defined(rb_cObject, rb_intern("Date")))
            date_class = rb_const_get(rb_cObject, rb_intern("Date"));
        if (date_time_class == CLASS_OF(v)) {
            v = rb_funcall(v, rb_intern("to_time"), 0);
        } else if (date_class == CLASS_OF(v)) {
            if (opts & SER_DATE_ISO) {
                // a calendar day; to_time would make it local midnight,
                // which is the previous day in UTC east of Greenwich
                add_string(s, rb_funcall(v, rb_intern("iso8601"), 0));
                break;
            }
            v = rb_funcall(v, rb_intern("to_time"), 0);
        } else if (opts & SER_DECIMAL_FLOAT) {
            if (NIL_P(big_decimal_class) && rb_const_defined(rb_cObject, rb_intern("BigDecimal")))
                big_decimal_class = rb_const_get(rb_cObject, rb_intern("BigDecimal"));
            // the exact class, like Date above: a subclass's to_f isn't ours to run
            if (!NIL_P(big_decimal_class) && CLASS_OF(v) == big_decimal_class) {
                ser_num(s, NUM2DBL(rb_funcall(v, rb_intern("to_f"), 0)));
                break;
            }
        }
        if (rb_cTime == CLASS_OF(v)) {
            struct timeval tv = rb_time_timeval(v);
            ser_date(s, tv.tv_sec*1e3 + tv.tv_usec/1e3);
        } else {
            static const char undefined_conversion[] = "Undefined Conversion";
            ser_string(s, undefined_conversion, sizeof(undefined_conversion)-1);
        }
        break;
    case T_NIL:
        ser_null(s);
        break;
    case T_UNDEF:
        ser_undefined(s);
        break;
    case T_TRUE:
        ser_bool(s, 1);
        break;
    case T_FALSE:
        ser_bool(s, 0);
        break;
    case T_BIGNUM:
        return serialize_bigint(s, v);
    case T_FIXNUM:
        ser_int(s, FIX2LONG(v));
        break;
    case T_FLOAT:
        ser_num(s, NUM2DBL(v));
        break;
    case T_SYMBOL:
        v = rb_sym2str(v);
        // fallthru
    case T_STRING:
        add_string(s, v);
        break;
    case T_OBJECT:
        // this is somewhat wide, but we have active support which creates
        // entirely new objects
        if (rb_respond_to(v, rb_intern("to_time"))) {
            v = rb_funcall(v, rb_intern("to_time"), 0);
            if (rb_obj_is_kind_of(v, rb_cTime)) {
                struct timeval tv = rb_time_timeval(v);
                ser_date(s, tv.tv_sec*1e3 + tv.tv_usec/1e3);
            } else {
                snprintf(s->err, sizeof(s->err), "unsupported type %s", rb_class2name(CLASS_OF(v)));
                return -1;
            }
        } else if (!NIL_P(binary_class) && rb_obj_is_kind_of(v, binary_class)) {
            t = rb_ivar_get(v, rb_intern("@data"));
            Check_Type(t, T_STRING);
            ser_uint8array(s, RSTRING_PTR(t), RSTRING_LEN(t));
        } else {
            snprintf(s->err, sizeof(s->err), "unsupported type %s", rb_class2name(CLASS_OF(v)));
            return -1;
        }
        break;
    default:
        snprintf(s->err, sizeof(s->err), "unsupported type %x", TYPE(v));
        return -1;
    }
    if (*s->err)
        return -1;
    return 0;
}

// don't mix with ser_array_begin/ser_object_begin because
// that will throw off the object reference count
// Raises if writing a request failed (too large or out of memory).
static void ser_check(Ser *s, const char *what)
{
    if (!*s->err)
        return;
    ser_reset(s);
    rb_raise(runtime_error, "%s: %s", what, s->err);
}

static int serialize(Ser *s, VALUE v, int opts)
{
    VALUE refs = rb_hash_new();
    // keyed by the object itself; rb_obj_id would pin an id on every one
    rb_funcall(refs, rb_intern("compare_by_identity"), 0);
    return serialize1(s, refs, v, 0, opts);
}

static struct timespec deadline_ms(int ms)
{
    static const int64_t ns_per_sec = 1000*1000*1000;
    struct timespec t;

#ifdef __APPLE__
    clock_gettime(CLOCK_REALTIME, &t);
#else
    clock_gettime(CLOCK_MONOTONIC, &t);
#endif
    t.tv_sec += ms/1000;
    t.tv_nsec += ms%1000 * ns_per_sec/1000;
    while (t.tv_nsec >= ns_per_sec) {
        t.tv_nsec -= ns_per_sec;
        t.tv_sec++;
    }
    return t;
}

static int timespec_le(struct timespec a, struct timespec b)
{
    if (a.tv_sec < b.tv_sec) return 1;
    return a.tv_sec == b.tv_sec && a.tv_nsec <= b.tv_nsec;
}

static int deadline_exceeded(struct timespec deadline)
{
    return timespec_le(deadline, deadline_ms(0));
}

static int64_t monotonic_ms(void)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec*1000 + t.tv_nsec/1000000;
}

static void timespec_add_ms(struct timespec *t, int64_t ms)
{
    static const int64_t ns_per_sec = 1000*1000*1000;

    t->tv_sec += ms/1000;
    t->tv_nsec += ms%1000 * ns_per_sec/1000;
    while (t->tv_nsec >= ns_per_sec) {
        t->tv_nsec -= ns_per_sec;
        t->tv_sec++;
    }
}

static void *v8_watchdog(void *arg)
{
    struct timespec deadline, until;
    int64_t seen, paused_ms;
    Context *c;

    c = arg;
    deadline = deadline_ms(c->timeout);
    seen = atomic_load(&c->dbg_paused_ms);
    pthread_mutex_lock(&c->wd.mtx);
    for (;;) {
        if (c->wd.cancel)
            break;
        // time spent stopped at a breakpoint doesn't count: push the
        // deadline out by it, and only poll while a pause is ongoing
        paused_ms = atomic_load(&c->dbg_paused_ms);
        if (paused_ms != seen) {
            timespec_add_ms(&deadline, paused_ms - seen);
            seen = paused_ms;
        }
        until = atomic_load(&c->dbg_paused) ? deadline_ms(100) : deadline;
        pthread_cond_timedwait(&c->wd.cv, &c->wd.mtx, &until);
        if (c->wd.cancel)
            break;
        if (atomic_load(&c->dbg_paused) || atomic_load(&c->dbg_paused_ms) != seen)
            continue;
        if (deadline_exceeded(deadline)) {
            v8_terminate_watchdog(c->pst);
            break;
        }
    }
    pthread_mutex_unlock(&c->wd.mtx);
    return NULL;
}

static void v8_timedwait(Context *c, const uint8_t *p, size_t n,
                         void (*func)(struct State *pst, const uint8_t *p, size_t n))
{
    pthread_t thr;
    int r;

    if (c->timeout <= 0 || c->wd.active) {
        func(c->pst, p, n);
        return;
    }
    c->wd.active = 1;
    r = pthread_create(&thr, NULL, v8_watchdog, c);
    if (r) {
        c->wd.active = 0;
        fprintf(stderr, "mini_racer: watchdog: pthread_create: %s\n", strerror(r));
        fflush(stderr);
    }
    func(c->pst, p, n);
    if (r)
        return;
    pthread_mutex_lock(&c->wd.mtx);
    c->wd.cancel = 1;
    pthread_cond_signal(&c->wd.cv);
    pthread_mutex_unlock(&c->wd.mtx);
    pthread_join(thr, NULL);
    v8_cancel_watchdog_termination(c->pst);
    c->wd.cancel = 0;
    c->wd.active = 0;
}

static void dispatch1(Context *c, const uint8_t *p, size_t n)
{
    uint8_t b;

    assert(n > 0);
    switch (*p) {
    case 'A': return v8_attach(c->pst, p+1, n-1);
    case 'C': return v8_timedwait(c, p+1, n-1, v8_call);
    case 'D': return v8_timedwait(c, p+1, n-1, v8_call_await);
    case 'E': return v8_timedwait(c, p+1, n-1, v8_eval);
    case 'F': return v8_timedwait(c, p+1, n-1, v8_eval_await);
    case 'H': return v8_heap_snapshot(c->pst);
    case 'M': return v8_perform_microtask_checkpoint(c->pst);
    case 'P': return v8_pump_message_loop(c->pst);
    case 'S': return v8_heap_stats(c->pst);
    case 'T': return v8_snapshot(c->pst, p+1, n-1);
    case 'W': return v8_warmup(c->pst, p+1, n-1);
    case 'L':
        b = 0;
        v8_reply(c, &b, 1); // doesn't matter what as long as it's not empty
        return v8_low_memory_notification(c->pst);
    }
    fprintf(stderr, "mini_racer: bad request %02x\n", *p);
    fflush(stderr);
}

static void dispatch_buf(Context *c, Buf *req)
{
    Buf local_req;

    // Called with Context.mtx held. Release it while V8 runs so an rb_nogvl
    // UBF can wake the Ruby thread to process interrupts with
    // rb_thread_check_ints(), without forcing termination first. Move the
    // request out first so cancellation cannot free a buffer V8 is reading.
    buf_move(req, &local_req);
    buf_reset(&c->res);
    c->res_ready = 0;
    pthread_mutex_unlock(&c->mtx);
    dispatch1(c, local_req.buf, local_req.len);
    pthread_mutex_lock(&c->mtx);
    buf_reset(&local_req);
    c->res_ready = 1;
    pthread_cond_signal(&c->cv);
}

static void dispatch(Context *c)
{
    dispatch_buf(c, &c->req);
}

// called by v8_isolate_and_context
void v8_thread_main(Context *c, struct State *pst)
{
    struct timespec deadline;
    bool issued_idle_gc = true;

    c->pst = pst;
    barrier_wait(&c->late_init);
    pthread_mutex_lock(&c->mtx);
    while (!c->quit) {
        if (!c->req.len && !c->inspector_pending) {
            if (c->idle_gc > 0) {
                deadline = deadline_ms(c->idle_gc);
                pthread_cond_timedwait(&c->cv, &c->mtx, &deadline);
                if (deadline_exceeded(deadline) && !issued_idle_gc) {
                    v8_low_memory_notification(c->pst);
                    issued_idle_gc = true;
                }
            } else {
                pthread_cond_wait(&c->cv, &c->mtx);
            }
        }
        if (c->inspector_pending) {
            c->inspector_pending = 0;
            pthread_mutex_unlock(&c->mtx);
            v8_inspector_dispatch(c->pst);
            pthread_mutex_lock(&c->mtx);
            continue;
        }
        if (!c->req.len)
            continue; // spurious wakeup or quit signal from other thread
        dispatch(c);
        issued_idle_gc = false;
        pthread_cond_signal(&c->cv);
    }
    // The inspector server thread takes the target lock, then |mtx| (to
    // wake us); shutting the inspector down takes the target lock, so it
    // must not run with |mtx| held.
    pthread_mutex_unlock(&c->mtx);
    v8_inspector_shutdown(pst);
    pthread_mutex_lock(&c->mtx);
}

// called by v8_thread_main and from mini_racer_v8.cc
void v8_dispatch(Context *c)
{
    pthread_mutex_lock(&c->mtx);
    dispatch_buf(c, &c->v8_req);
    pthread_mutex_unlock(&c->mtx);
}

// only called when inside v8_call, v8_eval (and their await variants),
// or v8_pump_message_loop
void v8_roundtrip(Context *c, const uint8_t **p, size_t *n)
{
    pthread_mutex_lock(&c->mtx);
    buf_reset(&c->v8_req);
    if (c->res.len)
        c->res_ready = 1;
    pthread_cond_signal(&c->cv);
    while (!c->req.len && !atomic_load(&c->quit))
        pthread_cond_wait(&c->cv, &c->mtx);
    if (!c->req.len && atomic_load(&c->quit)) {
        static const uint8_t disposed[] = "edisposed context";
        *p = disposed;
        *n = sizeof(disposed) - 1;
        pthread_mutex_unlock(&c->mtx);
        return;
    }
    buf_reset(&c->res);
    c->res_ready = 0;
    buf_move(&c->req, &c->v8_req);
    *p = c->v8_req.buf;
    *n = c->v8_req.len;
    pthread_mutex_unlock(&c->mtx);
}

// called from the inspector server thread
void v8_inspector_wake(Context *c)
{
    pthread_mutex_lock(&c->mtx);
    c->inspector_pending = 1;
    pthread_cond_signal(&c->cv);
    pthread_mutex_unlock(&c->mtx);
}

// Ends a pause that runs past |max_pause|. A thread of its own, because
// the v8 thread's pause loop can't check the clock while it runs a debugger
// expression (Debugger.evaluateOnCallFrame) that never returns.
// --- inspector lifecycle events ---
//
// A bounded, process-wide record of what happened to inspectable contexts,
// for a supervisor to audit or react to (MiniRacer::Inspector.events). Any
// thread appends; one Ruby consumer takes them. Past INSPECTOR_EVENTS
// unread, the oldest are dropped and counted, so nothing grows unbounded.

#define INSPECTOR_EVENTS 1024

typedef struct InspectorEvent {
    uint64_t seq;
    int type;                 // enum InspectorEventType
    int64_t at_ms;            // monotonic
    unsigned generation;      // the context's pause generation then
    char target[64];
    char reason[32];
} InspectorEvent;

static pthread_mutex_t ev_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ev_cv = PTHREAD_COND_INITIALIZER;
static InspectorEvent ev_ring[INSPECTOR_EVENTS];
static uint64_t ev_next;      // seq of the next event appended
static uint64_t ev_read;      // seq of the oldest unread event
static uint64_t ev_dropped;
static int ev_wakeup;         // the waiting Ruby thread was interrupted

static const char *const inspector_event_names[] = {
    "created", "destroyed", "attached", "detached", "paused", "resumed", "terminated",
};

static void ev_atfork_child(void)
{
    pthread_mutex_init(&ev_mtx, NULL);
    pthread_cond_init(&ev_cv, NULL);
    ev_next = ev_read = ev_dropped = 0;
    ev_wakeup = 0;
}

void v8_inspector_event(Context *c, int type, const char *reason)
{
    InspectorEvent *e;

    if (!c->inspector || !*c->inspector_target_id)
        return;
    pthread_mutex_lock(&ev_mtx);
    if (ev_next - ev_read == INSPECTOR_EVENTS) {
        ev_read++; // drop the oldest
        ev_dropped++;
    }
    e = &ev_ring[ev_next % INSPECTOR_EVENTS];
    e->seq = ev_next++;
    e->type = type;
    e->at_ms = monotonic_ms();
    e->generation = atomic_load(&c->pause_generation);
    snprintf(e->target, sizeof(e->target), "%s", c->inspector_target_id);
    snprintf(e->reason, sizeof(e->reason), "%s", reason ? reason : "");
    pthread_cond_broadcast(&ev_cv);
    pthread_mutex_unlock(&ev_mtx);
}

struct ev_wait {
    int64_t timeout_ms; // < 0: no timeout
    InspectorEvent *out;
    int max, n;
};

static void *ev_wait_nogvl(void *arg)
{
    struct ev_wait *w;
    struct timespec deadline;

    w = arg;
    if (w->timeout_ms >= 0)
        deadline = deadline_ms(w->timeout_ms > INT32_MAX ? INT32_MAX : (int)w->timeout_ms);
    pthread_mutex_lock(&ev_mtx);
    ev_wakeup = 0;
    while (ev_read == ev_next && !ev_wakeup && w->timeout_ms != 0) {
        if (w->timeout_ms < 0)
            pthread_cond_wait(&ev_cv, &ev_mtx);
        else if (pthread_cond_timedwait(&ev_cv, &ev_mtx, &deadline) == ETIMEDOUT)
            break;
    }
    while (ev_read < ev_next && w->n < w->max)
        w->out[w->n++] = ev_ring[ev_read++ % INSPECTOR_EVENTS];
    pthread_mutex_unlock(&ev_mtx);
    return NULL;
}

static void ev_wait_ubf(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&ev_mtx);
    ev_wakeup = 1;
    pthread_cond_broadcast(&ev_cv);
    pthread_mutex_unlock(&ev_mtx);
}

// [[seq, type name, at_ms, generation, target id, reason], ...] and the
// count dropped so far; |timeout_ms| < 0 waits until there is one
static VALUE inspector_events(VALUE self, VALUE timeout_ms, VALUE max)
{
    InspectorEvent buf[64];
    struct ev_wait w;
    VALUE a, e;
    int i;

    w.timeout_ms = NUM2LL(timeout_ms);
    w.max = NUM2INT(max);
    if (w.max < 1 || w.max > (int)(sizeof(buf)/sizeof(*buf)))
        rb_raise(rb_eArgError, "bad max");
    w.out = buf;
    w.n = 0;
    rb_thread_call_without_gvl(ev_wait_nogvl, &w, ev_wait_ubf, NULL);
    a = rb_ary_new_capa(w.n);
    for (i = 0; i < w.n; i++) {
        e = rb_ary_new_from_args(6,
            ULL2NUM(buf[i].seq),
            rb_str_new_cstr(inspector_event_names[buf[i].type]),
            LL2NUM(buf[i].at_ms),
            UINT2NUM(buf[i].generation),
            rb_str_new_cstr(buf[i].target),
            rb_str_new_cstr(buf[i].reason));
        rb_ary_push(a, e);
    }
    return a;
}

static VALUE inspector_events_dropped(VALUE self)
{
    uint64_t n;

    pthread_mutex_lock(&ev_mtx);
    n = ev_dropped;
    pthread_mutex_unlock(&ev_mtx);
    return ULL2NUM(n);
}

static void *v8_pause_watchdog(void *arg)
{
    struct timespec deadline;
    Context *c;

    c = arg;
    deadline = deadline_ms(c->max_pause);
    pthread_mutex_lock(&c->pw.mtx);
    while (!c->pw.cancel) {
        if (pthread_cond_timedwait(&c->pw.cv, &c->pw.mtx, &deadline) == ETIMEDOUT &&
            !c->pw.cancel) {
            v8_inspector_event(c, INSPECTOR_EVENT_TERMINATED, "max_pause");
            v8_terminate_execution(c->pst);
            break;
        }
    }
    pthread_mutex_unlock(&c->pw.mtx);
    return NULL;
}

// called from the v8 thread when it enters or leaves a breakpoint
void v8_inspector_paused(Context *c, int paused)
{
    if (paused) {
        atomic_store(&c->dbg_pause_start_ms, monotonic_ms());
        atomic_fetch_add(&c->pause_generation, 1);
        atomic_store(&c->dbg_paused, 1);
        v8_inspector_event(c, INSPECTOR_EVENT_PAUSED, NULL);
        if (c->max_pause > 0 && !c->pw.active) {
            c->pw.cancel = 0;
            c->pw.active = !pthread_create(&c->pw.thr, NULL, v8_pause_watchdog, c);
        }
    } else {
        if (c->pw.active) {
            pthread_mutex_lock(&c->pw.mtx);
            c->pw.cancel = 1;
            pthread_cond_signal(&c->pw.cv);
            pthread_mutex_unlock(&c->pw.mtx);
            pthread_join(c->pw.thr, NULL);
            c->pw.active = 0;
        }
        // publish the total before clearing the flag so the watchdog never
        // sees "not paused" without the time that pause took
        atomic_fetch_add(&c->dbg_paused_ms, monotonic_ms() - atomic_load(&c->dbg_pause_start_ms));
        atomic_store(&c->dbg_paused, 0);
        v8_inspector_event(c, INSPECTOR_EVENT_RESUMED, NULL);
    }
}

void v8_inspector_registered(Context *c, const char *target_id)
{
    snprintf(c->inspector_target_id, sizeof(c->inspector_target_id), "%s", target_id);
    v8_inspector_event(c, INSPECTOR_EVENT_CREATED, NULL);
}

int v8_inspector_detach_terminates(Context *c)
{
    return c->inspector_detach_terminates;
}

int64_t v8_inspector_max_pause(Context *c)
{
    return c->max_pause;
}

int v8_context_quitting(Context *c)
{
    return atomic_load(&c->quit) != 0;
}

// Returns 0, or BUF_TOO_LARGE or BUF_NO_MEMORY with the reply discarded, so
// Ruby never reads part of one.
int v8_reply(Context *c, const uint8_t *p, size_t n)
{
    int r;

    pthread_mutex_lock(&c->mtx);
    r = buf_put(&c->res, p, n);
    if (r)
        buf_reset(&c->res);
    pthread_mutex_unlock(&c->mtx);
    return r;
}

static void v8_once_init(void)
{
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, v8_global_init);
}

static void *v8_thread_start(void *arg)
{
    Context *c;

    c = arg;
    barrier_wait(&c->early_init);
    v8_once_init();
    v8_thread_init(c, c->snapshot.buf, c->snapshot.len, c->max_memory, c->verbose_exceptions,
                   c->inspector ? c->inspector_title : NULL, c->capture_on_throw,
                   (const char *)c->capture_expressions.buf, c->capture_expressions.len);
    while (c->quit < 2)
        pthread_cond_wait(&c->cv, &c->mtx);
    context_destroy(c);
    return NULL;
}

static VALUE deserialize1(DesCtx *d, const uint8_t *p, size_t n)
{
    char err[64];

    if (des(&err, p, n, d))
        rb_raise(runtime_error, "%s", err);
    if (*d->err)
        rb_raise(runtime_error, "%s", d->err);
    if (d->tos != d->stack) // should not happen
        rb_raise(runtime_error, "parse stack not empty");
    return d->tos->a;
}

static VALUE deserialize(VALUE arg)
{
    struct rendezvous_des *a;
    Buf *b;

    a = (void *)arg;
    b = a->res;
    return deserialize1(a->d, b->buf, b->len);
}

// called with |rr_mtx| and GVL held; can raise exception
static VALUE rendezvous_callback_do(VALUE arg)
{
    struct rendezvous_nogvl *a;
    VALUE func, args;
    Context *c;
    DesCtx d;
    Buf *b;
    long id;

    a = (void *)arg;
    b = a->res;
    c = a->context;
    assert(b->len > 0);
    assert(*b->buf == 'c');
    DesCtx_init(&d);
    args = deserialize1(&d, b->buf+1, b->len-1); // skip 'c' marker
    func = rb_ary_pop(args); // callback id
    if (!RB_INTEGER_TYPE_P(func))
        rb_raise(runtime_error, "bad callback id");
    id = NUM2LONG(func);
    if (id < 0 || id >= RARRAY_LEN(c->procs))
        rb_raise(runtime_error, "bad callback id");
    func = rb_ary_entry(c->procs, id);
    return rb_funcall2(func, rb_intern("call"), RARRAY_LENINT(args), RARRAY_PTR(args));
}

struct callback_serialize_args
{
    Ser *ser;
    VALUE value;
    int opts;
};

static VALUE callback_serialize(VALUE arg)
{
    struct callback_serialize_args *args;
    args = (void *)arg;
    return INT2FIX(serialize(args->ser, args->value, args->opts));
}

static VALUE callback_exception_to_s(VALUE exception)
{
    VALUE message;
    message = rb_funcall(exception, rb_intern("to_s"), 0);
    StringValue(message);
    return message;
}

static VALUE callback_exception_from_state(int state, int *pending_jump_tag)
{
    VALUE exception = rb_errinfo();
    rb_set_errinfo(Qnil);
    if (RB_TYPE_P(exception, T_OBJECT) &&
        rb_obj_is_kind_of(exception, rb_eException)) {
        return exception;
    }
    // Thread#kill and other non-exception jumps leave a sentinel or internal
    // throw data in errinfo; do not hand that to rb_funcall/rb_exc_raise.
    // Replay the jump once the V8 roundtrip has fully unwound.
    if (state && pending_jump_tag && !*pending_jump_tag)
        *pending_jump_tag = state;
    return Qnil;
}

static VALUE callback_internal_error(VALUE message)
{
    return rb_exc_new_cstr(internal_error, (const char *)message);
}

// called with |rr_mtx| and GVL held; |mtx| is unlocked
// callback data is in |a->res|, serialized result goes in |a->req|
static void *rendezvous_callback(void *arg)
{
    struct rendezvous_nogvl *a;
    struct callback_serialize_args args;
    const char *err;
    Context *c;
    int exc;
    VALUE r;
    Ser s;

    a = arg;
    c = a->context;
    r = rb_protect(rendezvous_callback_do, (VALUE)a, &exc);
    if (exc) {
        c->exception = callback_exception_from_state(exc, &c->pending_jump_tag);
        goto fail;
    }
    ser_init1(&s, 'c'); // callback reply
    args.ser = &s;
    args.value = r;
    args.opts = c->ser_opts;
    r = rb_protect(callback_serialize, (VALUE)&args, &exc);
    if (exc) {
        // A Ruby conversion hook, Check_Type(), or stack overflow escaped
        // serialize().  Keep the V8 thread waiting for a reply and turn it
        // into a normal callback exception instead.
        c->exception = callback_exception_from_state(exc, &c->pending_jump_tag);
        ser_reset(&s);
        goto fail;
    }
    if (NUM2INT(r)) {
        VALUE exception = rb_protect(callback_internal_error,
                                     (VALUE)s.err, &exc);
        if (exc) {
            c->exception = callback_exception_from_state(exc, &c->pending_jump_tag);
        } else {
            c->exception = exception;
        }
        ser_reset(&s);
        goto fail;
    }
out:
    buf_move(&s.b, a->req);
    return NULL;
fail:
    ser_init0(&s);   // ruby exception pending
    w_byte(&s, 'e'); // send ruby error message to v8 thread
    r = Qnil;
    if (!NIL_P(c->exception)) {
        VALUE original_exception = c->exception;
        r = rb_protect(callback_exception_to_s, c->exception, &exc);
        if (exc) {
            callback_exception_from_state(exc, &c->pending_jump_tag);
            r = Qnil;
        }
        // to_s can re-enter the context and consume c->exception. Keep the
        // original callback exception for the eventual Ruby-side re-raise.
        c->exception = original_exception;
    }
    if (!NIL_P(r))
        w(&s, RSTRING_PTR(r), RSTRING_LEN(r));
    if (NIL_P(r) || *s.err) { // no message, or too large to send
        ser_reset(&s);
        ser_init0(&s);
        w_byte(&s, 'e');
        err = "Ruby exception";
        w(&s, err, strlen(err));
    }
    goto out;
}

static void *single_threaded_runner(void *arg)
{
    Context *c;

    c = arg;
    pthread_mutex_lock(&c->mtx);
    for (;;) {
        while (!c->req.len && atomic_load(&c->quit) < 1)
            pthread_cond_wait(&c->cv, &c->mtx);
        if (atomic_load(&c->quit) >= 1)
            break;
        v8_single_threaded_enter(c->pst, c, dispatch);
        pthread_cond_signal(&c->cv);
    }
    pthread_mutex_unlock(&c->mtx);
    return NULL;
}

static int single_threaded_recover_after_fork(Context *c)
{
    pthread_condattr_t cattr;
    pid_t pid;
    int r;

    pid = getpid();
    if (!c->single_threaded_thr_started || c->single_threaded_pid == pid)
        return 0;
    if (c->depth || c->req.len || c->res.len)
        return EBUSY;

    if ((r = pthread_condattr_init(&cattr)))
        return r;
#ifndef __APPLE__
    pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
#endif
    r = pthread_cond_init(&c->cv, &cattr);
    pthread_condattr_destroy(&cattr);
    if (r)
        return r;

    c->single_threaded_thr_started = 0;
    c->single_threaded_pid = pid;
    return 0;
}

static int single_threaded_runner_start(Context *c)
{
    pid_t pid;
    int r;

    pid = getpid();
    if (c->single_threaded_thr_started && c->single_threaded_pid == pid)
        return 0;
    c->single_threaded_thr_started = 0;
    c->single_threaded_pid = pid;
    r = pthread_create(&c->single_threaded_thr, NULL, single_threaded_runner, c);
    if (!r)
        c->single_threaded_thr_started = 1;
    return r;
}

static void rendezvous_release(struct rendezvous_nogvl *a)
{
    Context *c;

    atomic_store(&a->active, 0);
    if (!a->has_rr_mtx)
        return;
    c = a->context;
    c->depth--;
    a->has_rr_mtx = 0;
    pthread_mutex_unlock(&c->rr_mtx);
}

static inline void *rendezvous_nogvl(void *arg)
{
    struct rendezvous_nogvl *a;
    Context *c;
    int r;

    a = arg;
    c = a->context;
    if (!a->started) {
        if (single_threaded && (r = single_threaded_recover_after_fork(c)))
            return (void *)(intptr_t)r;
        pthread_mutex_lock(&c->rr_mtx);
        a->has_rr_mtx = 1;
        if (c->depth > 0 && c->depth%50 == 0) { // TODO stop steep recursion
            fprintf(stderr, "mini_racer: deep js->ruby->js recursion, depth=%d\n", c->depth);
            fflush(stderr);
        }
        c->depth++;
        a->started = 1;
    }

next:
    atomic_store(&a->active, 1);
    pthread_mutex_lock(&c->mtx);
    if (atomic_load(&c->quit)) {
        buf_reset(a->req);
        pthread_mutex_unlock(&c->mtx);
        a->finished = 1;
        rendezvous_release(a);
        return (void *)(intptr_t)ECANCELED;
    }
    if (a->req->len) {
        assert(c->req.len == 0);
        assert(!c->res_ready);
        buf_move(a->req, &c->req); // v8 thread takes ownership of req
        if (single_threaded) {
            r = single_threaded_runner_start(c);
            if (r) {
                buf_move(&c->req, a->req);
                pthread_mutex_unlock(&c->mtx);
                a->finished = 1;
                rendezvous_release(a);
                return (void *)(intptr_t)r;
            }
        }
        pthread_cond_signal(&c->cv);
    }
    while (!c->res_ready && !atomic_load(&a->interrupted) && !atomic_load(&c->quit))
        pthread_cond_wait(&c->cv, &c->mtx);
    if (!c->res_ready && atomic_load(&a->interrupted)) {
        atomic_store(&a->active, 0);
        pthread_mutex_unlock(&c->mtx);
        return (void *)(intptr_t)EINTR;
    }
    if (!c->res_ready && atomic_load(&c->quit)) {
        buf_reset(a->req);
        pthread_mutex_unlock(&c->mtx);
        a->finished = 1;
        rendezvous_release(a);
        return (void *)(intptr_t)ECANCELED;
    }
    buf_move(&c->res, a->res);
    c->res_ready = 0;
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mtx);
    atomic_store(&a->active, 0);
    if (a->res->len && *a->res->buf == 'c') { // js -> ruby callback?
        rb_thread_call_with_gvl(rendezvous_callback, a);
        buf_reset(a->res);
        if (atomic_load(&c->quit)) {
            buf_reset(a->req);
            a->finished = 1;
            rendezvous_release(a);
            return (void *)(intptr_t)ECANCELED;
        }
        goto next;
    }
    a->finished = 1;
    rendezvous_release(a);
    return NULL;
}

static void rendezvous_ubf(void *arg)
{
    struct rendezvous_nogvl *a;
    Context *c;

    a = arg;
    if (!atomic_load(&a->active))
        return;
    atomic_store(&a->interrupted, 1);
    c = a->context;
    pthread_cond_broadcast(&c->cv);
}

static void terminate_ubf(void *arg)
{
    Context *c;

    c = arg;
    if (c->pst)
        v8_terminate_execution(c->pst);
    pthread_cond_broadcast(&c->cv);
}

static void *rendezvous_cancel_nogvl(void *arg)
{
    // Reply to any pending JS->Ruby callback with an 'e' marker plus message
    // so V8 throws, unwinds, and reaches its normal termination cleanup.
    static const uint8_t terminated[] = "eterminated";
    struct rendezvous_nogvl *a;
    Context *c;

    a = arg;
    c = a->context;
    atomic_store(&a->active, 0);
    if (c->pst)
        v8_terminate_execution(c->pst);
    pthread_mutex_lock(&c->mtx);
    pthread_cond_broadcast(&c->cv);
    while (!atomic_load(&c->quit)) {
        while (!c->res_ready && !atomic_load(&c->quit))
            pthread_cond_wait(&c->cv, &c->mtx);
        if (!c->res_ready)
            break;
        if (c->res.len && *c->res.buf != 'c')
            break;
        buf_reset(&c->res);
        c->res_ready = 0;
        buf_reset(&c->req);
        buf_put(&c->req, terminated, sizeof(terminated) - 1);
        pthread_cond_signal(&c->cv);
    }
    buf_reset(&c->req);
    buf_reset(&c->res);
    buf_reset(&c->v8_req);
    c->res_ready = 0;
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mtx);
    if (c->pst)
        v8_cancel_terminate_execution(c->pst);
    a->finished = 1;
    rendezvous_release(a);
    return NULL;
}

static VALUE rendezvous_no_des_body(VALUE arg)
{
    struct rendezvous_nogvl *a;
    void *r;

    a = (void *)arg;
    for (;;) {
        // Let the UBF wake this wait without deciding why Ruby interrupted it.
        // Back under the GVL, rb_thread_check_ints() runs signal traps and
        // raises real asynchronous exceptions (Timeout, Thread#raise, kill).
        atomic_store(&a->interrupted, 0);
        atomic_store(&a->active, 1);
        r = rb_nogvl(rendezvous_nogvl, a, rendezvous_ubf, a, RB_NOGVL_INTR_FAIL);
        atomic_store(&a->active, 0);
        if (a->finished || (r && (int)(intptr_t)r != EINTR))
            return LONG2NUM((long)(intptr_t)r);
        rb_thread_check_ints();
    }
}

static VALUE rendezvous_no_des_ensure(VALUE arg)
{
    struct rendezvous_nogvl *a;

    a = (void *)arg;
    if (a->started && !a->finished)
        rb_nogvl(rendezvous_cancel_nogvl, a, NULL, NULL, 0);
    buf_reset(a->req);
    return Qnil;
}

static void rendezvous_no_des(Context *c, Buf *req, Buf *res)
{
    void *r;
    VALUE rv;
    struct rendezvous_nogvl a;

    if (atomic_load(&c->quit)) {
        buf_reset(req);
        rb_raise(context_disposed_error, "disposed context");
    }
    a.context = c;
    a.req = req;
    a.res = res;
    atomic_init(&a.active, 0);
    atomic_init(&a.interrupted, 0);
    a.started = 0;
    a.finished = 0;
    a.has_rr_mtx = 0;
    rv = rb_ensure(rendezvous_no_des_body, (VALUE)&a,
                   rendezvous_no_des_ensure, (VALUE)&a);
    r = (void *)(intptr_t)NUM2LONG(rv);
    if ((int)(intptr_t)r == ECANCELED)
        rb_raise(context_disposed_error, "disposed context");
    if (r)
        rb_raise(runtime_error, "single-threaded runner: %s", strerror((int)(intptr_t)r));
}

// send request to & receive reply from v8 thread; takes ownership of |req|
// can raise exceptions and longjmp away but won't leak |req|
static VALUE rendezvous1(Context *c, Buf *req, DesCtx *d)
{
    VALUE r;
    Buf res;
    int exc;

    rendezvous_no_des(c, req, &res); // takes ownership of |req|
    int jump_tag = c->pending_jump_tag;
    c->pending_jump_tag = 0;
    if (jump_tag) {
        buf_reset(&res);
        rb_jump_tag(jump_tag);
    }
    r = c->exception;
    c->exception = Qnil;
    // if js land didn't handle exception from ruby callback, re-raise it now
    if (res.len == 1 && *res.buf == 'e') {
        if (NIL_P(r))
            rb_raise(context_disposed_error, "disposed context");
        rb_exc_raise(r);
    }
    r = rb_protect(deserialize, (VALUE)&(struct rendezvous_des){d, &res}, &exc);
    buf_reset(&res);
    if (exc) {
        r = rb_errinfo();
        rb_set_errinfo(Qnil);
        rb_exc_raise(r);
    }
    return r;
}

static VALUE rendezvous(Context *c, Buf *req)
{
    DesCtx d;

    DesCtx_init(&d);
    return rendezvous1(c, req, &d);
}

static void raise_exception_with_message(VALUE klass, VALUE e)
{
    long n;
    VALUE message, stack = Qnil, fields = rb_ary_new();

    if (RB_TYPE_P(e, T_ARRAY)) {
        fields = e;
        stack = rb_ary_entry(e, 1);
        e = rb_ary_entry(e, 0);
    }
    if (NIL_P(e))
        return;
    e = StringValue(e);
    n = RSTRING_LEN(e);
    if (n == 0 || RSTRING_PTR(e)[0] == NO_ERROR)
        return;
    message = rb_str_subseq(e, 1, n - 1);
    if (!NIL_P(stack)) {
        if (klass == runtime_error) {
            VALUE args[] = {message, stack};
            VALUE exc = rb_class_new_instance(2, args, klass);
            // Context.new(capture_on_throw:) sends [message, stack, capture]
            if (RARRAY_LEN(fields) > 2)
                rb_ivar_set(exc, rb_intern("@capture"), rb_ary_entry(fields, 2));
            rb_exc_raise(exc);
        }
        // SnapshotError retains its existing combined message/stack format.
        if (RSTRING_LEN(stack)) {
            rb_str_cat_cstr(message, "\n");
            rb_str_append(message, stack);
        }
    }
    rb_exc_raise(rb_exc_new_str(klass, message));
}

static void handle_exception(VALUE e)
{
    const char *s;
    VALUE klass, message;
    long n;

    if (NIL_P(e))
        return;
    message = RB_TYPE_P(e, T_ARRAY) ? rb_ary_entry(e, 0) : e;
    message = StringValue(message);
    n = RSTRING_LEN(message);
    if (n == 0)
        return;
    s = RSTRING_PTR(message);
    switch ((unsigned char)*s) {
    case NO_ERROR:
        return;
    case INTERNAL_ERROR:
        klass = internal_error;
        break;
    case MEMORY_ERROR:
        klass = memory_error;
        break;
    case PARSE_ERROR:
        klass = parse_error;
        break;
    case RUNTIME_ERROR:
        klass = runtime_error;
        break;
    case TERMINATED_ERROR:
        klass = terminated_error;
        break;
    default:
        rb_raise(internal_error, "bad error class %02x", (unsigned char)*s);
    }
    raise_exception_with_message(klass, e);
}

static VALUE context_alloc(VALUE klass)
{
    pthread_mutexattr_t mattr;
    pthread_condattr_t cattr;
    const char *cause;
    Context *c;
    int r;

    // Safe to lazy init because we hold the GVL
    if (NIL_P(binary_class)) {
        VALUE m = rb_const_get(rb_cObject, rb_intern("MiniRacer"));
        if (Qtrue == rb_funcall(m, rb_intern("const_defined?"), 1, rb_str_new_cstr("Binary")))
            binary_class = rb_const_get(m, rb_intern("Binary"));
    }
    c = ruby_xmalloc(sizeof(*c));
    memset(c, 0, sizeof(*c));
    c->exception = Qnil;
    c->procs = rb_ary_new();
    c->max_pause = 10*60*1000;
    buf_init(&c->snapshot);
    buf_init(&c->capture_expressions);
    buf_init(&c->req);
    buf_init(&c->res);
    buf_init(&c->v8_req);
    cause = "pthread_condattr_init";
    if ((r = pthread_condattr_init(&cattr)))
        goto fail0;
#ifndef __APPLE__
    pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
#endif
    cause = "pthread_mutexattr_init";
    if ((r = pthread_mutexattr_init(&mattr)))
        goto fail1;
    pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
    cause = "pthread_mutex_init";
    r = pthread_mutex_init(&c->rr_mtx, &mattr);
    pthread_mutexattr_destroy(&mattr);
    if (r)
        goto fail1;
    if (pthread_mutex_init(&c->mtx, NULL))
        goto fail2;
    cause = "pthread_cond_init";
    if ((r = pthread_cond_init(&c->cv, &cattr)))
        goto fail3;
    cause = "pthread_mutex_init";
    if ((r = pthread_mutex_init(&c->wd.mtx, NULL)))
        goto fail4;
    cause = "pthread_cond_init";
    if (pthread_cond_init(&c->wd.cv, &cattr))
        goto fail5;
    cause = "pthread_mutex_init";
    if ((r = pthread_mutex_init(&c->pw.mtx, NULL)))
        goto fail6;
    cause = "pthread_cond_init";
    if ((r = pthread_cond_init(&c->pw.cv, &cattr)))
        goto fail6a;
    cause = "barrier_init";
    if ((r = barrier_init(&c->early_init, 2)))
        goto fail6b;
    cause = "barrier_init";
    if ((r = barrier_init(&c->late_init, 2)))
        goto fail7;
    pthread_condattr_destroy(&cattr);
    return TypedData_Wrap_Struct(klass, &context_type, c);
fail7:
    barrier_destroy(&c->early_init);
fail6b:
    pthread_cond_destroy(&c->pw.cv);
fail6a:
    pthread_mutex_destroy(&c->pw.mtx);
fail6:
    pthread_cond_destroy(&c->wd.cv);
fail5:
    pthread_mutex_destroy(&c->wd.mtx);
fail4:
    pthread_cond_destroy(&c->cv);
fail3:
    pthread_mutex_destroy(&c->mtx);
fail2:
    pthread_mutex_destroy(&c->rr_mtx);
fail1:
    pthread_condattr_destroy(&cattr);
fail0:
    ruby_xfree(c);
    rb_raise(runtime_error, "%s: %s", cause, strerror(r));
    return Qnil; // pacify compiler
}

static void *context_free_do(void *arg)
{
    Context *c;

    c = arg;
    if (single_threaded && single_threaded_recover_after_fork(c)) {
        // The child forked while this inherited context was not idle. There is
        // no live runner thread to join and the inherited V8/pthread state is
        // not safe to tear down. A finalizer must not hang here; let the OS
        // reclaim the abandoned V8 state when the child exits.
        context_abandon(c);
        return NULL;
    }
    if (single_threaded && c->single_threaded_thr_started && c->single_threaded_pid == getpid()) {
        pthread_mutex_lock(&c->mtx);
        atomic_store(&c->quit, 2);
        pthread_cond_signal(&c->cv);
        pthread_mutex_unlock(&c->mtx);
        pthread_join(c->single_threaded_thr, NULL);
    }
    if (c->pst)
        v8_single_threaded_dispose(c->pst);
    pthread_mutex_lock(&c->mtx);
    context_destroy(c);
    return NULL;
}

static void context_free(void *arg)
{
    Context *c;

    c = arg;
    if (single_threaded) {
        // Free synchronously. A detached cleanup thread can race normal Ruby
        // process shutdown and trip glibc malloc corruption checks while V8 is
        // tearing down single-threaded contexts.
        context_free_do(c);
    } else {
        pthread_mutex_lock(&c->mtx);
        c->quit = 2; // 2 = v8 thread frees
        pthread_cond_signal(&c->cv);
        pthread_mutex_unlock(&c->mtx);
    }
}

static void context_abandon(Context *c)
{
    buf_reset(&c->snapshot);
    buf_reset(&c->capture_expressions);
    buf_reset(&c->req);
    buf_reset(&c->res);
    buf_reset(&c->v8_req);
    ruby_xfree(c);
}

static void context_destroy(Context *c)
{
    pthread_mutex_unlock(&c->mtx);
    pthread_mutex_destroy(&c->mtx);
    pthread_cond_destroy(&c->cv);
    barrier_destroy(&c->early_init);
    barrier_destroy(&c->late_init);
    pthread_mutex_destroy(&c->wd.mtx);
    pthread_cond_destroy(&c->wd.cv);
    pthread_mutex_destroy(&c->pw.mtx);
    pthread_cond_destroy(&c->pw.cv);
    buf_reset(&c->snapshot);
    buf_reset(&c->capture_expressions);
    buf_reset(&c->req);
    buf_reset(&c->res);
    buf_reset(&c->v8_req);
    ruby_xfree(c);
}

static void context_mark(void *arg)
{
    Context *c;

    c = arg;
    rb_gc_mark(c->procs);
    rb_gc_mark(c->exception);
}

static size_t context_size(const void *arg)
{
    const Context *c = arg;
    return sizeof(*c);
}

static VALUE context_attach(VALUE self, VALUE name, VALUE proc)
{
    Context *c;
    VALUE e;
    Ser s;
    long id;

    TypedData_Get_Struct(self, Context, &context_type, c);
    id = RARRAY_LEN(c->procs);
    if (id > INT32_MAX)
        rb_raise(runtime_error, "too many callbacks");
    // request is (A)ttach, [name, id] array
    ser_init1(&s, 'A');
    ser_array_begin(&s, 2);
    add_string(&s, name);
    ser_int(&s, id);
    ser_array_end(&s, 2);
    ser_check(&s, "Context.attach");
    rb_ary_push(c->procs, proc);
    // response is an exception or undefined
    e = rendezvous(c, &s.b);
    handle_exception(e);
    return Qnil;
}

static void *context_dispose_do(void *arg)
{
    Context *c;
    int r;

    c = arg;
    if (single_threaded) {
        if ((r = single_threaded_recover_after_fork(c)))
            return (void *)(intptr_t)r;
    }
    if (c->depth > 0) {
        r = pthread_mutex_trylock(&c->rr_mtx);
        if (!r) {
            pthread_mutex_unlock(&c->rr_mtx);
            return (void *)(intptr_t)EBUSY;
        }
        if (r != EBUSY)
            return (void *)(intptr_t)r;
        if (c->pst)
            v8_terminate_execution(c->pst);
        pthread_cond_broadcast(&c->cv);
    }
    if (single_threaded) {
        pthread_mutex_lock(&c->mtx);
        while (c->req.len || c->res.len)
            pthread_cond_wait(&c->cv, &c->mtx);
        atomic_store(&c->quit, 1);   // disposed
        if (c->single_threaded_thr_started && c->single_threaded_pid == getpid()) {
            pthread_cond_signal(&c->cv);
            pthread_mutex_unlock(&c->mtx);
            pthread_join(c->single_threaded_thr, NULL);
            pthread_mutex_lock(&c->mtx);
            c->single_threaded_thr_started = 0;
        }
        pthread_mutex_unlock(&c->mtx);
    } else {
        pthread_mutex_lock(&c->mtx);
        while (c->req.len || c->res.len)
            pthread_cond_wait(&c->cv, &c->mtx);
        atomic_store(&c->quit, 1);   // disposed
        pthread_cond_signal(&c->cv); // wake up v8 thread
        pthread_mutex_unlock(&c->mtx);
    }
    return NULL;
}

static VALUE context_dispose(VALUE self)
{
    Context *c;
    void *r;

    TypedData_Get_Struct(self, Context, &context_type, c);
    r = rb_thread_call_without_gvl(context_dispose_do, c, terminate_ubf, c);
    if (r)
        rb_raise(runtime_error, "context dispose: %s", strerror((int)(intptr_t)r));
    return Qnil;
}

static VALUE context_stop(VALUE self)
{
    Context *c;

    // does not grab |mtx| because Context.stop can be called from another
    // thread and then we deadlock if e.g. the V8 thread busy-loops in JS
    TypedData_Get_Struct(self, Context, &context_type, c);
    if (atomic_load(&c->quit))
        rb_raise(context_disposed_error, "disposed context");
    v8_terminate_execution(c->pst);
    return Qnil;
}

static VALUE context_inspector_status(VALUE self)
{
    Context *c;

    TypedData_Get_Struct(self, Context, &context_type, c);
    if (atomic_load(&c->quit))
        rb_raise(context_disposed_error, "disposed context");
    if (!c->inspector || !c->pst)
        return INT2FIX(0);
    return INT2FIX(v8_inspector_status(c->pst));
}

// [status bits, pause generation, total ms paused, ms into the current pause]
static VALUE context_inspector_state(VALUE self)
{
    long long start, now;
    Context *c;
    int paused;

    TypedData_Get_Struct(self, Context, &context_type, c);
    if (atomic_load(&c->quit))
        rb_raise(context_disposed_error, "disposed context");
    if (!c->inspector || !c->pst)
        return Qnil;
    paused = atomic_load(&c->dbg_paused);
    start = atomic_load(&c->dbg_pause_start_ms);
    now = monotonic_ms();
    return rb_ary_new_from_args(4,
        INT2FIX(v8_inspector_status(c->pst) | (paused ? INSPECTOR_PAUSED : 0)),
        UINT2NUM(atomic_load(&c->pause_generation)),
        LL2NUM(atomic_load(&c->dbg_paused_ms)),
        LL2NUM(paused && now > start ? now - start : 0));
}

static VALUE context_inspector_target_id(VALUE self)
{
    Context *c;

    TypedData_Get_Struct(self, Context, &context_type, c);
    if (atomic_load(&c->quit) || !c->inspector || !*c->inspector_target_id)
        return Qnil;
    return rb_str_new_cstr(c->inspector_target_id);
}

static VALUE context_inspector_disconnect(VALUE self)
{
    Context *c;

    TypedData_Get_Struct(self, Context, &context_type, c);
    if (!c->inspector || !*c->inspector_target_id)
        return Qfalse;
    return v8_inspector_disconnect(c->inspector_target_id) ? Qtrue : Qfalse;
}

static VALUE context_inspector_break_next(VALUE self)
{
    Context *c;

    TypedData_Get_Struct(self, Context, &context_type, c);
    if (atomic_load(&c->quit))
        rb_raise(context_disposed_error, "disposed context");
    if (c->inspector && c->pst)
        v8_inspector_break_next(c->pst);
    return Qnil;
}

// |settings| is an Array of 8 non-negative Integers, in v8_inspector_start's
// order; lib/mini_racer.rb validates their ranges
static VALUE inspector_start(VALUE self, VALUE host, VALUE port, VALUE token, VALUE settings)
{
    int64_t s[8];
    char err[256];
    int i, r;

    StringValue(host);
    StringValue(token);
    Check_Type(port, T_FIXNUM);
    if (FIX2LONG(port) < 0 || FIX2LONG(port) > 65535)
        rb_raise(rb_eArgError, "bad port");
    Check_Type(settings, T_ARRAY);
    if (RARRAY_LEN(settings) != 8)
        rb_raise(rb_eArgError, "bad inspector settings");
    for (i = 0; i < 8; i++) {
        s[i] = NUM2LL(rb_ary_entry(settings, i));
        if (s[i] < 0)
            rb_raise(rb_eArgError, "bad inspector settings");
    }
    r = v8_inspector_start(StringValueCStr(host), (int)FIX2LONG(port),
                           StringValueCStr(token), s, err, sizeof(err));
    if (r < 0)
        rb_raise(runtime_error, "inspector: %s", err);
    return INT2FIX(r);
}

static void *inspector_stop_nogvl(void *arg)
{
    (void)arg;
    return (void *)(intptr_t)v8_inspector_stop();
}

// waits for the server thread without the GVL: its disconnects reach V8
// threads that may need a Ruby thread to finish (a Ruby callback)
static VALUE inspector_stop(VALUE self)
{
    void *r;

    r = rb_thread_call_without_gvl(inspector_stop_nogvl, NULL, NULL, NULL);
    return r ? Qtrue : Qfalse;
}

static VALUE inspector_target_count(VALUE self)
{
    return LONG2NUM(v8_inspector_target_count());
}

static VALUE inspector_port(VALUE self)
{
    int r;

    r = v8_inspector_port();
    return r < 0 ? Qnil : INT2FIX(r);
}

static VALUE context_call_common(int argc, VALUE *argv, VALUE self, char op)
{
    VALUE name, args;
    VALUE a, e;
    Context *c;
    Ser s;

    TypedData_Get_Struct(self, Context, &context_type, c);
    rb_scan_args(argc, argv, "1*", &name, &args);
    Check_Type(name, T_STRING);
    rb_ary_unshift(args, name);
    // request is (C)all or (D) call_await, [name, args...] array
    ser_init1(&s, op);
    if (serialize(&s, args, c->ser_opts)) {
        ser_reset(&s);
        rb_raise(runtime_error, "Context.call: %s", s.err);
    }
    // response is [result, err] array
    a = rendezvous(c, &s.b); // takes ownership of |s.b|
    e = rb_ary_pop(a);
    handle_exception(e);
    return rb_ary_pop(a);
}

static VALUE context_call(int argc, VALUE *argv, VALUE self)
{
    return context_call_common(argc, argv, self, 'C');
}

static VALUE context_call_await(int argc, VALUE *argv, VALUE self)
{
    return context_call_common(argc, argv, self, 'D');
}

static VALUE context_eval_common(int argc, VALUE *argv, VALUE self, char op)
{
    VALUE a, e, source, filename, kwargs;
    Context *c;
    Ser s;

    TypedData_Get_Struct(self, Context, &context_type, c);
    filename = Qnil;
    rb_scan_args(argc, argv, "1:", &source, &kwargs);
    Check_Type(source, T_STRING);
    if (!NIL_P(kwargs))
        filename = rb_hash_aref(kwargs, rb_id2sym(rb_intern("filename")));
    if (NIL_P(filename))
        filename = rb_str_new_cstr("<eval>");
    Check_Type(filename, T_STRING);
    // request is (E)val or (F) eval_await, [filename, source] array
    ser_init1(&s, op);
    ser_array_begin(&s, 2);
    add_string(&s, filename);
    add_string(&s, source);
    ser_array_end(&s, 2);
    ser_check(&s, "Context.eval");
    // response is [result, errname] array
    a = rendezvous(c, &s.b); // takes ownership of |s.b|
    e = rb_ary_pop(a);
    handle_exception(e);
    return rb_ary_pop(a);
}

static VALUE context_eval(int argc, VALUE *argv, VALUE self)
{
    return context_eval_common(argc, argv, self, 'E');
}

static VALUE context_eval_await(int argc, VALUE *argv, VALUE self)
{
    return context_eval_common(argc, argv, self, 'F');
}

static VALUE context_heap_stats(VALUE self)
{
    VALUE a, h, k, v;
    Context *c;
    int i, n;
    Buf b;

    TypedData_Get_Struct(self, Context, &context_type, c);
    buf_init(&b);
    buf_putc(&b, 'S');     // (S)tats, returns object
    h = rendezvous(c, &b); // takes ownership of |b|
    a = rb_ary_new();
    rb_hash_foreach(h, collect, a);
    for (i = 0, n = RARRAY_LENINT(a); i < n; i += 2) {
        k = rb_ary_entry(a, i+0);
        v = rb_ary_entry(a, i+1);
        rb_hash_delete(h, k);
        rb_hash_aset(h, rb_str_intern(k), v); // turn "key" into :key
    }
    return h;
}

static VALUE buf_reset_ensure(VALUE arg)
{
    buf_reset((Buf *)arg);
    return Qnil;
}

static VALUE heap_snapshot_to_str(VALUE arg)
{
    Buf *res;

    res = (Buf *)arg;
    if (!res->len) // v8_reply refused it
        rb_raise(runtime_error, "heap snapshot too large (over 1 GiB) or out of memory");
    return rb_utf8_str_new((char *)res->buf, res->len);
}

static VALUE context_heap_snapshot(VALUE self)
{
    Buf req, res;
    Context *c;

    TypedData_Get_Struct(self, Context, &context_type, c);
    buf_init(&req);
    buf_putc(&req, 'H');              // (H)eap snapshot, returns plain bytes
    rendezvous_no_des(c, &req, &res); // takes ownership of |req|
    return rb_ensure(heap_snapshot_to_str, (VALUE)&res,
                     buf_reset_ensure, (VALUE)&res);
}

static VALUE context_perform_microtask_checkpoint(VALUE self)
{
    Context *c;
    Buf b;

    TypedData_Get_Struct(self, Context, &context_type, c);
    buf_init(&b);
    buf_putc(&b, 'M');        // (M)icrotask checkpoint, returns nil
    return rendezvous(c, &b); // takes ownership of |b|
}

static VALUE context_pump_message_loop(VALUE self)
{
    Context *c;
    Buf b;

    TypedData_Get_Struct(self, Context, &context_type, c);
    buf_init(&b);
    buf_putc(&b, 'P');        // (P)ump, returns bool
    return rendezvous(c, &b); // takes ownership of |b|
}

static VALUE context_low_memory_notification(VALUE self)
{
    Buf req, res;
    Context *c;

    TypedData_Get_Struct(self, Context, &context_type, c);
    buf_init(&req);
    buf_putc(&req, 'L');              // (L)ow memory notification, returns nothing
    rendezvous_no_des(c, &req, &res); // takes ownership of |req|
    buf_reset(&res);
    return Qnil;
}

static int platform_set_flag1(VALUE k, VALUE v)
{
    char *p, *q, *r, buf[256];
    long pn, vn, len;
    int ok;

    k = rb_funcall(k, rb_intern("to_s"), 0);
    Check_Type(k, T_STRING);
    if (!NIL_P(v)) {
        v = rb_funcall(v, rb_intern("to_s"), 0);
        Check_Type(v, T_STRING);
    }
    p = RSTRING_PTR(k);
    pn = RSTRING_LEN(k);
    if (memchr(p, '\0', pn))
        rb_raise(rb_eArgError, "flag contains NUL byte");
    if (pn >= 2 && p[0] == '-' && p[1] == '-') {
        p += 2;
        pn -= 2;
    }
    if (NIL_P(v)) {
        len = 2 + pn;
        if (len >= (long)sizeof(buf))
            rb_raise(rb_eArgError, "flag too long");
        q = buf;
        *q++ = '-';
        *q++ = '-';
        memcpy(q, p, pn);
        q += pn;
        *q = '\0';
    } else {
        q = RSTRING_PTR(v);
        vn = RSTRING_LEN(v);
        if (memchr(q, '\0', vn))
            rb_raise(rb_eArgError, "flag contains NUL byte");
        len = 3 + pn + vn;
        if (len >= (long)sizeof(buf))
            rb_raise(rb_eArgError, "flag too long");
        r = buf;
        *r++ = '-';
        *r++ = '-';
        memcpy(r, p, pn);
        r += pn;
        *r++ = '=';
        memcpy(r, q, vn);
        r += vn;
        *r = '\0';
    }
    p = buf;
    pthread_mutex_lock(&flags_mtx);
    if (!flags.buf)
        buf_init(&flags);
    ok = (*flags.buf != 1);
    if (ok) {
        if (buf_put(&flags, p, 1+strlen(p))) { // include trailing \0
            pthread_mutex_unlock(&flags_mtx);
            rb_raise(rb_eNoMemError, "MiniRacer::Platform.set_flags!: out of memory");
        }
        // strip dashes and underscores to reduce the number of variant
        // spellings (--no-single-threaded, --nosingle-threaded,
        // --no_single_threaded, etc.)
        p = q = buf;
        for (;;) {
            if (*p != '-')
                if (*p != '_')
                    *q++ = *p;
            if (!*p++)
                break;
        }
        if (!strcmp(buf, "singlethreaded")) {
            single_threaded = 1;
        } else if (!strcmp(buf, "nosinglethreaded")) {
            single_threaded = 0;
        }
    }
    pthread_mutex_unlock(&flags_mtx);
    return ok;
}

static VALUE platform_set_flags(int argc, VALUE *argv, VALUE klass)
{
    VALUE args, kwargs, k, v;
    int i, n;

    (void)&klass;
    rb_scan_args(argc, argv, "*:", &args, &kwargs);
    Check_Type(args, T_ARRAY);
    for (i = 0, n = RARRAY_LENINT(args); i < n; i++) {
        k = rb_ary_entry(args, i);
        v = Qnil;
        if (!platform_set_flag1(k, v))
            goto fail;
    }
    if (NIL_P(kwargs))
        return Qnil;
    Check_Type(kwargs, T_HASH);
    args = rb_ary_new();
    rb_hash_foreach(kwargs, collect, args);
    for (i = 0, n = RARRAY_LENINT(args); i < n; i += 2) {
        k = rb_ary_entry(args, i+0);
        v = rb_ary_entry(args, i+1);
        if (!platform_set_flag1(k, v))
            goto fail;
    }
    return Qnil;
fail:
    rb_raise(platform_init_error, "platform already initialized");
}

// called by v8_global_init; caller must free |*p| with free()
void v8_get_flags(char **p, size_t *n)
{
    *p = NULL;
    *n = 0;
    pthread_mutex_lock(&flags_mtx);
    if (!flags.len)
        goto out;
    if (flags.buf != flags.buf_s) {
        *p = (char *)flags.buf; // hand the heap buffer over, no copy
    } else {
        *p = malloc(flags.len);
        if (!*p) {
            // running V8 without the flags asked for (heap limits, say)
            // would be worse than not running it
            fprintf(stderr, "mini_racer: out of memory copying V8 flags\n");
            abort();
        }
        memcpy(*p, flags.buf, flags.len);
    }
    *n = flags.len;
out:
    buf_init(&flags);
    buf_putc(&flags, 1); // marker to indicate it's been cleared
    pthread_mutex_unlock(&flags_mtx);
    if (single_threaded)
        rb_thread_lock_native_thread();
}

// capture_on_throw: {expressions: [...]}: JavaScript to evaluate, side-effect
// free, in the failing frame. Returns them as one Ruby string, NUL-separated,
// or nil; context_initialize copies it into the Context only once no other
// option can raise, so a rejected Context.new leaks nothing.
static VALUE capture_expressions_option(VALUE opts)
{
    VALUE exprs, e, joined;
    long i, n;

    exprs = rb_hash_lookup(opts, ID2SYM(rb_intern("expressions")));
    if ((long)rb_hash_size_num(opts) != (NIL_P(exprs) ? 0 : 1))
        rb_raise(rb_eArgError, "capture_on_throw: the only option is expressions:");
    if (NIL_P(exprs))
        return Qnil;
    if (!RB_TYPE_P(exprs, T_ARRAY))
        rb_raise(rb_eArgError, "capture_on_throw: expressions: must be an array of strings");
    n = RARRAY_LEN(exprs);
    if (n > 20)
        rb_raise(rb_eArgError, "capture_on_throw: at most 20 expressions");
    joined = rb_str_buf_new(0);
    for (i = 0; i < n; i++) {
        e = rb_ary_entry(exprs, i);
        if (!RB_TYPE_P(e, T_STRING))
            rb_raise(rb_eArgError, "capture_on_throw: expressions: must be an array of strings");
        // rb_str_conv_enc returns the string unconverted when it can't convert
        if (rb_enc_str_coderange(e) == ENC_CODERANGE_BROKEN)
            rb_raise(rb_eArgError, "capture_on_throw: expression %ld is not valid in its encoding", i);
        e = rb_str_conv_enc(e, rb_enc_get(e), rb_utf8_encoding());
        if (rb_enc_get(e) != rb_utf8_encoding() && rb_enc_str_coderange(e) != ENC_CODERANGE_7BIT)
            rb_raise(rb_eArgError, "capture_on_throw: expression %ld can't be converted to UTF-8", i);
        if (RSTRING_LEN(e) < 1 || RSTRING_LEN(e) > 1000 ||
            memchr(RSTRING_PTR(e), '\0', RSTRING_LEN(e)))
            rb_raise(rb_eArgError, "capture_on_throw: each expression must be 1 to 1000 bytes, without NUL");
        rb_str_buf_cat(joined, RSTRING_PTR(e), RSTRING_LEN(e));
        rb_str_buf_cat(joined, "", 1);
    }
    return joined;
}

static void set_inspector_title(Context *c, VALUE title)
{
    long n;

    StringValue(title);
    title = rb_str_export_to_enc(title, rb_utf8_encoding());
    n = RSTRING_LEN(title);
    if (n > (long)sizeof(c->inspector_title) - 1) {
        n = sizeof(c->inspector_title) - 1;
        // don't cut a UTF-8 sequence in half
        while (n > 0 && (RSTRING_PTR(title)[n] & 0xC0) == 0x80)
            n--;
    }
    memcpy(c->inspector_title, RSTRING_PTR(title), n);
    c->inspector_title[n] = '\0';
    if (strlen(c->inspector_title) != (size_t)n)
        rb_raise(rb_eArgError, "inspector name contains a NUL byte");
}

static VALUE context_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE kwargs, a, k, v, capture_expressions = Qnil;
    pthread_attr_t attr;
    const char *cause;
    pthread_t thr;
    Snapshot *ss;
    Context *c;
    char *s;
    int r;

    TypedData_Get_Struct(self, Context, &context_type, c);
    rb_scan_args(argc, argv, ":", &kwargs);
    if (NIL_P(kwargs))
        goto init;
    a = rb_ary_new();
    rb_hash_foreach(kwargs, collect, a);
    while (RARRAY_LENINT(a)) {
        v = rb_ary_pop(a);
        k = rb_ary_pop(a);
        k = rb_sym2str(k);
        s = RSTRING_PTR(k);
        if (!strcmp(s, "ensure_gc_after_idle")) {
            Check_Type(v, T_FIXNUM);
            c->idle_gc = FIX2LONG(v);
            if (c->idle_gc < 0 || c->idle_gc > INT32_MAX)
                rb_raise(rb_eArgError, "bad ensure_gc_after_idle");
        } else if (!strcmp(s, "max_memory")) {
            Check_Type(v, T_FIXNUM);
            c->max_memory = FIX2LONG(v);
            if (c->max_memory < 0 || c->max_memory >= UINT32_MAX)
                rb_raise(rb_eArgError, "bad max_memory");
        } else if (!strcmp(s, "marshal_stack_depth")) { // backcompat, ignored
            Check_Type(v, T_FIXNUM);
        } else if (!strcmp(s, "timeout")) {
            Check_Type(v, T_FIXNUM);
            c->timeout = FIX2LONG(v);
            if (c->timeout < 0 || c->timeout > INT32_MAX)
                rb_raise(rb_eArgError, "bad timeout");
        } else if (!strcmp(s, "snapshot")) {
            if (NIL_P(v))
                continue;
            TypedData_Get_Struct(v, Snapshot, &snapshot_type, ss);
            if (buf_put(&c->snapshot, RSTRING_PTR(ss->blob), RSTRING_LENINT(ss->blob)))
                rb_raise(runtime_error, "out of memory");
        } else if (!strcmp(s, "date")) {
            c->ser_opts &= ~SER_DATE_ISO;
            if (v == ID2SYM(rb_intern("iso")))
                c->ser_opts |= SER_DATE_ISO;
            else if (!NIL_P(v) && v != ID2SYM(rb_intern("time")))
                rb_raise(rb_eArgError, "bad date: expected :time or :iso");
        } else if (!strcmp(s, "decimal")) {
            c->ser_opts &= ~SER_DECIMAL_FLOAT;
            if (v == ID2SYM(rb_intern("float")))
                c->ser_opts |= SER_DECIMAL_FLOAT;
            else if (!NIL_P(v))
                rb_raise(rb_eArgError, "bad decimal: expected :float or nil");
        } else if (!strcmp(s, "verbose_exceptions")) {
            c->verbose_exceptions = !(v == Qfalse || v == Qnil);
        } else if (!strcmp(s, "max_pause")) {
            Check_Type(v, T_FIXNUM);
            c->max_pause = FIX2LONG(v);
            if (c->max_pause < 0 || c->max_pause > INT32_MAX)
                rb_raise(rb_eArgError, "bad max_pause");
        } else if (!strcmp(s, "inspector")) {
            if (v == Qfalse || v == Qnil)
                continue;
            if (single_threaded)
                rb_raise(rb_eArgError, "inspector is not supported in single_threaded mode");
            c->inspector = 1;
            set_inspector_title(c, v == Qtrue ? rb_str_new_cstr("mini_racer") : v);
        } else if (!strcmp(s, "inspector_detach")) {
            if (v == ID2SYM(rb_intern("terminate")))
                c->inspector_detach_terminates = 1;
            else if (v == ID2SYM(rb_intern("resume")) || NIL_P(v))
                c->inspector_detach_terminates = 0;
            else
                rb_raise(rb_eArgError, "bad inspector_detach: expected :resume or :terminate");
        } else if (!strcmp(s, "capture_on_throw")) {
            c->capture_on_throw = !(v == Qfalse || v == Qnil);
            if (RB_TYPE_P(v, T_HASH))
                capture_expressions = capture_expressions_option(v);
            if (c->capture_on_throw && single_threaded)
                rb_raise(rb_eArgError, "capture_on_throw is not supported in single_threaded mode");
        } else {
            rb_raise(runtime_error, "bad keyword: %s", s);
        }
    }
    // both would drive V8's one pause-on-exceptions setting
    if (c->inspector && c->capture_on_throw)
        rb_raise(rb_eArgError, "capture_on_throw can't be combined with inspector");
    if (!NIL_P(capture_expressions) &&
        buf_put(&c->capture_expressions, RSTRING_PTR(capture_expressions),
                RSTRING_LEN(capture_expressions)))
        rb_raise(runtime_error, "out of memory");
    RB_GC_GUARD(capture_expressions);
init:
    if (single_threaded) {
        v8_once_init();
        c->pst = v8_thread_init(c, c->snapshot.buf, c->snapshot.len, c->max_memory, c->verbose_exceptions, NULL, 0, NULL, 0);
    } else {
        cause = "pthread_attr_init";
        if ((r = pthread_attr_init(&attr)))
            goto fail;
        pthread_attr_setstacksize(&attr, 2<<20); // 2 MiB
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        // v8 thread takes ownership of |c|
        cause = "pthread_create";
        r = pthread_create(&thr, &attr, v8_thread_start, c);
        pthread_attr_destroy(&attr);
        if (r)
            goto fail;
        barrier_wait(&c->early_init);
        barrier_wait(&c->late_init);
        if (c->inspector && !*c->inspector_target_id) {
            context_dispose(self);
            rb_raise(runtime_error, "inspector: too many targets (Inspector.start's max_targets:)");
        }
    }
    return Qnil;
fail:
    rb_raise(runtime_error, "Context.initialize: %s: %s", cause, strerror(r));
    return Qnil; // pacify compiler
}

static VALUE snapshot_alloc(VALUE klass)
{
    Snapshot *ss;

    ss = ruby_xmalloc(sizeof(*ss));
    ss->blob = rb_enc_str_new("", 0, rb_ascii8bit_encoding());
    return TypedData_Wrap_Struct(klass, &snapshot_type, ss);
}

static void snapshot_free(void *arg)
{
    ruby_xfree(arg);
}

static void snapshot_mark(void *arg)
{
    Snapshot *ss;

    ss = arg;
    rb_gc_mark(ss->blob);
}

static size_t snapshot_size(const void *arg)
{
    const Snapshot *ss;

    ss = arg;
    return sizeof(*ss) + RSTRING_LENINT(ss->blob);
}

static VALUE snapshot_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE a, e, code, cv;
    Snapshot *ss;
    Context *c;
    DesCtx d;
    Ser s;

    TypedData_Get_Struct(self, Snapshot, &snapshot_type, ss);
    rb_scan_args(argc, argv, "01", &code);
    if (NIL_P(code))
        code = rb_str_new_cstr("");
    Check_Type(code, T_STRING);
    cv = context_alloc(context_class);
    context_initialize(0, NULL, cv);
    TypedData_Get_Struct(cv, Context, &context_type, c);
    // request is snapsho(T), "code"
    ser_init1(&s, 'T');
    add_string(&s, code);
    ser_check(&s, "Snapshot.new");
    // response is [arraybuffer, error]
    DesCtx_init(&d);
    d.transcode_latin1 = 0; // don't mangle snapshot binary data
    a = rendezvous1(c, &s.b, &d);
    e = rb_ary_pop(a);
    context_dispose(cv);
    raise_exception_with_message(snapshot_error, e);
    ss->blob = rb_ary_pop(a);
    return Qnil;
}

static VALUE snapshot_warmup(VALUE self, VALUE arg)
{
    VALUE a, e, cv;
    Snapshot *ss;
    Context *c;
    DesCtx d;
    Ser s;

    TypedData_Get_Struct(self, Snapshot, &snapshot_type, ss);
    Check_Type(arg, T_STRING);
    cv = context_alloc(context_class);
    context_initialize(0, NULL, cv);
    TypedData_Get_Struct(cv, Context, &context_type, c);
    // request is (W)armup, [snapshot, "warmup code"]
    ser_init1(&s, 'W');
    ser_array_begin(&s, 2);
    ser_string8(&s, (const uint8_t *)RSTRING_PTR(ss->blob), RSTRING_LENINT(ss->blob));
    add_string(&s, arg);
    ser_array_end(&s, 2);
    ser_check(&s, "Snapshot.warmup!");
    // response is [arraybuffer, error]
    DesCtx_init(&d);
    d.transcode_latin1 = 0; // don't mangle snapshot binary data
    a = rendezvous1(c, &s.b, &d);
    e = rb_ary_pop(a);
    context_dispose(cv);
    raise_exception_with_message(snapshot_error, e);
    ss->blob = rb_ary_pop(a);
    return self;
}

static VALUE snapshot_dump(VALUE self)
{
    Snapshot *ss;

    TypedData_Get_Struct(self, Snapshot, &snapshot_type, ss);
    // Callers may mutate the returned String; never expose the blob that
    // Context.new/snapshot_warmup later hand to V8.
    return rb_str_dup(ss->blob);
}

static VALUE snapshot_load(VALUE klass, VALUE blob)
{
    Snapshot *ss;
    VALUE self;
    char err[128];

    Check_Type(blob, T_STRING);
    if (v8_snapshot_validate((const uint8_t *)RSTRING_PTR(blob),
                             (size_t)RSTRING_LEN(blob), err, sizeof(err))) {
        rb_raise(snapshot_error, "%s", err);
    }
    self = snapshot_alloc(klass);
    TypedData_Get_Struct(self, Snapshot, &snapshot_type, ss);
    ss->blob = rb_str_dup(blob);
    rb_enc_associate(ss->blob, rb_ascii8bit_encoding());
    ENC_CODERANGE_SET(ss->blob, ENC_CODERANGE_VALID);
    return self;
}

static VALUE snapshot_size0(VALUE self)
{
    Snapshot *ss;

    TypedData_Get_Struct(self, Snapshot, &snapshot_type, ss);
    return LONG2FIX(RSTRING_LENINT(ss->blob));
}

static VALUE script_error_cause(VALUE self)
{
    return rb_iv_get(self, "@cause");
}

__attribute__((visibility("default")))
void Init_mini_racer_extension(void)
{
    VALUE c, m;

    m = rb_define_module("MiniRacer");
    c = rb_define_class_under(m, "Error", rb_eStandardError);
    snapshot_error = rb_define_class_under(m, "SnapshotError", c);
    platform_init_error = rb_define_class_under(m, "PlatformAlreadyInitialized", c);
    context_disposed_error = rb_define_class_under(m, "ContextDisposedError", c);

    c = rb_define_class_under(m, "EvalError", c);
    parse_error = rb_define_class_under(m, "ParseError", c);
    memory_error = rb_define_class_under(m, "V8OutOfMemoryError", c);
    script_error = rb_define_class_under(m, "ScriptError", c);
    runtime_error = rb_define_class_under(m, "RuntimeError", c);
    internal_error = rb_define_class_under(m, "InternalError", c);
    terminated_error = rb_define_class_under(m, "ScriptTerminatedError", c);

    rb_define_method(script_error, "cause", script_error_cause, 0);

    c = context_class = rb_define_class_under(m, "Context", rb_cObject);
    rb_define_method(c, "initialize", context_initialize, -1);
    rb_define_method(c, "attach", context_attach, 2);
    rb_define_method(c, "dispose", context_dispose, 0);
    rb_define_method(c, "stop", context_stop, 0);
    rb_define_method(c, "call", context_call, -1);
    rb_define_method(c, "call_await", context_call_await, -1);
    rb_define_method(c, "eval", context_eval, -1);
    rb_define_method(c, "eval_await", context_eval_await, -1);
    rb_define_method(c, "heap_stats", context_heap_stats, 0);
    rb_define_method(c, "heap_snapshot", context_heap_snapshot, 0);
    rb_define_method(c, "perform_microtask_checkpoint", context_perform_microtask_checkpoint, 0);
    rb_define_method(c, "pump_message_loop", context_pump_message_loop, 0);
    rb_define_method(c, "low_memory_notification", context_low_memory_notification, 0);
    rb_define_private_method(c, "__inspector_status", context_inspector_status, 0);
    rb_define_private_method(c, "__inspector_break_next", context_inspector_break_next, 0);
    rb_define_private_method(c, "__inspector_state", context_inspector_state, 0);
    rb_define_private_method(c, "__inspector_disconnect", context_inspector_disconnect, 0);
    rb_define_method(c, "inspector_target_id", context_inspector_target_id, 0);
    rb_define_alloc_func(c, context_alloc);

    c = snapshot_class = rb_define_class_under(m, "Snapshot", rb_cObject);
    rb_define_method(c, "initialize", snapshot_initialize, -1);
    rb_define_method(c, "warmup!", snapshot_warmup, 1);
    rb_define_method(c, "dump", snapshot_dump, 0);
    rb_define_method(c, "size", snapshot_size0, 0);
    rb_define_singleton_method(c, "load", snapshot_load, 1);
    rb_define_alloc_func(c, snapshot_alloc);

    c = rb_define_module_under(m, "Inspector");
    rb_define_private_method(rb_singleton_class(c), "__start", inspector_start, 4);
    rb_define_private_method(rb_singleton_class(c), "__stop", inspector_stop, 0);
    rb_define_singleton_method(c, "target_count", inspector_target_count, 0);
    rb_define_private_method(rb_singleton_class(c), "__events", inspector_events, 2);
    rb_define_singleton_method(c, "events_dropped", inspector_events_dropped, 0);
    pthread_atfork(NULL, NULL, ev_atfork_child);
    rb_define_singleton_method(c, "port", inspector_port, 0);

    c = rb_define_class_under(m, "Platform", rb_cObject);
    rb_define_singleton_method(c, "set_flags!", platform_set_flags, -1);

    date_class = Qnil; // lazy init
    date_time_class = Qnil; // lazy init
    binary_class = Qnil; // lazy init
    big_decimal_class = Qnil; // lazy init
    js_function_class = rb_define_class_under(m, "JavaScriptFunction", rb_cObject);
}
