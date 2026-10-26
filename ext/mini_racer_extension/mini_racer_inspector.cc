#include "mini_racer_inspector.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <map>
#include <tuple>
#include <mutex>
#include <random>
#include <vector>

namespace mini_racer_inspector {

namespace {

constexpr size_t kMaxHttpRequest = 64u << 10;

// The rest are Settings (see the header for each), read by the server and V8
// threads while start_server may change them, hence atomics. Defaults:
// - max_message: largest WebSocket message from a frontend; protocol
//   messages are small, the cap only bounds memory
// - send_idle_ms / send_total_ms: a frontend that stops or slows down
//   reading must not stall the V8 thread (which sends synchronously) or the
//   server thread: a message that makes no progress for send_idle_ms, or
//   takes longer than send_total_ms in all, drops the connection
// - handshake_ms: a connection must finish its HTTP request or WebSocket
//   handshake this quickly, so idle sockets can't hold every slot
// - max_queued / max_queued_bytes: messages waiting for the V8 thread, per
//   target; a frontend that keeps sending while V8 is busy is disconnected
//   instead of growing memory the heap limit doesn't see
std::atomic<uint64_t> g_max_message{16u << 20};
std::atomic<size_t> g_max_conns{32};
std::atomic<int> g_send_idle_ms{10 * 1000};
std::atomic<int> g_send_total_ms{30 * 1000};
std::atomic<int> g_handshake_ms{10 * 1000};
std::atomic<size_t> g_max_queued_bytes{64u << 20};
std::atomic<size_t> g_max_queued{4096};
std::atomic<size_t> g_max_targets{0}; // 0: no cap

std::atomic<uint64_t> g_next_conn_id{1};

struct Conn
{
    int fd;
    // names the connection in queued events and Target::session, which
    // must not keep a closed connection (and its buffers) alive. Starts at
    // 1, as 0 means none; 2^64 connections, the point of wrapping, can't
    // happen at any real rate.
    const uint64_t id = g_next_conn_id.fetch_add(1);
    std::mutex wmu;       // serializes writes; guards |closed| and the queue
    bool closed = false;
    // WebSocket frames waiting to be written, oldest first; the server
    // thread writes them as the socket allows (see enqueue_frame)
    std::deque<std::string> out;
    size_t out_off = 0;   // bytes of out.front() already written
    size_t out_bytes = 0; // queued and not yet written
    std::chrono::steady_clock::time_point out_progress{}, out_started{};
    // server thread only
    std::string in;
    bool ws = false;
    std::string frag;
    bool fragmented = false; // a message's first frame came without FIN
    // when a partial frame or message was first seen; zero when there's none
    std::chrono::steady_clock::time_point partial_since{};
    std::weak_ptr<Target> target;
    std::chrono::steady_clock::time_point accepted = std::chrono::steady_clock::now();

    explicit Conn(int fd) : fd(fd) {}
};

} // namespace

struct Target
{
    std::string id, title;
    std::mutex mu;
    std::condition_variable cv;
    // frontend events and the id of the connection each came from;
    // guarded by |mu|
    std::deque<std::tuple<Event, std::string, uint64_t>> q;
    size_t q_bytes = 0;                          // guarded by |mu|
    std::shared_ptr<Conn> conn;                  // guarded by |mu|
    // The id of the frontend the V8 thread is talking to: set when poll()
    // hands it that connection's Connect, zero after its Disconnect. send()
    // writes to |conn| only while it's that one: a frontend that attaches
    // while the last one's commands are still queued sees no replies to
    // them, nor console entries they replayed. Guarded by |mu|.
    uint64_t session = 0;
    void (*wake)(void *) = nullptr;              // guarded by |mu|
    void *arg = nullptr;
    bool notified = false;                       // guarded by |mu|
};

namespace {

std::mutex g_mu; // guards everything below
std::map<std::string, std::shared_ptr<Target>> *g_targets =
    new std::map<std::string, std::shared_ptr<Target>>;
std::vector<int> g_conn_fds; // open frontend sockets, closed in fork children
std::string g_host;
std::string g_prefix; // "/<token>" when started with a token, else empty
int g_port = -1;
int g_lfd = -1;
// stop_server writes to g_wake_w; the server thread then closes everything
// and exits, and stop_server joins it
int g_wake_r = -1, g_wake_w = -1;
// the wake pipe also says "frames are queued"; this says "stop"
std::atomic<bool> g_stopping{false};
pthread_t g_thread;
bool g_thread_running = false;

// fork() only copies the calling thread: the server thread and every V8
// thread are gone in the child, and any lock they held stays held. Take
// g_mu across the fork so the child inherits it in a known state, then drop
// everything that belongs to the parent. Targets are leaked, not destroyed:
// their mutexes may be held by threads that no longer exist.
// wakes the server thread to write queued frames; any thread
void wake_server()
{
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_wake_w >= 0) {
        char b = 1; // a full pipe is fine: the server is due to wake anyway
        while (write(g_wake_w, &b, 1) < 0 && errno == EINTR) {}
    }
}

void atfork_prepare() { g_mu.lock(); }
void atfork_parent() { g_mu.unlock(); }
void atfork_child()
{
    g_targets = new std::map<std::string, std::shared_ptr<Target>>;
    for (int fd : g_conn_fds)
        close(fd);
    g_conn_fds.clear();
    if (g_lfd >= 0)
        close(g_lfd);
    if (g_wake_r >= 0)
        close(g_wake_r);
    if (g_wake_w >= 0)
        close(g_wake_w);
    g_lfd = g_wake_r = g_wake_w = -1;
    g_thread_running = false; // the thread didn't survive the fork
    g_port = -1;
    g_prefix.clear();
    g_mu.unlock();
}

void install_atfork()
{
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, [] {
        pthread_atfork(atfork_prepare, atfork_parent, atfork_child);
    });
}

void set_cloexec_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags >= 0)
        fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    flags = fcntl(fd, F_GETFL);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// --- SHA-1 and base64, for the WebSocket handshake only ---

uint32_t rol(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

void sha1(const std::string& s, uint8_t out[20])
{
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    std::vector<uint8_t> m(s.begin(), s.end());
    uint64_t bits = static_cast<uint64_t>(s.size()) * 8;
    m.push_back(0x80);
    while (m.size() % 64 != 56)
        m.push_back(0);
    for (int i = 7; i >= 0; i--)
        m.push_back(static_cast<uint8_t>(bits >> (i * 8)));
    for (size_t off = 0; off < m.size(); off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) {
            const uint8_t *p = &m[off + 4*i];
            w[i] = uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
        }
        for (int i = 16; i < 80; i++)
            w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
            uint32_t t = rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol(b, 30); b = a; a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
    for (int i = 0; i < 20; i++)
        out[i] = static_cast<uint8_t>(h[i/4] >> (24 - 8*(i%4)));
}

std::string base64(const uint8_t *p, size_t n)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = uint32_t(p[i]) << 16;
        if (i+1 < n) v |= uint32_t(p[i+1]) << 8;
        if (i+2 < n) v |= p[i+2];
        out += tbl[(v >> 18) & 63];
        out += tbl[(v >> 12) & 63];
        out += i+1 < n ? tbl[(v >> 6) & 63] : '=';
        out += i+2 < n ? tbl[v & 63] : '=';
    }
    return out;
}

std::string new_id()
{
    std::random_device rd;
    uint8_t b[16];
    for (int i = 0; i < 16; i += 4) {
        uint32_t v = rd();
        memcpy(b + i, &v, 4);
    }
    b[6] = (b[6] & 0x0F) | 0x40; // version 4
    b[8] = (b[8] & 0x3F) | 0x80; // variant
    static const char hex[] = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            s += '-';
        s += hex[b[i] >> 4];
        s += hex[b[i] & 15];
    }
    return s;
}

std::string json_escape(const std::string& s)
{
    std::string out;
    for (unsigned char ch : s) {
        switch (ch) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", ch);
                out += buf;
            } else {
                out += static_cast<char>(ch);
            }
        }
    }
    return out;
}

std::string lower(std::string s)
{
    for (char& ch : s)
        if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
    return s;
}

// --- events ---

void push_locked(Target& t, Event ev, std::string msg, const std::shared_ptr<Conn>& from)
{
    t.q_bytes += msg.size();
    t.q.emplace_back(ev, std::move(msg), from->id);
    t.cv.notify_all();
    // one wake per batch: the V8 thread drains the whole queue, so a wake
    // (and the interrupt it requests) is only needed when it was empty
    if (t.wake && t.q.size() == 1)
        t.wake(t.arg);
}

// False when the frontend is too far ahead of the V8 thread; the caller
// drops the connection.
bool push_message(Target& t, std::string msg, const std::shared_ptr<Conn>& from)
{
    std::lock_guard<std::mutex> lock(t.mu);
    if (t.q.size() >= g_max_queued.load() || t.q_bytes + msg.size() > g_max_queued_bytes.load())
        return false;
    push_locked(t, Event::Message, std::move(msg), from);
    return true;
}

// --- sockets ---

// Caller holds c.wmu. Sockets are non-blocking; see g_send_idle_ms.
bool write_all(Conn& c, const char *p, size_t n)
{
#ifdef MSG_NOSIGNAL
    const int flags = MSG_NOSIGNAL;
#else
    const int flags = 0; // SO_NOSIGPIPE is set on accept
#endif
    using clock = std::chrono::steady_clock;
    const int idle_ms = g_send_idle_ms.load();
    const auto deadline = clock::now() + std::chrono::milliseconds(g_send_total_ms.load());
    while (n > 0) {
        ssize_t r = ::send(c.fd, p, n, flags);
        if (r >= 0) {
            p += r;
            n -= static_cast<size_t>(r);
            continue;
        }
        if (errno == EINTR)
            continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return false;
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock::now()).count();
        if (left <= 0)
            return false;
        pollfd pfd{c.fd, POLLOUT, 0};
        if (::poll(&pfd, 1, static_cast<int>(left < idle_ms ? left : idle_ms)) == 0)
            return false;
    }
    return true;
}

bool send_raw(Conn& c, const std::string& data)
{
    std::lock_guard<std::mutex> lock(c.wmu);
    if (c.closed)
        return false;
    if (write_all(c, data.data(), data.size()))
        return true;
    // Let the server thread notice EOF and clean up; it owns close().
    shutdown(c.fd, SHUT_RDWR);
    return false;
}

std::string frame(int opcode, const std::string& payload)
{
    std::string h;
    h += static_cast<char>(0x80 | opcode);
    uint64_t n = payload.size();
    if (n < 126) {
        h += static_cast<char>(n);
    } else if (n < 65536) {
        h += static_cast<char>(126);
        h += static_cast<char>(n >> 8);
        h += static_cast<char>(n);
    } else {
        h += static_cast<char>(127);
        for (int i = 7; i >= 0; i--)
            h += static_cast<char>(n >> (i * 8));
    }
    return h + payload;
}

void wake_server();

// Queues a frame for the server thread to write; any thread. Never waits
// on the socket, so a frontend that stops reading can't stall the V8
// thread. A frontend whose unread frames pass max_queued_bytes is
// dropped instead.
bool enqueue_frame(Conn& c, int opcode, const std::string& payload)
{
    std::string f = frame(opcode, payload);
    {
        std::lock_guard<std::mutex> lock(c.wmu);
        if (c.closed)
            return false;
        if (c.out_bytes + f.size() > g_max_queued_bytes.load()) {
            shutdown(c.fd, SHUT_RDWR); // the server thread closes it
            return false;
        }
        if (c.out.empty())
            c.out_progress = c.out_started = std::chrono::steady_clock::now();
        c.out_bytes += f.size();
        c.out.push_back(std::move(f));
    }
    wake_server(); // after wmu: close_conn takes g_mu, then wmu
    return true;
}

// Server thread: writes what the socket takes now. False on an error, or a
// frontend that hasn't read for send_idle_ms or let one frame take longer
// than send_total_ms: the caller closes the connection.
bool flush_some(Conn& c)
{
#ifdef MSG_NOSIGNAL
    const int flags = MSG_NOSIGNAL;
#else
    const int flags = 0; // SO_NOSIGPIPE is set on accept
#endif
    using clock = std::chrono::steady_clock;
    std::lock_guard<std::mutex> lock(c.wmu);
    if (c.closed)
        return false;
    while (!c.out.empty()) {
        const std::string& f = c.out.front();
        ssize_t r = ::send(c.fd, f.data() + c.out_off, f.size() - c.out_off, flags);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) return false;
            break;
        }
        c.out_off += static_cast<size_t>(r);
        c.out_bytes -= static_cast<size_t>(r);
        c.out_progress = clock::now();
        if (c.out_off == f.size()) {
            c.out.pop_front();
            c.out_off = 0;
            c.out_started = c.out_progress;
        }
    }
    if (c.out.empty())
        return true;
    const auto now = clock::now();
    return now - c.out_progress < std::chrono::milliseconds(g_send_idle_ms.load()) &&
           now - c.out_started < std::chrono::milliseconds(g_send_total_ms.load());
}

bool has_output(Conn& c)
{
    std::lock_guard<std::mutex> lock(c.wmu);
    return !c.out.empty();
}

void close_conn(const std::shared_ptr<Conn>& c)
{
    {
        // g_mu so a concurrent fork never sees a closed, possibly reused,
        // fd in g_conn_fds; nothing takes g_mu while holding wmu
        std::lock_guard<std::mutex> glock(g_mu);
        std::lock_guard<std::mutex> lock(c->wmu);
        if (!c->closed) {
            c->closed = true;
            close(c->fd);
            for (auto it = g_conn_fds.begin(); it != g_conn_fds.end(); ++it) {
                if (*it == c->fd) {
                    g_conn_fds.erase(it);
                    break;
                }
            }
        }
    }
    if (auto t = c->target.lock()) {
        std::lock_guard<std::mutex> lock(t->mu);
        if (t->conn == c) {
            t->conn.reset();
            push_locked(*t, Event::Disconnect, std::string(), c);
        }
    }
}

// DNS rebinding guard, as in Node: a web page can make a browser send
// requests to 127.0.0.1 under its own hostname, so only accept requests
// addressed to localhost or to a literal IP address.
bool host_allowed(const std::string& host)
{
    if (host.empty() || host[0] == '[')
        return true; // HTTP/1.0 without Host, or an IPv6 literal
    std::string name = lower(host.substr(0, host.find(':')));
    if (name == "localhost" || (name.size() > 10 && name.compare(name.size() - 10, 10, ".localhost") == 0))
        return true;
    for (char ch : name)
        if (!((ch >= '0' && ch <= '9') || ch == '.'))
            return false;
    return !name.empty();
}

// Cross-site WebSocket guard: browsers send Origin on WebSocket upgrades and
// a page can open ws://127.0.0.1 directly. DevTools frontends either send a
// devtools:// or chrome:// origin or, like VS Code, none; some client
// libraries send http://<the Host header>, which no web page can have since
// this server serves no pages.
bool origin_allowed(const std::string& origin, const std::string& host)
{
    if (origin.empty() || (!host.empty() && lower(origin) == "http://" + lower(host)))
        return true;
    static const char *const ok[] = {"devtools://", "chrome://", "chrome-devtools://"};
    std::string o = lower(origin);
    for (const char *prefix : ok)
        if (o.compare(0, strlen(prefix), prefix) == 0)
            return true;
    return false;
}

std::string http_response(const char *status, const std::string& body)
{
    std::string r = "HTTP/1.1 ";
    r += status;
    r += "\r\nContent-Type: application/json; charset=UTF-8\r\nCache-Control: no-cache\r\nContent-Length: ";
    r += std::to_string(body.size());
    r += "\r\nConnection: close\r\n\r\n";
    r += body;
    return r;
}

std::string target_list(const std::string& hostport)
{
    std::string out = "[";
    std::lock_guard<std::mutex> lock(g_mu);
    bool first = true;
    for (auto& kv : *g_targets) {
        const Target& t = *kv.second;
        std::string ws = hostport + g_prefix + "/" + t.id;
        if (!first) out += ",";
        first = false;
        out += "{\"description\":\"mini_racer context\",";
        out += "\"devtoolsFrontendUrl\":\"devtools://devtools/bundled/js_app.html?experiments=true&v8only=true&ws=" + ws + "\",";
        out += "\"devtoolsFrontendUrlCompat\":\"devtools://devtools/bundled/inspector.html?experiments=true&v8only=true&ws=" + ws + "\",";
        out += "\"id\":\"" + t.id + "\",";
        out += "\"title\":\"" + json_escape(t.title) + "\",";
        out += "\"type\":\"node\",\"url\":\"file://\",";
        out += "\"webSocketDebuggerUrl\":\"ws://" + ws + "\"}";
    }
    out += "]";
    return out;
}

bool handle_ws(const std::shared_ptr<Conn>& c);

// RFC 7230 token characters, for header names
bool is_token(const std::string& s)
{
    if (s.empty()) return false;
    for (unsigned char ch : s) {
        if (ch <= 0x20 || ch >= 0x7F) return false;
        if (strchr("()<>@,;:\\\"/[]?={}", ch)) return false;
    }
    return true;
}

// a comma-separated header value contains |want|, case-insensitively, as a
// whole token ("keep-alive, Upgrade" contains "upgrade"; "notupgrade" doesn't)
bool has_token(const std::string& value, const char *want)
{
    size_t i = 0;
    while (i <= value.size()) {
        size_t j = value.find(',', i);
        if (j == std::string::npos) j = value.size();
        size_t a = i, b = j;
        while (a < b && (value[a] == ' ' || value[a] == '\t')) a++;
        while (b > a && (value[b - 1] == ' ' || value[b - 1] == '\t')) b--;
        if (lower(value.substr(a, b - a)) == want) return true;
        i = j + 1;
    }
    return false;
}

// RFC 6455 4.1: the key is 16 random bytes, base64: 22 characters and "=="
bool valid_websocket_key(const std::string& k)
{
    if (k.size() != 24 || k[22] != '=' || k[23] != '=') return false;
    for (size_t i = 0; i < 22; i++) {
        unsigned char ch = k[i];
        if (!isalnum(ch) && ch != '+' && ch != '/') return false;
    }
    // the last character carries 2 bits; the other 4 must be zero
    return strchr("AQgw", k[21]) != nullptr;
}

bool valid_utf8(const std::string& s)
{
    size_t i = 0, n = s.size();
    while (i < n) {
        unsigned char c = s[i];
        size_t len;
        uint32_t cp;
        if (c < 0x80) { i++; continue; }
        else if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
        else return false;
        if (i + len > n) return false;
        for (size_t k = 1; k < len; k++) {
            unsigned char cc = s[i + k];
            if ((cc & 0xC0) != 0x80) return false;
            cp = cp << 6 | (cc & 0x3F);
        }
        // no overlong forms, surrogates or code points past U+10FFFF
        if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000) ||
            (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF)
            return false;
        i += len;
    }
    return true;
}

// A close frame's payload: empty, or a status code an endpoint may send
// (RFC 6455 7.4) and a UTF-8 reason.
bool valid_close(const std::string& payload)
{
    if (payload.empty())
        return true;
    if (payload.size() < 2)
        return false;
    unsigned code = uint8_t(payload[0]) << 8 | uint8_t(payload[1]);
    bool known = (code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1014) ||
                 (code >= 3000 && code <= 4999);
    return known && valid_utf8(payload.substr(2));
}

// Returns false when the connection should be closed.
bool handle_http(const std::shared_ptr<Conn>& c)
{
    size_t end = c->in.find("\r\n\r\n");
    if (end == std::string::npos)
        return c->in.size() < kMaxHttpRequest;
    if (end + 4 > kMaxHttpRequest)
        return false; // the read that ended the head also took it past the limit
    std::string head = c->in.substr(0, end);
    c->in.erase(0, end + 4);

    size_t eol = head.find("\r\n");
    std::string line = head.substr(0, eol);
    std::map<std::string, std::string> headers;
    // Strict parsing: a header the server and a proxy in front of it could
    // read differently (a second Host, a folded line, "Host :") is refused
    // rather than guessed at.
    bool malformed = false;
    while (eol != std::string::npos) {
        size_t start = eol + 2;
        eol = head.find("\r\n", start);
        std::string h = head.substr(start, eol == std::string::npos ? std::string::npos : eol - start);
        size_t colon = h.find(':');
        if (colon == std::string::npos || !is_token(h.substr(0, colon))) {
            malformed = true; // also catches obsolete line folding
            break;
        }
        size_t v = colon + 1;
        while (v < h.size() && (h[v] == ' ' || h[v] == '\t')) v++;
        size_t ve = h.size();
        while (ve > v && (h[ve - 1] == ' ' || h[ve - 1] == '\t')) ve--;
        std::string name = lower(h.substr(0, colon));
        for (size_t i = v; i < ve && !malformed; i++) {
            unsigned char ch = h[i];
            malformed = (ch < 0x20 && ch != '\t') || ch == 0x7F; // RFC 9110 5.5
        }
        if (malformed)
            break;
        if (headers.count(name)) {
            malformed = true; // duplicates are never needed here
            break;
        }
        headers[name] = h.substr(v, ve - v);
    }
    size_t sp1 = line.find(' ');
    size_t sp2 = sp1 == std::string::npos ? sp1 : line.find(' ', sp1 + 1);
    std::string version = sp2 == std::string::npos ? std::string() : line.substr(sp2 + 1);
    if (malformed || sp2 == std::string::npos ||
        (version != "HTTP/1.1" && version != "HTTP/1.0") ||
        (version == "HTTP/1.1" && !headers.count("host"))) { // RFC 9112 3.2
        send_raw(*c, http_response("400 Bad Request", "{}"));
        return false;
    }
    std::string method = line.substr(0, sp1);
    std::string path = line.substr(sp1 + 1, sp2 - sp1 - 1);
    path = path.substr(0, path.find('?'));
    std::string host = headers["host"];
    if (!host_allowed(host)) {
        send_raw(*c, http_response("403 Forbidden", "{\"error\":\"Host header must be localhost or an IP address\"}"));
        return false;
    }
    std::string hostport = host, prefix;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (hostport.empty())
            hostport = g_host + ":" + std::to_string(g_port);
        prefix = g_prefix;
    }
    // with a token every URL starts with it, discovery included; compare
    // all of it so timing doesn't leak a prefix
    if (!prefix.empty()) {
        bool match = path.size() > prefix.size() && path[prefix.size()] == '/';
        unsigned char diff = 0;
        for (size_t i = 0; i < prefix.size(); i++)
            diff |= static_cast<unsigned char>(prefix[i] ^ (i < path.size() ? path[i] : 0));
        if (!match || diff) {
            send_raw(*c, http_response("404 Not Found", "{}"));
            return false;
        }
        path.erase(0, prefix.size());
    }

    if (lower(headers["upgrade"]) == "websocket") {
        // a strict handshake, so that only a WebSocket client can get here:
        // a plain HTTP client tricked into sending an Upgrade header (SSRF)
        // can't also produce frames, and pipelined bytes are refused
        if (method != "GET" || version != "HTTP/1.1" || !has_token(headers["connection"], "upgrade") ||
            headers["sec-websocket-version"] != "13" || !valid_websocket_key(headers["sec-websocket-key"]) ||
            headers.count("content-length") || headers.count("transfer-encoding") ||
            !c->in.empty()) {
            send_raw(*c, http_response("400 Bad Request", "{\"error\":\"bad WebSocket handshake\"}"));
            return false;
        }
        if (!origin_allowed(headers["origin"], host)) {
            send_raw(*c, http_response("403 Forbidden", "{\"error\":\"WebSocket connections from web pages are not allowed\"}"));
            return false;
        }
        std::string id = path.size() > 1 ? path.substr(1) : std::string();
        std::shared_ptr<Target> t;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            auto it = g_targets->find(id);
            if (it != g_targets->end()) t = it->second;
        }
        if (!t) {
            send_raw(*c, http_response("404 Not Found", "{\"error\":\"no such target\"}"));
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(t->mu);
            if (t->conn) {
                send_raw(*c, http_response("409 Conflict", "{\"error\":\"a debugger is already attached\"}"));
                return false;
            }
            // Connect and Disconnect bypass push_message's limits; while V8
            // is busy, reconnecting over and over could grow the queue
            if (t->q.size() >= g_max_queued.load()) {
                send_raw(*c, http_response("503 Service Unavailable", "{\"error\":\"the context is busy\"}"));
                return false;
            }
        }
        uint8_t digest[20];
        sha1(headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", digest);
        std::string resp =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: " + base64(digest, sizeof(digest)) + "\r\n\r\n";
        if (!send_raw(*c, resp))
            return false;
        {
            std::lock_guard<std::mutex> lock(t->mu);
            if (t->conn || !t->wake)
                return false; // lost a race with another frontend, or target gone
            t->conn = c;
            push_locked(*t, Event::Connect, std::string(), c);
        }
        c->ws = true;
        c->target = t;
        return handle_ws(c);
    }

    if (method != "GET") {
        send_raw(*c, http_response("405 Method Not Allowed", "{}"));
    } else if (path == "/json" || path == "/json/list") {
        send_raw(*c, http_response("200 OK", target_list(hostport)));
    } else if (path == "/json/version") {
        send_raw(*c, http_response("200 OK", "{\"Browser\":\"mini_racer\",\"Protocol-Version\":\"1.1\"}"));
    } else {
        send_raw(*c, http_response("404 Not Found", "{}"));
    }
    return false;
}

bool handle_ws(const std::shared_ptr<Conn>& c)
{
    for (;;) {
        const std::string& in = c->in;
        if (in.size() < 2)
            return true;
        uint8_t b0 = static_cast<uint8_t>(in[0]);
        uint8_t b1 = static_cast<uint8_t>(in[1]);
        bool fin = b0 & 0x80;
        int op = b0 & 0x0F;
        if (b0 & 0x70)
            return false; // RSV bits: no extension was negotiated
        if (!(b1 & 0x80))
            return false; // clients must mask
        uint64_t len = b1 & 0x7F;
        size_t hdr = 2;
        if (len == 126) {
            if (in.size() < 4) return true;
            len = uint64_t(uint8_t(in[2])) << 8 | uint8_t(in[3]);
            if (len < 126)
                return false; // RFC 6455 5.2: the minimal number of bytes
            hdr = 4;
        } else if (len == 127) {
            if (in.size() < 10) return true;
            len = 0;
            for (int i = 2; i < 10; i++)
                len = len << 8 | uint8_t(in[i]);
            if (len >> 63)
                return false; // RFC 6455 5.2: the top bit must be 0
            if (len < 65536)
                return false; // and the minimal number of bytes
            hdr = 10;
        }
        if (op >= 0x8 && (len > 125 || !fin))
            return false; // RFC 6455 5.5: control frames are short and unfragmented
        const uint64_t max_message = g_max_message.load();
        if (len > max_message || c->frag.size() + len > max_message)
            return false;
        if (in.size() < hdr + 4 + len)
            return true;
        const char *mask = in.data() + hdr;
        std::string payload = in.substr(hdr + 4, static_cast<size_t>(len));
        for (size_t i = 0; i < payload.size(); i++)
            payload[i] ^= mask[i % 4];
        c->in.erase(0, hdr + 4 + static_cast<size_t>(len));
        // a whole message arrived: what follows it gets its own
        // handshake_timeout (see server_main), not what's left of this one's
        if (fin && (op < 0x8 || !c->fragmented))
            c->partial_since = std::chrono::steady_clock::time_point();

        switch (op) {
        case 0x8: // close
            // best effort, and only if nothing is queued ahead of it:
            // echo a valid status code (RFC 6455 5.5.1, 7.4), or answer a
            // malformed close with 1002, protocol error
            if (!has_output(*c)) {
                std::string f = frame(0x8, valid_close(payload) ? payload.substr(0, 2)
                                                                : std::string("\x03\xea", 2));
                std::lock_guard<std::mutex> lock(c->wmu);
                if (!c->closed)
                    (void)::send(c->fd, f.data(), f.size(), 0);
            }
            return false;
        case 0x9: // ping
            if (!enqueue_frame(*c, 0xA, payload))
                return false;
            break;
        case 0xA: // pong
            break;
        case 0x1: // text
        case 0x2: // binary; DevTools only sends text, accept both
            if (c->fragmented)
                return false; // a new message before the last one finished
            c->frag = std::move(payload);
            [[fallthrough]];
        case 0x0: // continuation
            if (op == 0x0) {
                if (!c->fragmented)
                    return false; // continues nothing
                c->frag += payload;
            }
            c->fragmented = !fin;
            if (fin) {
                // protocol messages are JSON text; refuse what V8 would
                // have to guess at
                if (!valid_utf8(c->frag))
                    return false;
                if (auto t = c->target.lock())
                    if (!push_message(*t, std::move(c->frag), c))
                        return false;
                c->frag.clear();
            }
            break;
        default:
            return false;
        }
    }
}

bool handle_read(const std::shared_ptr<Conn>& c)
{
    char buf[65536];
    ssize_t n = recv(c->fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n == 0)
        return false;
    if (n < 0)
        return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
    c->in.append(buf, static_cast<size_t>(n));
    return c->ws ? handle_ws(c) : handle_http(c);
}

struct ServerFds { int lfd, wake; };

void *server_main(void *arg)
{
    ServerFds fds = *static_cast<ServerFds *>(arg);
    delete static_cast<ServerFds *>(arg);
    const int lfd = fds.lfd;
    std::vector<std::shared_ptr<Conn>> conns;
    for (;;) {
        std::vector<pollfd> pfds;
        pfds.push_back({lfd, POLLIN, 0});
        pfds.push_back({fds.wake, POLLIN, 0});
        for (auto& c : conns)
            pfds.push_back({c->fd, static_cast<short>(POLLIN | (has_output(*c) ? POLLOUT : 0)), 0});
        // wake up now and then to expire connections that never finished
        // their request, or stopped reading
        if (poll(pfds.data(), pfds.size(), conns.empty() ? -1 : 1000) < 0) {
            if (errno == EINTR) continue;
            return nullptr;
        }
        if (pfds[1].revents) {
            char buf[256];
            while (read(fds.wake, buf, sizeof(buf)) > 0) {}
            if (g_stopping.load()) { // stop_server
                for (auto& c : conns)
                    close_conn(c); // each target sees Event::Disconnect
                close(lfd);
                close(fds.wake);
                return nullptr;
            }
        }
        const auto now = std::chrono::steady_clock::now();
        const auto handshake = std::chrono::milliseconds(g_handshake_ms.load());
        std::vector<std::shared_ptr<Conn>> keep;
        for (size_t i = 2; i < pfds.size(); i++) {
            auto& c = conns[i - 2];
            if ((pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) && !handle_read(c)) {
                close_conn(c);
                continue;
            }
            if (has_output(*c) && !flush_some(*c)) {
                close_conn(c);
                continue;
            }
            if (!c->ws && now - c->accepted >= handshake) {
                close_conn(c);
                continue;
            }
            // once connected, a frame or a fragmented message left half sent
            // for as long as a handshake may take is dropped, so a client
            // can't hold a slot (and up to max_message bytes) by stalling
            if (c->ws && (!c->in.empty() || c->fragmented)) {
                if (c->partial_since == std::chrono::steady_clock::time_point())
                    c->partial_since = now;
                else if (now - c->partial_since >= handshake) {
                    close_conn(c);
                    continue;
                }
            } else {
                c->partial_since = std::chrono::steady_clock::time_point();
            }
            keep.push_back(c);
        }
        conns.swap(keep);
        if (pfds[0].revents & POLLIN) {
            std::lock_guard<std::mutex> lock(g_mu); // see close_conn
            int fd = accept(lfd, nullptr, nullptr); // non-blocking
            if (fd >= 0 && conns.size() >= g_max_conns.load()) {
                close(fd);
            } else if (fd >= 0) {
                set_cloexec_nonblock(fd);
                int one = 1;
#ifdef SO_NOSIGPIPE
                setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
                setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                g_conn_fds.push_back(fd);
                conns.push_back(std::make_shared<Conn>(fd));
            }
        }
    }
}

} // namespace

std::shared_ptr<Target> register_target(const std::string& title,
                                        void (*wake)(void *), void *arg)
{
    auto t = std::make_shared<Target>();
    t->id = new_id();
    t->title = title;
    t->wake = wake;
    t->arg = arg;
    install_atfork();
    std::lock_guard<std::mutex> lock(g_mu);
    size_t max = g_max_targets.load();
    if (max && g_targets->size() >= max)
        return nullptr;
    (*g_targets)[t->id] = t;
    return t;
}

void unregister_target(const std::shared_ptr<Target>& t)
{
    {
        std::lock_guard<std::mutex> lock(g_mu);
        g_targets->erase(t->id);
    }
    std::shared_ptr<Conn> conn;
    {
        std::lock_guard<std::mutex> lock(t->mu);
        t->wake = nullptr;
        t->arg = nullptr;
        conn = std::move(t->conn);
        t->session = 0;
        t->q.clear();
        t->q_bytes = 0;
    }
    if (conn) {
        std::lock_guard<std::mutex> lock(conn->wmu);
        if (!conn->closed)
            shutdown(conn->fd, SHUT_RDWR); // server thread closes it
    }
}

const std::string& target_id(const Target& t)
{
    return t.id;
}

bool disconnect(const std::string& id)
{
    std::shared_ptr<Target> t;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        auto it = g_targets->find(id);
        if (it == g_targets->end())
            return false;
        t = it->second;
    }
    std::shared_ptr<Conn> conn;
    {
        std::lock_guard<std::mutex> lock(t->mu);
        conn = t->conn;
    }
    if (conn) {
        std::lock_guard<std::mutex> lock(conn->wmu);
        if (!conn->closed)
            shutdown(conn->fd, SHUT_RDWR); // the server thread closes it
    }
    return true;
}

Event poll(Target& t, std::string *msg, bool hold_connect)
{
    std::lock_guard<std::mutex> lock(t.mu);
    if (t.q.empty())
        return Event::None;
    if (hold_connect && std::get<0>(t.q.front()) == Event::Connect)
        return Event::None;
    auto ev = std::move(t.q.front());
    t.q.pop_front();
    t.q_bytes -= std::get<1>(ev).size();
    if (std::get<0>(ev) == Event::Connect)
        t.session = std::get<2>(ev);
    else if (std::get<0>(ev) == Event::Disconnect)
        t.session = 0; // even the reply to discardConsoleEntries goes nowhere
    if (msg)
        *msg = std::move(std::get<1>(ev));
    return std::get<0>(ev);
}

void wait(Target& t, int ms)
{
    std::unique_lock<std::mutex> lock(t.mu);
    t.cv.wait_for(lock, std::chrono::milliseconds(ms),
                  [&] { return !t.q.empty() || t.notified; });
    t.notified = false;
}

void notify(Target& t)
{
    std::lock_guard<std::mutex> lock(t.mu);
    t.notified = true;
    t.cv.notify_all();
}

void send(Target& t, const std::string& utf8)
{
    std::shared_ptr<Conn> conn;
    {
        std::lock_guard<std::mutex> lock(t.mu);
        if (t.conn && t.conn->id == t.session) // see Target::session
            conn = t.conn;
    }
    if (conn)
        enqueue_frame(*conn, 0x1, utf8);
}

int start_server(const std::string& host, int port, const std::string& token,
                 const Settings& settings, std::string *err)
{
    install_atfork();
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_port > 0)
        return g_port; // reset in fork children, see atfork_child
    if (g_thread_running) {
        *err = "the previous server is still stopping";
        return -1;
    }
    g_max_message = settings.max_message;
    g_max_conns = settings.max_connections;
    g_send_idle_ms = settings.send_idle_ms;
    g_send_total_ms = settings.send_total_ms;
    g_handshake_ms = settings.handshake_ms;
    g_max_queued = settings.max_queued;
    g_max_queued_bytes = settings.max_queued_bytes;
    g_max_targets = settings.max_targets;
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    std::string service = std::to_string(port);
    int r = getaddrinfo(host.c_str(), service.c_str(), &hints, &res);
    if (r) {
        *err = std::string("getaddrinfo: ") + gai_strerror(r);
        return -1;
    }
    int lfd = -1;
    std::string last = "no address";
    for (addrinfo *ai = res; ai; ai = ai->ai_next) {
        lfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (lfd < 0) { last = strerror(errno); continue; }
        set_cloexec_nonblock(lfd);
        int one = 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(lfd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(lfd, 16) == 0)
            break;
        last = strerror(errno);
        close(lfd);
        lfd = -1;
    }
    freeaddrinfo(res);
    if (lfd < 0) {
        *err = "bind " + host + ":" + service + ": " + last;
        return -1;
    }
    sockaddr_storage ss{};
    socklen_t sl = sizeof(ss);
    getsockname(lfd, reinterpret_cast<sockaddr *>(&ss), &sl);
    int bound = ntohs(ss.ss_family == AF_INET6
                      ? reinterpret_cast<sockaddr_in6 *>(&ss)->sin6_port
                      : reinterpret_cast<sockaddr_in *>(&ss)->sin_port);
    int wake[2];
    if (pipe(wake) < 0) {
        close(lfd);
        *err = std::string("pipe: ") + strerror(errno);
        return -1;
    }
    set_cloexec_nonblock(wake[0]);
    set_cloexec_nonblock(wake[1]);
    r = pthread_create(&g_thread, nullptr, server_main, new ServerFds{lfd, wake[0]});
    if (r) {
        close(lfd);
        close(wake[0]);
        close(wake[1]);
        *err = std::string("pthread_create: ") + strerror(r);
        return -1;
    }
    g_thread_running = true;
    g_stopping = false;
    g_wake_r = wake[0];
    g_wake_w = wake[1];
    g_lfd = lfd;
    g_host = host.find(':') != std::string::npos ? "[" + host + "]" : host;
    g_port = bound;
    g_prefix = token.empty() ? std::string() : "/" + token;
    return bound;
}

bool stop_server()
{
    pthread_t thr;
    int wake_w;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (g_port < 0 || !g_thread_running)
            return false;
        g_port = -1; // reported as stopped from here on
        // g_prefix stays until the thread has exited: a request it is still
        // answering must keep being checked against the token
        thr = g_thread;
        wake_w = g_wake_w;
        // the server thread closes g_lfd and g_wake_r itself
        g_lfd = g_wake_r = g_wake_w = -1;
    }
    g_stopping = true;
    char b = 0;
    while (write(wake_w, &b, 1) < 0 && errno == EINTR) {}
    pthread_join(thr, nullptr); // it takes g_mu in close_conn: not held here
    close(wake_w);
    std::lock_guard<std::mutex> lock(g_mu);
    g_thread_running = false;
    g_prefix.clear();
    return true;
}

size_t target_count()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_targets->size();
}

int server_port()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_port;
}

} // namespace mini_racer_inspector
