#include "mini_racer_inspector.h"

#include <arpa/inet.h>
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

#include <chrono>
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <random>
#include <vector>

namespace mini_racer_inspector {

namespace {

// Largest WebSocket message accepted from a frontend. Protocol messages are
// small; the cap only bounds memory if something else talks to the port.
constexpr uint64_t kMaxMessage = 16u << 20;
constexpr size_t kMaxHttpRequest = 64u << 10;
constexpr size_t kMaxConns = 32;
// A frontend that stops or slows down reading must not stall the V8 thread
// (which sends protocol messages synchronously) or the server thread for
// long: a message that makes no progress for kSendIdleMs, or takes longer
// than kSendTotalMs in all, drops the connection.
constexpr int kSendIdleMs = 10 * 1000;
constexpr int kSendTotalMs = 30 * 1000;

struct Conn
{
    int fd;
    std::mutex wmu;       // serializes writes; guards |closed|
    bool closed = false;
    // server thread only
    std::string in;
    bool ws = false;
    std::string frag;
    std::weak_ptr<Target> target;

    explicit Conn(int fd) : fd(fd) {}
};

} // namespace

struct Target
{
    std::string id, title;
    std::mutex mu;
    std::condition_variable cv;
    std::deque<std::pair<Event, std::string>> q; // guarded by |mu|
    std::shared_ptr<Conn> conn;                  // guarded by |mu|
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

// fork() only copies the calling thread: the server thread and every V8
// thread are gone in the child, and any lock they held stays held. Take
// g_mu across the fork so the child inherits it in a known state, then drop
// everything that belongs to the parent. Targets are leaked, not destroyed:
// their mutexes may be held by threads that no longer exist.
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
    g_lfd = -1;
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

void push_locked(Target& t, Event ev, std::string msg)
{
    t.q.emplace_back(ev, std::move(msg));
    t.cv.notify_all();
    if (t.wake)
        t.wake(t.arg);
}

void push(Target& t, Event ev, std::string msg)
{
    std::lock_guard<std::mutex> lock(t.mu);
    push_locked(t, ev, std::move(msg));
}

// --- sockets ---

// Caller holds c.wmu. Sockets are non-blocking; see kSendIdleMs.
bool write_all(Conn& c, const char *p, size_t n)
{
#ifdef MSG_NOSIGNAL
    const int flags = MSG_NOSIGNAL;
#else
    const int flags = 0; // SO_NOSIGPIPE is set on accept
#endif
    using clock = std::chrono::steady_clock;
    const auto deadline = clock::now() + std::chrono::milliseconds(kSendTotalMs);
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
        if (::poll(&pfd, 1, static_cast<int>(left < kSendIdleMs ? left : kSendIdleMs)) == 0)
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

bool send_frame(Conn& c, int opcode, const std::string& payload)
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
    std::lock_guard<std::mutex> lock(c.wmu);
    if (c.closed)
        return false;
    if (write_all(c, h.data(), h.size()) && write_all(c, payload.data(), payload.size()))
        return true;
    shutdown(c.fd, SHUT_RDWR);
    return false;
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
            push_locked(*t, Event::Disconnect, std::string());
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

// Returns false when the connection should be closed.
bool handle_http(const std::shared_ptr<Conn>& c)
{
    size_t end = c->in.find("\r\n\r\n");
    if (end == std::string::npos)
        return c->in.size() < kMaxHttpRequest;
    std::string head = c->in.substr(0, end);
    c->in.erase(0, end + 4);

    size_t eol = head.find("\r\n");
    std::string line = head.substr(0, eol);
    std::map<std::string, std::string> headers;
    while (eol != std::string::npos) {
        size_t start = eol + 2;
        eol = head.find("\r\n", start);
        std::string h = head.substr(start, eol == std::string::npos ? std::string::npos : eol - start);
        size_t colon = h.find(':');
        if (colon == std::string::npos) continue;
        size_t v = colon + 1;
        while (v < h.size() && (h[v] == ' ' || h[v] == '\t')) v++;
        headers[lower(h.substr(0, colon))] = h.substr(v);
    }
    size_t sp1 = line.find(' ');
    size_t sp2 = sp1 == std::string::npos ? sp1 : line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) {
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
        if (method != "GET" || lower(headers["connection"]).find("upgrade") == std::string::npos ||
            headers["sec-websocket-version"] != "13" || headers["sec-websocket-key"].size() != 24 ||
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
            push_locked(*t, Event::Connect, std::string());
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
        if (!(b1 & 0x80))
            return false; // clients must mask
        uint64_t len = b1 & 0x7F;
        size_t hdr = 2;
        if (len == 126) {
            if (in.size() < 4) return true;
            len = uint64_t(uint8_t(in[2])) << 8 | uint8_t(in[3]);
            hdr = 4;
        } else if (len == 127) {
            if (in.size() < 10) return true;
            len = 0;
            for (int i = 2; i < 10; i++)
                len = len << 8 | uint8_t(in[i]);
            hdr = 10;
        }
        if (op >= 0x8 && (len > 125 || !fin))
            return false; // RFC 6455 5.5: control frames are short and unfragmented
        if (len > kMaxMessage || c->frag.size() + len > kMaxMessage)
            return false;
        if (in.size() < hdr + 4 + len)
            return true;
        const char *mask = in.data() + hdr;
        std::string payload = in.substr(hdr + 4, static_cast<size_t>(len));
        for (size_t i = 0; i < payload.size(); i++)
            payload[i] ^= mask[i % 4];
        c->in.erase(0, hdr + 4 + static_cast<size_t>(len));

        switch (op) {
        case 0x8: // close
            send_frame(*c, 0x8, payload.substr(0, 2));
            return false;
        case 0x9: // ping
            send_frame(*c, 0xA, payload);
            break;
        case 0xA: // pong
            break;
        case 0x1: // text
        case 0x2: // binary; DevTools only sends text, accept both
            c->frag = std::move(payload);
            [[fallthrough]];
        case 0x0: // continuation
            if (op == 0x0)
                c->frag += payload;
            if (fin) {
                if (auto t = c->target.lock())
                    push(*t, Event::Message, std::move(c->frag));
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

void *server_main(void *arg)
{
    int lfd = static_cast<int>(reinterpret_cast<intptr_t>(arg));
    std::vector<std::shared_ptr<Conn>> conns;
    for (;;) {
        std::vector<pollfd> pfds;
        pfds.push_back({lfd, POLLIN, 0});
        for (auto& c : conns)
            pfds.push_back({c->fd, POLLIN, 0});
        if (poll(pfds.data(), pfds.size(), -1) < 0) {
            if (errno == EINTR) continue;
            return nullptr;
        }
        std::vector<std::shared_ptr<Conn>> keep;
        for (size_t i = 1; i < pfds.size(); i++) {
            auto& c = conns[i - 1];
            if (pfds[i].revents && !handle_read(c)) {
                close_conn(c);
                continue;
            }
            keep.push_back(c);
        }
        conns.swap(keep);
        if (pfds[0].revents & POLLIN) {
            std::lock_guard<std::mutex> lock(g_mu); // see close_conn
            int fd = accept(lfd, nullptr, nullptr); // non-blocking
            if (fd >= 0 && conns.size() >= kMaxConns) {
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
        t->q.clear();
    }
    if (conn) {
        std::lock_guard<std::mutex> lock(conn->wmu);
        if (!conn->closed)
            shutdown(conn->fd, SHUT_RDWR); // server thread closes it
    }
}

Event poll(Target& t, std::string *msg)
{
    std::lock_guard<std::mutex> lock(t.mu);
    if (t.q.empty())
        return Event::None;
    auto ev = std::move(t.q.front());
    t.q.pop_front();
    if (msg)
        *msg = std::move(ev.second);
    return ev.first;
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
        conn = t.conn;
    }
    if (conn)
        send_frame(*conn, 0x1, utf8);
}

int start_server(const std::string& host, int port, const std::string& token,
                 std::string *err)
{
    install_atfork();
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_port > 0)
        return g_port; // reset in fork children, see atfork_child
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
    pthread_t thr;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    r = pthread_create(&thr, &attr, server_main, reinterpret_cast<void *>(static_cast<intptr_t>(lfd)));
    pthread_attr_destroy(&attr);
    if (r) {
        close(lfd);
        *err = std::string("pthread_create: ") + strerror(r);
        return -1;
    }
    g_lfd = lfd;
    g_host = host.find(':') != std::string::npos ? "[" + host + "]" : host;
    g_port = bound;
    g_prefix = token.empty() ? std::string() : "/" + token;
    return bound;
}

int server_port()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_port;
}

} // namespace mini_racer_inspector
