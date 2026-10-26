#pragma once
// Chrome DevTools Protocol transport for mini_racer: a process-wide
// HTTP + WebSocket server that DevTools (chrome://inspect, VS Code) discovers
// through /json/list, and one Target per inspectable Context.
//
// Knows nothing about V8 or Ruby. The V8 thread registers a Target, drains
// frontend events from it and sends protocol messages back; the server thread
// owns all sockets and only ever touches a Target under its mutex.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace mini_racer_inspector {

struct Target;

enum class Event { None, Connect, Disconnect, Message };

// |wake| is called from the server thread, with the target's lock held,
// whenever an event is queued; it must not call back into this module.
// Returns nullptr when Settings::max_targets are already registered.
std::shared_ptr<Target> register_target(const std::string& title,
                                        void (*wake)(void *arg), void *arg);
// Closes the frontend connection, if any, and stops further wake calls.
void unregister_target(const std::shared_ptr<Target>& t);
// The id in /json/list and the WebSocket URL; fixed for the target's life.
const std::string& target_id(const Target& t);
// Drops the frontend attached to target |id|, if any; any thread. The
// target sees Event::Disconnect as usual. False if there's no such target.
bool disconnect(const std::string& id);

// Pops the next frontend event; *msg is set for Event::Message.
Event poll(Target& t, std::string *msg);
// Blocks for at most |ms| milliseconds or until an event or notify().
void wait(Target& t, int ms);
void notify(Target& t);
// Sends a protocol message to the attached frontend; dropped if none.
void send(Target& t, const std::string& utf8);

// Limits for the server and every target; see Inspector.start in
// lib/mini_racer.rb for what each means.
struct Settings
{
    uint64_t max_message = 16u << 20;
    size_t max_connections = 32;
    int send_idle_ms = 10 * 1000;
    int send_total_ms = 30 * 1000;
    int handshake_ms = 10 * 1000;
    size_t max_queued = 4096;
    size_t max_queued_bytes = 64u << 20;
    size_t max_targets = 0; // 0: no cap; register_target then returns nullptr
};

// Returns the bound port, or -1 and sets *err. Starting again in the same
// process returns the existing port. A non-empty |token| becomes the first
// path segment of every URL the server answers, /json/list included.
int start_server(const std::string& host, int port, const std::string& token,
                 const Settings& settings, std::string *err);
// Stops listening, drops every frontend (each target sees Event::Disconnect)
// and waits for the server thread. Targets stay registered; start_server
// can run again. False if it wasn't running.
bool stop_server();
size_t target_count();
int server_port(); // -1 when not started in this process

} // namespace mini_racer_inspector
