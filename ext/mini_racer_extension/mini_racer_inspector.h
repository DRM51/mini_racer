#pragma once
// Chrome DevTools Protocol transport for mini_racer: a process-wide
// HTTP + WebSocket server that DevTools (chrome://inspect, VS Code) discovers
// through /json/list, and one Target per inspectable Context.
//
// Knows nothing about V8 or Ruby. The V8 thread registers a Target, drains
// frontend events from it and sends protocol messages back; the server thread
// owns all sockets and only ever touches a Target under its mutex.
#include <memory>
#include <string>

namespace mini_racer_inspector {

struct Target;

enum class Event { None, Connect, Disconnect, Message };

// |wake| is called from the server thread, with the target's lock held,
// whenever an event is queued; it must not call back into this module.
std::shared_ptr<Target> register_target(const std::string& title,
                                        void (*wake)(void *arg), void *arg);
// Closes the frontend connection, if any, and stops further wake calls.
void unregister_target(const std::shared_ptr<Target>& t);

// Pops the next frontend event; *msg is set for Event::Message.
Event poll(Target& t, std::string *msg);
// Blocks for at most |ms| milliseconds or until an event or notify().
void wait(Target& t, int ms);
void notify(Target& t);
// Sends a protocol message to the attached frontend; dropped if none.
void send(Target& t, const std::string& utf8);

// Returns the bound port, or -1 and sets *err. Starting again in the same
// process returns the existing port.
int start_server(const std::string& host, int port, std::string *err);
int server_port(); // -1 when not started in this process

} // namespace mini_racer_inspector
