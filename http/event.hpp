#pragma once
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/event.h"
#include "event2/http.h"
#include "event2/http_struct.h"
#include "event2/listener.h"
extern "C" {
#include "http-internal.h" //TODO: check if it needs
}

#include <chrono>
#include <cstring>
#include <functional>
#include <mutex>
#include <optional>
#include <utility>

#include <arpa/inet.h>

class Event
{
public:
    ///////////////////////////////////////////////////////////////////////
    // Schedule a callback
    static int run_forever() { return event_base_dispatch(Event::event_base_global()); }

    // static int stop() { event_del(Event::event_base_global()); }

    ///////////////////////////////////////////////////////////////////////
    // Schedule a callback
    template <class F, class... Args>
    static void call_soon(F f, Args... args)
    {
        struct wrapper
        {
            wrapper(F func_, Args... args) : func(std::bind(func_, args...)) {}

            void operator()() { func(); }

            std::function<void()> func;
        };

        auto event_base_once_cb = [](evutil_socket_t fd, short what, void * ptr) {
            wrapper * p = (wrapper *) ptr;
            (*p)();
            delete p;
        };

        event_base_once(Event::event_base_global(), -1, EV_TIMEOUT, event_base_once_cb, new wrapper(std::move(f), args...), NULL);
    }

    template <class F, class... Args>
    static void call_soon_threadsafe(F && f, Args... args)
    {
        std::lock_guard lock(Event::event_mutex_);
        call_soon(std::bind(f, args...));
    }

    template <class F, class... Args>
    static void call_later(std::chrono::seconds delay, F && f, Args... args)
    {
        struct wrapper
        {
            wrapper(F func_, Args... args) : func(std::bind(func_, args...)) {}

            void operator()() { func(); }

            std::function<void()> func;
        };

        auto event_base_once_cb = [](evutil_socket_t fd, short what, void * ptr) {
            wrapper * p = (wrapper *) ptr;
            (*p)();
            delete p;
        };

        struct timeval tv = { .tv_sec = delay.count(), .tv_usec = 0 };

        event_base_once(Event::event_base_global(), -1, EV_TIMEOUT, event_base_once_cb, new wrapper(std::move(f), args...), &tv);
    }

    template <class F, class... Args>
    static void call_later(int sec, F && f, Args... args)
    {
        call_later(std::chrono::seconds(sec), f, args...);
    }

    template <class F, class... Args>
    static void call_at(int sec, F && f, Args... args)
    {
        if (sec < Event::time())
            return;

        int lap_sec = sec - Event::time();
        Event::call_later(lap_sec, std::move(f), args...);
    }

    static int time()
    {
        return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    static event_base * event_base_global()
    {
        if (event_base_ == NULL)
            event_base_ = event_base_new();

        return event_base_;
    }

private:
    static event_base * event_base_;
    static std::mutex event_mutex_;
};

event_base * Event::event_base_ = NULL;
std::mutex Event::event_mutex_;

namespace Event_helper {

std::optional<std::string> evhttp_request_header_get(evhttp_request * req, const std::string & key)
{
    const char * value = evhttp_find_header(evhttp_request_get_input_headers(req), key.c_str());
    return value == NULL ? std::nullopt : std::optional<std::string>(value);
}

std::optional<std::string> evhttp_request_uri_get_path(evhttp_request * req)
{
    const char * value = evhttp_uri_get_path(req->uri_elems);
    return value == NULL ? std::nullopt : std::optional<std::string>(value);
}

void evhttp_request_output_header_set(evhttp_request * req, const std::string & key, const std::string & val)
{
    evhttp_add_header(evhttp_request_get_output_headers(req), key.c_str(), val.c_str());
}

// TCP helper
namespace tcp {

// int make_socket_nonblocking(uint16_t port) {}
} // namespace tcp

// listener
template <class F, class... Args>
void listener_new(uint16_t port, F f, Args... args)
{
    class _internal_data
    {
    public:
        _internal_data(F f, Args... args) : cb(std::bind(f, args...)) {}

        void operator()() { cb(); }

    private:
        std::function<void()> cb;
    };

    auto on_accept = [](struct evconnlistener * evconnecion_listener_, evutil_socket_t fd, struct sockaddr * da, int socklen,
                        void * arg) {
        _internal_data * p                 = (_internal_data *) arg;
        struct evhttp_bound_socket * bound = arg;

        struct evhttp * http = bound->http;

        struct bufferevent * bev = NULL;
        if (bound->bevcb)
            bev = bound->bevcb(http->base, bound->bevcbarg);

        (*p)(static_cast<int>(fd));
    };

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    addr.sin_port = htons(port);
    int flags     = 0;
    flags |= LEV_OPT_CLOSE_ON_FREE;
    flags |= LEV_OPT_CLOSE_ON_EXEC;
    flags |= LEV_OPT_REUSEABLE;
    struct sockaddr * sa = (struct sockaddr *) &addr;

    auto listener = evconnlistener_new_bind(Event::event_base_global(), on_accept, new _internal_data(f, args...), flags, -1, sa,
                                            sizeof(sockaddr_in));
    if (listener == NULL)
        return listener;

    // auto accept = [](struct evconnlistener *, evutil_socket_t, struct sockaddr *, int socklen, void *) {
    //     std::cout << "[DEBUG] accept " << std::endl;
    // };

    // evconnlistener_set_cb(listener, accept, NULL);

    return listener;
}

void listener_del(evconnlistener * listener_)
{
    evconnlistener_free(listener_);
    listener_ = NULL;
}

} // namespace Event_helper
