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

#include <functional>
#include <mutex>
#include <utility>

class Event
{
public:
    template <class F, class... Args>
    static void call_soon(F && f, Args... args)
    {
        struct wrapper
        {
            wrapper(F && func_, Args... args) : func(std::bind(std::move(func_), args...)) {}

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

    static int base_dispatch() { return event_base_dispatch(Event::event_base_global()); }

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
