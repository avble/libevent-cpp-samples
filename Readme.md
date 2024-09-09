# Introduction
samples in cpp for libevents

# Compile
``` shell
$ mkdir build && cd build && cmake ..
$ make
```
* It has been compiled and run in development environment(Ubuntu 22.04.2 LTS)

# samples
## [http](https://github.com/avble/libevent-cpp-samples/tree/main/http)

``` cpp
#include "http.hpp"

int main(int argc, char ** argv)
{
    event_base * base = event_base_global();

    auto http = make_http(base, "0.0.0.0", 12345);

    http->add_handler("/route_01", [](std::shared_ptr<http::request> req) { req->do_write("hello from route 01\n"); });
    http->add_handler("/route_02", [](std::shared_ptr<http::request> req) { req->do_write("hello from route 02\n"); });
    http->start();

    event_base_dispatch(base);

    event_base_free(base);
}
```

## [websocket chat application](https://github.com/avble/libevent-cpp-samples/tree/main/websocket_chat)

The example code of program is as below.

``` cpp
#include "http.hpp"

// ws handle for chat application
void ws_chat_handler(const std::string & msg, std::shared_ptr<ws_connection> sp)
{
    std::cout << "[DEBUG][ws_chat_handler] ENTER" << std::endl;
    auto peers = ws_connection::peer_mgr[sp->topic];
    for (auto & peer : peers)
    {
        // deliver message to peers which has the same topics
        if (auto peer_lock = peer.lock())
            Event::call_soon(std::bind(&ws_connection::do_write_msg, peer_lock, std::placeholders::_1), msg);
    }
};

// main
int main(int argc, char ** argv)
{
    //.........
    event_base * base = Event::event_base_global();

    auto ws = make_ws(base, addr, port);

    ws->add_ws_handler(ws_chat_handler);

    ws->start();
    //........
}
```