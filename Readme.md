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
    typedef std::function<void(std::shared_ptr<http::request>)> route_hanhdl_func;

    evhttp * p_evhttp = evhttp_new(Event::event_base_global());
    std::string addr  = "127.0.0.1";
    uint16_t port     = 12345;
    std::unordered_map<std::string, route_hanhdl_func> routes;

    routes["/route_01"] = [](std::shared_ptr<http::request> req) { req->do_write("hello from route 01\n"); };
    routes["/route_02"] = [](std::shared_ptr<http::request> req) { req->do_write("hello from route 02\n"); };

    const auto request_dispatch = [&routes](std::shared_ptr<http::request> req) {
        auto path = req->get_uri_path();
        if (auto route_ = (path.has_value() ? routes[path.value()] : route_hanhdl_func()))
        {
            route_(req);
        }
        else
        {
            req->do_write("wowo...");
        }
    };

    auto on_accept = [&request_dispatch](struct evhttp_connection * evcon) {
        std::make_shared<http_connection>(evcon, std::bind(request_dispatch, ::_1))->start();
    };

    http::start_async(p_evhttp, port, on_accept, ::_1);

    Event::run_forever();
```

## [websocket chat application](https://github.com/avble/libevent-cpp-samples/tree/main/websocket_chat)

source code of websocket looks like below

``` cpp
    evhttp * p_evhttp = evhttp_new(Event::event_base_global());

    auto ws_chat_handler = [](const std::string & msg, std::shared_ptr<ws_connection> sp) {
        auto peers = ws_connection::peer_mgr[sp->topic];
        for (auto & peer : peers)
        {
            // deliver message to peers which has the same topics
            if (auto peer_lock = peer.lock())
                Event::call_soon(std::bind(&ws_connection::do_write_msg, peer_lock, std::placeholders::_1), msg);
        }
    };

    auto on_accept = [&ws_chat_handler](struct evhttp_connection * evcon) {
        std::make_shared<ws_connection>(evcon, std::bind(ws_chat_handler, ::_1, ::_2))->start();
    };

    // start server
    http::start_async(p_evhttp, port, on_accept, ::_1);

    Event::run_forever();
```