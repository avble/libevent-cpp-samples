# Introduction
This repository provides examples written in cpp and backed by libevents.

# Compile
``` shell
$ mkdir build && cd build && cmake ..
$ make
```
* It has been compiled and run in development environment(Ubuntu 22.04.2 LTS)

# samples
## [http](https://github.com/avble/libevent-cpp-samples/tree/main/http)

The server can be started at below.
``` cpp
    http2::start_server(port, [](int rc, http2::response res) {
        res.body() = "hello world";
        res.send_reply(200);
    });
```

In case you want to create your own routing, a route handler can be written as below example

``` cpp
    std::unordered_map<std::string, http2::on_read_request_complete_func> routes;

    routes["/route_01"] = [](int rc, http2::response res) {
        res.body() = "hello from route_01";
        res.send_reply();
    };
    routes["/route_02"] = [](int rc, http2::response res) {
        res.body() = "hello from route_02";
        res.send_reply();
    };

    auto route_handler = [&routes](int rc, http2::response res) {
        std::shared_ptr<http2::request> req = res.reqwest();
        auto path                           = req->get_uri_path();
        if (auto route_ = (path.has_value() ? routes[path.value()] : http2::on_read_request_complete_func()))
            route_(rc, std::move(res));
        else
            res.send_reply(404);
    };

    http2::start_server(port, route_handler);

```

## [http upload (chunk)] (https://github.com/avble/libevent-cpp-samples/tree/main/http_chunk)

```cpp
    std::string addr(args[1]);
    uint16_t port = static_cast<uint16_t>(std::atoi(args[2]));

    event_base * base = event_base_new();
    evhttp * p_evhttp = evhttp_new(base);

    on_write_func on_write = [](evhttp_connection * evcon, on_read_func on_read, int rc) { read_async(evcon, on_read); };

    on_read_func on_read_chunk = [&on_write, &on_read_chunk](int rc, evhttp_request * req) {
        // std::cout << "[DEBUG][file] ENTER" << std::endl;
        std::ofstream of("./file_01");
        std::vector<uint8_t> buff = request_get_chunk_from_input_buffer(req);
        for (const auto & v : buff)
            of << v;

        write_async(req, 200, "OK", "", std::bind(on_write, req->evcon, on_read_chunk, ::_1));
    };

    auto on_accept = [&on_read_chunk](struct evhttp_connection * evcon) { read_async(evcon, on_read_chunk); };

    start_async(p_evhttp, port, on_accept, ::_1);

    event_base_dispatch(base);
```

Test with the below command to upload 1Gb byte, it works
``` shell
# run sever
$./http_srv_chunk 0.0.0.0 12345
# upload file with curl command
$ curl -H "Transfer-Encoding" --data-binary  @file_1gb 127.0.0.1:12345
```

## [http upload (chunk)] (https://github.com/avble/libevent-cpp-samples/tree/main/http_chunk)

```cpp
    std::string addr(args[1]);
    uint16_t port = static_cast<uint16_t>(std::atoi(args[2]));

    event_base * base = event_base_new();
    evhttp * p_evhttp = evhttp_new(base);

    on_write_func on_write = [](evhttp_connection * evcon, on_read_func on_read, int rc) { read_async(evcon, on_read); };

    on_read_func on_read_chunk = [&on_write, &on_read_chunk](int rc, evhttp_request * req) {
        // std::cout << "[DEBUG][file] ENTER" << std::endl;
        std::ofstream of("./file_01");
        std::vector<uint8_t> buff = request_get_chunk_from_input_buffer(req);
        for (const auto & v : buff)
            of << v;

        write_async(req, 200, "OK", "", std::bind(on_write, req->evcon, on_read_chunk, ::_1));
    };

    auto on_accept = [&on_read_chunk](struct evhttp_connection * evcon) { read_async(evcon, on_read_chunk); };

    start_async(p_evhttp, port, on_accept, ::_1);

    event_base_dispatch(base);
```

Test with the below command to upload 1Gb byte, it works
``` shell
# run sever
$./http_srv_chunk 0.0.0.0 12345
# upload file with curl command
$ curl -H "Transfer-Encoding" --data-binary  @file_1gb 127.0.0.1:12345
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