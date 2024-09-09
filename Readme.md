# Introduction
samples in cpp for libevents

# Compile
``` shell
$ mkdir build && cd build && cmake ..
$ make
```

# samples
## [http](https://github.com/avble/libevent-cpp-samples/http)

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