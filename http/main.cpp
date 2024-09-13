#include "http.hpp"

using namespace std::placeholders;

int main(int argc, char ** argv)
{
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
}
