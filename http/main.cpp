#include "http.hpp"

using namespace std::placeholders;

int main(int argc, char ** args)
{
    if (argc != 3)
    {
        std::cerr << "\nUsage: " << args[0] << " address port\n" << "Example: \n" << args[0] << " 0.0.0.0 12345" << std::endl;
        return -1;
    }

    std::string addr(args[1]);
    uint16_t port = static_cast<uint16_t>(std::atoi(args[2]));

    {
        http2::start_server(port, [](int rc, http2::response res) {
            res.body() = "hello world";
            res.send_reply(200);
        });
    }

    {
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
    }
}
