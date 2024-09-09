// Descriptions

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
int main(int argc, char ** args)
{

    if (argc != 3)
    {
        std::cerr << "\nUsage: " << args[0] << " address port\n" << "Example: \n" << args[0] << " 0.0.0.0 12345" << std::endl;
        return -1;
    }

    std::string addr(args[1]);
    uint16_t port = static_cast<uint16_t>(std::atoi(args[2]));

    std::cout << "server running on: (" << addr << " : " << port << ")" << std::endl;

    event_base * base = Event::event_base_global();

    auto ws = make_ws(base, addr, port);

    ws->add_ws_handler(ws_chat_handler);

    ws->start();

    Event::base_dispatch();
}
