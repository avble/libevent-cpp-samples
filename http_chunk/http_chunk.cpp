#include <fstream>

#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/event.h"
#include "event2/http.h"
#include "event2/http_struct.h"
#include "event2/listener.h"
extern "C" {
#include "http-internal.h" //Notes: as libevent's http design, the struct evhttp_connection is not exposed to out side.
}

#include <cstring>
#include <functional>
#include <iostream>

#include <arpa/inet.h>

using namespace std::placeholders;

template <class F, class... Args>
void start_async(evhttp * http, unsigned short port, F f, Args... args);

void read_async(evhttp_connection * evhttp_con, std::function<void(int rc, evhttp_request * req)> func_complete_);

void write_async(evhttp_request * req, int response_code, std::string reason, std::string data,
                 std::function<void(int rc)> complete_func);

std::vector<uint8_t> request_get_chunk_from_input_buffer(evhttp_request * req);

int main(int argc, char * args[])
{

    typedef std::function<void(int, evhttp_request *)> on_read_func;
    typedef std::function<void(evhttp_connection *, on_read_func, int)> on_write_func;

    if (argc != 3)
    {
        std::cerr << "\nUsage: " << args[0] << " address port\n" << "Example: \n" << args[0] << " 0.0.0.0 12345" << std::endl;
        return -1;
    }

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
}

template <class F, class... Args>
void start_async(evhttp * http, unsigned short port, F f, Args... args)
{
    class evconnlistener_obj_cb
    {
    public:
        evconnlistener_obj_cb(evhttp * _http, F f, Args... args) : cb(std::bind(f, args...)) { http_ = _http; }

        void operator()(evhttp_connection * evcon) { cb(evcon); }

        event_base * base() { return http_->base; }
        evhttp * http() { return http_; }

    private:
        evhttp * http_;

    private:
        std::function<void(evhttp_connection *)> cb;
    };

    auto on_accept = [](struct evconnlistener * listener, evutil_socket_t fd, struct sockaddr * sa, int socklen, void * arg) {
        evconnlistener_obj_cb * p = (evconnlistener_obj_cb *) arg;

        char addr[256]{ 0 };
        int16_t port = ((struct sockaddr_in *) sa)->sin_port;
        if (sa->sa_family == AF_INET)
        {
            if (inet_ntop(AF_INET, &((struct sockaddr_in *) sa)->sin_addr, &addr[0], sizeof(addr)) == NULL)
                std::cerr << "can not get ip address" << std::endl;
            else
                std::cout << "[DEBUG] incomming addr: " << addr << ":" << port << std::endl;
        }

        evhttp_connection * evcon = evhttp_connection_base_bufferevent_new(p->base(), NULL, NULL, addr, port);
        evcon->http_server        = p->http();
        TAILQ_INSERT_TAIL(&p->http()->connections, evcon, next);
        p->http()->connection_cnt++;

        evcon->max_headers_size = p->http()->default_max_headers_size;
        evcon->max_body_size    = p->http()->default_max_body_size;
        if (p->http()->flags & EVHTTP_SERVER_LINGERING_CLOSE)
            evcon->flags |= EVHTTP_CON_LINGERING_CLOSE;

        evcon->flags |= EVHTTP_CON_INCOMING;
        evcon->state = EVCON_READING_FIRSTLINE;

        if (bufferevent_replacefd(evcon->bufev, fd))
            goto err;
        (*p)(evcon);
        return;
    err:
        evhttp_connection_free(evcon);
    };

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    addr.sin_port        = htons(port);
    int flags            = LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE;
    struct sockaddr * sa = (struct sockaddr *) &addr;

    auto listener = evconnlistener_new_bind(http->base, on_accept, new evconnlistener_obj_cb(http, f, args...), flags, -1, sa,
                                            sizeof(sockaddr_in));
};

void read_async(evhttp_connection * evhttp_con, std::function<void(int rc, evhttp_request * req)> func_complete_)
{
    class request_cb_obj
    {
        typedef std::function<void(int, evhttp_request *)> on_read_cb;

    public:
        request_cb_obj(on_read_cb && on_read_) { on_read = std::move(on_read_); }

        void operator()(int ec, evhttp_request * req) { on_read(ec, req); }

    public:
        on_read_cb on_read;
    };

    if (TAILQ_EMPTY(&evhttp_con->requests)) // create new request if it is empty in list
    {
        auto request_complete_cb = [](evhttp_request * req, void * arg) {
            TAILQ_REMOVE(&req->evcon->requests, req, next);
            request_cb_obj * on_read_cb_ = (request_cb_obj *) arg;
            (*on_read_cb_)(0, req);
            req->cb_arg = NULL; // avoid dangling pointer
            req->cb     = NULL;
            evhttp_request_free(req);
            delete on_read_cb_;
        };

        auto request_err_cb = [](enum evhttp_request_error ec, void * arg) {
            request_cb_obj * on_read_cb_ = (request_cb_obj *) arg;
            (*on_read_cb_)(ec, NULL);
            delete on_read_cb_;
        };

        struct evhttp_request * req = evhttp_request_new(request_complete_cb, new request_cb_obj(std::move(func_complete_)));
        evhttp_request_set_error_cb(req, request_err_cb);
        TAILQ_INSERT_HEAD(&evhttp_con->requests, req, next);
        req->evcon    = evhttp_con; /* the request ends up owning the connection */
        req->userdone = 1;
        req->flags |= EVHTTP_REQ_OWN_CONNECTION;
        req->kind = EVHTTP_REQUEST;
    }

    evhttp_request * req = TAILQ_FIRST(&evhttp_con->requests);
    evhttp_start_read_(evhttp_con);
}

void write_async(evhttp_request * req, int response_code, std::string reason, std::string data,
                 std::function<void(int rc)> complete_func)
{

    class bufev_cb_obj
    {
        typedef std::function<void(int rc)> on_write_cb;

    public:
        bufev_cb_obj(on_write_cb && on_write_) : on_write(std::move(on_write_)) {}

        void operator()(int rc) { on_write(rc); }

    private:
        on_write_cb on_write;
    };

    // std::cout << "[DEBUG][write_async] data: " << data << "req: " <<
    evbuffer * evb = evbuffer_new();
    evbuffer_add(evb, data.c_str(), data.size());

    evhttp_response_code_(req, response_code, reason == "" ? NULL : reason.c_str());
    struct evhttp_connection * evcon = req->evcon;

    /* we expect no more calls form the user on this request */
    req->userdone = 1;

    /* xxx: not sure if we really should expose the data buffer this way */
    if (evb != NULL)
        evbuffer_add_buffer(req->output_buffer, evb);

    /* Adds headers to the response */
    evhttp_make_header(evcon, req);

    bufferevent_data_cb write_cb = [](struct bufferevent * bufev, void * arg) {
        bufev_cb_obj * on_write = (bufev_cb_obj *) arg;
        (*on_write)(0);
        delete on_write;
    };

    bufferevent_data_cb readcb_ptr   = NULL;
    bufferevent_data_cb writecb_ptr  = NULL;
    bufferevent_event_cb eventcb_ptr = NULL;
    void * arg;
    bufferevent_getcb(evcon->bufev, &readcb_ptr, &writecb_ptr, &eventcb_ptr, &arg);

    bufferevent_setcb(evcon->bufev, NULL, /*read*/
                      write_cb, eventcb_ptr, new bufev_cb_obj(std::move(complete_func)));

    bufferevent_disable(evcon->bufev, EV_READ);
    bufferevent_enable(evcon->bufev, EV_WRITE);

    evbuffer_free(evb);
}

std::vector<uint8_t> request_get_chunk_from_input_buffer(evhttp_request * req)
{
    int len = evbuffer_get_length(req->input_buffer);
    std::vector<uint8_t> ans(len);
    evbuffer_remove(req->input_buffer, ans.data(), len);
    return ans;
}
