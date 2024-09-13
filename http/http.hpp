#pragma once
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/event.h"
#include "event2/http.h"
#include "event2/http_struct.h"
#include "event2/listener.h"
#include "event2/util.h"

#include "event.hpp"

#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/queue.h>

namespace net {
class listener_ev_cb_obj
{
    typedef std::function<void(int ec, evhttp_connection * evcon)> on_accept_cb;

public:
    listener_ev_cb_obj(on_accept_cb && on_accept_, struct evhttp * p_)
    {
        on_accept = std::move(on_accept_);
        p_evhttp  = p_;
    }

    void operator()(int ec, evhttp_connection * evcon) { on_accept(ec, evcon); }

    struct evhttp * get_evhttp() const { return p_evhttp; }

private:
    on_accept_cb on_accept;
    struct evhttp * p_evhttp;
};

}; // namespace net

namespace http {
class request_cb_obj
{
    typedef std::function<void(int, evhttp_request *)> on_read_cb;

public:
    request_cb_obj(on_read_cb && on_read_) { on_read = std::move(on_read_); }

    void operator()(int ec, evhttp_request * req) { on_read(ec, req); }

public:
    on_read_cb on_read;
};

class bufev_cb_obj
{
    typedef std::function<void()> on_write_cb;

public:
    bufev_cb_obj(on_write_cb && on_write_) : on_write(std::move(on_write_)) {}

    void operator()() { on_write(); }

    on_write_cb on_write;
};

class request : public std::enable_shared_from_this<request>
{
    class base
    {
    public:
        virtual void do_write(std::shared_ptr<request> req, std::string data) = 0;
        virtual ~base() {}
    };

    template <typename T>
    class wrapper : public base
    {
    public:
        wrapper(std::weak_ptr<T> p_) { p = p_; }
        wrapper(const wrapper & other) { p = other.p; }

        void do_write(std::shared_ptr<request> req, std::string data)
        {
            if (auto w_p = p.lock())
            {
                w_p->do_write(req, data);
            }
        }

        ~wrapper() {}

        std::weak_ptr<T> p;
    };
    enum state
    {
        NOT_RESPONSE,
        RESPONSE
    };

public:
    template <class T>
    request(std::weak_ptr<T> connect_, evhttp_request * req_)
    {
        base_         = new wrapper<T>(connect_);
        req           = req_;
        response_code = 200;
        send_state    = state::NOT_RESPONSE;
    }

    void do_write()
    {
        if (send_state == state::NOT_RESPONSE)
        {
            send_state = state::RESPONSE;
            base_->do_write(this->shared_from_this(), response_body);
        }
    }

    void do_write(std::string data)
    {
        response_body = data;
        do_write();
    }

    void set_res_body(std::string data) { response_body = data; }

    std::optional<std::string> get_uri_path()
    {
        auto path = Event_helper::evhttp_request_uri_get_path(req);

        return path;
    }

    evhttp_request * get_native_request() const { return req; }

    ~request()
    {

        evhttp_request_free(req);
        delete base_;
        req = NULL;
    }

    evhttp_request * get_request() const { return req; }

    void print_header() {}

private:
    base * base_;
    std::string response_body;
    evhttp_request * req;
    state send_state;

public:
    int response_code;
};

template <class F, class... Args>
void start_async(evhttp * http, unsigned short port, F f, Args... args)
{
    class _internal_data
    {
    public:
        _internal_data(evhttp * http_, F f, Args... args) : cb(std::bind(f, args...)) { http = http_; }

        void operator()(evhttp_connection * evcon) { cb(evcon); }

    public:
        evhttp * http;

    private:
        std::function<void(evhttp_connection *)> cb;
    };

    auto on_accept = [](struct evconnlistener * listener, evutil_socket_t fd, struct sockaddr * sa, int socklen, void * arg) {
        _internal_data * p = (_internal_data *) arg;

        char addr[256]{ 0 };
        int16_t port = ((struct sockaddr_in *) sa)->sin_port;
        if (sa->sa_family == AF_INET)
        {
            if (inet_ntop(AF_INET, &((struct sockaddr_in *) sa)->sin_addr, &addr[0], sizeof(addr)) == NULL)
                std::cerr << "can not get ip address" << std::endl;
            else
                std::cout << "[DEBUG] incomming addr: " << addr << ":" << port << std::endl;
        }

        evhttp_connection * evcon = evhttp_connection_base_bufferevent_new(Event::event_base_global(), NULL, NULL, addr, port);
        evcon->http_server        = p->http;
        TAILQ_INSERT_TAIL(&p->http->connections, evcon, next);
        p->http->connection_cnt++;

        evcon->max_headers_size = p->http->default_max_headers_size;
        evcon->max_body_size    = p->http->default_max_body_size;
        if (p->http->flags & EVHTTP_SERVER_LINGERING_CLOSE)
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

    addr.sin_port = htons(port);
    int flags     = 0;
    flags |= LEV_OPT_CLOSE_ON_FREE;
    flags |= LEV_OPT_CLOSE_ON_EXEC;
    flags |= LEV_OPT_REUSEABLE;
    struct sockaddr * sa = (struct sockaddr *) &addr;

    auto listener = evconnlistener_new_bind(Event::event_base_global(), on_accept, new _internal_data(http, f, args...), flags, -1,
                                            sa, sizeof(sockaddr_in));
};

void read_async(evhttp_connection * evhttp_con, std::function<void(int rc, evhttp_request * req)> func_complete_)
{
    if (TAILQ_EMPTY(&evhttp_con->requests)) // create new request if it is empty in list
    {
        auto request_complete_cb = [](evhttp_request * req, void * arg) {
            TAILQ_REMOVE(&req->evcon->requests, req, next);
            request_cb_obj * on_read_cb_ = (request_cb_obj *) arg;
            (*on_read_cb_)(0, req);
            req->cb_arg = NULL; // avoid dangling pointer
            req->cb     = NULL;
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

void write_async(std::shared_ptr<http::request> req, std::string data, std::function<void()> complete_func)
{
    // std::cout << "[DEBUG][write_async] data: " << data << "req: " <<
    // req->get_request() << std::endl;
    evbuffer * evb = evbuffer_new();
    evbuffer_add(evb, data.c_str(), data.size());

    evhttp_response_code_(req->get_request(), req->response_code, NULL);
    struct evhttp_connection * evcon = req->get_request()->evcon;

    /* we expect no more calls form the user on this request */
    req->get_request()->userdone = 1;

    /* xxx: not sure if we really should expose the data buffer this way */
    if (evb != NULL)
        evbuffer_add_buffer(req->get_request()->output_buffer, evb);

    /* Adds headers to the response */
    evhttp_make_header(evcon, req->get_request());

    bufferevent_data_cb write_cb = [](struct bufferevent * bufev, void * arg) {
        bufev_cb_obj * on_write = (bufev_cb_obj *) arg;
        (*on_write)();
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
} // namespace http

class http_connection : public std::enable_shared_from_this<http_connection>
{
    typedef std::function<void(std::shared_ptr<http::request>)> route_handler;

public:
    http_connection(evhttp_connection * evcon, route_handler route_hdl_)
    {
        route_hdl  = route_hdl_;
        evhttp_con = evcon;
    }

    void start() { do_read(); }

    void do_read()
    {
        std::cout << "[DEBUG] do_read ENTER " << std::endl;
        http::read_async(evhttp_con,
                         std::bind(&http_connection::on_read, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void on_read(int ec, evhttp_request * req)
    {
        std::cout << "[DEBUG] on_read ENTER " << std::endl;
        std::weak_ptr<http_connection> wp = shared_from_this();
        if (route_hdl)
            route_hdl(std::make_shared<http::request>(wp, req));
        else
            do_write(std::make_shared<http::request>(wp, req), "Not support route");
    }

    void do_write(std::shared_ptr<http::request> req, const std::string & data)
    {
        std::cout << "[DEBUG] do_write ENTER " << std::endl;
        auto self(shared_from_this());
        auto cb = [self]() { self->on_write(); };
        Event::call_soon(http::write_async, req, data, cb);
    }

    void on_write() { do_read(); }

private:
    evhttp_connection * evhttp_con;
    route_handler route_hdl;
};