#pragma once
extern "C" {
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/event.h"
#include "event2/http.h"
#include "event2/http_compat.h"
#include "event2/http_struct.h"
#include "event2/listener.h"
#include "event2/util.h"
#include "http-internal.h" //TODO: check if it needs
}

#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/queue.h>

// helper of libevent
static event_base * event_base_ = NULL;

event_base * event_base_global()
{
    if (event_base_ == NULL)
        event_base_ = event_base_new();

    return event_base_;
}

std::optional<std::string> evhttp_request_header_get(evhttp_request * req, const std::string & key)
{
    const char * value = evhttp_find_header(evhttp_request_get_input_headers(req), key.c_str());
    return value == NULL ? std::nullopt : std::optional<std::string>(value);
}

std::optional<std::string> evhttp_request_uri_get_path(evhttp_request * req)
{
    const char * value = evhttp_uri_get_path(req->uri_elems);
    return value == NULL ? std::nullopt : std::optional<std::string>(value);
}

void evhttp_request_header_set(evhttp_request * req, const std::string & key, const std::string & val)
{
    evhttp_add_header(evhttp_request_get_output_headers(req), key.c_str(), val.c_str());
}

namespace net {
class listener_ev_cb_obj
{
    typedef std::function<void(int ec, evhttp_connection * evhttp_con)> on_accept_cb;

public:
    listener_ev_cb_obj(on_accept_cb && on_accept_, struct evhttp * p_)
    {
        on_accept = std::move(on_accept_);
        p_evhttp  = p_;
    }

    void operator()(int ec, evhttp_connection * evhttp_con) { on_accept(ec, evhttp_con); }

    struct evhttp * get_evhttp() const { return p_evhttp; }

private:
    on_accept_cb on_accept;
    struct evhttp * p_evhttp;
};

void stream_accept_async(struct evhttp * p_evhttp, std::string addr, int port,
                         std::function<void(int ec, evhttp_connection * evhttp_con)> && func)
{
    evconnlistener_cb accept_cb = [](struct evconnlistener * listener_ev, evutil_socket_t fd, struct sockaddr * sa, int socklen,
                                     void * arg) {
        listener_ev_cb_obj * on_accept = (listener_ev_cb_obj *) arg;
        evhttp_connection * evcon      = evhttp_get_request_connection_wrapper(on_accept->get_evhttp(), fd, sa, socklen);
        evcon->http_server             = on_accept->get_evhttp();
        TAILQ_INSERT_TAIL(&evcon->http_server->connections, evcon, next);
        (*on_accept)(0, evcon);
    };
    struct evhttp_bound_socket * bound_socket = evhttp_bind_socket_with_handle(p_evhttp, addr.c_str(), port);
    evconnlistener_set_cb(bound_socket->listener, accept_cb, new listener_ev_cb_obj(std::move(func), p_evhttp));
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
    bufev_cb_obj(on_write_cb && on_write_) { on_write = std::move(on_write_); }

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
        base_      = new wrapper<T>(connect_);
        req        = req_;
        send_state = state::NOT_RESPONSE;
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
        auto path = evhttp_request_uri_get_path(req);

        return path;
    }

    ~request()
    {

        evhttp_request_free(req);
        delete base_;
        req = NULL;
    }

    evhttp_request * get_request() const { return req; }

private:
    base * base_;
    std::string response_body;
    evhttp_request * req;
    state send_state;
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

    evhttp_response_code_(req->get_request(), HTTP_OK, NULL);
    struct evhttp_connection * evcon = req->get_request()->evcon;

    /* we expect no more calls form the user on this request */
    req->get_request()->userdone = 1;

    /* xxx: not sure if we really should expose the data buffer this way */
    if (evb != NULL)
        evbuffer_add_buffer(req->get_request()->output_buffer, evb);

    /* Adds headers to the response */
    evhttp_make_header_wrapper(evcon, req->get_request());

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

typedef void (*write_asyn_func)(std::shared_ptr<http::request>, std::string, std::function<void()>);
void event_once_call_write_async(write_asyn_func func, std::shared_ptr<http::request> req, std::string data,
                                 std::function<void()> cb)
{
    struct wrapper
    {
        wrapper(write_asyn_func func_, std::shared_ptr<http::request> req_, std::string data_, std::function<void()> cb_)
        {
            func = func_;
            req  = req_;
            data = data_;
            cb   = cb_;
        }

        write_asyn_func func;
        std::shared_ptr<http::request> req;
        std::string data;
        std::function<void()> cb;
    };

    auto event_base_once_cb = [](evutil_socket_t fd, short what, void * ptr) {
        wrapper * p = (wrapper *) ptr;
        p->func(p->req, p->data, p->cb);
        delete p;
    };

    event_base_once(event_base_global(), -1, EV_TIMEOUT, event_base_once_cb, new wrapper(func, req, data, cb), NULL);
}

class http_connection : public std::enable_shared_from_this<http_connection>
{
    typedef std::function<void(std::shared_ptr<http::request>)> route_handler;
    typedef struct wrapper_s
    {

        wrapper_s(std::shared_ptr<http_connection> p) { p_http = p; }

        ~wrapper_s() { p_http.reset(); }

        std::shared_ptr<http_connection> p_http;
    } wrapper;

public:
    http_connection(evhttp_connection * evhttp_con_, route_handler route_hdl_)
    {
        evhttp_con = evhttp_con_;
        route_hdl  = route_hdl_;
    }

    ~http_connection() {}

    void start()
    {
        // per connection handler
        auto con_close_cb = [](struct evhttp_connection * http_con_, void * arg) {
            wrapper * p = (wrapper *) arg;

            struct evhttp_request * req;
            while ((req = TAILQ_FIRST(&http_con_->requests)) != NULL)
            {
                http::request_cb_obj * req_cb_ = (http::request_cb_obj *) req->cb_arg;
                req->cb_arg                    = NULL;
                TAILQ_REMOVE(&http_con_->requests, req, next);
                delete req_cb_;
            }

            delete p;
        };

        evhttp_connection_set_closecb(evhttp_con, con_close_cb, new wrapper(shared_from_this()));

        do_read();
    }

    void do_read()
    {
        http::read_async(this->evhttp_con,
                         std::bind(&http_connection::on_read, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void on_read(int ec, evhttp_request * req)
    {
        std::weak_ptr<http_connection> wp = shared_from_this();
        if (route_hdl)
            route_hdl(std::make_shared<http::request>(wp, req));
        else
            do_write(std::make_shared<http::request>(wp, req), "Not support route");
    }

    void do_write(std::shared_ptr<http::request> req, const std::string & data)
    {
        event_once_call_write_async(http::write_async, req, data, std::bind(&http_connection::on_write, shared_from_this()));
    }

    void on_write() { do_read(); }

private:
    evhttp_connection * evhttp_con;
    route_handler route_hdl;
};

class http_app : public std::enable_shared_from_this<http_app>
{
    typedef std::function<void(std::shared_ptr<http::request>)> route_hanhdl_func;
    typedef struct wrapper_s
    {

        wrapper_s(std::shared_ptr<http_app> p) { p_http = p; }
        ~wrapper_s() { p_http.reset(); }
        std::shared_ptr<http_app> p_http;
    } wrapper;

public:
    http_app(event_base * base_, std::string addr_, u_int16_t port_)
    {
        addr     = addr_;
        port     = port_;
        p_evhttp = evhttp_new(base_);
    }

    ~http_app()
    {
        // TODO: free p_evhttp
    }

    void start()
    {
        net::stream_accept_async(p_evhttp, addr, port,
                                 std::bind(&http_app::on_accept, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void add_handler(const std::string & route, route_hanhdl_func func_handler_) { routes[route] = func_handler_; }

    evhttp * get_evhttp() const { return this->p_evhttp; }

private:
    void on_accept(int ec, evhttp_connection * evhttp_con)
    {
        auto p = std::shared_ptr<http_connection>(
            new http_connection(evhttp_con,
                                std::bind(&http_app::route_handler, http_app::shared_from_this(), std::placeholders::_1)),
            [](const auto p) {
                /*std::cout << "[DEBUG] http_connection is deleted. " << std::endl; */
                delete p;
            });
        p->start();
    }

    void route_handler(std::shared_ptr<http::request> req)
    {
        if (auto path = req->get_uri_path(); auto route_ = (path.has_value() ? routes[path.value()] : route_hanhdl_func()))
        {
            route_(req);
        }
        else
        {
            req->do_write("wowo...");
        }
    }

private:
    evhttp * p_evhttp;
    std::string addr;
    int port;
    std::unordered_map<std::string, route_hanhdl_func> routes;
};

// helper function
std::shared_ptr<http_app> make_http(event_base * base, const std::string & addr, uint16_t port)
{
    std::shared_ptr<http_app> p(new http_app(base, addr, port), [](auto p) {
        // std::cout << "[DEBUG][http_app] is deleted. \n";
        delete p;
    });
    return p;
}
