#pragma once

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

namespace http2 {

// forward declaration
class request;
class response;
using tcp_stream                      = evhttp_connection *;
using on_accept_complete_func         = std::function<void(tcp_stream)>;
using on_write_response_complete_func = std::function<void(int rc)>;
using on_read_request_complete_func   = std::function<void(int rc, response)>;
void write_async(std::shared_ptr<request> req, std::string data, on_write_response_complete_func complete_func);

class request : public std::enable_shared_from_this<request>
{
    class base
    {
    public:
        virtual void on_write_response(int rc) = 0;
        virtual ~base() {}
    };

    template <typename T>
    class wrapper : public base
    {
    public:
        wrapper(std::shared_ptr<T> p_) { p = p_; }
        wrapper(const wrapper & other) { p = other.p; }

        void on_write_response(int rc) { p->on_write_response(rc); }

        ~wrapper() {}

        std::shared_ptr<T> p;
    };
    enum state
    {
        NOT_RESPONSE,
        RESPONSE
    };

public:
    request()                             = delete;
    request(const request & other)        = delete;
    request & operator=(const request &)  = delete;
    request & operator=(const request &&) = delete;

    template <class T>
    request(std::shared_ptr<T> connect_, evhttp_request * req_)
    {
        base_         = new wrapper<T>(connect_);
        req           = req_;
        response_code = 200;
        send_state    = state::NOT_RESPONSE;
    }

    void do_write(on_write_response_complete_func && complete_func_)
    {
        if (send_state == state::NOT_RESPONSE)
        {
            auto self(shared_from_this());

            auto on_write = [self, &complete_func_](int rc) { self->base_->on_write_response(rc); };

            send_state = state::RESPONSE;
            Event::call_soon(write_async, shared_from_this(), response_body, on_write);
        }
    }

    std::optional<std::string> get_uri_path() const { return Event_helper::evhttp_request_uri_get_path(req); }

    evhttp_request * reqwest() { return req; };

    ~request()
    {
        evhttp_request_free(req);
        req = NULL;
        delete base_;
    }

private:
    evhttp_request * req;
    state send_state;
    std::string response_body;
    int response_code;
    std::string reason;
    base * base_;

public:
    friend void write_async(std::shared_ptr<request> req, std::string data, on_write_response_complete_func complete_func);
    friend std::vector<uint8_t> request_get_input_buffer(std::shared_ptr<request>);
    friend class response;
};

std::vector<uint8_t> request_get_input_buffer(std::shared_ptr<request> req)
{
    int len = evbuffer_get_length(req->req->input_buffer);
    std::vector<uint8_t> ans(len);
    evbuffer_remove(req->req->input_buffer, ans.data(), len);
    return ans;
}

std::vector<uint8_t> request_get_input_buffer(evhttp_request * req)
{
    int len = evbuffer_get_length(req->input_buffer);
    std::vector<uint8_t> ans(len);
    evbuffer_remove(req->input_buffer, ans.data(), len);
    return ans;
}

class response
{
public:
    response()                                    = delete;
    response(response & other)                    = delete;
    response & operator=(const response & other)  = delete;
    response & operator=(const response && other) = delete;

    response(std::shared_ptr<request> req_) { req = req_; }
    response(response && other) { req = other.req; }

    void set_header(const std::string & key, const std::string & val)
    {
        Event_helper::evhttp_request_output_header_set(req->req, key.c_str(), val.c_str());
    }

    std::string & body() { return req->response_body; }

    void send_reply(unsigned short response_code, std::string reason, on_write_response_complete_func && on_write_func)
    {
        req->response_code = response_code;
        req->reason        = reason;
        req->do_write(std::move(on_write_func));
    }
    void send_reply(int response_code, on_write_response_complete_func && on_write_func)
    {
        send_reply(response_code, "", std::move(on_write_func));
    }
    void send_reply(on_write_response_complete_func && on_write_func) { send_reply(200, "", std::move(on_write_func)); }

    void send_reply(unsigned short response_code, std::string reason)
    {
        on_write_response_complete_func on_write_complete = [](int rc) {};
        send_reply(response_code, reason, std::move(on_write_complete));
    }
    void send_reply(int response_code) { send_reply(response_code, ""); }
    void send_reply() { send_reply(200, ""); }

    const std::shared_ptr<request> reqwest() const { return req; }

    ~response() { /*/ std::cout << "[DEBUG][~response] is called.\n"; */ }

private:
    std::shared_ptr<request> req;
};

class request_cb_obj
{
public:
    request_cb_obj(std::function<void(int, evhttp_request *)> && on_read_) { on_read = std::move(on_read_); }

    void operator()(int ec, evhttp_request * req) { on_read(ec, req); }

    ~request_cb_obj() { on_read = nullptr; }

public:
    std::function<void(int, evhttp_request *)> on_read;
};

evconnlistener * start_async(unsigned short port, on_accept_complete_func on_accept_complete)
{
    class evconnlistener_obj_cb
    {
    public:
        evconnlistener_obj_cb(evhttp * http_, on_accept_complete_func on_accept_complete) : cb(on_accept_complete) { http = http_; }
        void operator()(tcp_stream stream) { cb(stream); }

        ~evconnlistener_obj_cb() { std::cout << "[~evconnlistener_obj_cb] is called.\n"; }

    public:
        evhttp * http;

    private:
        const on_accept_complete_func cb;
    };

    evhttp * http = evhttp_new(Event::event_base_global());

    auto on_accept = [](struct evconnlistener * listener, evutil_socket_t fd, struct sockaddr * sa, int socklen, void * arg) {
        evconnlistener_obj_cb * p = (evconnlistener_obj_cb *) arg;

        char addr[256]{ 0 };
        uint16_t port = ((struct sockaddr_in *) sa)->sin_port;
        if (sa->sa_family == AF_INET)
        {
            if (inet_ntop(AF_INET, &((struct sockaddr_in *) sa)->sin_addr, &addr[0], sizeof(addr)) == NULL)
                std::cerr << "can not get ip address" << std::endl;
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

        void (*on_con_close)(struct evhttp_connection * evcon, void * arg) = [](struct evhttp_connection * evcon, void * arg) {
            evhttp_request * req = NULL;
            while ((req = TAILQ_FIRST(&evcon->requests)) != NULL)
            {
                request_cb_obj * p = (request_cb_obj *) req->cb_arg;
                TAILQ_REMOVE(&evcon->requests, req, next);
                evhttp_request_free(req);
                delete p;
            }
            // delete listener
            evconnlistener_obj_cb * p = (evconnlistener_obj_cb *) evcon->cb_arg;
            delete p;
        };
        evhttp_connection_set_closecb(evcon, on_con_close, NULL);

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

    evconnlistener * listener =
        evconnlistener_new_bind(Event::event_base_global(), on_accept, new evconnlistener_obj_cb(http, on_accept_complete), flags,
                                -1, sa, sizeof(sockaddr_in));

    return listener;
};

void read_async(tcp_stream stream, std::function<void(int, evhttp_request *)> func_complete_)
{
    evhttp_connection * evcon = static_cast<evhttp_connection *>(stream);

    if (TAILQ_EMPTY(&evcon->requests)) // create new request if it is empty in list
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
        TAILQ_INSERT_HEAD(&evcon->requests, req, next);
        req->evcon    = evcon; /* the request ends up owning the connection */
        req->userdone = 1;
        req->flags |= EVHTTP_REQ_OWN_CONNECTION;
        req->kind = EVHTTP_REQUEST;
    }

    evhttp_start_read_(evcon);
}

void write_async(std::shared_ptr<request> req, std::string data, on_write_response_complete_func complete_func)
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

    evhttp_request * req_internal = req->req;
    evhttp_connection * evcon     = req_internal->evcon;

    evhttp_response_code_(req_internal, req->response_code, req->reason == "" ? NULL : req->reason.c_str());

    /* we expect no more calls form the user on this request */
    req_internal->userdone = 1;

    /* Add buffer to body*/
    evbuffer_add(req_internal->output_buffer, data.c_str(), data.size());
    /* Adds headers to the response */
    evhttp_make_header(evcon, req_internal);

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
}

// specialize start_async
void start_server(unsigned short port, on_read_request_complete_func && on_read_request_complete)
{
    class http_session : public std::enable_shared_from_this<http_session>
    {
    public:
        http_session(tcp_stream stream_, on_read_request_complete_func route_hdl_)
        {
            route_hdl = route_hdl_;
            stream    = stream_;
        }
        void start() { do_read_request(); }

        void on_write_response(int ec)
        {
            // std::cout << "[DEBUG][on_write] ENTER" << std::endl;
            do_read_request();
        }

    private:
        http_session()                                  = delete;
        http_session(const http_session &)              = delete;
        http_session(const http_session &&)             = delete;
        http_session & operator=(const http_session &)  = delete;
        http_session & operator=(const http_session &&) = delete;

        void do_read_request()
        {
            http2::read_async(
                stream, std::bind(&http_session::on_request, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
        }

        void on_request(int ec, evhttp_request * req)
        {
            std::shared_ptr<http2::request> request__{ new http2::request(shared_from_this(), req), [](http2::request * req) {
                                                          /*std::cout << "[DEBUG] request is deleted\n"; */
                                                          delete req;
                                                      } };
            if (route_hdl)
                route_hdl(0, http2::response{ request__ });
            else
                http2::response{ request__ }.send_reply(404);
        }

    private:
        tcp_stream stream;
        on_read_request_complete_func route_hdl;
        friend class request;
    };

    on_accept_complete_func on_accept = [on_request = std::move(on_read_request_complete)](http2::tcp_stream stream) {
        std::shared_ptr<http_session>
        {
            new http_session(stream, std::move(on_request)), [](http_session * p) {
                /*std::cout << "[DEBUG] http_session is deleted.\n";*/
                delete p;
            }
        } -> start();
    };

    if (nullptr != start_async(port, on_accept))
    {
        std::cout << "the server is running on 127.0.0.1:" << port << std::endl;
        Event::run_forever();
    }

    Event::run_forever();
}

} // namespace http2
