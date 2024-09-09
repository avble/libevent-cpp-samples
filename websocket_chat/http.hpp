#pragma once
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/event.h"
#include "event2/http.h"
#include "event2/http_struct.h"
#include "event2/listener.h"
extern "C" {
#include "http-internal.h" //TODO: check if it needs
}

#include "event.hpp"
#include "sha1.h"

#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/queue.h>

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
        auto path = evhttp_request_uri_get_path(req);

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

private:
    base * base_;
    std::string response_body;
    evhttp_request * req;
    state send_state;

public:
    int response_code;
};

void http_init(struct evhttp * p_evhttp, std::string addr, int port,
               std::function<void(int ec, evhttp_connection * evhttp_con)> && func)
{
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

namespace websocket {

enum struct Opcodes : int8_t
{
    WS_OPCODE_CON  = 0x0, // Continuous frame
    WS_OPCODE_TEXT = 0x01 // Text frame
};

bool is_websocket_req(evhttp_request * req)
{
    if (auto val = evhttp_request_header_get(req, "Upgrade"); val.value_or("") != "websocket")
        return false;

    if (auto val = evhttp_request_header_get(req, "sec-websocket-key"); not val.has_value())
        return false;

    return true;
}

std::optional<std::string> frame_read(bufferevent * bev_)
{
    std::optional<std::string> ans;
    char ws_header[11] = { 0 };
    size_t len;
    int ws_header_len       = 2;
    struct evbuffer * input = bufferevent_get_input(bev_);

    len = evbuffer_copyout(input, &ws_header[0], ws_header_len);
    if (len < ws_header_len) // Not enought data
        return std::nullopt;

    int opcode = ws_header[0] & 0x0F;
    int mask   = ws_header[1] & 0x80;

    int payload_len = ws_header[1] & 0x7F;
    if (payload_len == 126)
    {
        ws_header_len += 2;
        len = evbuffer_copyout(input, &ws_header[0], ws_header_len);
        if (len < ws_header_len) // Not enought data
            return std::nullopt;

        payload_len = ws_header[2] << 8 | ws_header[3];
    }
    else if (payload_len == 127)
    {
        ws_header_len += 4;
        len = evbuffer_copyout(input, &ws_header[0], ws_header_len);
        if (len < ws_header_len) // Not enought data
            return std::nullopt;

        payload_len = ws_header[2] << 24 | ws_header[3] << 16 | ws_header[4] << 8 || ws_header[5];
    }

    char * ws_payload = (char *) calloc(1, payload_len + 10);
    if (mask == 0)
    {
        if (evbuffer_get_length(input) < ws_header_len + payload_len) // Not enought data
            goto done;
    }
    else
    {
        if (evbuffer_get_length(input) < ws_header_len + payload_len + 4) // Not enought data
            goto done;
    }

    len = evbuffer_remove(input, &ws_header[0], ws_header_len);

    if (mask)
    {
        char mask_key[4] = { 0 };
        len              = evbuffer_remove(input, &mask_key[0], 4);
        len              = evbuffer_remove(input, ws_payload, payload_len);
        for (int i = 0; i < payload_len; i++)
        {
            ws_payload[i] = ws_payload[i] ^ mask_key[i % 4];
        }
    }
    else
        len = evbuffer_remove(input, ws_payload, payload_len);

    if (opcode == (int) Opcodes::WS_OPCODE_TEXT)
        ans = std::string(&ws_payload[0], &ws_payload[0] + payload_len);

    free(ws_payload);

done:
    return ans;
}

void frame_data_write(bufferevent * bufev, const std::string & data)
{
    int offset      = 2;
    int len         = data.size();
    char * ws_frame = (char *) calloc(1, 11 + data.size());
    ws_frame[0]     = 0x80 | static_cast<uint8_t>(Opcodes::WS_OPCODE_TEXT);
    if (len <= 125)
    {
        ws_frame[1] = (char) len; // mask should be 0
    }
    else if (len >= 126 && len <= 65536 /* 2^16 */)
    {
        offset += 2;
        ws_frame[1] = 126;
        ws_frame[2] = (len & 0xFF00) >> 8;
        ws_frame[3] = (len & 0x00FF);
    }
    else if (len > 65536)
    {
        offset += 4;
        ws_frame[1] = 127;
        ws_frame[2] = (len & 0xFF000000) >> 24;
        ws_frame[3] = (len & 0x00FF0000) >> 16;
        ws_frame[4] = (len & 0x0000FF00) >> 8;
        ws_frame[5] = (len & 0x000000FF);
    }
    std::memcpy(&ws_frame[offset], data.data(), data.size());

    bufferevent_write(bufev, ws_frame, offset + data.size());

    free(ws_frame);
}
} // namespace websocket

class ws_connection : public std::enable_shared_from_this<ws_connection>
{
public:
    typedef std::function<void(const std::string &, std::shared_ptr<ws_connection>)> ws_on_read_func;
    typedef struct wrapper_s
    {

        wrapper_s(std::shared_ptr<ws_connection> p) {}

        ~wrapper_s() {}

    } wrapper;

public:
    ws_connection(evhttp_connection * evhttp_con_, ws_on_read_func on_msg_hdl_)
    {
        pevhttp_con = evhttp_con_;
        on_msg_hdl  = on_msg_hdl_;
    }
    ~ws_connection() {}

    void start()
    {
        // per connection handler
        auto con_close_cb = [](struct evhttp_connection * http_con_, void * arg) {
            wrapper * p = (wrapper *) arg;

            delete p;
        };

        evhttp_connection_set_closecb(pevhttp_con, con_close_cb, new wrapper(shared_from_this()));

        do_read_req();
    }

    void do_read_req()
    {
        http::read_async(this->pevhttp_con,
                         std::bind(&ws_connection::on_read_req, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void on_read_req(int ec, evhttp_request * req)
    {
        std::weak_ptr<ws_connection> wp = shared_from_this();

        if (websocket::is_websocket_req(req))
        {
            topic = evhttp_request_uri_get_path(req).value_or("");
            ws_connection::peer_mgr[topic].push_back(shared_from_this());
            do_upgade(std::make_shared<http::request>(wp, req));
        }
        else
            do_write(std::make_shared<http::request>(wp, req), "Not support route");
    }

    void do_write(std::shared_ptr<http::request> req, const std::string & data)
    {
        auto cb = [self = std::bind(&ws_connection::on_write, shared_from_this())] { self(); };
        Event::call_soon(http::write_async, req, data, cb);
    }
    void on_write() {}

private:
    void do_upgade(std::shared_ptr<http::request> req)
    {
        auto sec_key    = evhttp_request_header_get(req->get_native_request(), "sec-websocket-key");
        std::string key = sec_key.value() + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        std::vector<char> sha1 = SHA1_CPP(key);

        evhttp_add_header(evhttp_request_get_output_headers(req->get_native_request()), "Upgrade", "websocket");
        evhttp_add_header(evhttp_request_get_output_headers(req->get_native_request()), "Connection", "Upgrade");
        evhttp_add_header(evhttp_request_get_output_headers(req->get_native_request()), "Sec-WebSocket-Accept",
                          base64_encode_cpp(sha1).c_str());

        req->response_code = 101; // continue
        auto cb            = [self = shared_from_this()]() { self->on_upgrade(); };
        Event::call_soon(http::write_async, req, "", cb);
        return;
    }

    void on_upgrade()
    {
        class wrapper
        {
        public:
            wrapper(std::shared_ptr<ws_connection> sp_) { sp_ws = sp_; }

            std::shared_ptr<ws_connection> sp_ws;
        };

        // per connection handler
        auto con_close_cb = [](struct evhttp_connection * http_con_, void * arg) {
            wrapper * p = (wrapper *) arg;

            delete p;
        };
        evhttp_connection_set_closecb(pevhttp_con, con_close_cb, new wrapper(shared_from_this()));
        auto on_bufev_read_cb = [](bufferevent * bev, void * ctx) {
            wrapper * p      = (wrapper *) ctx;
            auto frame_data_ = websocket::frame_read(bev);
            if (frame_data_.has_value())
                p->sp_ws->on_msg_read(0, frame_data_.value());
        };

        auto on_bufev_write_cb = [](bufferevent * bev, void * ctx) {
            wrapper * p = (wrapper *) ctx;
            // p->sp_ws->on_write_msg(0); // TODO: add support the callback function
        };

        auto on_bufev_event_cb = [](bufferevent * bev, short what, void * ctx) {
            wrapper * p = (wrapper *) ctx;
            bufferevent_setcb(p->sp_ws->pevhttp_con->bufev, NULL, NULL, NULL, NULL);
            bufferevent_disable(p->sp_ws->pevhttp_con->bufev, EV_READ | EV_WRITE);
            delete p;
        };

        bufferevent_setcb(pevhttp_con->bufev, on_bufev_read_cb, on_bufev_write_cb, on_bufev_event_cb,
                          new wrapper(shared_from_this()));

        bufferevent_enable(pevhttp_con->bufev, EV_READ | EV_WRITE);
    }

    void on_msg_read(int ec, const std::string & data)
    {
        // std::cout << "[DEBUG][ws_connection][on_read] data: " << data << std::endl;
        if (on_msg_hdl)
            on_msg_hdl(data, shared_from_this());
    }

public:
    void do_write_msg(const std::string & data)
    {
        // std::cout << "[DEBUG][ws_connection][do_write] data: " << std::endl;
        websocket::frame_data_write(pevhttp_con->bufev, data);
    }

private:
    evhttp_connection * pevhttp_con;
    ws_on_read_func on_msg_hdl;

public:
    std::string topic;
    static std::unordered_map<std::string, std::vector<std::weak_ptr<ws_connection>>> peer_mgr;
};

std::unordered_map<std::string, std::vector<std::weak_ptr<ws_connection>>> ws_connection::peer_mgr;

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
        base     = base_;
        p_evhttp = evhttp_new(base_);
    }

    ~http_app()
    {
        // TODO: free p_evhttp
    }

    void start()
    {
        http::http_init(p_evhttp, addr, port,
                        std::bind(&http_app::on_accept, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void add_ws_handler(ws_connection::ws_on_read_func ws_on_read_) { ws_on_read = ws_on_read_; };

private:
    void on_accept(int ec, evhttp_connection * evhttp_con)
    {
        auto p = std::shared_ptr<ws_connection>(new ws_connection(evhttp_con,
                                                                  std::bind(&http_app::on_msg_read, http_app::shared_from_this(),
                                                                            std::placeholders::_1, std::placeholders::_2)),
                                                [](const auto p) {
                                                    std::cout << "[DEBUG] ws_connection is deleted. " << std::endl;
                                                    delete p;
                                                });
        p->start();
    }

    void on_msg_read(std::string msg, std::shared_ptr<ws_connection> sp)
    {
        std::cout << "[DEBUG][http_app] ENTER" << std::endl;
        if (ws_on_read)
            ws_on_read(msg, sp);
    }

private:
    evhttp * p_evhttp;
    std::string addr;
    int port;
    event_base * base;
    ws_connection::ws_on_read_func ws_on_read;
};

// helper function
std::shared_ptr<http_app> make_ws(event_base * base, const std::string & addr, uint16_t port)
{
    std::shared_ptr<http_app> p(new http_app(base, addr, port), [](auto p) {
        // std::cout << "[DEBUG][http_app] is deleted. \n";
        delete p;
    });
    return p;
}
