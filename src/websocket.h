#ifndef __WEBSOCKET_H__
#define __WEBSOCKET_H__

#include <sys/queue.h>
struct websock_connection_t;

struct ws_channel_cb{
	TAILQ_ENTRY(ws_channel_cb) next;

	char *channel;
	void (*cb)(struct websock_connection_t *, char *, void *);
	void *cbarg;
};


struct ws_ops_s {
	// when a data is full read.
	int (*on_read)(struct websock_connection_t *, char *data, int len, char *usr_data);

	// when a data is fully written.
	int (*on_write)(struct websock_connection_t *, char *data, int len, char *usr_data);

	// when an event is happened.
	int (*on_event)(struct websock_connection_t *, int what, char *usr_data);

	// arg
	char *usr_data;
};

/*
per each http
*/
struct websock_handle_t{
	TAILQ_HEAD(wscbq, ws_channel_cb) callbacks;

	struct ws_ops_s ops;
};

struct websock_handle_t* 
websock_handle_new(struct evhttp *http);

void 
ws_connection_send_data(struct websock_connection_t *ws_connection, void *data, int len);

int
websock_set_channel_handler(struct websock_handle_t *ws_handle, const char *channel,
    void (*cb)(struct websock_connection_t *, char *, void *), void *cbarg);

void websocket_set_cb(struct websock_handle_t* ws_handle, 
	int (*on_read)(struct websock_connection_t *, char *data, int len, char *arg),
	int (*on_write)(struct websock_connection_t *, char *data, int len, char *arg),
	int (*on_event)(struct websock_connection_t *, int what, char *arg),
	char *usr_data
	);
	
#define WS_OPCODE_CON  0x0 // Continuous frame 
#define WS_OPCODE_TEXT 0x01 // Text frame 
#define WS_OPCODE_BIN  0x02  // Binary frame
#define WS_OPCODE_CLOSE 0x08 // Connection close
#define WS_OPCODE_PING 0x09  // Ping frame 
#define WS_OPCODE_PONG 0x0A // Pong frame

#endif