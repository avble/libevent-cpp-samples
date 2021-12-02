#include <string.h>

#include "event2/http.h"
#include "event2/event.h"
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/http_struct.h"
#include "event2/http_compat.h"
#include "event2/util.h"
#include "event2/listener.h"
#include "http-internal.h"
#include "mm-internal.h"

#include "sha1.h"
#include "websocket.h"


// prototype
/* interface with buffer event module */
static void
websock_evbuff_read_cb(struct bufferevent *bufev, void *arg);

/* interface with buffer event module */
static void
websock_evbuff_write_cb(struct bufferevent *bufev, void *arg);

/* interface with buffer event module */
static void
websock_evbuff_event_cb(struct bufferevent *bufev, short what, void *arg);

/*
per each connection
*/
struct websock_connection_t{
	struct websock_handle_t *ws_handle; // websock scope

	struct evhttp_connection *evcon;

	char *uri;
};

static struct websock_connection_t* ws_connection_new(struct websock_handle_t *ws_handle)
{
	struct websock_connection_t* ws_connection = NULL;

	if ((ws_connection = mm_calloc(1, sizeof(struct websock_connection_t))) == NULL) {
		event_warn("%s: calloc", __func__);
		return (NULL);
	}

	ws_connection->ws_handle = ws_handle;
	return (ws_connection);
}

/*
 * write a data-frame
 */
void ws_connection_send_data(struct websock_connection_t *ws_connection, void *data, int len)
{
	int offset = 2;
	char *ws_frame = calloc(1, 11 + len);
	ws_frame[0] = 0x80 | WS_OPCODE_TEXT;
	if (len <= 125)
	{
		ws_frame[1] = (char)len; // mask should be 0
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
	memcpy(&ws_frame[offset], data, len);

	bufferevent_write(ws_connection->evcon->bufev, ws_frame, offset + len);
	bufferevent_enable(ws_connection->evcon->bufev, EV_READ|EV_WRITE);
}

/*
	Called when http upgrade request is fullly read.
	interface with http
 */
void
ws_upgrade_handle(struct evhttp_request *req, void *arg)
{
	// printf("[DEBUG] %s, %d \n", __FILE__, __LINE__);
    // Sanity check if it is websocket protocols
	if (strcmp(evhttp_find_header(evhttp_request_get_input_headers(req),  "Upgrade"), "websocket") != 0)
    {
        // It is not the websocket header 
        evhttp_send_reply(req, HTTP_NOTFOUND, "Not Found", NULL);
    }

    struct evkeyvalq *headers;
    struct evkeyval *header;

    headers = evhttp_request_get_input_headers(req);

	printf("Request header \n");
    for (header = headers->tqh_first; header;
       header = header->next.tqe_next) {
         printf("  %s: %s\n", header->key, header->value);
     }

    char *key = evhttp_find_header(evhttp_request_get_input_headers(req),  "sec-websocket-key");

    char keykey[256] = {0};
    strcpy(keykey, key);

    strcat(keykey, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

    unsigned char *sha1 = NULL;
	sha1 = (unsigned char *)calloc(1, 20);

    SHA1(sha1, keykey, strlen(keykey));

	// printf("[DEBUG] %s, %d  key: %s \n", __FILE__, __LINE__, keykey);
	// printf("before \n");
	// for (int i = 0; i < 20; i++)
	// 	printf("%hhX", sha1[i]);

    size_t len;
    char *b64 = base64_encode(sha1, 20, &len);

    evhttp_add_header(evhttp_request_get_output_headers(req), "Upgrade", "websocket");
    evhttp_add_header(evhttp_request_get_output_headers(req), "Connection", "Upgrade");
    evhttp_add_header(evhttp_request_get_output_headers(req), "Sec-WebSocket-Accept", b64);

    evhttp_send_reply(req, 101, "Switching Protocols", NULL);

	struct websock_handle_t *ws_handle = (struct websock_handle_t*)arg;
	struct websock_connection_t *ws_connection = ws_connection_new(ws_handle);
	ws_connection->uri = mm_strdup(req->uri);
	ws_connection->evcon = req->evcon;

	// XXX: 
	// Detach http from current connection
	// clean up the http's connection resource
	// websocket take over the connection
    bufferevent_setcb(ws_connection->evcon->bufev,
        websock_evbuff_read_cb,
        websock_evbuff_write_cb,
		websock_evbuff_event_cb,
        ws_connection);

	free(sha1);
	free(b64);

    return;

error:
	evhttp_send_reply(req, HTTP_INTERNAL, "Internal Error", NULL);
}

struct websock_handle_t* websock_handle_new(struct evhttp *http)
{
	struct websock_handle_t* ws_handle = NULL;

	if ((ws_handle = mm_calloc(1, sizeof(struct websock_handle_t))) == NULL) {
		event_warn("%s: calloc", __func__);
		return (NULL);
	}

	TAILQ_INIT(&ws_handle->callbacks);

	memset(&ws_handle->ops, 0, sizeof(struct ws_ops_s));

	evhttp_set_cb(http, "/ws", ws_upgrade_handle, ws_handle);

	return (ws_handle);
}

void websocket_set_cb(struct websock_handle_t* ws_handle, 
	int (*on_read)(struct websock_connection_t *, char *data, int len, char *arg),
	int (*on_write)(struct websock_connection_t *, char *data, int len, char *arg),
	int (*on_event)(struct websock_connection_t *, int what, char *arg),
	char *usr_data
	)
{
	ws_handle->ops.on_read = on_read;
	ws_handle->ops.on_write = on_write;
	ws_handle->ops.on_event = on_event;
	ws_handle->ops.usr_data = usr_data;
}

/*
insert a callback
*/
int
websock_set_channel_handler(struct websock_handle_t *handle, const char *channel,
    void (*cb)(struct websock_connection_t *, char *, void *), void *cbarg)
{
	struct ws_channel_cb *ws_channel_cb;

	TAILQ_FOREACH(ws_channel_cb, &handle->callbacks, next) {
		if (strcmp(ws_channel_cb->channel, channel) == 0)
			return (-1); // exist
	}

	if ((ws_channel_cb = mm_calloc(1, sizeof(struct ws_channel_cb))) == NULL) {
		event_warn("%s: calloc", __func__);
		return (-2);
	}

	ws_channel_cb->channel = mm_strdup(channel);
	if (ws_channel_cb->channel == NULL) {
		event_warn("%s: strdup", __func__);
		mm_free(ws_channel_cb);
		return (-3);
	}

	ws_channel_cb->cb = cb;
	ws_channel_cb->cbarg = cbarg;

	TAILQ_INSERT_TAIL(&handle->callbacks, ws_channel_cb, next);

	return (0);
}

/*
+ Get the callback
*/
static struct ws_channel_cb *
websocket_channel_hdl_get(struct websock_handle_t *ws_handle, char *channel)
{
	struct ws_channel_cb *cb = NULL;

	TAILQ_FOREACH(cb, &ws_handle->callbacks, next) {
		if (!strcmp(cb->channel, channel)) {
			return (cb);
		}
	}

	return (NULL);
}

/* the format of uri
ws?channel=xyz
*/

static void ws_connection_dispatch(struct websock_connection_t *ws_connection, char *data, int len)
{
	char *par1 = NULL, *val1 = NULL;
	char *uri = strdup(ws_connection->uri);

	char *token = strtok(uri, "?");
	if (token == NULL)
	{ // discard the data
		goto done;
		return;
	}
	token = strtok(NULL, "=");

	if (token != NULL)
	{
		token = strtok(NULL, "=");
		if (token != NULL)
			val1 = token;
	}

	while (strtok(NULL, "=") != NULL);

	if (val1 != NULL)
	{
		// printf("[DEBUG] channel: %s \n", val1);
		// Searching the callback
		struct ws_channel_cb *cb = websocket_channel_hdl_get(ws_connection->ws_handle, val1);
		if (cb != NULL)
		{
			// printf("[DEBUG] %s, %d \n", __FILE__, __LINE__);
			cb->cb(ws_connection, data, cb->cbarg);
		}else {

			struct ws_ops_s *ops =  &ws_connection->ws_handle->ops;

			if (ops->on_read != NULL)
			{
				ws_connection->ws_handle->ops.on_read(ws_connection, data, len, ops->usr_data);
			}
		}
		// printf("[DEBUG] %s, %d \n", __FILE__, __LINE__);
	}

done:
	free(uri);
}

/*
Called when data is being sent after handshake.
+ interface with bufferevent's module
*/
static void
websock_evbuff_read_cb(struct bufferevent *bufev, void *arg)
{
	struct websock_connection_t* ws_connection = (struct websock_connection_t*)arg;

	struct evbuffer *input =  bufferevent_get_input(bufev);
	char ws_header[11] = {0};
	size_t len;
	int ws_header_len = 2;
	len = evbuffer_copyout(input, &ws_header[0], ws_header_len);
	if (len < ws_header_len) // Not enought data
		return;
	
	int opcode = ws_header[0] & 0x0F;
	int mask = ws_header[1] & 0x80;

	int payload_len = ws_header[1] & 0x7F;
	if (payload_len == 126)
	{
		ws_header_len += 2;
		len = evbuffer_copyout(input, &ws_header[0], ws_header_len);
		if (len < ws_header_len) // Not enought data
			return;

		payload_len = ws_header[2] << 8 | ws_header[3];
	}else if (payload_len == 127)
	{
		ws_header_len += 4;
		len = evbuffer_copyout(input, &ws_header[0], ws_header_len);
		if (len < ws_header_len) // Not enought data
			return;

		payload_len = ws_header[2] << 24 | ws_header[3] << 16 | ws_header[4] << 8 || ws_header[5];
	}

	char *ws_payload = calloc(1, payload_len + 10);
	if (mask == 0)
	{
		if (evbuffer_get_length(input) < ws_header_len + payload_len) // Not enought data
			goto done;
	}else 
	{
		if (evbuffer_get_length(input) < ws_header_len + payload_len + 4) // Not enought data
			goto done;	
	}

	len = evbuffer_remove(input, &ws_header[0], ws_header_len);
	
	if (mask){
		char mask_key[4] = {0};
		len = evbuffer_remove(input, &mask_key[0], 4);
		len = evbuffer_remove(input, ws_payload, payload_len);
		for (int i = 0; i < payload_len; i++)
		{
			ws_payload[i] = ws_payload[i] ^ mask_key[i%4];
		}
	}else
		len = evbuffer_remove(input, ws_payload, payload_len);

	printf("Received payload: \n");
	// printf("[DEBUG] %s-%d \n", __FILE__, __LINE__);
	DumpHex(ws_payload, payload_len > 32? 32: payload_len);
	printf("\n");

	// struct evws
	// printf("[DEBUG] URI: %s \n", ws->uri);
	if (opcode == WS_OPCODE_TEXT){
		ws_connection_dispatch(ws_connection, &ws_payload[0], payload_len);
	}

done:
	free(ws_payload);

}

/*
	interface with the bufferevent module

*/
static void
websock_evbuff_write_cb(struct bufferevent *bufev, void *arg)
{
	//printf("[DEBUG][WS-write] Hello \n");

}


static void
websock_evbuff_event_cb(struct bufferevent *bufev, short what, void *arg)
{
	struct websock_connection_t *ws_connection = (struct websock_connection_t *)arg;
	if (what | BEV_EVENT_EOF || what | BEV_EVENT_ERROR)
	{ 
		// occur either the read or write socket is closed.
		// OR error has occurr 
	    bufferevent_free(ws_connection->evcon->bufev);

		// manually close socket connection
		evutil_closesocket(ws_connection->evcon->fd);  
	    free(ws_connection);
	}


}
