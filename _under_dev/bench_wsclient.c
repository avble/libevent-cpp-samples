/*

 */

#include "util-internal.h"


#include <sys/types.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "event2/event-config.h"

#include "strlcpy-internal.h"
#include "event2/http.h"
#include "event2/event.h"
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/http_struct.h"
#include "event2/http_compat.h"
#include "event2/util.h"
#include "event2/listener.h"
#include "log-internal.h"
#include "util-internal.h"
#include "http-internal.h"
#include "mm-internal.h"
#include "bufferevent-internal.h"


const char *resource = NULL;
struct event_base *base = NULL;

int total_n_handled = 0;
int total_n_errors = 0;
int total_n_launched = 0;
size_t total_n_bytes = 0;
struct timeval total_time = {0,0};
int n_errors = 0;

const int PARALLELISM = 100;
const int N_REQUESTS = 10000;

struct request_info {
	size_t n_read;
	struct timeval started;
    int state; // 0: connecting, 1: connected, 2: end
};

static int launch_request(void);
static void readcb(struct bufferevent *b, void *arg);
static void eventcb(struct bufferevent *b, short what, void *arg);

void websock_send_data(struct bufferevent *bufev, void *data, int len)
{
	int offset = 2;
	char *ws_frame = calloc(1, 11 + len);
	ws_frame[0] = 0x80 | 0x01;
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

	bufferevent_write(bufev, ws_frame, offset + len);
	bufferevent_enable(bufev, EV_READ|EV_WRITE);
}

static void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

static void evebuff_print(struct evbuffer *buf)
{
	#define N_IO  10
    int n, i;
    struct evbuffer_iovec v[N_IO];
    n = evbuffer_peek(buf, -1, NULL, v, N_IO);
    for (i=0; i<n; ++i) { /* There might be less than two chunks available. */
        DumpHex(v[i].iov_base, v[i].iov_len);
    }
}

static void
readcb(struct bufferevent *b, void *arg)
{
	struct request_info *ri = (struct request_info *)arg;

    // printf ("[DEBUG] %s, %d \n", __FILE__, __LINE__);
    if (ri->state == 0 /*connecting*/)
    {
        // printf ("[DEBUG] %s, %d \n", __FILE__, __LINE__);

        struct evbuffer *in = bufferevent_get_input(b);
		char s_text[4]; // \r\n\r\n
		s_text[0] = 0x0D;
		s_text[1] = 0x0A;
		s_text[2] = 0x0D;
		s_text[3] = 0x0A;

        struct evbuffer_ptr  found = evbuffer_search(in, &s_text[0], 4,  NULL);

        if (found.pos == -1)
            return;
        ri->state = 1;

        // drain all data in buffer 
        evbuffer_drain(in, evbuffer_get_length(in));
        // printf ("[DEBUG] %s, %d \n", __FILE__, __LINE__);

        // send echo 
        websock_send_data(b, "echo", strlen("echo"));

    } else if (ri->state == 1)
    {
        struct evbuffer *input =  bufferevent_get_input(b);
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

        if (mask == 0)
        {
            if (evbuffer_get_length(input) < ws_header_len + payload_len) // Not enought data
                return;
        }else 
        {
            if (evbuffer_get_length(input) < ws_header_len + payload_len + 4) // Not enought data
                return;
        }

		ri->state = 2;
        evbuffer_drain(input, ws_header_len + payload_len);

		bufferevent_trigger_event(b, BEV_EVENT_EOF, 0);  // trigger event EOF at state (2) for to close
    }
}

static void
eventcb(struct bufferevent *b, short what, void *arg)
{

	struct request_info *ri = arg;
	struct timeval now, diff;
	if (what & BEV_EVENT_EOF && ri->state == 2) {
		++total_n_handled;
		total_n_bytes += ri->n_read;
		evutil_gettimeofday(&now, NULL);
		evutil_timersub(&now, &ri->started, &diff);
		evutil_timeradd(&diff, &total_time, &total_time);

		if (total_n_handled && (total_n_handled%100)==0)
			printf("%d requests done\n",total_n_handled);

		if (total_n_launched < N_REQUESTS) {
			if (launch_request() < 0)
				perror("Can't launch");
		}

	    // bufferevent_disable(b, EV_READ|EV_WRITE);
	    bufferevent_free(b);
	    free(ri);
    }
    else {
		++total_n_errors;
		printf("state: %d - event: %X \n", ri->state, what);
		perror("Unexpected event");
	}
}

static void
frob_socket(evutil_socket_t sock)
{
#ifdef EVENT__HAVE_STRUCT_LINGER
	struct linger l;
#endif
	int one = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*)&one, sizeof(one))<0)
		perror("setsockopt(SO_REUSEADDR)");
#ifdef EVENT__HAVE_STRUCT_LINGER
	l.l_onoff = 1;
	l.l_linger = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_LINGER, (void*)&l, sizeof(l))<0)
		perror("setsockopt(SO_LINGER)");
#endif
}

static int
launch_request(void)
{
	evutil_socket_t sock;
	struct sockaddr_in sin;
	struct bufferevent *b;

	struct request_info *ri;

	memset(&sin, 0, sizeof(sin));

	++total_n_launched;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	sin.sin_port = htons(8080);
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;
	if (evutil_make_socket_nonblocking(sock) < 0) {
		evutil_closesocket(sock);
		return -1;
	}
	frob_socket(sock);
	if (connect(sock, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
		int e = evutil_socket_geterror(sock);
		if (! EVUTIL_ERR_CONNECT_RETRIABLE(e)) {
			evutil_closesocket(sock);
			return -1;
		}
	}

	ri = malloc(sizeof(*ri));
	ri->n_read = 0;
    ri->state = 0;
	evutil_gettimeofday(&ri->started, NULL);

	b = bufferevent_socket_new(base, sock, BEV_OPT_CLOSE_ON_FREE);

    struct evbuffer *ouput = bufferevent_get_output(b);
	bufferevent_setcb(b, readcb, NULL, eventcb, ri);
    // evbuffer_w
    evbuffer_add_printf(ouput,
			"GET %s HTTP/1.0\r\n", resource);
    evbuffer_add_printf(ouput,
			"Upgrade: websocket\r\n");
    evbuffer_add_printf(ouput,
			"Connection: Upgrade\r\n");
    evbuffer_add_printf(ouput,
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");

	bufferevent_enable(b, EV_READ|EV_WRITE);
	return 0;
}


int
main(int argc, char **argv)
{
	int i;
	struct timeval start, end, total;
	long long usec;
	double throughput;

	resource = "/ws?channel=echo";

	setvbuf(stdout, NULL, _IONBF, 0);

	base = event_base_new();

	for (i=0; i < PARALLELISM; ++i) {
		if (launch_request() < 0)
			perror("launch");
	}

	evutil_gettimeofday(&start, NULL);

	event_base_dispatch(base);

	evutil_gettimeofday(&end, NULL);
	evutil_timersub(&end, &start, &total);
	usec = total_time.tv_sec * (long long)1000000 + total_time.tv_usec;

	if (!total_n_handled) {
		puts("Nothing worked.  You probably did something dumb.");
		return 0;
	}


	throughput = total_n_handled /
	    (total.tv_sec+ ((double)total.tv_usec)/1000000.0);

#define I64_FMT "%lld"
#define I64_TYP long long int

	printf("\n%d requests in %d.%06d sec. (%.2f throughput)\n"
	    "Each took about %.02f msec latency\n"
	    I64_FMT "bytes read. %d errors.\n",
	    total_n_handled,
	    (int)total.tv_sec, (int)total.tv_usec,
	    throughput,
	    (double)(usec/1000) / total_n_handled,
	    (I64_TYP)total_n_bytes, n_errors);

	return 0;
}
