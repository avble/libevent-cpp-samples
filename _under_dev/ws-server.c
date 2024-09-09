/*
  A trivial static websocket webserver using Libevent's evhttp.

  This is not the best code in the world, and it does some fairly stupid stuff
  that you would never want to do in a production webserver. Caveat hackor!

 */

#include "util-internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include <signal.h>

#ifdef EVENT__HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef EVENT__HAVE_AFUNIX_H
#include <afunix.h>
#endif

#include <event2/event.h>
#include <event2/http.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>


#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#endif

#include "websocket.h"


struct options {
	int port;
	int verbose;
};

static void
print_usage(FILE *out, const char *prog, int exit_code)
{
	fprintf(out,
		"Syntax: %s [ OPTS ]\n"
		" -p      - port\n"
		" -v      - verbosity, enables libevent debug logging too\n", prog);
	exit(exit_code);
}
static struct options
parse_opts(int argc, char **argv)
{
	struct options o;
	int opt;

	memset(&o, 0, sizeof(o));

	while ((opt = getopt(argc, argv, "hp:v")) != -1) {
		switch (opt) {
			case 'p': o.port = atoi(optarg); break;
			case 'v': ++o.verbose; break;
			case 'h': print_usage(stdout, argv[0], 0); break;
			default : fprintf(stderr, "Unknown option %c\n", opt); break;
		}
	}

	return o;
}

static void
do_term(int sig, short events, void *arg)
{
	struct event_base *base = arg;
	event_base_loopbreak(base);
	fprintf(stderr, "Got %i, Terminating\n", sig);
}

static int
display_listen_sock(struct evhttp_bound_socket *handle)
{
	struct sockaddr_storage ss;
	evutil_socket_t fd;
	ev_socklen_t socklen = sizeof(ss);
	char addrbuf[128];
	void *inaddr;
	const char *addr;
	int got_port = -1;

	fd = evhttp_bound_socket_get_fd(handle);
	memset(&ss, 0, sizeof(ss));
	if (getsockname(fd, (struct sockaddr *)&ss, &socklen)) {
		perror("getsockname() failed");
		return 1;
	}

	if (ss.ss_family == AF_INET) {
		got_port = ntohs(((struct sockaddr_in*)&ss)->sin_port);
		inaddr = &((struct sockaddr_in*)&ss)->sin_addr;
	} else if (ss.ss_family == AF_INET6) {
		got_port = ntohs(((struct sockaddr_in6*)&ss)->sin6_port);
		inaddr = &((struct sockaddr_in6*)&ss)->sin6_addr;
	}
#ifdef EVENT__HAVE_STRUCT_SOCKADDR_UN
	else if (ss.ss_family == AF_UNIX) {
		printf("Listening on <%s>\n", ((struct sockaddr_un*)&ss)->sun_path);
		return 0;
	}
#endif
	else {
		fprintf(stderr, "Weird address family %d\n",
		    ss.ss_family);
		return 1;
	}

	addr = evutil_inet_ntop(ss.ss_family, inaddr, addrbuf,
	    sizeof(addrbuf));
	if (addr) {
		printf("Listening on %s:%d\n", addr, got_port);
	} else {
		fprintf(stderr, "evutil_inet_ntop failed\n");
		return 1;
	}

	return 0;
}

static void 
ws_channel_echo_handler(struct websock_connection_t *ws, char *data, void * arg)
{
	ws_connection_send_data(ws, data, strlen(data));
}

static void 
ws_channel_ping_handler(struct websock_connection_t *ws, char *data, void * arg)
{
	ws_connection_send_data(ws, "pong", strlen("pong"));
}

int
main(int argc, char **argv)
{
	struct event_config *cfg = NULL;
	struct event_base *base = NULL;
	struct evhttp *http = NULL;
	struct evhttp_bound_socket *handle = NULL;
	struct event *term = NULL;
	struct options o = parse_opts(argc, argv);
	int ret = 0;

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		ret = 1;
		goto err;
	}

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	/** Read env like in regress */
	if (o.verbose || getenv("EVENT_DEBUG_LOGGING_ALL"))
		event_enable_debug_logging(EVENT_DBG_ALL);

	cfg = event_config_new();

	base = event_base_new_with_config(cfg);
	if (!base) {
		fprintf(stderr, "Couldn't create an event_base: exiting\n");
		ret = 1;
	}
	event_config_free(cfg);
	cfg = NULL;

	/* Create a new evhttp object to handle requests. */
	http = evhttp_new(base);
	if (!http) {
		fprintf(stderr, "couldn't create evhttp. Exiting.\n");
		ret = 1;
	}

	struct websock_handle_t *ws;
	ws = websock_handle_new(http);

	// Register 2 handler (echo and ping)
	websock_set_channel_handler(ws, "echo", ws_channel_echo_handler, NULL);
	websock_set_channel_handler(ws, "ping", ws_channel_ping_handler, NULL);

	/* Create a websocket object */

    handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", o.port);
    if (!handle) {
        fprintf(stderr, "couldn't bind to port %d. Exiting.\n", o.port);
        ret = 1;
        goto err;
    }

	if (display_listen_sock(handle)) {
		ret = 1;
		goto err;
	}

	term = evsignal_new(base, SIGINT, do_term, base);
	if (!term)
		goto err;
	if (event_add(term, NULL))
		goto err;

	event_base_dispatch(base);

err:
	if (cfg)
		event_config_free(cfg);
	if (http)
		evhttp_free(http);
	if (term)
		event_free(term);
	if (base)
		event_base_free(base);

	return ret;
}
