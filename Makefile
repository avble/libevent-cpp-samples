CFLAGS =  -Ideps/libevent-2.1
LIB_DEP = deps/libevent-2.1/.libs/libevent.a

OBJS =	src/sha1.o
OBJS +=	src/ws-server.o
OBJS +=	src/websocket.o

BENCH_CLIENT_OBJS = src/sha1.o
BENCH_CLIENT_OBJS += src/websocket.o
BENCH_CLIENT_OBJS += src/bench_wsclient.o

all: $(OBJS) $(BENCH_CLIENT_OBJS)
	gcc $(OBJS) $(LIB_DEP) -o wsserver
	gcc $(BENCH_CLIENT_OBJS) $(LIB_DEP) -o wsclient

$(OBJS): %.o: %.c
	gcc -c $(CFLAGS) $< -o $@
		
clean:
	rm -rf *.o *.out src/*.o
