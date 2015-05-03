/* See LICENSE file for copyright and license details. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libwebsockets.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <ev.h>
#include <arpa/inet.h>
#include <stdint.h>
#include "portable_endian.h"

#define FIL(x) \
	extern char _binary_ ## x ## _start[]; \
	extern void *_binary_ ## x ## _size; \
	static char *x = _binary_ ## x ## _start; \
	static size_t x ## N = (size_t)&_binary_ ## x ## _size;
#define FRAMESIZ 1504
#define MAGIC "BTuN"

/* STRUCTS */
struct Frame {
	char magic[5];
	uint64_t seq;
	uint16_t size;
	unsigned char buffer[FRAMESIZ];
};

struct FrameList {
	unsigned int ref;
	struct FrameList *next;
	struct Frame frame;
};

struct WsData {
	uint64_t seq;
	size_t sendoff;
	struct FrameList *send;
	size_t recvoff;
	struct Frame recv;
};

struct HttpData {
	char *type;
	int code;
	int position;
	unsigned int size;
	char *buffer;
};

/* FUNCTIONS */
static int cbhttp(struct libwebsocket_context *context,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason, void *user,
		void *in, size_t len);
static void cbtun(EV_P_ ev_io *w, int revents);
static int cbws(struct libwebsocket_context *context,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason, void *user,
		void *in, size_t len);
static void cleanframes();
static int initfiles();
static int inittun();
static int initws();
static void printd(const char *format, ...);
static void printlog(int level, const char *line);
static int recvframe(void *in, size_t len, struct WsData *data);
static int run();
static int senddata(struct libwebsocket *wsi, struct HttpData *data);
static int sendframes(struct libwebsocket *wsi, struct WsData *data);
static int sendheader(struct libwebsocket *wsi, struct HttpData *data);

/* GLOBALS */
static char *local = "/", *remote = NULL, *wsbind = NULL;
static int wsport, infd, outfd, debug = 0;
ev_io tunwatcher;
static struct ev_loop *loop;
static struct libwebsocket_context *context;
static struct ifreq ifr = { 0 };
static struct FrameList *frames = NULL, *lastFrame = NULL;
static uint64_t sendseq = 0, recvseq = 0;
static int connections = 0;
static struct libwebsocket_protocols protocols[] = {
	{
		.name = "http-only",
		.callback = cbhttp,
		.per_session_data_size = sizeof(struct HttpData),
		.rx_buffer_size = 0
	},
	{
		.name = "ws",
		.callback = cbws,
		.per_session_data_size = sizeof(struct WsData),
		.rx_buffer_size = 0
	},
	{ 0 }
};

FIL(index_html)
FIL(script_js)

/* IMPLEMENTATION */
int
cbhttp(struct libwebsocket_context *context,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason, void *user,
		void *in, size_t len) {
	struct HttpData *data = (struct HttpData *)user;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		printd("http: requested URI: %s", (char *)in);
		data->position = 0;
		data->code = 404;
		data->buffer = "404 - Not found";
		data->size = strlen(data->buffer);
		data->type = "text/plain";
		if(remote == NULL) {
			// always return 404 if remote is undefined
		} else if(strcmp(in, "/") == 0) {
			data->code = 200;
			data->buffer = index_html;
			data->size = index_htmlN;
			data->type = "text/html";
		} else if(strcmp(in, "/script.js") == 0){
			data->code = 200;
			data->buffer = script_js;
			data->size = script_jsN;
			data->type = "application/javascript";
		}

		if(sendheader(wsi, data))
			return -1;

		libwebsocket_callback_on_writable(context, wsi);

		break;
	case LWS_CALLBACK_HTTP_WRITEABLE:
		senddata(wsi, data);
		break;
	case LWS_CALLBACK_CLOSED_HTTP:
		//TODO
		break;
	case LWS_CALLBACK_ADD_POLL_FD:
	case LWS_CALLBACK_DEL_POLL_FD:
	case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
	case LWS_CALLBACK_LOCK_POLL:
	case LWS_CALLBACK_UNLOCK_POLL:
	case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
	case LWS_CALLBACK_PROTOCOL_INIT:
	case LWS_CALLBACK_WSI_CREATE:
	case LWS_CALLBACK_WSI_DESTROY:
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		break;
	default:
		printd("unhandled callback %i", reason);
		break;
	}

	return 0;
}

void
cbtun(EV_P_ ev_io *w, int revents) {
	int n;
	struct FrameList *frame;

	if(connections == 0)
		return;
	else if (revents & EV_READ) {
		frame = calloc(1, sizeof(struct FrameList));
		n = read(infd, frame->frame.buffer, FRAMESIZ);
		if(n < 0) {
			perror("read");
			exit(EXIT_FAILURE);
		}
		frame->frame.size = n;
		frame->frame.seq = ++sendseq;
		if(lastFrame) {
			lastFrame->next = frame;
			lastFrame = frame;
		}
		else {
			lastFrame = frames = frame;
		}

		// request a write slot on all clients
		libwebsocket_callback_on_writable_all_protocol(&protocols[1]);
	}
}

int
cbws(struct libwebsocket_context *context,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason, void *user,
		void *in, size_t len) {
	struct WsData *data = (struct WsData *)user;

	switch(reason) {
	case LWS_CALLBACK_ESTABLISHED:
		bzero(data, sizeof(struct WsData));
		connections++;
		printd("new connection: %d clients connected", connections);
		break;
	case LWS_CALLBACK_SERVER_WRITEABLE:
		printd("client is writable");
		sendframes(wsi, data);
		break;
	case LWS_CALLBACK_RECEIVE:
		recvframe(in, len, data);
		break;
	case LWS_CALLBACK_CLOSED:
		if(data->send) {
			data->send->ref--;
		}
		cleanframes();
		connections--;
		printd("closing connection: %d clients connected", connections);
		if(connections == 0) {
			printd("no connections left, resetting message sequence");
			sendseq = recvseq = 0;
		}
		break;
	case LWS_CALLBACK_ADD_POLL_FD:
	case LWS_CALLBACK_DEL_POLL_FD:
	case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
	case LWS_CALLBACK_LOCK_POLL:
	case LWS_CALLBACK_UNLOCK_POLL:
	case LWS_CALLBACK_PROTOCOL_INIT:
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		break;
	default:
		printd("unhandled callback %i", reason);
		break;
	}
	return 0;
}

void
cleanframes() {
	struct FrameList *frame;
	int i = 0;
	while(frames && frames->ref == 0) {
		i++;
		frame = frames;
		frames = frames->next;
		free(frame);
	}
	if(frames == NULL)
		lastFrame = NULL;
	printd("%i frames cleaned", i);
}

int
initfiles() {
	int len;
	char *p;

	len = script_jsN;

	if(remote != NULL)
		len += strlen(remote);

	if(local != NULL)
		len += strlen(local);

	if(!(p = calloc(len+1, sizeof(char)))) {
		perror("calloc");
		return -1;
	}

	script_jsN = snprintf(p, len+1, script_js, remote?remote:"", local?local:"");
	script_js = p;

	return 0;
}

int
inittun() {
	int fd, err;
	char *clonedev = "/dev/net/tun";

	if((fd = open(clonedev, O_RDWR)) < 0) {
		perror(clonedev);
		return -1;
	}

	ifr.ifr_flags = IFF_TUN;

	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
		perror(clonedev);
		close(fd);
		return -1;
	}

	infd = outfd = fd;
	return 0;
}

int
initws() {
	struct lws_context_creation_info info = { 0 };

	lws_set_log_level(debug ? 7 : 0, printlog);

	info.protocols = protocols;
	info.ssl_cert_filepath = NULL;
	info.ssl_private_key_filepath = NULL;
	info.gid = -1;
	info.uid = -1;
	info.options = LWS_SERVER_OPTION_LIBEV;
	info.port = wsport;
	info.iface = wsbind;

	context = libwebsocket_create_context(&info);

	return 0;
}

void
printd(const char *format, ...) {
	va_list ap;

	if(!debug)
		return;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	fputc('\n', stderr);
	va_end(ap);
}

void
printlog(int level, const char *line) {
	int len;
	char buf[128] = { 0 };

	// remove nl at the end.
	strncpy(buf, line, 127);
	len = strlen(buf);
	if(len > 0)
		buf[len - 1] = '\0';
	printd("libwebsockets: %s", buf);
}

int
recvframe(void *in, size_t len, struct WsData *data) {
	int sent;
	struct Frame *frame = (struct Frame*)in;

	// TODO: bound check
	if(strcmp(MAGIC, frame->magic) != 0) {
		printd("invalid magic: drop frame");
		return 0;
	}
	data->recv.seq = data->recv.seq = be64toh(frame->seq);
	data->recv.size = ntohs(frame->size);
	printd("frame received: payload: %d, received: %d", data->recv.size, len);
	len -= sizeof(struct Frame) - FRAMESIZ;

	if(data->recv.seq <= recvseq) {
		printd("old sequence number: drop frame");
		data->recvoff = 0;
		return 0;
	}

	memcpy(data->recv.buffer + data->recvoff, frame->buffer, len);
	data->recvoff += len;
	if(data->recvoff >= data->recv.size) {
		data->recvoff = 0;
		recvseq = data->recv.seq;
		sent = write(outfd, data->recv.buffer, data->recv.size);
		if(sent < 0) {
			perror("write");
			return -1;
		}
		printd("frame received: size: %d, written: %d", data->recv.size, sent);
	}
}

int
run() {
	struct ev_loop *loop = ev_default_loop(0);
	ev_io_init(&tunwatcher, cbtun, infd, EV_READ);
	ev_io_start(loop, &tunwatcher);

	libwebsocket_initloop(context, loop);
	ev_loop(loop, 0);

	return 0;
}

int
senddata(struct libwebsocket *wsi, struct HttpData *data) {
	// TODO: HTTP2 needs LWS_SEND_BUFFER_PRE_PADDING
	// TODO: get lws_get_peer_write_allowance(wsi) to determine how much bytes
	// we can send.
	return libwebsocket_write(wsi,
			data->buffer,
			data->size,
			LWS_WRITE_HTTP) < 0;
}

int
sendframes(struct libwebsocket *wsi, struct WsData *data) {
	int sent;
	unsigned buf[LWS_SEND_BUFFER_PRE_PADDING + sizeof(struct Frame) +
		LWS_SEND_BUFFER_POST_PADDING];
	struct Frame *frame = (struct Frame* )&buf[LWS_SEND_BUFFER_PRE_PADDING];

	if(data->send == NULL && frames != NULL) {
		data->send = frames;
		data->send->ref++;
	}

	while(data->send) {
		strcpy(frame->magic, MAGIC);
		frame->seq = htobe64(data->send->frame.seq);
		frame->size = htons(data->send->frame.size);
		memcpy(frame->buffer, data->send->frame.buffer + data->sendoff,
				data->send->frame.size - data->sendoff);
		sent = libwebsocket_write(wsi, (unsigned char *)frame,
				sizeof(struct Frame) - FRAMESIZ +
				data->send->frame.size - data->sendoff, LWS_WRITE_BINARY);
		if(sent < 0) {
			printd("write failed. closing connection.");
			return -1;
		} else if(sent <= sizeof(struct Frame) - FRAMESIZ) {
			printd("short write. closing connection.");
			return -1;
		}

		printd("frame sent: payload: %d, sent: %d", data->send->frame.size, sent);
		data->sendoff += sent - (sizeof(struct Frame) - FRAMESIZ);

		// libwebsocket_write could send partial data
		// If so break here and wait till websocket gets
		// writable again.
		if(data->sendoff < data->send->frame.size) {
			libwebsocket_callback_on_writable(context, wsi);
			break;
		}

		// Skip to next buffer
		data->send->ref--;
		data->send = data->send->next;
		if(data->send)
			data->send->ref++;
		data->sendoff = 0;
	}

	cleanframes();
	return 0;
}

int
sendheader(struct libwebsocket *wsi, struct HttpData *data) {
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + BUFSIZ +
		LWS_SEND_BUFFER_POST_PADDING];
	unsigned char *end = &buf[LWS_SEND_BUFFER_PRE_PADDING + BUFSIZ];
	unsigned char *p = &buf[LWS_SEND_BUFFER_PRE_PADDING];

	if(lws_add_http_header_status(context, wsi, data->code, &p, end))
		return -1;
	if (lws_add_http_header_by_token(context, wsi,
				WSI_TOKEN_HTTP_SERVER,
				(unsigned char *)"pbp",
				3, &p, end))
		return -1;
	if (lws_add_http_header_by_token(context, wsi,
				WSI_TOKEN_HTTP_CONTENT_TYPE,
				data->type,
				strlen(data->type), &p, end))
		return -1;
	if (lws_add_http_header_content_length(context, wsi,
				data->size, &p, end))
		return -1;
	if (lws_finalize_http_header(context, wsi, &p, end))
		return -1;

	return libwebsocket_write(wsi,
			buf + LWS_SEND_BUFFER_PRE_PADDING,
			p - (buf + LWS_SEND_BUFFER_PRE_PADDING),
			LWS_WRITE_HTTP_HEADERS) < 0;
}

int
main (int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "dl:s:t:v")) != -1) {
		switch(opt) {
		case 'l':
			local = optarg;
			break;
		case 's':
			remote = optarg;
			break;
		case 't':
			strncpy(ifr.ifr_name, optarg, IFNAMSIZ);
			ifr.ifr_name[IFNAMSIZ] = 0;
			break;
		case 'd':
			debug = 1;
			break;
		case 'v':
			fputs("btun-" VERSION "\n", stderr);
			return EXIT_FAILURE;
usage:
		default:
			fprintf(stderr,
					"Usage: %s [-d] [-l local] [-s remote] [-t tundev] [bind_address] port\n",
					argv[0]);
			return EXIT_FAILURE;
		}
	}
	if(argc == optind + 2)
		wsbind = argv[optind];
	else if(argc != optind + 1)
		goto usage;

	wsport = atoi(argv[argc-1]);

	if(initfiles())
		return EXIT_FAILURE;

	if(inittun())
		return EXIT_FAILURE;

	if(initws())
		return EXIT_FAILURE;

	if(run())
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
