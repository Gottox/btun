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

#define FIL(x) \
	extern char _binary_ ## x ## _start[]; \
	extern void *_binary_ ## x ## _size; \
	char *x = _binary_ ## x ## _start; \
	size_t x ## N = (size_t)&_binary_ ## x ## _size;
#define FRAMESIZ 1500

/* STRUCTS */
struct HttpData {
	char *type;
	int position;
	unsigned int size;
	char *buffer;
};

struct Frame {
	unsigned long seq;
	struct Frame *next;
	unsigned int ref;
	size_t size;
	unsigned char buffer[FRAMESIZ];
};

struct WsData {
	struct Frame *frame;
	size_t offset;
};

/* FUNCTIONS */
static int tunalloc();
static int wsinit();
static int run();
static int sendheader(struct libwebsocket *wsi, struct HttpData *data);
static int senddata(struct libwebsocket *wsi, struct HttpData *data);
static callback_http(struct libwebsocket_context *context,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason, void *user,
		void *in, size_t len);
static callback_ws(struct libwebsocket_context *context,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason, void *user,
		void *in, size_t len);
static void cleanframes();
static void callback_tun(EV_P_ ev_io *w, int revents);
static int setupFiles();

/* GLOBALS */
static char *local = "/", *remote = NULL, *wsbind = NULL;
static int wsport, tunfd;
ev_io tunwatcher;
struct ev_loop *loop;
static struct libwebsocket_context *context;
static struct ifreq ifr = { 0 };
static struct Frame *frames = NULL, *lastFrame = NULL;
unsigned long sendseq = 0, recseq = 0;

static struct libwebsocket_protocols protocols[] = {
	{
		.name = "http-only",
		.callback = callback_http,
		.per_session_data_size = sizeof(struct HttpData),
		.rx_buffer_size = 0
	},
	{
		.name = "ws",
		.callback = callback_ws,
		.per_session_data_size = sizeof(struct WsData),
		.rx_buffer_size = 0
	},
	{ 0 }
};

FIL(index_html)
FIL(script_js)

/* IMPLEMENTATION */

int
tunalloc() {
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

	tunfd = fd;
	return 0;
}

int
wsinit() {
	struct lws_context_creation_info info = { 0 };

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

int
run() {
	struct ev_loop *loop = ev_default_loop(0);
	ev_io_init(&tunwatcher, callback_tun, tunfd, EV_READ);
	ev_io_start(loop, &tunwatcher);

	libwebsocket_initloop(context, loop);
	ev_loop(loop, 0);

	return 0;
}

int
sendheader(struct libwebsocket *wsi, struct HttpData *data) {
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + BUFSIZ + LWS_SEND_BUFFER_POST_PADDING];
	unsigned char *end = &buf[LWS_SEND_BUFFER_PRE_PADDING + BUFSIZ];
	unsigned char *p = &buf[LWS_SEND_BUFFER_PRE_PADDING];

	if(lws_add_http_header_status(context, wsi, 200, &p, end))
		return 1;
	if (lws_add_http_header_by_token(context, wsi,
				WSI_TOKEN_HTTP_SERVER,
				(unsigned char *)"pbp",
				3, &p, end))
		return 1;
	if (lws_add_http_header_by_token(context, wsi,
				WSI_TOKEN_HTTP_CONTENT_TYPE,
				data->type,
				strlen(data->type), &p, end))
		return 1;
	if (lws_add_http_header_content_length(context, wsi,
				data->size, &p, end))
		return 1;
	if (lws_finalize_http_header(context, wsi, &p, end))
		return 1;

	return libwebsocket_write(wsi,
			buf + LWS_SEND_BUFFER_PRE_PADDING,
			p - (buf + LWS_SEND_BUFFER_PRE_PADDING),
			LWS_WRITE_HTTP_HEADERS) < 0;
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

void
cleanframes() {
	struct Frame *frame;
	int i = 0;
	while(frames && frames->ref == 0) {
		i++;
		frame = frames;
		frames = frames->next;
		free(frame);
	}
	if(frames == NULL)
		lastFrame = NULL;
	printf("%i frames cleaned", i);
}

int
callback_ws(struct libwebsocket_context *context,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason, void *user,
		void *in, size_t len) {
	struct WsData *data = (struct WsData *)user;
	int sent = 0;
	unsigned long seq;
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + sizeof(long) + FRAMESIZ + LWS_SEND_BUFFER_POST_PADDING];

	switch(reason) {
	case LWS_CALLBACK_ESTABLISHED:
		bzero(data, sizeof(struct WsData));
		break;
	case LWS_CALLBACK_SERVER_WRITEABLE:
		if(data->frame == NULL && frames != NULL) {
			data->frame = frames;
			data->frame->ref++;
		}

		while(data->frame) {
			memcpy(buf + LWS_SEND_BUFFER_PRE_PADDING,
					&data->frame->seq, sizeof(long));
			memcpy(buf + LWS_SEND_BUFFER_PRE_PADDING + sizeof(long),
					data->frame->buffer + data->offset,
					data->frame->size - data->offset);
			sent = libwebsocket_write(wsi, buf,
					data->frame->size - data->offset, LWS_WRITE_BINARY);
			if(sent < 0)
				return -1;
			data->offset += sent;
			// Buffer could be sent completely
			// break here and wait till websocket gets
			// writable again.
			if(data->offset < data->frame->size)
				break;

			// Skip to next buffer
			data->frame->ref--;
			data->frame = data->frame->next;
			if(data->frame)
				data->frame->ref++;
			data->offset = 0;
		}

		cleanframes();
	}
	return 0;
}

int
callback_http(struct libwebsocket_context *context,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason, void *user,
		void *in, size_t len) {
	struct HttpData *data = (struct HttpData *)user;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_WRITEABLE:
		printf("connection established\n");
		break;

	case LWS_CALLBACK_HTTP:
		printf("requested URI: %s\n", (char *)in);
		break;

		data->position = 0;
		if(strcmp(in, "/") == 0) {
			data->buffer = index_html;
			data->size = index_htmlN;
			data->type = "text/html";
		}
		else {
			data->buffer = script_js;
			data->size = script_jsN;
			data->type = "application/javascript";
		}

		if(sendheader(wsi, data))
			return 1;

		libwebsocket_callback_on_writable(context, wsi);

		break;
	case LWS_CALLBACK_HTTP_WRITEABLE:
		senddata(wsi, data);
		break;
	default:
		printf("unhandled callback %i\n", reason);
		break;
	}

	return 0;
}

void
callback_tun(EV_P_ ev_io *w, int revents) {
	int n;
	struct Frame *frame;

	if (revents & EV_READ) {
		frame = calloc(1, sizeof(struct Frame));
		n = read(tunfd, frame->buffer, FRAMESIZ);
		if(n < 0) {
			perror("read");
			return;
		}
		frame->size = n;
		frame->seq = htonl(++sendseq);
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
setupFiles() {
	int len;
	char *p;

	len = script_jsN;

	if(remote != NULL)
		len += strlen(remote);

	if(local != NULL)
		len += strlen(local);

	if(!(p = malloc((len+1) * sizeof(char)))) {
		perror("malloc");
		return -1;
	}

	snprintf(p, len+1, script_js, remote?remote:"", local?local:"");
	script_js = p;
	script_jsN = strlen(p);

	return 0;
}

int
main (int argc, char *argv[])
{
	char opt;

	while ((opt = getopt(argc, argv, "l:s:t:")) != -1) {
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
usage:
		default:
			fprintf(stderr,
					"Usage: %s [-l local] [-s remote] [-t tundev] [bind_address] port\n",
					argv[0]);
			return EXIT_FAILURE;
		}
	}
	if(argc == optind + 2)
		wsbind = argv[optind];
	else if(argc != optind + 1)
		goto usage;

	wsport = atoi(argv[argc-1]);

	if(setupFiles())
		return EXIT_FAILURE;

	if(tunalloc())
		return EXIT_FAILURE;

	if(wsinit())
		return EXIT_FAILURE;

	if(run())
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
