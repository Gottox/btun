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
#include <alloca.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "portable_endian.h"

#define FIL(x) \
	extern char _binary_ ## x ## _start[]; \
	extern void *_binary_ ## x ## _size; \
	static char *x = _binary_ ## x ## _start; \
	static size_t x ## N = (size_t)&_binary_ ## x ## _size;
#define FRAMESIZ 1500
#define MAGIC "BTuN"
#define CRYPTO_ROUNDS 5

/* STRUCTS */
struct Frame {
	char magic[sizeof(MAGIC)];
	uint64_t seq;
	uint16_t size;
	char buffer[FRAMESIZ];
};

struct FrameList {
	unsigned int ref;
	struct FrameList *next;
	struct Frame frame;
};

struct WsData {
	size_t sendoff;
	struct FrameList *send;
	size_t recvoff;
	struct Frame recv;
	EVP_CIPHER_CTX enctx, dectx;
};

struct HttpData {
	char *type;
	int code;
	int position;
	size_t size;
	char *buffer;
};

/* FUNCTIONS */
static void cbtun(EV_P_ ev_io *w, int revents);
static void cleanframes();
static int encrypt(struct WsData *data, struct Frame *frame, unsigned char *output, int len);
static int decrypt(struct WsData *data, struct Frame *frame, unsigned char *input, int len);
static int http(struct lws *wsi,
		enum lws_callback_reasons reason, void *user,
		void *in, size_t len);
static int initcrypto();
static int initfiles();
static int inittun();
static int initwebsocket();
static void printd(const char *format, ...);
static void printlog(int level, const char *line);
static int recvframe(void *in, size_t len, struct WsData *data);
static int run();
static int senddata(struct lws *wsi, struct HttpData *data);
static int sendframes(struct lws *wsi, struct WsData *data);
static int sendheader(struct lws *wsi, struct HttpData *data);
static int websocket(struct lws *wsi,
		enum lws_callback_reasons reason, void *user,
		void *in, size_t len);

/* GLOBALS */
static char *local = "/", *remote = NULL, *wsbind = NULL;
static int wsport = 8000, infd, outfd, debug = 0;
static ev_io tunwatcher;
static char *keyfile;
static struct lws_context *context;
static struct ifreq ifr = {{{0}}};
static struct FrameList *frames = NULL, *lastFrame = NULL;
static uint64_t sendseq = 0, recvseq = 0;
static int connections = 0;
static unsigned char *keydata = NULL;
static int keylen = 0;
static const EVP_MD *digest;
static const EVP_CIPHER *cipher;
static struct lws_protocols protocols[] = {
	{
		.name = "http-only",
		.callback = http,
		.per_session_data_size = sizeof(struct HttpData),
		.rx_buffer_size = 0
	},
	{
		.name = "ws",
		.callback = websocket,
		.per_session_data_size = sizeof(struct WsData),
		.rx_buffer_size = 0
	},
	{ 0 }
};

FIL(index_html)
FIL(script_js)

/* IMPLEMENTATION */
void
cbtun(EV_P_ ev_io *w, int revents) {
	int n;
	struct FrameList *frame;

	if (connections == 0)
		return;
	else if (revents & EV_READ) {
		frame = calloc(1, sizeof(struct FrameList));
		n = read(infd, frame->frame.buffer, FRAMESIZ);
		if (n < 0) {
			perror("read");
			exit(EXIT_FAILURE);
		}
		frame->frame.size = n;
		frame->frame.seq = ++sendseq;
		if (lastFrame) {
			lastFrame->next = frame;
			lastFrame = frame;
		}
		else {
			lastFrame = frames = frame;
		}

		// request a write slot on all clients
		lws_callback_on_writable_all_protocol(context, &protocols[1]);
	}
}

void
cleanframes() {
	struct FrameList *frame;
	unsigned int i;

	for (i = 0; frames && frames->ref == 0; i++) {
		frame = frames;
		frames = frames->next;
		free(frame);
	}
	if (frames == NULL)
		lastFrame = NULL;
	printd("frames: %i cleaned", i);
}

int
decrypt(struct WsData *data, struct Frame *frame, unsigned char *input, int len) {
	int plen, flen;
	long err;
	unsigned char *plain = alloca(len);

	if(!EVP_DecryptInit_ex(&data->dectx, NULL, NULL, NULL, NULL) ||
			!EVP_DecryptUpdate(&data->dectx, plain, &plen, input, len) ||
			!EVP_DecryptFinal_ex(&data->dectx, plain+plen, &flen)){
		err = ERR_get_error();
		printd("decrypt: %s failed: %s", ERR_GET_FUNC(err), ERR_GET_REASON(err));
		return -1;
	}

	len = plen + flen;

	if(len > sizeof(struct Frame)) {
		printd("decrypt: Frame is overflowing. Dropping frame.");
		return -1;
	}

	memcpy(frame, plain, len);

	return len;
}

int
encrypt(struct WsData *data, struct Frame *frame, unsigned char *output, int len) {
	int clen = len + EVP_CIPHER_CTX_block_size(&data->enctx) - 1, flen = 0;
	long err;

	if(!EVP_DecryptInit_ex(&data->enctx, NULL, NULL, NULL, NULL) ||
			!EVP_EncryptUpdate(&data->enctx, output, &clen, (unsigned char *)frame, len) ||
			!EVP_EncryptFinal_ex(&data->enctx, output+clen, &flen)){
		err = ERR_get_error();
		printd("encrypt: %s failed: %s", ERR_GET_FUNC(err), ERR_GET_REASON(err));
		return -1;
	}

	return clen + flen;
}

int
http(struct lws *wsi,
		enum lws_callback_reasons reason, void *user,
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
		if (remote == NULL) {
			// always return 404 if remote is undefined
		} else if (strcmp(in, "/") == 0) {
			data->code = 200;
			data->buffer = index_html;
			data->size = index_htmlN;
			data->type = "text/html";
		} else if (strcmp(in, "/script.js") == 0){
			data->code = 200;
			data->buffer = script_js;
			data->size = script_jsN;
			data->type = "application/javascript";
		}

		if (sendheader(wsi, data))
			return -1;

		lws_callback_on_writable(wsi);

		break;
	case LWS_CALLBACK_HTTP_WRITEABLE:
		senddata(wsi, data);
		break;
	case LWS_CALLBACK_CLOSED_HTTP:
		//TODO
		break;
	case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
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
		printd("http: unhandled callback %i", reason);
		break;
	}

	return 0;
}

int
initcrypto() {
	FILE *f;
	int rv = 0;

	/* init crypto */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	cipher = EVP_aes_256_cbc();
	digest = EVP_sha1();

	/* load key */
	if((f = fopen(keyfile, "r")) == NULL) {
		perror(keyfile);
		return -1;
	}
	do {
		keylen += rv;
		keydata = realloc(keydata, keylen+128);
	} while((rv = fread(keydata, sizeof(char), 128, f)) <= 0);
	if(rv < 0 || fclose(f) < 0) {
		perror(keyfile);
		return -1;
	}

	return 0;
}

int
initfiles() {
	int len;
	char *p;

	len = script_jsN;

	if (remote != NULL)
		len += strlen(remote);

	if (local != NULL)
		len += strlen(local);

	if (!(p = calloc(len+1, sizeof(char)))) {
		perror("calloc");
		return -1;
	}

	script_jsN = snprintf(p, len, script_js, remote?remote:"", local?local:"");
	if(script_jsN > 0)
		script_js--;
	script_js = p;

	return 0;
}

int
inittun() {
	int fd, err;
	const char *clonedev = "/dev/net/tun";

	if ((fd = open(clonedev, O_RDWR)) < 0) {
		perror(clonedev);
		return -1;
	}

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		perror(clonedev);
		close(fd);
		return -1;
	}

	infd = outfd = fd;
	return 0;
}

int
initwebsocket() {
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

	context = lws_create_context(&info);
	return 0;
}

void
printd(const char *format, ...) {
	va_list ap;

	if (!debug)
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
	if (len > 0)
		buf[len - 1] = '\0';
	printd("libwebsockets: %s", buf);
}

int
recvframe(void *in, size_t len, struct WsData *data) {
	int sent;
	struct Frame *frame = (struct Frame*)in;

	if (sizeof(struct Frame) - FRAMESIZ < len &&
			strcmp(MAGIC, frame->magic) != 0) {
		printd("recvframe: Invalid header. Drop frame.");
		data->recvoff = 0;
		return 0;
	}
	data->recv.seq = be64toh(frame->seq);
	data->recv.size = ntohs(frame->size);
	printd("recvframe: Payload: %d, received: %d", data->recv.size, len);
	len -= sizeof(struct Frame) - FRAMESIZ;

	if(data->recvoff + len > FRAMESIZ) {
		printd("recvframe: message overflows. Drop frame.");
		data->recvoff = 0;
		return 0;
	}
	else if (data->recv.seq <= recvseq) {
		printd("recvframe: Old sequence number. Drop frame.");
		data->recvoff = 0;
		return 0;
	}
	memcpy(data->recv.buffer + data->recvoff, frame->buffer, len);
	data->recvoff += len;
	if (data->recvoff >= data->recv.size) {
		data->recvoff = 0;
		recvseq = data->recv.seq;
		sent = write(outfd, data->recv.buffer, data->recv.size);
		if (sent < 0) {
			perror("recvframe: write");
			return -1;
		}
		printd("recvframe: Size: %d, written: %d", data->recv.size, sent);
	}

	return 0;
}

int
run() {
	struct ev_loop *loop = ev_default_loop(0);

	ev_io_init(&tunwatcher, cbtun, infd, EV_READ);
	ev_io_start(loop, &tunwatcher);
	lws_initloop(context, loop);
	ev_loop(loop, 0);

	return 0;
}

int
senddata(struct lws *wsi, struct HttpData *data) {
	// TODO: HTTP2 needs LWS_SEND_BUFFER_PRE_PADDING
	// TODO: get lws_get_peer_write_allowance(wsi) to determine how much bytes
	// we can send.
	return lws_write(wsi,
			(unsigned char*)data->buffer,
			data->size,
			LWS_WRITE_HTTP) < 0;
}

int
sendframes(struct lws *wsi, struct WsData *data) {
	int sent;
	unsigned buf[LWS_SEND_BUFFER_PRE_PADDING + sizeof(struct Frame) +
		LWS_SEND_BUFFER_POST_PADDING];
	struct Frame *frame = (struct Frame* )&buf[LWS_SEND_BUFFER_PRE_PADDING];


	if (data->send == NULL && frames != NULL) {
		data->send = frames;
		data->send->ref++;
	}

	while (data->send) {
		strcpy(frame->magic, MAGIC);
		frame->seq = htobe64(data->send->frame.seq);
		frame->size = htons(data->send->frame.size);
		memcpy(frame->buffer, data->send->frame.buffer + data->sendoff,
				data->send->frame.size - data->sendoff);
		sent = lws_write(wsi, (unsigned char *)frame,
				sizeof(struct Frame) - FRAMESIZ +
				data->send->frame.size - data->sendoff, LWS_WRITE_BINARY);
		if (sent < 0) {
			printd("sendframes: Write failed. Closing connection.");
			return -1;
		} else if (sent <= sizeof(struct Frame) - FRAMESIZ) {
			printd("sendframes: Short write. Closing connection.");
			return -1;
		}

		printd("sendframes: Payload: %d, sent: %d", data->send->frame.size, sent);
		data->sendoff += sent - (sizeof(struct Frame) - FRAMESIZ);

		// lws_write could send partial data
		// If so break here and wait till websocket gets
		// writable again.
		if (data->sendoff < data->send->frame.size) {
			lws_callback_on_writable(wsi);
			break;
		}

		// Skip to next buffer
		data->send->ref--;
		data->send = data->send->next;
		if (data->send)
			data->send->ref++;
		data->sendoff = 0;
	}

	cleanframes();
	return 0;
}

int
sendheader(struct lws *wsi, struct HttpData *data) {
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + BUFSIZ +
		LWS_SEND_BUFFER_POST_PADDING];
	unsigned char *end = &buf[LWS_SEND_BUFFER_PRE_PADDING + BUFSIZ];
	unsigned char *p = &buf[LWS_SEND_BUFFER_PRE_PADDING];

	if (lws_add_http_header_status(wsi, data->code, &p, end))
		return -1;
	if (lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_SERVER,
				(unsigned char *)"btun",
				3, &p, end))
		return -1;
	if (lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_CONTENT_TYPE,
				(unsigned char*)data->type,
				strlen(data->type), &p, end))
		return -1;
	if (lws_add_http_header_content_length(wsi,
				data->size, &p, end))
		return -1;
	if (lws_finalize_http_header(wsi, &p, end))
		return -1;

	return lws_write(wsi,
			buf + LWS_SEND_BUFFER_PRE_PADDING,
			p - (buf + LWS_SEND_BUFFER_PRE_PADDING),
			LWS_WRITE_HTTP_HEADERS) < 0;
}

int
websocket(struct lws *wsi,
		enum lws_callback_reasons reason, void *user,
		void *in, size_t len) {
	struct WsData *data = (struct WsData *)user;
	unsigned char salt[PKCS5_SALT_LEN] = "ufGKfj0C";
	unsigned char key[EVP_MAX_KEY_LENGTH] = {0};
	unsigned char iv[EVP_MAX_IV_LENGTH] = {0};

	switch(reason) {
	case LWS_CALLBACK_ESTABLISHED:
		bzero(data, sizeof(struct WsData));

		// TODO: instead of a static salt, use what the browser gives us.
		EVP_BytesToKey(cipher, digest, salt, keydata, keylen, CRYPTO_ROUNDS, key, iv);
		EVP_CIPHER_CTX_init(&data->enctx);
		EVP_EncryptInit_ex(&data->enctx, EVP_aes_256_cbc(), NULL, key, iv);
		EVP_CIPHER_CTX_init(&data->dectx);
		EVP_DecryptInit_ex(&data->dectx, EVP_aes_256_cbc(), NULL, key, iv);
		connections++;
		printd("websocket: New connection: %d clients connected", connections);
		break;
	case LWS_CALLBACK_SERVER_WRITEABLE:
		printd("websocket: Client is writable");
		sendframes(wsi, data);
		break;
	case LWS_CALLBACK_RECEIVE:
		recvframe(in, len, data);
		break;
	case LWS_CALLBACK_CLOSED:
		if (data->send) {
			data->send->ref--;
		}
		cleanframes();
		EVP_CIPHER_CTX_cleanup(&data->dectx);
		EVP_CIPHER_CTX_cleanup(&data->enctx);
		connections--;
		printd("websocket: Closing connection: %d clients connected", connections);
		if (connections == 0) {
			printd("websocket: No connections left. Resetting message numbers.");
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
		printd("websocket: unhandled callback %i", reason);
		break;
	}
	return 0;
}

int
main (int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "b:dl:p:s:t:v")) != -1) {
		switch(opt) {
		case 'l':
			local = optarg;
			break;
		case 's':
			remote = optarg;
			break;
		case 't':
			strncpy(ifr.ifr_name, optarg, IFNAMSIZ);
			ifr.ifr_name[IFNAMSIZ - 1] = 0;
			break;
		case 'd':
			debug = 1;
			break;
		case 'v':
			fputs("btun-" VERSION "\n", stderr);
			return EXIT_FAILURE;
		case 'b':
			wsbind = optarg;
			break;
		case 'p':
			wsport = atoi(optarg);
			break;
usage:
		default:
			fprintf(stderr,
					"Usage: %s [-d] [-l local] [-s remote] [-t tundev] [-p port] [-b bind_address] keyfile\n",
					argv[0]);
			return EXIT_FAILURE;
		}
	}
	if (argc != optind + 1)
		goto usage;

	keyfile = argv[optind];

	if (initcrypto())
		return EXIT_FAILURE;

	if (initfiles())
		return EXIT_FAILURE;

	if (inittun())
		return EXIT_FAILURE;

	if (initwebsocket())
		return EXIT_FAILURE;

	if (run())
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
