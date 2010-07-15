/* system includes */
#include <stdio.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

/* lib includes */
#include <librtmp/rtmp.h>
#include <librtmp/log.h>
#include <libavformat/avformat.h>
#include <ev.h>

/* local includes */
#include "librtmp.h"

#define BACKLOG           20

#define HOSTNAME "moneypenny"

typedef struct client_ctx {
    int fd;
    int id;
    int reads;
    ev_io write_watcher;
    ev_io read_watcher;
    RTMP rtmp;
    RTMPPacket packet;
    struct client_ctx *next;
}client_ctx;

typedef struct srv_ctx {
    int fd;
    int connections;
    int total_cxns;
    struct ev_loop *loop;
    ev_io io;             /* socket listener event */
    client_ctx *clients;
}srv_ctx;

static int resolve_host(struct sockaddr_in *addr, const char *hostname)
{
    /* hostname lookup might not be needed */
    if (!inet_aton(hostname, &addr->sin_addr))
    {
        struct addrinfo hints, *res, *cur;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(hostname, addr->sin_zero, NULL, &res)) {
            return -1;
        }

        /* only do ipv4 for now */
        for (cur = res; cur; cur = cur->ai_next) {
            if (cur->ai_family == AF_INET) {
                addr->sin_addr = ((struct sockaddr_in *)cur->ai_addr)->sin_addr;
                break;
            }
        }
        freeaddrinfo(res);
    }
    return 0;
}

static int setup_socket(const char *hostname, int port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0), tmp = 1;
    struct sockaddr_in addr = {0};
    const char *errstr;

    if (sockfd < 0) {
        sockfd = 0;
        errstr = "Failed to create socket";
        goto fail;
    }

    addr.sin_port = htons(RTMP_PORT);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));

    /* forgive those of us who have sinned */
    memcpy(addr.sin_zero, RTMP_PORT_STRING, sizeof(RTMP_PORT_STRING));
    if (resolve_host(&addr, HOSTNAME)) {
        errstr = "Failed to resolve host";
        goto fail;
    }

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr))) {
        errstr = "Socket binding failed";
        goto fail;
    }

    if (listen(sockfd, BACKLOG)) {
        errstr = "Failed to listen to port";
        goto fail;
    }

    fprintf(stdout, "Starting server at %s:%d\n", HOSTNAME, RTMP_PORT);
    return sockfd;

fail:
    fprintf(stderr, "%s: %s\n", errstr, strerror(errno));
    if(sockfd) close(sockfd);
    return -errno;
}

static void free_client(srv_ctx *ctx, client_ctx *client)
{
    client_ctx *c = ctx->clients, *p = NULL;
    while (c != client) { //TODO get rid of the list
        p = c;
        c = c->next;
    }
    if (!p)
        ctx->clients = c->next;
    else
        p->next = c->next;

    ev_io_stop(ctx->loop, &c->read_watcher);
    ev_io_stop(ctx->loop, &c->write_watcher);

    /* close()ing this socket, although seemingly
     * the Right Thing, could break a lot of things!
     * apparently when a cxn closes while another is
     * pending, Linux will silently reuse the old
     * FD for the new cxn... */
    //close(c->fd);
    fprintf(stdout, "(%d) Disconnecting\n", c->id);
    if (c->rtmp.Link.hostname.av_len)
        free(c->rtmp.Link.hostname.av_val);
    RTMP_Close(&c->rtmp);
    free(c);
    ctx->connections--;
}

static void free_all(srv_ctx *ctx)
{
    client_ctx *c = ctx->clients;

    //TODO refactor into free_client. better yet, get rid of the list.
    while (c) {
        client_ctx *d = c;
        c = c->next;
        close(d->fd);
        if(d->rtmp.Link.hostname.av_len)
            free(d->rtmp.Link.hostname.av_val); // XXX fix this
        RTMP_Close(&d->rtmp);
        ev_io_stop(ctx->loop, &d->read_watcher);
        ev_io_stop(ctx->loop, &d->write_watcher);
        free(d);
    }
    ctx->clients = NULL;

    close(ctx->fd);
    ev_io_stop(ctx->loop, &ctx->io);
    ev_unloop(ctx->loop, EVUNLOOP_ALL);
    free(ctx);
    ctx = NULL;
    fprintf(stdout, "Shutting down\n");
}

static void close_cb(struct ev_loop *loop, ev_signal *signal, int revents)
{
    free_all((srv_ctx*)signal->data);
}

static inline client_ctx* get_client_from_reader(ev_io *w)
{
    return (client_ctx*)((char *)w - offsetof(client_ctx, read_watcher));
}

static void client_read_cb(struct ev_loop *loop, ev_io *io, int revents)
{
    srv_ctx *ctx = io->data;
    client_ctx *client = get_client_from_reader(io);
    RTMP *rtmp = &client->rtmp;
    RTMPPacket *pkt = &client->packet;
    //fprintf(stdout, "id %d, read %d (%d %x)... ",
      //      client->id, client->reads++,
      //`      client->fd, (unsigned)&client->read_watcher);
    //fflush(stdout);

    if (RTMP_IsConnected(rtmp)) {
        if (RTMP_ReadPacket(rtmp, pkt) &&
            RTMPPacket_IsReady(pkt)) {
                switch (pkt->m_packetType) {
                case 0x03: /* bytes read */
                    // do we realy need to do anything?
                    //AMF_DecodeInt32(pkt->m_body);
                    break;
                case 0x14: /* invoke */
                    rtmp_invoke(rtmp, pkt);
                    break;
                }
                RTMPPacket_Free(pkt);
                RTMPPacket_Reset(pkt);
        }
        if (!RTMP_IsConnected(rtmp)) {
            free_client(ctx, client);
        }
    } else { /* disconnected. TODO tie this in to events or smth */
        free_client(ctx, client);
    }

    //fprintf(stdout, "exiting\n");
}

static void client_write_cb(struct ev_loop *loop, ev_io *io, int revents)
{
    fprintf(stdout, "writing.\n");
}

static void incoming_cb(struct ev_loop *loop, ev_io *io, int revents)
{
    int clientfd, len = 0;
    srv_ctx *ctx = io->data;
    client_ctx *client;
    struct sockaddr_in addr = {0};
    const char *errstr;

    /* accept cxn, alloc space and setup client context */
    if ((clientfd = accept(ctx->fd,
                           (struct sockaddr *)&addr, &len)) < 0) {
        clientfd = 0;
        errstr = strerror(errno);
        goto fail;
    }

    if (!(client = malloc(sizeof(client_ctx)))) {
        errstr = "Failed to allocate memory for client cxn.";
        goto fail;
    }
    client->next = ctx->clients;
    ctx->clients = client;
    ctx->connections++;
    RTMP_Init(&client->rtmp);
    memset(&client->packet, 0, sizeof(RTMPPacket));
    client->rtmp.m_sb.sb_socket = clientfd;
    client->rtmp.Link.timeout = 5; // i reckon this is useless
    client->rtmp.Link.hostname.av_len = 0;
    client->fd = clientfd;
    client->id = ctx->total_cxns++;
    client->reads = 0;

    if (!RTMP_Serve(&client->rtmp)) {
        errstr = "RTMP handshake failed";
        goto fail;
    }
    //fcntl(clientfd, F_SETFL, O_NONBLOCK); // doesnt work well with librtmp

    /* setup the rest of the events */
    client->read_watcher.data = ctx;
    ev_io_init(&client->read_watcher, client_read_cb, client->fd, EV_WRITE);
    ev_io_start(ctx->loop, &client->read_watcher);

    client->write_watcher.data = client;
    ev_io_init(&client->write_watcher, client_write_cb, client->fd, EV_READ);

    // we can convert this to a readable hostname later
    // during some postprocessing/analytics stage.
    fprintf(stdout, "(%d) Accepted connection from %u\n",
            client->id, addr.sin_addr.s_addr);
    return;

fail:
    fprintf(stderr, "%s", errstr);
    if (clientfd) close(clientfd);
    free_all(ctx);
}

static ev_signal signal_watcher_int;
static ev_signal signal_watcher_term;

static void setup_events(srv_ctx *ctx)
{
    sigset_t sigpipe;

    //XXX what does the auto method use?
    // select() offers better response times, but
    // epoll is MUCH more scalable
    ctx->loop = ev_default_loop(EVFLAG_AUTO);
    ctx->io.data = ctx;

    /* setup primary acceptor */
    ev_io_init(&ctx->io, incoming_cb, ctx->fd, EV_READ);
    ev_io_start(ctx->loop, &ctx->io);

    signal_watcher_int.data = ctx;
    ev_signal_init(&signal_watcher_int, close_cb, SIGINT);
    ev_signal_start(ctx->loop, &signal_watcher_int);

    signal_watcher_term.data = ctx;
    ev_signal_init(&signal_watcher_term, close_cb, SIGTERM);
    ev_signal_start(ctx->loop, &signal_watcher_term);

    // ignore SIGPIPE
    sigemptyset(&sigpipe);
    sigaddset(&sigpipe, SIGPIPE);
    sigprocmask(SIG_BLOCK, &sigpipe, NULL);
}

int main(int argc, char** argv)
{
    int serverfd = 0;
    int tmp = 1, len;
    const char *errstr;
    srv_ctx *ctx = malloc(sizeof(srv_ctx));

    if ((serverfd = setup_socket(HOSTNAME, RTMP_PORT)) < 0) {
        serverfd = 0;
        errstr = "Failed to set up socket";
        goto fail;
    }

    ctx->fd = serverfd;
    ctx->connections = 0;
    ctx->total_cxns = 0;
    ctx->clients = NULL;
    setup_events(ctx);
    ev_loop(ctx->loop, EVBACKEND_EPOLL);

    // shut up librtmp error messages.
    // none of these seem to work...
    RTMP_LogSetOutput(0); // /dev/null
    RTMP_LogSetLevel(RTMP_LOGCRIT);
    RTMP_debuglevel = RTMP_LOGCRIT;

    return 0;

fail:
    fprintf(stderr, "%s: %s\n", errstr, strerror(errno));
    return 0;
}
