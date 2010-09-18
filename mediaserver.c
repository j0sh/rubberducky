/* system includes */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

/* lib includes */
#include <librtmp/log.h>
#include <ev.h>

/* local includes */
#include "mediaserver.h"
#include "rtmp.h"
#include "process_messages.h"

#define BACKLOG           20

#define HOSTNAME "moneypenny"

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

    fprintf(stdout, "(%d) Disconnecting\n", c->id);
    rtmp_free(&c->rtmp);
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
        rtmp_free(&d->rtmp);
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

static void rtmp_read_cb(rtmp *r, struct rtmp_packet *pkt, void *opaque)
{
    srv_ctx *ctx = (srv_ctx*)opaque;
    switch(pkt->msg_type) {
    case 0x14:
        rtmp_invoke(r, pkt, ctx);
        break;
    default:
        fprintf(stdout, "default in cb\n");
    }
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
    client->id = ctx->total_cxns++;
    client->reads = 0;

    rtmp_parser_init(&client->rtmp);
    client->rtmp.fd = clientfd;
    client->rtmp.read_watcher.data = ctx;

    fcntl(clientfd, F_SETFL, O_NONBLOCK);

    /* setup the events */
    ev_io_init(&client->rtmp.read_watcher, rtmp_read, client->rtmp.fd, EV_READ);
    ev_io_start(ctx->loop, &client->rtmp.read_watcher);

    // we can convert this to a readable hostname later
    // during some postprocessing/analytics stage.
    fprintf(stdout, "(%d) Accepted connection from %u\n",
            client->id, addr.sin_addr.s_addr);
    return;

fail:
    fprintf(stderr, "%s", errstr);
    if (clientfd) close(clientfd);
    if (ctx->clients == client)
        free_client(ctx, client);
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
    ctx->stream.cxn_count = 0;
    setup_events(ctx);
    ev_loop(ctx->loop, EVBACKEND_EPOLL);

    return 0;

fail:
    fprintf(stderr, "%s: %s\n", errstr, strerror(errno));
    return 0;
}
