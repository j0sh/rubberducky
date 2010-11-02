/* system includes */
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
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
#include <librtmp/amf.h>
#include <ev.h>

/* local includes */
#include "mediaserver.h"
#include "rtmp.h"

#define BACKLOG           20

#define HOSTNAME "localhost"
#define RTMP_PORT_STRING  QUOTEVALUE(RTMP_PORT)

static int resolve_host(struct sockaddr_in *addr,
                        const char *hostname, const char *port)
{
    /* hostname lookup might not be needed */
    if (!inet_aton(hostname, &addr->sin_addr))
    {
        struct addrinfo hints, *res, *cur;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(hostname, port, NULL, &res)) {
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

    addr.sin_port = htons(port);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));

    if (resolve_host(&addr, HOSTNAME, QUOTEVALUE(RTMP_PORT))) {
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

static void free_client(client_ctx *client)
{
    int i;
    srv_ctx *ctx = client->srv;
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

    // free streams in the server tree
    for (i = 0; i < RTMP_MAX_STREAMS; i++)
        if (c->rtmp.streams[i] && c->rtmp.streams[i]->name) {
            printf("Deleting stream %s\n", c->rtmp.streams[i]->name);
            rxt_delete(c->rtmp.streams[i]->name, ctx->streams);
        }

    rtmp_free(&c->rtmp);
    if (c->recvs) free(c->recvs);
    ev_io_stop(ctx->loop, &c->read_watcher);
    free(c);
    ctx->connections--;
}

static void free_all(srv_ctx *ctx)
{
    client_ctx *c = ctx->clients;

    //TODO Get rid of the list? Options?
    while (c) {
        client_ctx *d = c;
        c = c->next;
        free_client(d);
    }
    ctx->clients = NULL;

    close(ctx->fd);
    ev_io_stop(ctx->loop, &ctx->io);
    ev_unloop(ctx->loop, EVUNLOOP_ALL);
    rxt_free(ctx->streams);
    ctx->streams = NULL;
    free(ctx);
    ctx = NULL;
    fprintf(stdout, "Shutting down\n");
}

static void close_cb(struct ev_loop *loop, ev_signal *signal, int revents)
{
    free_all((srv_ctx*)signal->data);
}

static inline client_ctx* get_client(rtmp *r)
{
    return (client_ctx*)((uint8_t*)r - offsetof(client_ctx, rtmp));
}

static void rd_rtmp_close_cb(rtmp *r)
{
    free_client(get_client(r));
}

static void rd_rtmp_publish_cb(rtmp *r, rtmp_stream *stream)
{
#define MAX_CLIENTS 10
    client_ctx *client;
    recv_ctx *recvs;
    srv_ctx *srv;

    client = get_client(r);
    recvs = malloc(MAX_CLIENTS * sizeof(rtmp*) + sizeof(recv_ctx));
    srv = client->srv;
    if (!recvs) {
        fprintf(stderr, "Out of memory when mallocing receivers!\n");
        return; // TODO something drastic
    }
    memset(recvs, 0, MAX_CLIENTS * sizeof(rtmp*) + sizeof(recv_ctx));
    recvs->max_recvs = MAX_CLIENTS;
    client->recvs = recvs;

    rxt_put(stream->name, client, srv->streams);
#undef MAX_CLIENTS
}

static void rd_rtmp_delete_cb(rtmp *r, rtmp_stream *s)
{
    client_ctx *client = get_client(r);
    srv_ctx *srv = client->srv;
    if (s->name)
        rxt_delete(s->name, srv->streams);
}

static void incoming_cb(struct ev_loop *loop, ev_io *io, int revents)
{
    int clientfd;
    socklen_t len = 0; // weird type to sate the compiler
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
    client->srv = ctx;
    client->id = ctx->total_cxns++;
    client->recvs = NULL;

    rtmp_init(&client->rtmp);
    client->rtmp.fd = clientfd;
    client->read_watcher.data = &client->rtmp;
    client->rtmp.close_cb = rd_rtmp_close_cb;
    client->rtmp.publish_cb = rd_rtmp_publish_cb;
    client->rtmp.delete_cb = rd_rtmp_delete_cb;

    fcntl(clientfd, F_SETFL, O_NONBLOCK);

    /* setup the events */
    ev_io_init(&client->read_watcher, rtmp_read, client->rtmp.fd, EV_READ);
    ev_io_start(ctx->loop, &client->read_watcher);

    // we can convert this to a readable hostname later
    // during some postprocessing/analytics stage.
    fprintf(stdout, "(%d) Accepted connection from %u\n",
            client->id, addr.sin_addr.s_addr);
    return;

fail:
    fprintf(stderr, "%s", errstr);
    if (clientfd) close(clientfd);
    if (ctx->clients == client)
        free_client(client);
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
    ctx->streams = rxt_init();
    setup_events(ctx);
    ev_loop(ctx->loop, EVBACKEND_EPOLL);

    return 0;

fail:
    fprintf(stderr, "%s: %s\n", errstr, strerror(errno));
    return 0;
}
