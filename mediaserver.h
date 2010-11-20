#ifndef VIDEOAPI_MEDIASERVER_H
#define VIDEOAPI_MEDIASERVER_H

#include <ev.h>

#include "radixtree/radix.h"
#include "rtmp.h"

#ifndef videoapi_unused
#if defined(__GNUC__)
#   define videoapi_unused __attribute__((unused))
#else
#   define videoapi_unused
#endif
#endif

#define QUOTELITERAL(x) #x
#define QUOTEVALUE(x) QUOTELITERAL(x)

typedef struct {
    rtmp *rtmp_handle;
    rtmp_stream *stream;
}stream_mapping;

typedef struct {
    stream_mapping **list; // receivers
    rtmp_stream *stream;
    int nb_recvs;
    int max_recvs;
}recv_ctx;

struct srv_ctx;

typedef struct client_ctx {
    int id;
    rtmp rtmp_handle;
    recv_ctx *outgoing;
    ev_io read_watcher;
    struct srv_ctx *srv;
    struct client_ctx *next;
}client_ctx;

typedef struct srv_ctx {
    int fd;
    int connections;
    int total_cxns;
    struct ev_loop *loop;
    ev_io io;             /* socket listener event */
    client_ctx *clients;
    rxt_node *streams;
}srv_ctx;

#endif //VIDEOAPI_MEDIASERVER_H
