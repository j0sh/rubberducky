#ifndef VIDEOAPI_MEDIASERVER_H
#define VIDEOAPI_MEDIASERVER_H

#include <ev.h>

#include "rtmp.h"

#ifndef videoapi_unused
#if defined(__GNUC__)
#   define videoapi_unused __attribute__((unused))
#else
#   define videoapi_unused
#endif
#endif

typedef struct client_ctx {
    int id;
    int reads;
    rtmp rtmp;
    struct client_ctx *next;
}client_ctx;

typedef struct stream_ctx {
    int fd;
    int cxn_count;
    char name[128];
    rtmp *fds[1024];
    //ev_io read_watcher;
} stream_ctx;

typedef struct srv_ctx {
    int fd;
    int connections;
    int total_cxns;
    struct ev_loop *loop;
    ev_io io;             /* socket listener event */
    client_ctx *clients;
    stream_ctx stream;
}srv_ctx;

#endif //VIDEOAPI_MEDIASERVER_H
