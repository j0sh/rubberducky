#ifndef VIDEOAPI_MEDIASERVER_H
#define VIDEOAPI_MEDIASERVER_H

#include <librtmp/rtmp.h>
#include <ev.h>

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

typedef struct stream_ctx {
    int fd;
    int cxn_count;
    char name[128];
    RTMP *fds[1024];
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
