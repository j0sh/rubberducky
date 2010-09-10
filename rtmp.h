#ifndef VIDEOAPI_RTMP_H
#define VIDEOAPI_RTMP_H

#include <stdint.h>
#include <ev.h>

// emulated things
#define FMS_VER_MAJOR 3
#define FMS_VER_MINOR 5
#define FMS_VER_MICRO 1
#define FMS_VER_NANO  1

typedef struct {
    int cs; // current state of the packet parser
    int fd;
    int off; // handshake offset. When off == 0, signals pre-FP9 cxns
    unsigned char read_buf[1600];
    unsigned char write_buf[1600];
    ev_io read_watcher;
}rtmp;

int rtmp_parser_init(rtmp *r);
void rtmp_read(struct ev_loop *loop, ev_io *io, int revents);
void CalculateDigest(unsigned int digestPos, uint8_t *handshakeMessage,
		        const uint8_t *key, size_t keyLen, uint8_t *digest);

#endif
