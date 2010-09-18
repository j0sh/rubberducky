#ifndef VIDEOAPI_RTMP_H
#define VIDEOAPI_RTMP_H

#include <stdint.h>
#include <ev.h>

// emulated things
#define FMS_VER_MAJOR 3
#define FMS_VER_MINOR 5
#define FMS_VER_MICRO 1
#define FMS_VER_NANO  1

#define RTMP_CHANNELS 65600
#define RTMP_DEFAULT_CHUNKSIZE 128

// size in bytes
typedef enum chunk_sizes { CHUNK_SIZE_LARGE  = 11,
                   CHUNK_SIZE_MEDIUM =  7,
                   CHUNK_SIZE_SMALL  =  3,
                   CHUNK_SIZE_TINY   =  0
}chunk_sizes;

typedef enum chunk_types { CHUNK_LARGE = 0,
                           CHUNK_MEDIUM,
                           CHUNK_SMALL,
                           CHUNK_TINY
}chunk_types;

typedef struct rtmp_packet {
    int chunk_id;
    int msg_id; // useless?
    int msg_type;
    int size;
    int read;
    uint32_t timestamp;
    chunk_types chunk_type;
    uint8_t *body;
 }rtmp_packet;

typedef struct rtmp {
    int cs; // current state of the packet parser
    int fd;
    int off; // handshake offset. When off == 0, signals pre-FP9 cxns
    int chunk_size; // max 65546 bytes
    uint8_t read_buf[2600]; // TODO investigate max size
    uint8_t write_buf[1600];
    rtmp_packet *in_channels[RTMP_CHANNELS]; // find a better way
    rtmp_packet *out_channels[RTMP_CHANNELS];
    ev_io read_watcher;
    void (*read_cb)(struct rtmp *r, rtmp_packet *pkt);
}rtmp;

void rtmp_parser_init(rtmp *r);
void rtmp_init(rtmp *r);
void rtmp_free(rtmp *r);
void rtmp_read(struct ev_loop *loop, ev_io *io, int revents);
void CalculateDigest(unsigned int digestPos, uint8_t *handshakeMessage,
		        const uint8_t *key, size_t keyLen, uint8_t *digest);

#endif
