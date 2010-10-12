#ifndef VIDEOAPI_RTMP_H
#define VIDEOAPI_RTMP_H

#include <stdint.h>
#include <ev.h>

#define MKTAG(a, b, c, d) ((a) | ((b) << 8) | ((c) << 16) | ((d) << 24))

#define RTMPERR(error) -error
#define INVALIDDATA MKTAG('I','N','V','L')

// emulated things
#define FMS_VER_MAJOR 3
#define FMS_VER_MINOR 5
#define FMS_VER_MICRO 1
#define FMS_VER_NANO  1

// 3 (chunk header) + 11 (header) + 4 (extended timestamp) = 18
#define RTMP_MAX_HEADER_SIZE 18
#define RTMP_CHANNELS 65600
#define RTMP_DEFAULT_CHUNKSIZE 128
#define RTMP_PORT 1935
#define RTMP_DEFAULT_ACK 2500000

// arbitrary constants, not protocol specific
#define RTMP_MAX_STREAMS 16

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

typedef enum rtmp_state { UNINIT = 0,
                          HANDSHAKE,
                          READ
}rtmp_state;

typedef enum amf_encoding { AMF0 = 0,
                            AMF3 = 3
}amf_encoding;

typedef struct rtmp_packet {
    int chunk_id;
    int msg_id; // stream id?
    int msg_type;
    int size;
    int read;
    uint32_t timestamp;
    chunk_types chunk_type;
    uint8_t *body;
    int alloc_size; // amount allocated for body (size <= alloc_size)
 }rtmp_packet;

typedef struct rtmp_stream {
    int id;
    char *name;
}rtmp_stream;

typedef struct rtmp {
    int fd;
    int off; // handshake offset. When off == 0, signals pre-FP9 cxns
    int chunk_size; // max 65546 bytes
    uint32_t ack_size; // acknowledgement window
    uint32_t prev_ack;
    uint32_t rx;
    uint32_t tx;
    amf_encoding encoding;
    rtmp_state state;

    // chunk header buffer
    uint8_t hdr[RTMP_MAX_HEADER_SIZE];
    int hdr_bytes;

    rtmp_packet *prev_pkt; // used when chunks are split across tcp packets
    int chunk_alignment;

    rtmp_packet *in_channels[RTMP_CHANNELS]; // find a better way
    rtmp_packet *out_channels[RTMP_CHANNELS];
    rtmp_stream *streams[RTMP_MAX_STREAMS];
    char *app; // application name string
    char *url; // protocol, hostname and application name
    ev_io read_watcher;
    void (*read_cb)(struct rtmp *r, rtmp_packet *pkt, void *opaque);
}rtmp;

void rtmp_init(rtmp *r);
void rtmp_free(rtmp *r);
void rtmp_free_stream(rtmp_stream **stream);
void rtmp_read(struct ev_loop *loop, ev_io *io, int revents);
int  rtmp_send(rtmp *r, struct rtmp_packet *pkt);
void CalculateDigest(unsigned int digestPos, uint8_t *handshakeMessage,
		        const uint8_t *key, size_t keyLen, uint8_t *digest);

#endif
