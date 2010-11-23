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

typedef enum {  VOD = 0,
                LIVE,
                RECORD,
                APPEND
}stream_type;

typedef struct rtmp_packet {
    int chunk_id;
    int msg_id; // stream id?
    int msg_type;
    int size;
    int read;
    uint32_t timestamp;
    int ts_delta; // timestamp delta
    chunk_types chunk_type;
    uint8_t *body;
    int alloc_size; // amount allocated for body (size <= alloc_size)
    uint8_t header[RTMP_MAX_HEADER_SIZE];
    int header_size;
 }rtmp_packet;

typedef struct rtmp_stream {
    int id;
    int type;
    int acodec, vcodec;

    // various caches
    int metadata_size;
    uint8_t *metadata;
    int aac_seq_size; // AAC sequence header
    uint8_t *aac_seq;
    int avc_seq_size;
    uint8_t *avc_seq; // AVC sequence header
    char *name;
}rtmp_stream;

typedef struct rtmp {
    int fd;
    int off; // handshake offset. When off == 0, signals pre-FP9 cxns
    int in_chunk_size; // max 65546 bytes
    int out_chunk_size;
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

    // for streaming
    int keyframe_pending;

    rtmp_packet *in_channels[RTMP_CHANNELS]; // find a better way
    rtmp_packet *out_channels[RTMP_CHANNELS];
    rtmp_stream *streams[RTMP_MAX_STREAMS];
    char *app; // application name string
    char *url; // protocol, hostname and application name
    void (*read_cb)(struct rtmp *r, rtmp_packet *pkt);
    void (*close_cb)(struct rtmp *r);
    void (*publish_cb)(struct rtmp *r, rtmp_stream *s);
    void (*delete_cb)(struct rtmp *r, rtmp_stream *s);
    int  (*play_cb)(struct rtmp *r, rtmp_stream *s);
}rtmp;

/*     each stream has 5 channels; the last 2 are unknown.
       0 and 1 are used for signalling large chunk/channel IDs,
       while 2 and 3 are used for protocol control.

       stream       chunk id       type
          1              4            data
          1              5           audio
          1              6           video
          2              9            data
          2             10           audio
                ... and so on ...           */

static inline int calc_chunk_id(int stream_id, int type_offset)
{
    return (stream_id - 1) * 5 + type_offset;
}
static inline int data_chunk_id(int stream_id)
{
    return calc_chunk_id(stream_id, 4);
}
static inline int audio_chunk_id(int stream_id)
{
    return calc_chunk_id(stream_id, 5);
}
static inline int video_chunk_id(int stream_id)
{
    return calc_chunk_id(stream_id, 6);
}

void rtmp_init(rtmp *r);
void rtmp_free(rtmp *r);
void rtmp_free_stream(rtmp_stream **stream);
void rtmp_read(rtmp *r);
int  rtmp_send(rtmp *r, struct rtmp_packet *pkt);

#endif
