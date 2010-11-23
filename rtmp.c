/* system includes */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <netinet/in.h>
#include <assert.h>

/* these are primarily for get_uptime */
#include <stdint.h>
#include <sys/times.h>
#include <unistd.h>

/* local includes */
#include "rtmp.h"
#include "amf.h"
#include "mediaserver.h"


static uint32_t clk_tck;
static uint32_t get_uptime()
{
    struct tms t;
    if (!clk_tck) clk_tck = sysconf(_SC_CLK_TCK);
    return times(&t) * 1000 / clk_tck;
}

static int send_chunksize(rtmp *r, int chunksize, int ts)
{
    uint8_t pbuf[4];
    uint8_t *body = pbuf, *end = pbuf + sizeof(pbuf);
    rtmp_packet packet = {
        .chunk_id = 0x02,
        .msg_id = 0,
        .msg_type = 0x01,
        .timestamp = ts,
        .size = end - body,
        .body = body
    };
    amf_write_i32(body, end, chunksize);
    r->out_chunk_size = chunksize;
    fprintf(stdout, "Setting outbound chunk size to %d bytes\n", chunksize);
    return rtmp_send(r, &packet);
}

static int send_ack(rtmp *r, int ts)
{
    uint8_t pbuf[4];
    uint8_t *body = pbuf, *end = pbuf + sizeof(pbuf);
    rtmp_packet packet = {
        .chunk_id  = 0x02,
        .msg_id    = 0,
        .msg_type  = 0x03,
        .timestamp = ts,
        .size      = end - body,
        .body      = body
    };

    amf_write_i32(body, end, r->rx);

    fprintf(stdout, "Sending ack for %d bytes\n", r->rx);
    return rtmp_send(r, &packet);
}

static int send_usercontrol(rtmp *r, int msg, int data, int ts)
{
    uint8_t pbuf[6];
    uint8_t *body = pbuf, *end = pbuf + sizeof(pbuf);
    rtmp_packet packet = {
        .chunk_id  = 0x02,
        .msg_id    = 0,
        .msg_type  = 0x04,
        .timestamp = ts,
        .size      = end - body,
        .body      = body
    };
    amf_write_i16(body, end, msg);
    body += 2;
    amf_write_i32(body, end, data);

    return rtmp_send(r, &packet);
}

enum {
    STREAM_BEGIN = 0,
    STREAM_EOF,
    STREAM_DRY,
    SET_BUF_LEN,
    STREAM_RECORDED,
    PING = 6,
    PONG
}; // control types

static inline int send_stream_begin(rtmp *r, int stream_id, int ts)
{
    return send_usercontrol(r, STREAM_BEGIN, stream_id, ts);
}

static inline int send_stream_recorded(rtmp *r, int stream_id, int ts)
{
    return send_usercontrol(r, STREAM_RECORDED, stream_id, ts);
}

static inline int send_ping(rtmp *r, int ts)
{
    // XXX get_uptime() should actually be the server time??
    return send_usercontrol(r, PING, get_uptime(), ts);
}

static inline int send_pong(rtmp *r, uint32_t ping_t, int ts)
{
    return send_usercontrol(r, PONG, ping_t, ts);
}

static videoapi_unused int send_buflen(rtmp *r, int stream_id, int ts)
{
#define BUFLEN 3000
    uint8_t pbuf[10];
    uint8_t *body = pbuf, *end = pbuf + sizeof(pbuf);
    rtmp_packet packet = {
        .chunk_id  = 0x02,
        .msg_id    = 0,
        .msg_type  = 0x04,
        .timestamp = ts,
        .size      = end - body,
        .body      = body
    };

    amf_write_i16(body, end, 0x07);
    body += 2;
    amf_write_i32(body, end, stream_id);
    body += 4;
    amf_write_i32(body, end, BUFLEN);

    fprintf(stdout, "Sending buflen for stream %d, %d-ms buffer\n",
            stream_id, BUFLEN);
    return rtmp_send(r, &packet);
#undef BUFLEN
}

static int send_ack_size(rtmp *r, int ts)
{
    uint8_t pbuf[4];
    rtmp_packet packet = {
        .chunk_id = 0x02,
        .msg_id   = 0,
        .msg_type = 0x05,
        .timestamp = ts,
        .size = sizeof(pbuf),
        .body = pbuf
    };

    amf_write_i32(pbuf, pbuf + sizeof(pbuf), r->ack_size);

    fprintf(stdout, "Sending ack window for size %d\n", r->ack_size);
    return rtmp_send(r, &packet);
}

static int send_peer_bw(rtmp *rtmp, int ts)
{
    uint8_t pbuf[5];
    amf_write_i32(pbuf, pbuf + 4, 0x0fffffff);
    pbuf[4] = 2; // uhhh wtf? XXX review spec
    rtmp_packet packet = {
        .chunk_id = 0x02,
        .msg_id = 0,
        .msg_type = 0x06,
        .timestamp = 0,
        .size = sizeof(pbuf),
        .body = pbuf
    };
    fprintf(stdout, "sending clientbw, rx: %d, tx %d\n", rtmp->rx, rtmp->tx);
    return rtmp_send(rtmp, &packet);
}

static int read_bytes(rtmp *r, uint8_t *p, int howmany)
{
    int len;
    len = recv(r->fd, p, howmany, 0);
    if (!len) {
        // If no messages are available to be received and the peer
        // has performed an orderly shutdown, recv() shall return 0.
        errno = EIO;
    }
    if (len > 0)
        r->rx += len;

    // send return report if rx exceeds ack window
    if (r->rx >= r->prev_ack + r->ack_size) {
        send_ack(r, 0); // TODO fix timestamp
        r->prev_ack = r->rx;
    }
    return len ;
}

#include "handshake.c"
#include "process_messages.c"

static int handle_control(rtmp *r, rtmp_packet *pkt)
{
    int ctrl_type;
    uint8_t *body = pkt->body;

    if (pkt->size < 6) // includes 4-byte that is common to all types
        goto control_error;

    ctrl_type = amf_read_i16(body);
    body += 2;

    switch (ctrl_type) {
    case STREAM_BEGIN:
    case STREAM_EOF:
    case STREAM_DRY:
    case STREAM_RECORDED:
    case PONG:
        fprintf(stdout, "control %d, value %d\n",
                ctrl_type, amf_read_i32(body));
        body += 4;
        break;
    case PING:
        send_pong(r, amf_read_i32(body), pkt->timestamp + 1);
        body += 4;
        break;
    case SET_BUF_LEN:
        // XXX use this to set the tx rate?
        if (pkt->size < 8)
            goto control_error;
        fprintf(stdout, "setting buffer length: stream %d, %d-ms buffer\n",
                amf_read_i32(body), amf_read_i32(body + 4));
        body += 8;
        break;
    default:
        fprintf(stderr, "Unknown control type.\n");
        goto control_error;
    }

    return 0;

control_error:
    fprintf(stderr, "Not enough bytes in control packet, exiting.\n");
    return -1;
}

static int handle_setpeerbw(rtmp *r, rtmp_packet *pkt)
{
    int ack;
    if (pkt->size < 4) goto peerbw_fail;
    ack = amf_read_i32(pkt->body);
    if (ack != r->ack_size) {
        r->ack_size = ack;
        return send_ack_size(r, pkt->timestamp + 1);
    }

    return 0;

peerbw_fail:
    fprintf(stderr, "Not enough bytes when reading peer bw packet.\n");
    return -1;
}

static void parse_metadata(rtmp *r, rtmp_stream *stream)
{
    // only extract the things we care about
    AMFObject metadata, metaobjs;
    // skip over \0x2\0x00\0xaonMetaData
    int len = AMF_Decode(&metadata, (char*)stream->metadata + 13,
                         stream->metadata_size - 13, FALSE);
    if (len < 0) {
        fprintf(stderr, "Error decoding metadata!\n");
        return;
    }

    // slight problem: zero will be returned if the key is not found,
    // but zero is a valid audio codec ID (linear PCM).
    // let's hope we don't have any LPCM-specific stuff
    // TODO check bounds, especially validity of metaobjs
    AMFProp_GetObject(AMF_GetProp(&metadata, NULL, 0), &metaobjs); //ugh
    stream->vcodec = (int)amf_read_dbl_kv(&metaobjs, "videocodecid");
    stream->acodec = (int)amf_read_dbl_kv(&metaobjs, "audiocodecid");
    AMF_Reset(&metadata);
}

static void handle_notify(rtmp *r, rtmp_packet *pkt)
{
    // XXX hack for leading whitespace in 0x0f messages
    uint8_t *body = pkt->body;
    int size = pkt->size, offset = 0;
    while (!*body) { body++; size--; offset++; }

    if (!memcmp("\x02\x00\x0d@setDataFrame\x02\x00\x0aonMetaData",
                (char*)body, 29)) {
        rtmp_stream *s = r->streams[pkt->msg_id];
        size -= 16; // skip @setDataFrame only
        s->metadata = malloc(size + 1);
        if (!s->metadata) {
            fprintf(stderr, "Out of memory for metadata!\n");
            return;
        }
        memcpy(s->metadata, body + 16, size);
        s->metadata[size] = '\0';
        s->metadata_size = size;
        parse_metadata(r, s);
    } else
        fprintf(stdout, "Unhandled metadata!\n");
}

static void handle_audio(rtmp *r, rtmp_packet *pkt)
{
    // intercept the AAC sequence header and cache it
    if (10 == (pkt->body[0] >> 4) && !pkt->body[1]) {
        uint8_t *cache = malloc(pkt->size);
        if (!cache) {
            fprintf(stderr, "Out of memory for AAC cache!\n");
            return;
        }
        memcpy(cache, pkt->body, pkt->size);
        if (r->streams[pkt->msg_id]->aac_seq) {
            // AFAIK this should not really happen as the AAC sequence
            // is only really stored at the beginning of the stream
            fprintf(stdout, "Warning: removing previous AAC sequence.\n");
            free(r->streams[pkt->msg_id]->aac_seq);
        }
        r->streams[pkt->msg_id]->aac_seq = cache;
        r->streams[pkt->msg_id]->aac_seq_size = pkt->size;
        fprintf(stdout, "AAC extradata cached %d.\n", pkt->size);
    }
}

static void handle_video(rtmp *r, rtmp_packet *pkt)
{
    // intercept the AVC sequence header and cache it
    if (7 == (pkt->body[0] & 0x0f) && !pkt->body[1]) {
        uint8_t *cache = malloc(pkt->size);
        if (!cache) {
            fprintf(stderr, "Out of memory for AVC cache!\n");
            return;
        }
        memcpy(cache, pkt->body, pkt->size);
        if (r->streams[pkt->msg_id]->avc_seq) {
            // AVC sequence is only really stored at stream start
            fprintf(stderr, "Warning: removing previous AVC sequence.\n");
            free(r->streams[pkt->msg_id]->avc_seq);
        }
        r->streams[pkt->msg_id]->avc_seq = cache;
        r->streams[pkt->msg_id]->avc_seq_size = pkt->size;
        fprintf(stdout, "AVC extradata cached %d.\n", pkt->size);
    }

    if (5 == (pkt->body[0] & 0x0f)) {
        fprintf(stderr, "Got  video info/command frame; what to do??\n");
    }
}

static int handle_msg(rtmp *r, struct rtmp_packet *pkt)
{
    switch (pkt->msg_type) {
    case 0x01: // set chunk size
        r->in_chunk_size = amf_read_i32(pkt->body);
        break;
    case 0x02: // abort message
        break;
    case 0x03:
        fprintf(stdout, "Ack: %d Bytes Read\n", amf_read_i32(pkt->body));
        break;
    case 0x04:
        handle_control(r, pkt);
        break;
    case 0x05:
        fprintf(stdout, "Set Ack Size: %d\n", amf_read_i32(pkt->body));
        break;
    case 0x06: // set window ack size.
        handle_setpeerbw(r, pkt);
        break;
    case 0x07: // for edge-origin distribution
        break;
    case 0x08: // audio
        handle_audio(r, pkt);
        break;
    case 0x09: // video
        handle_video(r, pkt);
        break;
    case 0x0f: // flex stream (HACK)
    case 0x12:
        handle_notify(r, pkt);
        break;
    case 0x11: // Flex message
    case 0x14:
        handle_invoke(r, pkt);
        break;
    default:
        fprintf(stdout, "default in cb: 0x%x\n", pkt->msg_type);
    }
    if (r->read_cb)
        r->read_cb(r, pkt);
    return 0;
}

static uint32_t read_i32_le(uint8_t *c)
{
    return (c[3] << 24) | (c[2] << 16) | (c[1] << 8) | c[0];
}

static int process_packet(rtmp *r)
{
    int header_type, chunk_id, chunk_size, to_increment = 0, copy_header = 0;
    rtmp_packet *pkt = r->prev_pkt;
    uint8_t *p, *pe;

    p = r->hdr;
    // if a prev packet already exists, no need to read in header again
    if (!r->prev_pkt) {
        // overread the header a little to avoid having to call recv
        // for each byte as we need it.
        // later, copy leftover/unused data in the header buffer to body
        if ((r->hdr_bytes += read_bytes(r, p + r->hdr_bytes, sizeof(r->hdr) - r->hdr_bytes)) <= 0) {
            fprintf(stdout, "ZOMGBROKEN\n");
            return RTMPERR(errno);
        }
    pe  = p + r->hdr_bytes;

    if ((pe - p) < 1)
        goto parse_pkt_fail;
        header_type = (*p & 0xc0) >> 6;
        chunk_id = *p & 0x3f;
        p += 1;

    if ((chunk_id > 319 && (pe - p) < 2) ||
       (chunk_id > 64 && (pe - p) < 1)) {
        goto parse_pkt_fail;
    }
    if (!chunk_id) {
        chunk_id = *p + 64;
        p += 1;
    } else if (1 == chunk_id ) {
        chunk_id = (*p << 8) + p[1] + 64;
        p += 2;
    }

    // get previous packet in chunk
    if (r->in_channels[chunk_id]) {
        pkt = r->in_channels[chunk_id];
    } else {
        if(!(pkt = malloc(sizeof(rtmp_packet)))) {
            fprintf(stderr, "Failed to malloc space for packet!\n");
        return RTMPERR(ENOMEM);
        }
        memset(pkt, 0, sizeof(rtmp_packet)); // zero out
        pkt->chunk_id = chunk_id;
        r->in_channels[chunk_id] = pkt;
    }
    pkt->chunk_type = header_type;

    // NB:  we intentionally fallthrough here
    switch (header_type) {
    case CHUNK_LARGE:
        if ((pe - p) < CHUNK_SIZE_LARGE) goto parse_pkt_fail;
        pkt->msg_id = read_i32_le(&p[7]);
        to_increment += 4;
    case CHUNK_MEDIUM:
        if ((pe - p) < CHUNK_SIZE_MEDIUM ) goto parse_pkt_fail;
        pkt->msg_type = p[6];
        pkt->size = amf_read_i24(&p[3]); // size exclusive of header
        pkt->read = 0;
        to_increment += 4;
    case CHUNK_SMALL: {
        uint32_t ts;
        if ((pe - p) < CHUNK_SIZE_SMALL) goto parse_pkt_fail; // XXX error out
        ts = amf_read_i24(p);
        to_increment += 3;
        if (0xffffff == ts) {
            // read in extended timestamp
            static const int header_sizes[] = { CHUNK_SIZE_LARGE,
                                                CHUNK_SIZE_MEDIUM,
                                                CHUNK_SIZE_SMALL };
            int hsize = header_sizes[header_type];
            if (p + hsize + 4 > pe) goto parse_pkt_fail;

            ts = amf_read_i32(p+hsize);
            to_increment += 4;
        }
        if (!header_type) {
            pkt->timestamp = ts; // abs timestamp
            pkt->ts_delta = 0;
        } else {
            pkt->timestamp += ts; // timestamp delta
            pkt->ts_delta = ts;
        }
    }
    case 3:
        break;
    }
    p += to_increment;

    // enlarge packet body if needed
    if (!pkt->read && pkt->alloc_size < pkt->size) {
        // allocate packet body
        if (pkt->body) {
            free(pkt->body);
            pkt->body = NULL;
            pkt->alloc_size = 0;
        }
        if (!(pkt->body = malloc(pkt->size))) {
            fprintf(stderr, "Out of memory when allocating packet!\n");
            return RTMPERR(ENOMEM);
        }
        pkt->alloc_size = pkt->size;
    }

    // copy packet data
    chunk_size = r->in_chunk_size < (pkt->size - pkt->read) ?
                 r->in_chunk_size : (pkt->size - pkt->read);

        // copy over any data leftover from header buffer
        int leftover = r->hdr_bytes - (p - r->hdr);
        chunk_size -= leftover;
        if (chunk_size < 0) {
            // we fucked up and overread into the next packet
            leftover += chunk_size;
            r->hdr_bytes = -chunk_size;
            chunk_size = 0;
            copy_header = 1;
        }

        // candidate for synthetic microbenchmarking against a while loop
        memcpy(pkt->body + pkt->read, p, leftover);
        p         += leftover;
        pkt->read += leftover;
    } else {
        chunk_size = r->chunk_alignment;
	    r->chunk_alignment = 0;
    }

    if (chunk_size) {
        int len;
        if ((len = read_bytes(r, pkt->body + pkt->read, chunk_size)) <= 0) {
	        if (errno == EAGAIN){
	            len = 0;
            } else {
                fprintf(stderr, "Error reading bytes!\n");
                return RTMPERR(errno);
            }
        }

        // chunk was split across TCP packets
        if (len != chunk_size) {
            pkt->read += len;
            r->chunk_alignment = chunk_size - len;
            r->prev_pkt = pkt;
            return RTMPERR(EAGAIN);
	    }
        r->hdr_bytes = 0; // we've completed our chunk
    } else if (copy_header) {
        // we copied way too much in the header and spilled over
        // into the next packet; save the leftover leftover bytes
        // into a temp buffer
        // XXX probably should verify size of write_buf!
        assert(r->hdr_bytes <= sizeof(r->hdr));
        memmove(r->hdr, p, r->hdr_bytes);
    } else {
        // this condition is triggered when we have:
        // a) chunk body (or remainder thereof) that fits into header buf
        // b) no overflow that spills over to the next chunk
        // (in short, the chunk terminates on a TCP packet boundary)
        r->hdr_bytes = 0;
    }
    r->prev_pkt = NULL;
    pkt->read += chunk_size;

   /*
        fprintf(stdout, "Packet/Chunk parameters:\n"
                        "%15s %d\n%15s %d\n%15s %u\n"
                        "%15s %d\n%15s %d\n%15s 0x%x\n"
                        "%15s %d\n%15s %d\n",
                        "header type", header_type,
                        "chunk id",    chunk_id,
                        "timestamp",   pkt->timestamp,
                        "body size",   pkt->size,
                        "read",        pkt->read,
                        "msg type",    pkt->msg_type,
                        "msg id",      pkt->msg_id,
                        "chunksize",   chunk_size);
    */
    if (pkt->read == pkt->size) {
        handle_msg(r, pkt);
        pkt->read = 0;
    }
    return 1;

parse_pkt_fail:
    return RTMPERR(EAGAIN);
}

void rtmp_read(rtmp *r)
{
    int bytes_read;

    switch (r->state) {
    case UNINIT:
        bytes_read = init_handshake(r);
        if (1 == bytes_read) r->state = HANDSHAKE;
        break;
    case HANDSHAKE:
        bytes_read = handshake2(r);
        if (1 == bytes_read) r->state = READ;
        break;
    case READ:
        bytes_read = process_packet(r);
        break;
    }
    if (bytes_read <= 0 && bytes_read != RTMPERR(EAGAIN)) goto read_error;

    return;

read_error:
    if (bytes_read == RTMPERR(INVALIDDATA))
        fprintf(stderr, "Invalid data\n");
    fprintf(stderr, "Error %d, disconnecting fd %d \n", bytes_read, r->fd);
    if (r->close_cb)
        r->close_cb(r);
}
