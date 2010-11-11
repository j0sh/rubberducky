#include "rtmp.h"
#include "amf.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/socket.h>
#include <unistd.h>

void rtmp_init(rtmp *r)
{
    memset(r, 0, sizeof(rtmp));
    r->out_chunk_size = RTMP_DEFAULT_CHUNKSIZE;
    r->in_chunk_size = RTMP_DEFAULT_CHUNKSIZE;
    r->ack_size   = RTMP_DEFAULT_ACK;
}

void rtmp_free_stream(rtmp_stream **stream)
{
    rtmp_stream *s = *stream;
    if (!s) return;
    if (s->name) free(s->name);
    s->name = NULL;
    if (s->metadata) free(s->metadata);
    s->metadata = NULL;
    if (s->aac_seq) free(s->aac_seq);
    s->aac_seq = NULL;
    if (s->avc_seq) free(s->avc_seq);
    s->avc_seq = NULL;
    free(s);
    *stream = NULL;
}

static void free_packet(rtmp_packet **packet) {
    rtmp_packet *pkt = *packet;
    if (pkt) {
        if (pkt->body) {
            free(pkt->body);
            pkt->body = NULL;
        }
        free(pkt);
        *packet = NULL;
    }
}

void rtmp_free(rtmp *r)
{
    int i;
    for (i = 0; i < RTMP_CHANNELS; i++) {
        free_packet(&r->in_channels[i]);
        free_packet(&r->out_channels[i]);
    }
    for (i = 0; i < RTMP_MAX_STREAMS; i++) {
        if (r->streams[i])
            rtmp_free_stream(&r->streams[i]);
    }
    close(r->fd);
    if (r->app) free(r->app);
    if (r->url) free(r->url);
}

// really useless, should have a define stubbing this out for LE systems
static inline int write_i32_le(uint8_t *buf, uint8_t *end, int n)
{
    if (end - buf < 4) return 0;
    buf[0] = (n >> 0)  & 0xff;
    buf[1] = (n >> 8)  & 0xff;
    buf[2] = (n >> 16) & 0xff;
    buf[3] = (n >> 24) & 0xff;
    return 4;
}

int rtmp_send(rtmp *r, rtmp_packet *pkt) {
    rtmp_packet *prev = r->out_channels[pkt->chunk_id];
    uint32_t ts;
    uint8_t *header, *start, *body;
    int header_size, chunk_header_size, chunk_size, to_write;

    pkt->chunk_type = CHUNK_LARGE;
    if (!prev) pkt->ts_delta = 0;
    else pkt->ts_delta = pkt->timestamp - prev->timestamp;

    if (prev && pkt->msg_id == prev->msg_id) {
        if (pkt->msg_type == prev->msg_type &&
            pkt->size == prev->size) {
            pkt->chunk_type = CHUNK_SMALL;
            if (pkt->ts_delta == prev->ts_delta)
                pkt->chunk_type = CHUNK_TINY;
        } else
            pkt->chunk_type = CHUNK_MEDIUM;
    }

    if (pkt->chunk_id > 319)
        chunk_header_size = 3;
    else if (pkt->chunk_id > 63)
        chunk_header_size = 2;
    else
        chunk_header_size = 1;

    switch (pkt->chunk_type) {
    case CHUNK_LARGE:  header_size = CHUNK_SIZE_LARGE; break;
    case CHUNK_MEDIUM: header_size = CHUNK_SIZE_MEDIUM; break;
    case CHUNK_SMALL:  header_size = CHUNK_SIZE_SMALL; break;
    case CHUNK_TINY:   header_size = CHUNK_SIZE_TINY; break;
    default:
        // may be hit when both conditions are met:
        // a) pkt->chunk_type uninitialized
        // b) packet is the first of its channel_id
        header_size = CHUNK_SIZE_LARGE;
        pkt->chunk_type = CHUNK_LARGE;
    }

    ts = CHUNK_LARGE == pkt->chunk_type ? pkt->timestamp : pkt->ts_delta;

    if (ts >= 0xffffff) {
        header_size += 4;
        // just write the extended timestamp now
        amf_write_i32(pkt->body - 4, pkt->body, ts);
    }

    // XXX make sure there is room behind the packet body!
    header     = pkt->body - header_size - chunk_header_size;
    start      = header;
    body       = pkt->body;
    to_write   = pkt->size;
    chunk_size = r->out_chunk_size;

    // encode header proper
    header += chunk_header_size; // fast-forward; skip chunk hdr for now
    switch (pkt->chunk_type) {
    case CHUNK_LARGE:
        write_i32_le(&header[7], &header[7]+header_size, pkt->msg_id);
    case CHUNK_MEDIUM:
        header[6] = pkt->msg_type;
        amf_write_i24(&header[3], &header[3]+header_size, pkt->size);
    case CHUNK_SMALL:
        amf_write_i24(header, header+header_size, ts > 0xffffff ? 0xffffff : ts);
    case CHUNK_TINY:
        break;
    }
    header += header_size;

    while (to_write) {
        if (to_write < chunk_size)
            chunk_size = to_write;

        // encode chunk header
        // XXX bencmark this fragment against librtmp
        header = start;
        *header = (pkt->chunk_type << 6);
        switch (chunk_header_size) {
        case 1:
            *header |= pkt->chunk_id;
            break;
        case 3:
            *header |= 1;
            header[2] = (pkt->chunk_id - 64) >> 8;
        case 2:
            header[1] = (pkt->chunk_id - 64) & 0xff;
        }

        // start includes headers, body comes after headers
        send(r->fd, start, body + chunk_size - start, 0);

        // reset stuff
        to_write -= chunk_size;
        body     += chunk_size;
        start     = body - chunk_header_size;
        pkt->chunk_type = CHUNK_TINY;
    }

    if (!r->out_channels[pkt->chunk_id]) {
        rtmp_packet *p = malloc(sizeof(rtmp_packet));
        if (!p) {
            fprintf(stderr, "ENOMEM when sending packet\n");
            goto send_error;
        }
        r->out_channels[pkt->chunk_id] = p;
    }
    memcpy(r->out_channels[pkt->chunk_id], pkt, sizeof(rtmp_packet));
    if (CHUNK_LARGE == pkt->chunk_type)
        r->out_channels[pkt->chunk_id]->ts_delta = pkt->timestamp;
    r->out_channels[pkt->chunk_id]->body = NULL; // dont store for outbound
    r->tx += chunk_header_size + header_size + to_write;
    return chunk_header_size + header_size + to_write;

send_error:
    return -1; //XXX do something drastic
}
