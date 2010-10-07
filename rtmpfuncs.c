#include "rtmp.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/socket.h>
#include <unistd.h>

#include <librtmp/amf.h>

void rtmp_init(rtmp *r)
{
    memset(r, 0, sizeof(rtmp));
    r->chunk_size = RTMP_DEFAULT_CHUNKSIZE;
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
    close(r->fd);
    if (r->app) free(r->app);
}

int rtmp_send(rtmp *r, rtmp_packet *pkt) {
    rtmp_packet *prev = r->out_channels[pkt->chunk_id];
    uint32_t ts = pkt->timestamp;
    uint8_t *header, *start, *body;
    char *amf_header; //work around compiler warnings
    int header_size, chunk_header_size, chunk_size, to_write;

    if (prev && CHUNK_LARGE != pkt->chunk_type) {
        if (prev->size == pkt->size &&
            prev->msg_type == pkt->msg_type &&
            CHUNK_MEDIUM == pkt->chunk_type) {
            pkt->chunk_type = CHUNK_SMALL;
        } else if (prev->timestamp == pkt->timestamp &&
            CHUNK_SMALL == pkt->chunk_type) {
            pkt->chunk_type = CHUNK_TINY;
        } else {
            pkt->chunk_type = CHUNK_MEDIUM;
        }
        ts -= prev->timestamp;
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

    if (ts >= 0xffffff) {
        header_size += 4;
        // just write the extended timestamp now
        AMF_EncodeInt32((char*)pkt->body - 4, (char*)pkt->body, ts);
    }

    // XXX make sure there is room behind the packet body!
    header     = pkt->body - header_size - chunk_header_size;
    start      = header;
    body       = pkt->body;
    to_write   = pkt->size;
    chunk_size = r->chunk_size;

    // encode header proper
    header += chunk_header_size; // fast-forward; skip chunk hdr for now
    amf_header = (char*)header; // quieten compiler
    switch (pkt->chunk_type) {
    case CHUNK_LARGE:
        AMF_EncodeInt24(&amf_header[7], &amf_header[7]+header_size, pkt->msg_id);
    case CHUNK_MEDIUM:
        amf_header[6] = pkt->msg_type;
        AMF_EncodeInt24(&amf_header[3], &amf_header[3]+header_size, pkt->size);
    case CHUNK_SMALL:
        AMF_EncodeInt24(amf_header, amf_header+header_size, ts > 0xffffff ? 0xffffff : ts);
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
    r->out_channels[pkt->chunk_id]->body = NULL; // dont store for outbound
    r->tx += chunk_header_size + header_size + to_write;
    return chunk_header_size + header_size + to_write;

send_error:
    return -1; //XXX do something drastic
}
