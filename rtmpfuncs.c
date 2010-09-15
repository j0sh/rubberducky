#include "rtmp.h"

#include <string.h>
#include <stdlib.h>

int rtmp_init(rtmp *r)
{
    memset(r->in_channels, 0, sizeof(struct rtmp_packet*) * RTMP_CHANNELS);
    r->chunk_size = RTMP_DEFAULT_CHUNKSIZE;
    r->read_cb = NULL;
}

static void free_packet(struct rtmp_packet **packet) {
    struct rtmp_packet *pkt = *packet;
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
    }
}
