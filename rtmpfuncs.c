#include "rtmp.h"

#include <string.h>
#include <stdlib.h>

int rtmp_init(rtmp *r)
{
    memset(r->in_channels, 0, sizeof(struct rtmp_packet*) * RTMP_CHANNELS);
    r->chunk_size = RTMP_DEFAULT_CHUNKSIZE;
    r->read_cb = NULL;
}

void rtmp_free(rtmp *r)
{
    int i;
    for (i = 0; i < RTMP_CHANNELS; i++) {
        struct rtmp_packet *pkt = r->in_channels[i];
        if (pkt) {
            if (pkt->body) {
                free(pkt->body);
                pkt->body = NULL;
            }
            free(pkt);
            r->in_channels[i] = NULL;
        }
    }
}
