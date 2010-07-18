#include <librtmp/rtmp.h>

#define QUOTELITERAL(x) #x
#define QUOTEVALUE(x) QUOTELITERAL(x)

#define RTMP_PORT         1935
#define RTMP_PORT_STRING  QUOTEVALUE(RTMP_PORT)

#include "mediaserver.h"

void rtmp_invoke(RTMP *rtmp, RTMPPacket *pkt, srv_ctx *ctx);
