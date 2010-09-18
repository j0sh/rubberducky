#define QUOTELITERAL(x) #x
#define QUOTEVALUE(x) QUOTELITERAL(x)

#define RTMP_PORT         1935
#define RTMP_PORT_STRING  QUOTEVALUE(RTMP_PORT)

#include "mediaserver.h"

void rtmp_invoke(rtmp *rtmp, struct rtmp_packet *pkt, srv_ctx *ctx);
