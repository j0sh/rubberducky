#include <librtmp/rtmp.h>

#define QUOTELITERAL(x) #x
#define QUOTEVALUE(x) QUOTELITERAL(x)

#define RTMP_PORT         1935
#define RTMP_PORT_STRING  QUOTEVALUE(RTMP_PORT)

void rtmp_invoke(RTMP *rtmp, RTMPPacket *pkt);
