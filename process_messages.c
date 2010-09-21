/* Bindings for the librtmp library.
 */

/**
 * TODO take packet init off the stack and use a slab-type allocator
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <librtmp/amf.h>

#include "process_messages.h"

// yanked wholesale from librtmp
#define SAVC(x) static const AVal av_##x = AVC(#x)
// client connect parms
SAVC(connect);
SAVC(app);
SAVC(flashVer);
SAVC(tcUrl);
SAVC(pageUrl);
SAVC(audioCodecs);
SAVC(videoCodecs);
SAVC(objectEncoding);

// server connect parms
SAVC(_result);
SAVC(fmsVer);
SAVC(capabilities);
SAVC(mode);
SAVC(level);
SAVC(code);
SAVC(description);

// other netconnection commands
SAVC(releaseStream);
SAVC(FCPublish);
SAVC(FCUnpublish);
SAVC(createStream);
SAVC(deleteStream);
SAVC(publish);
SAVC(play);

#define STR2AVAL(av,str)	av.av_val = str; av.av_len = strlen(av.av_val)

static int set_peer_bw(rtmp *rtmp)
{
    uint8_t pbuf[RTMP_MAX_HEADER_SIZE+5] = {0};
    AMF_EncodeInt32(pbuf + RTMP_MAX_HEADER_SIZE, pbuf + RTMP_MAX_HEADER_SIZE + 4, 0x0fffffff);
    pbuf[RTMP_MAX_HEADER_SIZE + 4] = 2;
    rtmp_packet packet = {
        .chunk_id = 0x02,
        .msg_id = 0,
        .msg_type = 0x06,
        .timestamp = 0,
        .size = sizeof(pbuf) - RTMP_MAX_HEADER_SIZE,
        .body = pbuf + RTMP_MAX_HEADER_SIZE
    };
    fprintf(stdout, "sending clientbw, rx: %d, tx %d\n", rtmp->rx, rtmp->tx);
    return rtmp_send(rtmp, &packet);
}

static int window_ack_size(rtmp *rtmp)
{
    uint8_t pbuf[RTMP_MAX_HEADER_SIZE + 4] = { 0 };
    AMF_EncodeInt32(pbuf + RTMP_MAX_HEADER_SIZE, pbuf + RTMP_MAX_HEADER_SIZE + 4, 0x0fffffff);
    rtmp_packet packet = {
        .chunk_id = 0x02,
        .msg_id = 0,
        .msg_type = 0x05,
        .timestamp = 0,
        .size = sizeof(pbuf) - RTMP_MAX_HEADER_SIZE,
        .body = pbuf + RTMP_MAX_HEADER_SIZE
    };
    return rtmp_send(rtmp, &packet);
}

static int send_ping(rtmp *rtmp)
{
    time_t now = time(NULL);
    uint8_t pbuf[RTMP_MAX_HEADER_SIZE+4];
    AMF_EncodeInt32(pbuf + RTMP_MAX_HEADER_SIZE, pbuf + sizeof(pbuf), now);
    memset(pbuf, 0, RTMP_MAX_HEADER_SIZE);
    rtmp_packet packet = {
        .chunk_id = 0x02,
        .msg_id = 0,
        .msg_type = 0x04,
        .timestamp = 0,
        .size = sizeof(pbuf) - RTMP_MAX_HEADER_SIZE,
        .body = pbuf + RTMP_MAX_HEADER_SIZE
    };
    return rtmp_send(rtmp, &packet);
}

//XXX figure out just WTF the stream id is used for
static int send_result(rtmp *rtmp, double txn, double stream_id)
{
    uint8_t pbuf[128], *end = pbuf+sizeof(pbuf), *enc = pbuf+RTMP_MAX_HEADER_SIZE, *foo;
    enc = AMF_EncodeString(enc, end, &av__result);
    enc = AMF_EncodeNumber(enc, end, txn);
    *enc++ = AMF_NULL; //command object
    enc = AMF_EncodeNumber(enc, end, stream_id); // IS THIS A HEADER?!?
    foo = pbuf+RTMP_MAX_HEADER_SIZE;
    rtmp_packet packet = {
        .chunk_id = 0x03,
        .msg_type = 0x14,
        .msg_id = 0,
        .timestamp = 0,
        .size = enc - foo,
        .body = foo
    };
    return rtmp_send(rtmp, &packet);
}

static int send_onbw_done(rtmp *rtmp)
{
    // i have never actually seen a flash client make use of this.
    SAVC(onBWDone);
    uint8_t pbuf[128], *end = pbuf+sizeof(pbuf), *enc = pbuf+RTMP_MAX_HEADER_SIZE, *foo;
    enc = AMF_EncodeString(enc, end, &av_onBWDone);
    enc = AMF_EncodeNumber(enc, end, 0);
    *enc++ = AMF_NULL; // command object
    foo = pbuf+RTMP_MAX_HEADER_SIZE;
    rtmp_packet packet = {
        .chunk_id = 0x03,
        .msg_type = 0x14,
        .msg_id = 0,
        .timestamp = 0,
        .size = enc - foo,
        .body = foo
    };
    return rtmp_send(rtmp, &packet);
}

static int send_cxn_resp(rtmp *rtmp, double txn)
{
    rtmp_packet packet;
  uint8_t pbuf[384], *pend = pbuf+sizeof(pbuf), *enc;
  AMFObject obj;
  AMFObjectProperty p, op;
  AVal av;

    packet.chunk_id = 0x03; // control channel
    packet.msg_type = 0x14;
    packet.msg_id = 0;
    packet.timestamp = 0;
    packet.body = pbuf + RTMP_MAX_HEADER_SIZE;

    memset(pbuf, 0, RTMP_MAX_HEADER_SIZE);
    enc = AMF_EncodeString(packet.body, pend, &av__result);
  enc = AMF_EncodeNumber(enc, pend, txn);
  *enc++ = AMF_OBJECT;

  STR2AVAL(av, "FMS/3,5,1,525");
  enc = AMF_EncodeNamedString(enc, pend, &av_fmsVer, &av);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_capabilities, 31.0);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_mode, 1.0);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  *enc++ = AMF_OBJECT;

  STR2AVAL(av, "status");
  enc = AMF_EncodeNamedString(enc, pend, &av_level, &av);
  STR2AVAL(av, "NetConnection.Connect.Success");
  enc = AMF_EncodeNamedString(enc, pend, &av_code, &av);
  STR2AVAL(av, "Connection succeeded.");
  enc = AMF_EncodeNamedString(enc, pend, &av_description, &av);
  //enc = AMF_EncodeNamedNumber(enc, pend, &av_objectEncoding, rtmp->m_fEncoding);
  STR2AVAL(p.p_name, "version");
  STR2AVAL(p.p_vu.p_aval, "3,5,1,525");
  p.p_type = AMF_STRING;
  obj.o_num = 1;
  obj.o_props = &p;
  op.p_type = AMF_OBJECT;  // nested
  STR2AVAL(op.p_name, "data");
  op.p_vu.p_object = obj;
  enc = AMFProp_Encode(&op, enc, pend);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

    packet.size = enc - packet.body;
    return rtmp_send(rtmp, &packet);
}

typedef enum {publish = 0, unpublish, play} stream_cmd;
static int send_fcpublish(rtmp *rtmp, AVal *streamname,
                          double txn, stream_cmd action)
{
    uint8_t pbuf[256], *end = pbuf+sizeof(pbuf), *enc = pbuf+RTMP_MAX_HEADER_SIZE, *foo;
    AVal key, value;
    switch (action) {
    case publish:
        STR2AVAL(key, "onFCPublish");
        STR2AVAL(value, "NetStream.Publish.Start");
        break;
    case unpublish:
        STR2AVAL(key, "onFCUnpublish");
        STR2AVAL(value, "NetStream.Unpublish.Success");
        break;
    default:
        STR2AVAL(value, "We.fucked.up.sorry");
    }

    enc = AMF_EncodeString(enc, end, &key);
    enc = AMF_EncodeNumber(enc, end, txn);
    *enc++ = AMF_NULL; // command object

    *enc++ = AMF_OBJECT;
    STR2AVAL(key, "code");
    enc = AMF_EncodeNamedString(enc, end, &key, &value);
    STR2AVAL(key, "description");
    enc = AMF_EncodeNamedString(enc, end, &key, streamname);
    *enc++ = 0;
    *enc++ = 0;
    *enc++ = AMF_OBJECT_END;

    foo = pbuf+RTMP_MAX_HEADER_SIZE;
    rtmp_packet packet = {
        .chunk_id = 0x03,
        .msg_type = 0x14,
        .msg_id = 0,
        .timestamp = 0,
        .size = enc - foo,
        .body = foo
    };

    return rtmp_send(rtmp, &packet);
}

static int send_onstatus(rtmp *rtmp, AVal *streamname, stream_cmd action)
{
    uint8_t pbuf[256], *end = pbuf+sizeof(pbuf), *enc = pbuf+RTMP_MAX_HEADER_SIZE, *foo;
    uint8_t tbuf[64], pubstr[64]; //XXX this might not be enough later on
    AVal key, value;
    STR2AVAL(value, "onStatus");
    enc = AMF_EncodeString(enc, end, &value);
    enc = AMF_EncodeNumber(enc, end, 0); // transaction id
    *enc++ = AMF_NULL; // command object

    // TODO checks to enforce string bounds here (and everywhere else)
    switch(action) {
    case publish:
        strncpy(pubstr, "NetStream.Publish.Start", sizeof(pubstr));
        snprintf(tbuf, sizeof(tbuf), "%s is now published.", streamname->av_val);
        break;
    case unpublish:
        strncpy(pubstr, "NetStream.Unpublish.Success", sizeof(pubstr));
        snprintf(tbuf, sizeof(tbuf), "%s is now unpublished.", streamname->av_val);
        break;
    case play:
        //XXX this state really should be 'play pending' or something
        //TODO send PlayPublishNotify when actually ready to play
        //TODO send Play.Reset chunk before Play.Start
        strncpy(pubstr, "NetStream.Play.Start", sizeof(pubstr));
        snprintf(tbuf, sizeof(tbuf), "%s is now published.", streamname->av_val);
        break;
    default:
        strncpy(pubstr, "oops", sizeof(pubstr));
    }

    *enc++ = AMF_OBJECT;
    STR2AVAL(key, "level");
    STR2AVAL(value, "status");
    enc = AMF_EncodeNamedString(enc, end, &key, &value);
    STR2AVAL(key, "code");
    STR2AVAL(value, pubstr);
    enc = AMF_EncodeNamedString(enc, end, &key, &value);
    STR2AVAL(key, "description");
    STR2AVAL(value, tbuf);
    enc = AMF_EncodeNamedString(enc, end, &key, &value);
    STR2AVAL(key, "clientid");
    STR2AVAL(value, "RUBBERDUCKY"); //XXX fix
    enc = AMF_EncodeNamedString(enc, end, &key, &value);
    *enc++ = 0;
    *enc++ = 0;
    *enc++ = AMF_OBJECT_END;

    foo = pbuf+RTMP_MAX_HEADER_SIZE;
    rtmp_packet packet = {
        .chunk_id = 0x04,
        .msg_type = 0x14,
        .msg_id = 0,
        .timestamp = 0,
        .size = enc - foo,
        .body = foo
    };

    return rtmp_send(rtmp, &packet);
}

static void handle_connect(rtmp *rtmp, rtmp_packet *pkt, AMFObject *obj)
{
        AMFObject cobj;
        AVal pname, pval;
        int i;
        AMFProp_GetObject(AMF_GetProp(obj, NULL, 2), &cobj);
        for(i = 0; i < cobj.o_num; i++)
        {
            pname = cobj.o_props[i].p_name;
            pval.av_val = NULL;
            pval.av_len = 0;
            if(AMF_STRING == cobj.o_props[i].p_type)
            {
                pval = cobj.o_props[i].p_vu.p_aval;// dammit, ugly
            }
            if(AVMATCH(&pname, &av_app))
            {
                //rtmp->Link.app = pval;
                pval.av_val = NULL;
            } else if(AVMATCH(&pname, &av_flashVer))
            {
                //rtmp->Link.flashVer = pval;
                pval.av_val = NULL;
            } else if(AVMATCH(&pname, &av_tcUrl))
            {
                char *r1 = NULL, *r2;
                int len;
                //rtmp->Link.tcUrl = pval;
                if ('r' == (pval.av_val[0] | 0x40) &&
                    't' == (pval.av_val[1] | 0x40) &&
                    'm' == (pval.av_val[2] | 0x40) &&
                    'p' == (pval.av_val[3] | 0x40))
                {
                    if(':' == pval.av_val[4])
                    {
                        //rtmp->Link.protocol = RTMP_PROTOCOL_RTMP;
                        r1 = pval.av_val+7;
                    } else if('e' == (pval.av_val[4] | 0x40) &&
                              ':' == pval.av_val[5])
                    {
                        //rtmp->Link.protocol = RTMP_PROTOCOL_RTMPE;
                        r1 = pval.av_val+8;
                    }
                    r2 = strchr(r1, '/');
                    len = r2 ? r2 - r1 : pval.av_len - (r1 - pval.av_val);
                    r2 = malloc(len+1); //XXX fix this; LEAKS
                    memcpy(r2, r1, len);
                    r2[len] = '\0';
                    //rtmp->Link.hostname.av_val = r2;
                    r1 = strrchr(r2, ':');
                    if(r1)
                    {
                        //rtmp->Link.hostname.av_len = r1 - r2;
                        *r1++ = '\0';
                        //rtmp->Link.port = atoi(r1);
                    } else {
                        //rtmp->Link.hostname.av_len = len;
                        //rtmp->Link.port = RTMP_PORT;
                    }
                }
                pval.av_val = NULL;
            } else if(AVMATCH(&pname, &av_pageUrl))
            {
                //rtmp->Link.pageUrl = pval;
                pval.av_val = NULL;
            } else if(AVMATCH(&pname, &av_audioCodecs))
            {
                //rtmp->m_fAudioCodecs = cobj.o_props[i].p_vu.p_number;
            } else if(AVMATCH(&pname, &av_videoCodecs))
            {
                //rtmp->m_fVideoCodecs = cobj.o_props[i].p_vu.p_number;
            } else if(AVMATCH(&pname, &av_objectEncoding))
            {
                //rtmp->m_fEncoding = cobj.o_props[i].p_vu.p_number;
                ////rtmp->m_bSendEncoding = TRUE;
            }
            // unrecognized string
            if(pval.av_val)
            {
                // do something? log?
            }
            //rtmp->m_bSendCounter = FALSE; // for sending bytes received message
        }
}

void rtmp_invoke(rtmp *rtmp, rtmp_packet *pkt, srv_ctx *ctx)
{
    uint8_t *body = pkt->body;
    int pkt_len = pkt->size;
    double txn; // transaction id
    const char *errstr;
    AMFObject obj;
    AVal method, val;

    if (body[0] != 0x02) // sanity check
    {
        errstr = "Body not 0x02";
        goto invoke_error;
    }
    if((pkt_len = AMF_Decode(&obj, body, pkt_len, FALSE)) < 0)
    {
        errstr = "Error decoding AMF object";
        goto invoke_error;
    }
    AMFProp_GetString(AMF_GetProp(&obj, NULL, 0), &method);
    txn = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 1));

    if(AVMATCH(&method, &av_connect))
    {
        window_ack_size(rtmp);
        set_peer_bw(rtmp);
        send_ping(rtmp);
        send_onbw_done(rtmp);
        handle_connect(rtmp, pkt, &obj);
        send_cxn_resp(rtmp, txn);
    } else if(AVMATCH(&method, &av_releaseStream))
    {
        send_result(rtmp, txn, 6);
    } else if(AVMATCH(&method, &av_FCPublish))
    {
        send_result(rtmp, txn, 6);
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &val);
        send_fcpublish(rtmp, &val, txn, publish);
    } else if(AVMATCH(&method, &av_FCUnpublish))
    {
        send_result(rtmp, txn, 0);
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &val);
        send_fcpublish(rtmp, &val, txn, unpublish);
    } else if(AVMATCH(&method, &av_createStream))
    {
        send_result(rtmp, txn, 0);
    } else if(AVMATCH(&method, &av_publish))
    {
        AVal type;
        // transaction id (index 1) is always zero here,
        // command object (index 2) is always null here.
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &val);
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 4), &type); //XXX live/recod/append
        send_onstatus(rtmp, &val, publish);
        //ctx->stream.fd = rtmp->m_sb.sb_socket; // ???
        strncpy(ctx->stream.name, val.av_val, sizeof(ctx->stream.name));
    } else if(AVMATCH(&method, &av_deleteStream))
    {
        AVal type;
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &val);
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 4), &type);
        send_onstatus(rtmp, &val, unpublish);
    } else if(AVMATCH(&method, &av_play))
    {
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &val);
        send_onstatus(rtmp, &val, play);
        //ctx->stream.fds[ctx->stream.cxn_count++] = rtmp;
    }
    AMF_Reset(&obj);

    return;

invoke_error:
    fprintf(stderr, "%s\n", errstr);

}
