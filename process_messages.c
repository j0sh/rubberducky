#ifndef _RTMP_HANDLE_INVOKE_C_
#define _RTMP_HANDLE_INVOKE_C_

// functions to handle 0x14 messages stuff
// in a separate file because they're ugly

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <librtmp/amf.h>

#include "mediaserver.h"
#include "amf.h"

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

// other netconnection commands
SAVC(releaseStream);
SAVC(FCPublish);
SAVC(FCUnpublish);
SAVC(createStream);
SAVC(deleteStream);
SAVC(publish);
SAVC(play);

#define STR2AVAL(av,str)	av.av_val = str; av.av_len = strlen(av.av_val)

static int send_result(rtmp *rtmp, double txn, double stream_id, int ts)
{
    uint8_t pbuf[128], *end = pbuf+sizeof(pbuf), *enc = pbuf, *foo;
    enc = amf_write_str(enc, end, "_result");
    enc = amf_write_dbl(enc, end, txn);
    *enc++ = AMF_NULL; //command object
    enc = amf_write_dbl(enc, end, stream_id); // IS THIS A HEADER?!?
    foo = pbuf;
    rtmp_packet packet = {
        .chunk_id = 0x03,
        .msg_type = 0x14,
        .msg_id = 0,
        .timestamp = ts,
        .size = enc - foo,
        .body = foo
    };
    return rtmp_send(rtmp, &packet);
}

static int send_onbw_done(rtmp *rtmp, int ts)
{
    uint8_t pbuf[128], *end = pbuf+sizeof(pbuf), *enc = pbuf, *foo;
    enc = amf_write_str(enc, end, "onBWDone");
    enc = amf_write_dbl(enc, end, 0);
    *enc++ = AMF_NULL; // command object
    foo = pbuf;
    rtmp_packet packet = {
        .chunk_id = 0x03,
        .msg_type = 0x14,
        .msg_id = 0,
        .timestamp = ts,
        .size = enc - foo,
        .body = foo
    };
    return rtmp_send(rtmp, &packet);
}

static int send_cxn_resp(rtmp *rtmp, double txn, int ts)
{
    rtmp_packet packet;
    uint8_t pbuf[384], *pend = pbuf+sizeof(pbuf), *enc;
  AMFObject obj;
  AMFObjectProperty p, op;

    packet.chunk_id = 0x03; // control channel
    packet.msg_type = 0x14;
    packet.msg_id = 0;
    packet.timestamp = ts;
    packet.body = enc = pbuf;

  enc = amf_write_str(enc, pend, "_result");
  enc = amf_write_dbl(enc, pend, txn);
  *enc++ = AMF_OBJECT;

  enc = amf_write_str_kv(enc, pend, "fmsVer", "FMS/3,5,1,525");
  enc = amf_write_dbl_kv(enc, pend, "capabilities", 31.0);
  enc = amf_write_dbl_kv(enc, pend, "mode", 1.0);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  *enc++ = AMF_OBJECT;

  enc = amf_write_str_kv(enc, pend, "level", "status");
  enc = amf_write_str_kv(enc, pend, "code", "NetConnection.Connect.Success");
  enc = amf_write_str_kv(enc, pend, "description", "Connection succeeded.");
  enc = amf_write_dbl_kv(enc, pend, "objectEncoding", rtmp->encoding);
  STR2AVAL(p.p_name, "version");
  STR2AVAL(p.p_vu.p_aval, "3,5,1,525");
  p.p_type = AMF_STRING;
  obj.o_num = 1;
  obj.o_props = &p;
  op.p_type = AMF_OBJECT;  // nested
  STR2AVAL(op.p_name, "data");
  op.p_vu.p_object = obj;
  enc = (uint8_t*)AMFProp_Encode(&op, (char*)enc, (char*)pend);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

    packet.size = enc - packet.body;
    return rtmp_send(rtmp, &packet);
}

typedef enum {PUBLISH = 0, UNPUBLISH, PLAY, RESET} stream_cmd;
static int send_fcpublish(rtmp *rtmp, const char *streamname,
                          double txn, stream_cmd action, int ts)
{
    uint8_t pbuf[256], *end = pbuf+sizeof(pbuf), *enc = pbuf, *foo;
    const char *key, *value;
    switch (action) {
    case PUBLISH:
        key = "onFCPublish";
        value = "NetStream.Publish.Start";
        break;
    case UNPUBLISH:
        key = "onFCUnpublish";
        value = "NetStream.Unpublish.Success";
        break;
    default:
        value = "We.fucked.up.sorry";
    }

    enc = amf_write_str(enc, end, key);
    enc = amf_write_dbl(enc, end, txn);
    *enc++ = AMF_NULL; // command object

    *enc++ = AMF_OBJECT;
    enc = amf_write_str_kv(enc, end, "code", value);
    enc = amf_write_str_kv(enc, end, "description", streamname);
    *enc++ = 0;
    *enc++ = 0;
    *enc++ = AMF_OBJECT_END;

    foo = pbuf;
    rtmp_packet packet = {
        .chunk_id = 0x03,
        .msg_type = 0x14,
        .msg_id = 0,
        .timestamp = ts,
        .size = enc - foo,
        .body = foo
    };

    return rtmp_send(rtmp, &packet);
}

static int send_onstatus(rtmp *r, rtmp_stream *s,
                         stream_cmd action, int ts)
{
    uint8_t pbuf[256], *end = pbuf+sizeof(pbuf), *enc = pbuf, *foo;
    char tbuf[64], pubstr[64]; //XXX this might not be enough later on
    enc = amf_write_str(enc, end, "onStatus");
    enc = amf_write_dbl(enc, end, 0); // transaction id
    *enc++ = AMF_NULL; // command object

    // TODO checks to enforce string bounds here (and everywhere else)
    switch(action) {
    case PUBLISH:
        strncpy(pubstr, "NetStream.Publish.Start", sizeof(pubstr));
        snprintf(tbuf, sizeof(tbuf), "%s is now published.", s->name);
        break;
    case UNPUBLISH:
        strncpy(pubstr, "NetStream.Unpublish.Success", sizeof(pubstr));
        snprintf(tbuf, sizeof(tbuf), "%s is now unpublished.", s->name);
        break;
    case PLAY:
        //XXX this state really should be 'play pending' or something
        //TODO send PlayPublishNotify when actually ready to play
        strncpy(pubstr, "NetStream.Play.Start", sizeof(pubstr));
        snprintf(tbuf, sizeof(tbuf), "%s is now published.", s->name);
        break;
    case RESET:
        strncpy(pubstr, "NetStream.Play.Reset", sizeof(pubstr));
        snprintf(tbuf, sizeof(tbuf), "Playing and resetting %s.", s->name);
        break;
    default:
        strncpy(pubstr, "oops", sizeof(pubstr));
    }

    *enc++ = AMF_OBJECT;
    enc = amf_write_str_kv(enc, end, "level", "status");
    enc = amf_write_str_kv(enc, end, "code", pubstr);
    enc = amf_write_str_kv(enc, end, "description", tbuf);
    enc = amf_write_str_kv(enc, end, "details", s->name);
    enc = amf_write_str_kv(enc, end, "clientid", "RUBBERDUCKY"); // TODO fix
    *enc++ = 0;
    *enc++ = 0;
    *enc++ = AMF_OBJECT_END;

    foo = pbuf;
    rtmp_packet packet = {
        .chunk_id = 0x04,
        .msg_type = 0x14,
        .msg_id = s->id,
        .timestamp = ts,
        .size = enc - foo,
        .body = foo
    };

    return rtmp_send(r, &packet);
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
                char *app = malloc(pval.av_len + 1);
                if (!app) { // do something drastic!
                    fprintf(stderr, "Out of memory!\n");
                }
                strncpy(app, pval.av_val, pval.av_len);
                app[pval.av_len] = '\0'; // pval may not be nulled
                rtmp->app = app;
                fprintf(stdout, "app: %s\n", rtmp->app);
                pval.av_val = NULL;
            } else if(AVMATCH(&pname, &av_flashVer))
            {
                //rtmp->Link.flashVer = pval;
                pval.av_val = NULL;
            } else if(AVMATCH(&pname, &av_tcUrl))
            {
                fprintf(stdout, "tcUrl: %s\n", pval.av_val);
                rtmp->url = malloc(pval.av_len + 1);
                if (!rtmp->url) { // TODO something drastic
                    fprintf(stderr, "Out of memory when allocating tc_url!\n");
                    return;
                }
                strncpy(rtmp->url, pval.av_val, pval.av_len);
                rtmp->url[pval.av_len] = '\0';
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
                switch((int)cobj.o_props[i].p_vu.p_number) {
                case AMF0:
                    rtmp->encoding = AMF0;
                    break;
                case AMF3:
                    rtmp->encoding = AMF3;
                    break;
                default:
                    fprintf(stderr, "Unknown AMF encoding %d\n",
                            (int)cobj.o_props[i].p_vu.p_number);
                    return; // XXX do something drastic; close cxn?
                }
                fprintf(stderr, "object encoding: AMF%d\n",
                        rtmp->encoding);
            }
            // unrecognized string
            if(pval.av_val)
            {
                // do something? log?
            }
            //rtmp->m_bSendCounter = FALSE; // for sending bytes received message
        }
}

static int send_avc_seq(rtmp *r, rtmp_stream *stream)
{
    uint8_t *body = stream->avc_seq;
    int size = stream->avc_seq_size;
    rtmp_packet packet = {
        .chunk_id  = 0x04,
        .msg_id    = stream->id,
        .msg_type  = 0x09,
        .timestamp = 0,
        .body      = body,
        .size      = size
    };
    fprintf(stdout, "Sending AVC sequence header.\n");
    return rtmp_send(r, &packet);
}

static int send_aac_seq(rtmp *r, rtmp_stream *stream)
{
    uint8_t *body = stream->aac_seq;
    int size = stream->aac_seq_size;
    rtmp_packet packet = {
        .chunk_id  = 0x04,
        .msg_id    = stream->id,
        .msg_type  = 0x08,
        .timestamp = 0,
        .body      = body,
        .size      = size
    };
    fprintf(stdout, "Sending AAC sequence header.\n");
    return rtmp_send(r, &packet);
}

static int send_metadata(rtmp *r, rtmp_stream *stream)
{
    uint8_t *body = stream->metadata;
    int size = stream->metadata_size;
    rtmp_packet packet = {
        .chunk_id = 0x04,
        .msg_id = stream->id,
        .msg_type = 0x12,
        .timestamp = 0,
        .body = body,
        .size = size
    };
    fprintf(stdout, "Sending metadata!\n");
    return rtmp_send(r, &packet);
}

static void handle_invoke(rtmp *r, rtmp_packet *pkt)
{
    uint8_t *body = pkt->body;
    int pkt_len = pkt->size;
    double txn; // transaction id
    const char *errstr;
    AMFObject obj;
    AVal method, val;

    while (!*body){
        // for the fucked case in which: type 11 (Flex/AMF3) message
        // is received but in AMF0 format, *and* prefixed with an
        // an extra zero byte. Flash sux
        body++;
        pkt_len--;
    }
    if (body[0] != 0x02) // sanity check
    {
        errstr = "Body not 0x02";
        goto invoke_error;
    }
    if((pkt_len = AMF_Decode(&obj, (char*)body, pkt_len, FALSE)) < 0)
    {
        errstr = "Error decoding AMF object";
        goto invoke_error;
    }
    AMFProp_GetString(AMF_GetProp(&obj, NULL, 0), &method);
    txn = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 1));

    if(AVMATCH(&method, &av_connect))
    {
        int ts = pkt->timestamp + 1;
        send_ack_size(r, ts++);
        send_peer_bw(r, ts++);
        send_ping(r, ts++);
        send_onbw_done(r, ts++);
        handle_connect(r, pkt, &obj);
        send_cxn_resp(r, txn, ts++);
    } else if(AVMATCH(&method, &av_releaseStream))
    {
        send_result(r, txn, pkt->msg_id, pkt->timestamp + 1);
    } else if(AVMATCH(&method, &av_FCPublish))
    {
        send_result(r, txn, pkt->msg_id, pkt->timestamp + 1);
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &val);
        send_fcpublish(r, val.av_val, txn, PUBLISH, pkt->timestamp + 2);
    } else if(AVMATCH(&method, &av_FCUnpublish))
    {
        send_result(r, txn, pkt->msg_id, pkt->timestamp + 1);
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &val);
        send_fcpublish(r, val.av_val, txn, UNPUBLISH, pkt->timestamp + 2);
    } else if(AVMATCH(&method, &av_createStream))
    {
        int i;
        // XXX stream ids, for some reason, *must* be >1!
        for (i = 1; i < RTMP_MAX_STREAMS; i++) {
            if (!r->streams[i]) {
                rtmp_stream *stream = malloc(sizeof(rtmp_stream));
                if (!stream) { // TODO something drastic
                    fprintf(stderr, "Out of memory for stream!\n");
                    return;
                }
                memset(stream, 0, sizeof(rtmp_stream));
                stream->id = i;
                r->streams[i] = stream;
                break;
            }
        }
        if (i != RTMP_MAX_STREAMS)
            send_result(r, txn, r->streams[i]->id, pkt->timestamp + 1);
        else
            fprintf(stderr, "Maximum number of streams exceeded!\n");
    } else if(AVMATCH(&method, &av_publish))
    {
        AVal type = {0, 0};
        rtmp_stream *stream;
        // transaction id (index 1) is always zero here,
        // command object (index 2) is always null here.
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &val);
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 4), &type); //XXX live/recod/append
        stream = r->streams[pkt->msg_id];
        if (!stream) {
            fprintf(stderr, "Unable to publish; stream ID invalid.\n");
            return;
        }
                stream->name = malloc(val.av_len + 1);
                if (!stream->name) { // TODO something drastic
                    free(stream);
                    fprintf(stderr, "Out of memory for stream name!\n");
                    return;
                }
                strncpy(stream->name, val.av_val, val.av_len);
                stream->name[val.av_len] = '\0';

                // use strncmp variant because the type is not likely to
                // be null-terminated, so avoid a 1-byte overread. Note
                // the type is usually the last element in the packet body
                if (!type.av_len || !strncmp(type.av_val, "live", 4)) {
                    stream->type = LIVE;
                } else if (!strncmp(type.av_val, "record", 6)) {
                    stream->type = RECORD;
                } else if (!strncmp(type.av_val, "append", 6)) {
                    stream->type = APPEND;
                }

        if (r->publish_cb)
            r->publish_cb(r, stream);
        send_onstatus(r, stream, PUBLISH, pkt->timestamp + 1);
        fprintf(stdout, "publishing %s (id %d)\n",
                stream->name, stream->id);
    } else if(AVMATCH(&method, &av_deleteStream))
    {
        int stream_id;
        stream_id = (int)AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 3));
        if (!r->streams[stream_id]) {
            fprintf(stderr, "Unable to delete stream; invalid id %d\n", stream_id);
            return;
        }

        // only for published streams
        if (VOD != r->streams[stream_id]->type)
            send_onstatus(r, r->streams[stream_id], UNPUBLISH,
                          pkt->timestamp + 1);
        if (r->delete_cb) r->delete_cb(r, r->streams[stream_id]);
        rtmp_free_stream(&r->streams[stream_id]);
        fprintf(stderr, "Deleting stream %d\n", stream_id);
    } else if(AVMATCH(&method, &av_play))
    {
        char *streamname; // because val won't be null terminated
        int start, duration, reset, ts = pkt->timestamp + 1;
        rtmp_stream *stream = r->streams[pkt->msg_id];
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &val);
        start = (int)AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 4));
        duration = (int)AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 5));
        reset = AMFProp_GetBoolean(AMF_GetProp(&obj, NULL, 6));

        streamname = malloc(val.av_len + 1);
        if (!streamname){ errstr = "Outta memory!"; goto invoke_error; }
        strncpy(streamname, val.av_val, val.av_len);
        streamname[val.av_len] = '\0';
        stream->name = streamname;

        if (r->play_cb && !r->play_cb(r, stream))
            return;

        // send allll the messages flash player requires
        send_chunksize(r, 1400, ts++); // close to MTU
        // XXX send streamisrecorded usercontrol message (????)
        send_stream_begin(r, stream->id, ts++);
        send_onstatus(r, stream, PLAY, ts++);
        if (reset)
            send_onstatus(r, stream, RESET, ts++);
        if (stream->metadata) send_metadata(r, stream);
        if (stream->aac_seq) send_aac_seq(r, stream);
        if (stream->avc_seq) send_avc_seq(r, stream);

        fprintf(stderr, "Playing video %s\n", streamname);
    }
    AMF_Reset(&obj);

    return;

invoke_error:
    fprintf(stderr, "%s\n", errstr);

}

#endif
