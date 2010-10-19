#include "amf.h"

// NB: mostly serves to get rid of signedness warnings with -Wall.

#define AVALSTR(s) { .av_val = (char*)s, .av_len = strlen(s) }

// Encoding functions
uint8_t inline *amf_write_i32(uint8_t *s, uint8_t *e, int i)
{
    return (uint8_t*)AMF_EncodeInt32((char*)s, (char*)e, i);
}

uint8_t inline *amf_write_i24(uint8_t *s, uint8_t *e, int i)
{
    return (uint8_t*)AMF_EncodeInt24((char*)s, (char*)e, i);
}

uint8_t inline *amf_write_i16(uint8_t *s, uint8_t *e, int i)
{
    return (uint8_t*)AMF_EncodeInt16((char*)s, (char*)e, i);
}

uint8_t inline *amf_write_dbl(uint8_t *s, uint8_t *e, double d)
{
    return (uint8_t*)AMF_EncodeNumber((char*)s, (char*)e, d);
}

uint8_t inline *amf_write_str(uint8_t *s, uint8_t *e, const char *c)
{
    AVal a = AVALSTR(c);
    return (uint8_t*)AMF_EncodeString((char*)s, (char*)e, &a);
}

uint8_t inline *amf_write_dbl_kv(uint8_t *s, uint8_t *e, const char *k, double v)
{
    AVal a = AVALSTR(k);
    return (uint8_t*)AMF_EncodeNamedNumber((char*)s, (char*)e, &a, v);
}

uint8_t inline *amf_write_str_kv(uint8_t *s, uint8_t *e, const char *k, const char *v)
{
    AVal a = AVALSTR(k);
    AVal b = AVALSTR(v);
    return (uint8_t *)AMF_EncodeNamedString((char*)s, (char*)e, &a, &b);
}

// Decoding functions
uint32_t inline amf_read_i32(const uint8_t *b)
{
    return (uint32_t)AMF_DecodeInt32((const char*)b);
}

uint32_t inline amf_read_i24(const uint8_t *b)
{
    return (uint32_t)AMF_DecodeInt24((const char *)b);
}

uint32_t inline amf_read_i16(const uint8_t *b)
{
    return (uint32_t)AMF_DecodeInt16((const char*)b);
}

double inline amf_read_dbl(const uint8_t *b)
{
    return (double)AMF_DecodeNumber((const char*)b);
}

void inline amf_read_str(const uint8_t *b, AVal *a)
{
    AMF_DecodeString((const char *)b, a);
}

#undef AVALSTR
