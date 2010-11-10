#ifndef VIDEOAPI_AMF_H
#define VIDEOAPI_AMF_H

#include <stdint.h>
#include <string.h>

// NB: mostly serves to silence signedness warnings with -Wall.

#include <librtmp/amf.h>

// Encoding functions
uint8_t *amf_write_i32(uint8_t *s, uint8_t *e, int i);
uint8_t *amf_write_i24(uint8_t *s, uint8_t *e, int i);
uint8_t *amf_write_i16(uint8_t *s, uint8_t *e, int i);
uint8_t *amf_write_dbl(uint8_t *s, uint8_t *e, double d);
uint8_t *amf_write_str(uint8_t *s, uint8_t *e, const char *c);
uint8_t *amf_write_dbl_kv(uint8_t *s, uint8_t *e, const char *k, double v);
uint8_t *amf_write_str_kv(uint8_t *s, uint8_t *e, const char *k, const char *v);

// Decoding functions
uint32_t amf_read_i32(const uint8_t *b);
uint32_t amf_read_i24(const uint8_t *b);
uint32_t amf_read_i16(const uint8_t *b);
double   amf_read_dbl(const uint8_t *b);
double   amf_read_dbl_kv(AMFObject *o, const char *k);
void     amf_read_str(const uint8_t *b, AVal *a);

#endif
