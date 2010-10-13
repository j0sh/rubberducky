/* system includes */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <netinet/in.h>
#include <assert.h>

/* these are primarily for get_uptime */
#include <stdint.h>
#include <sys/times.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>

#if OPENSSL_VERSION_NUMBER < 0x0090800 || !defined(SHA256_DIGEST_LENGTH)
#error Your OpenSSL is too old, need 0.9.8 or newer with SHA256
#endif
#define HMAC_setup(ctx, key, len)	HMAC_CTX_init(&ctx); HMAC_Init_ex(&ctx, key, len, EVP_sha256(), 0)
#define HMAC_crunch(ctx, buf, len)	HMAC_Update(&ctx, buf, len)
#define HMAC_finish(ctx, dig, dlen)	HMAC_Final(&ctx, dig, &dlen); HMAC_CTX_cleanup(&ctx)

/* local includes */
#include "rtmp.h"
#include "amf.h"
#include "mediaserver.h"

#define RTMP_SIG_SIZE 1536
#define SHA256_DIGEST_LENGTH 32

static const uint8_t genuine_fms_key[] = {
  0x47, 0x65, 0x6e, 0x75, 0x69, 0x6e, 0x65, 0x20, 0x41, 0x64, 0x6f, 0x62,
    0x65, 0x20, 0x46, 0x6c,
  0x61, 0x73, 0x68, 0x20, 0x4d, 0x65, 0x64, 0x69, 0x61, 0x20, 0x53, 0x65,
    0x72, 0x76, 0x65, 0x72,
  0x20, 0x30, 0x30, 0x31,	/* Genuine Adobe Flash Media Server 001 */

  0xf0, 0xee, 0xc2, 0x4a, 0x80, 0x68, 0xbe, 0xe8, 0x2e, 0x00, 0xd0, 0xd1,
  0x02, 0x9e, 0x7e, 0x57, 0x6e, 0xec, 0x5d, 0x2d, 0x29, 0x80, 0x6f, 0xab,
    0x93, 0xb8, 0xe6, 0x36,
  0xcf, 0xeb, 0x31, 0xae
};				/* 68 */

static const uint8_t genuine_fp_key[] = {
  0x47, 0x65, 0x6E, 0x75, 0x69, 0x6E, 0x65, 0x20, 0x41, 0x64, 0x6F, 0x62,
    0x65, 0x20, 0x46, 0x6C,
  0x61, 0x73, 0x68, 0x20, 0x50, 0x6C, 0x61, 0x79, 0x65, 0x72, 0x20, 0x30,
    0x30, 0x31,			/* Genuine Adobe Flash Player 001 */
  0xF0, 0xEE,
  0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1, 0x02, 0x9E,
    0x7E, 0x57, 0x6E, 0xEC,
  0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB, 0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB,
    0x31, 0xAE
};				/* 62 */



// 772 is for FP10, 8 otherwise.
const static int digest_offset_values[] = { 8, 772 };

const static int dh_offset_values[] = { 1532, 768 };

// offset for the diffie-hellman key pair. rtmpe only; unused now
static videoapi_unused unsigned int
get_dh_offset(uint8_t *handshake, unsigned int len,
              int initial_offset, int second_offset)
{
  unsigned int offset = 0;
  uint8_t *ptr = handshake + initial_offset;

  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);

  offset = (offset % 632) + second_offset;

  if (offset + 128 > (initial_offset - 1)) {
    fprintf(stderr, "Couldn't calculate correct DH offset (got %d), "
                     "exiting!", offset);
    //TODO close cxn here
  }
  return offset;
}

static int get_digest_offset(uint8_t *b, int initial_offset)
{
    uint8_t *ptr = b+initial_offset;
    unsigned int offset = 0;

    offset += *ptr;
    ptr++;
    offset += *ptr;
    ptr++;
    offset += *ptr;
    ptr++;
    offset += *ptr;

    // we deal with some mysterious numbers here
    offset = (offset % 728) + initial_offset + 4;
    if (offset + 32 > initial_offset + 765) {
        fprintf(stderr, "Digest offset calculations whacked\n");
        //TODO close cxn here
    }

    return offset;
}

/* Calculates a HMAC-SHA256. */
static void hmac(const uint8_t *message, size_t messageLen,
                 const uint8_t *key, size_t keylen, uint8_t *digest)
{
  unsigned int digestLen;
  HMAC_CTX ctx;

  HMAC_setup(ctx, key, keylen);
  HMAC_crunch(ctx, message, messageLen);
  HMAC_finish(ctx, digest, digestLen);

  assert(digestLen == 32);
}

static void calc_digest(unsigned int digestPos, uint8_t *handshake_msg,
                        const uint8_t *key, size_t keylen,
                        uint8_t *digest)
{
    const int messageLen = RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH;
    uint8_t message[RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH];

    memcpy(message, handshake_msg, digestPos);
    memcpy(message + digestPos,
	       &handshake_msg[digestPos + SHA256_DIGEST_LENGTH],
    messageLen - digestPos);
    hmac(message, messageLen, key, keylen, digest);
}


static inline int cmp_digest(unsigned int digestPos, uint8_t* handshake_msg,
                          const uint8_t *key, size_t keylen)
{
    uint8_t the_digest[SHA256_DIGEST_LENGTH];
    calc_digest(digestPos, handshake_msg, key, keylen, the_digest);

    return memcmp(&handshake_msg[digestPos], the_digest, SHA256_DIGEST_LENGTH) == 0;
}

// returns the offset of the signature, zero if digest is invalid.
static int verify_digest(uint8_t* msg, const uint8_t *key, size_t keylen, int offidx)
{
    int off = get_digest_offset(msg, digest_offset_values[offidx]);
    if (cmp_digest(off, msg, key, keylen))
        return off;

    off = get_digest_offset(msg, digest_offset_values[offidx^1]);
    if (cmp_digest(off, msg, key, keylen))
        return off;

    return 0;
}

static uint32_t clk_tck;
static uint32_t get_uptime()
{
    struct tms t;
    if (!clk_tck) clk_tck = sysconf(_SC_CLK_TCK);
    return times(&t) * 1000 / clk_tck;
}

static inline rtmp* get_rtmp(ev_io *w)
{
    return (rtmp*)((uint8_t*)w - offsetof(rtmp, read_watcher));
}

static int read_bytes(rtmp *r, uint8_t *p, int howmany)
{
    int len;
    len = recv(r->fd, p, howmany, 0);
    if (!len) {
        // If no messages are available to be received and the peer
        // has performed an orderly shutdown, recv() shall return 0.
        errno = EIO;
    }
    if (len > 0)
        r->rx += len;
    // TODO send return report if rx exceeds ack size
    return len ;
}

static int init_handshake(ev_io *io)
{
    rtmp *r = get_rtmp(io);
    int len, version, i, *bi, read_size = RTMP_SIG_SIZE + 1;
        uint32_t uptime;
    uint8_t *b, *bend, *signature;
    uint8_t *p, *pe;
    rtmp_packet *pkt = r->in_channels[0], *out = r->out_channels[0];

    if (!out) {
        out = malloc(sizeof(rtmp_packet));
        if (!out) return RTMPERR(ENOMEM);
        memset(out, 0, sizeof(rtmp_packet));
        out->alloc_size = out->size = read_size;
        out->body = malloc(read_size);
        if (!out->body) return RTMPERR(ENOMEM);
        r->out_channels[0] = out;
    }
    b = out->body;
    bend = b + out->size;

    // by convention, we use chunk id 0 for the handshake
    if (!pkt) {
        pkt = malloc(sizeof(rtmp_packet));
        if (!pkt) return RTMPERR(ENOMEM);
        memset(pkt, 0, sizeof(rtmp_packet));
        pkt->alloc_size = pkt->size = read_size;
        pkt->body = malloc(read_size);
        if (!pkt->body) return RTMPERR(ENOMEM);
        r->in_channels[0] = pkt;
    }
    p = pkt->body;

    if ((len = read_bytes(r, p + pkt->read, read_size)) <= 0)
        return RTMPERR(errno);
    pkt->read += len;
    pe  = p + pkt->read;

    // start handshaking
    version = *p;
    switch (version) {
    case 0x03: break;
    case 0x06:
    case 0x08:
        fprintf(stdout, "Encrypted cxns not supported!\n");
        return RTMPERR(ENOSYS);
    case 'P':
    case 'p':
        fprintf(stdout, "Tunnelled cxns not supported!\n");
        return RTMPERR(ENOSYS);
    default:
        fprintf(stdout, "Unknown handshake type %d\n", version);
        return RTMPERR(INVALIDDATA);
    }
    p += 1;

    if (pe - p < RTMP_SIG_SIZE) {
        // we probably haven't received enough data on the wire yet since
        // RTMP_SIG_SIZE is larger than the TCP data MTU
        return RTMPERR(EAGAIN);
    }

        *b++ = version;  // copy version given by client
        uptime = htonl(get_uptime());
        memcpy(b, &uptime, 4); // timestamp
        b += 4;

        // server version. FP9 only
        *b++ = FMS_VER_MAJOR;
        *b++ = FMS_VER_MINOR;
        *b++ = FMS_VER_MICRO;
        *b++ = FMS_VER_NANO;

        // random bytes to complete the handshake
        bi = (int*)b;
        for (i = 2; i < RTMP_SIG_SIZE/4; i++)
            *bi++ = rand();
        b = out->body+1;

        if (p[4]) {
            // imprint key
            r->off = get_digest_offset(b, digest_offset_values[0]);
            calc_digest(r->off, b, genuine_fms_key, 36, b+r->off);
        } else
            r->off = 0;

        send(r->fd, out->body, (bend - out->body), 0);
        r->tx += bend - out->body;

        // decode client request
        memcpy(&uptime, p, 4);
        uptime = ntohl(uptime);
        fprintf(stdout, "client uptime: %d\n", uptime);
        fprintf(stdout, "player version: %d.%d.%d.%d\n", p[4], p[5], p[6], p[7]);

        // only if this is a Flash Player 9+ handshake
        // FP9 handshakes are only if major player version is >0
        if (r->off) {
            uint8_t the_digest[SHA256_DIGEST_LENGTH];
            int off;
            if (!(off = verify_digest(p, genuine_fp_key, 30, 0))) {
                fprintf(stderr, "client digest failed\n");
                return RTMPERR(INVALIDDATA);
            }

            if ((pe - p) != RTMP_SIG_SIZE) {
                fprintf(stderr, "Client buffer not big enough\n");
                return RTMPERR(INVALIDDATA);
            }

            // imprint server signature into client response
            signature = p+RTMP_SIG_SIZE-SHA256_DIGEST_LENGTH;
            hmac(&p[off], SHA256_DIGEST_LENGTH, genuine_fms_key,
                       sizeof(genuine_fms_key), the_digest);
            hmac(p, RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH, the_digest,
                       SHA256_DIGEST_LENGTH, signature);
        }
        send(r->fd, p, RTMP_SIG_SIZE, 0);
        r->tx += RTMP_SIG_SIZE;
        pkt->read = 0; // this bookkeping sucks. fix.
        return 1;
    }

static int handshake2(ev_io *io)
{
    rtmp *r = get_rtmp(io);
    int len;
    rtmp_packet *pkt = r->in_channels[0], *out = r->out_channels[0];
    uint8_t *p = pkt->body, *pe;

    if (!pkt || !pkt->body || pkt->size < RTMP_SIG_SIZE) {
        fprintf(stderr, "Something weird is going on: packet nonexistent "
                         "in second part of handshake\n");
        return RTMPERR(INVALIDDATA);
    }

    if ((len = read_bytes(r, p + pkt->read, RTMP_SIG_SIZE)) <= 0)
        return RTMPERR(errno);
    pkt->read += len;
    pe  = p + pkt->read;

        // second part of the handshake.
        if ((pe - p) < RTMP_SIG_SIZE) {
        return RTMPERR(EAGAIN);
        }

        // FP9 only
        if (r->off) {
            uint8_t signature[SHA256_DIGEST_LENGTH];
            uint8_t thedigest[SHA256_DIGEST_LENGTH];
            uint8_t *b = out->body+1;
            // verify client response
            hmac(&b[r->off], SHA256_DIGEST_LENGTH, genuine_fp_key,
                 sizeof(genuine_fp_key), thedigest);
            hmac(p, RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH, thedigest,
                 SHA256_DIGEST_LENGTH, signature);
            if (memcmp(signature, &p[RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH],
                       SHA256_DIGEST_LENGTH)) {
                fprintf(stderr, "Client not genuine Adobe\n");
                return RTMPERR(INVALIDDATA);
            }
        }
        // we should verify the bytes returned match in pre-fp9 handshakes
        // but: Postel's Law.

        fprintf(stdout, "Great success: client handshake successful!\n");
        free(pkt->body);
        pkt->body = NULL;
        r->in_channels[pkt->chunk_id] = NULL;
        free(pkt);
        free(out->body);
        out->body = NULL;
        r->out_channels[out->chunk_id] = NULL;
        free(out);
        return 1;
    }

static int handle_msg(rtmp *r, struct rtmp_packet *pkt, ev_io *io)
{
    switch (pkt->msg_type) {
    case 0x01: // set chunk size
    case 0x02: // abort message
        break;
    case 0x03:
        fprintf(stdout, "Ack: %d Bytes Read\n", amf_read_i32(pkt->body));
        break;
    case 0x05:
        fprintf(stdout, "Set Ack Size: %d\n", amf_read_i32(pkt->body));
        break;
    case 0x06: // set window ack size. TODO send 0x03 pkt if size differs
    case 0x07: // for edge-origin distribution
        break;
    case 0x08:
    case 0x09:
        break; // audio and video
    case 0x11: // Flex message
    case 0x14:
        rtmp_invoke(r, pkt, io->data);
        break;
    default:
        fprintf(stdout, "default in cb: 0x%x\n", pkt->msg_type);
    }
    if (r->read_cb)
        r->read_cb(r, pkt, io->data);
    return 0;
}

static int process_packet(ev_io *io)
{
    rtmp *r = get_rtmp(io);
    int header_type, chunk_id, chunk_size, to_increment = 0, copy_header = 0;
    rtmp_packet *pkt = r->prev_pkt;
    uint8_t *p, *pe;

    p = r->hdr;
    // if a prev packet already exists, no need to read in header again
    if (!r->prev_pkt) {
        // overread the header a little to avoid having to call recv
        // for each byte as we need it.
        // later, copy leftover/unused data in the header buffer to body
        if ((r->hdr_bytes += read_bytes(r, p + r->hdr_bytes, sizeof(r->hdr) - r->hdr_bytes)) <= 0) {
            fprintf(stdout, "ZOMGBROKEN\n");
            return RTMPERR(errno);
        }
    pe  = p + r->hdr_bytes;

    if ((pe - p) < 1)
        goto parse_pkt_fail;
        header_type = (*p & 0xc0) >> 6;
        chunk_id = *p & 0x3f;
        p += 1;

    if ((chunk_id > 319 && (pe - p) < 2) ||
       (chunk_id > 64 && (pe - p) < 1)) {
        goto parse_pkt_fail;
    }
    if (!chunk_id) {
        chunk_id = *p + 64;
        p += 1;
    } else if (1 == chunk_id ) {
        chunk_id = (*p << 8) + p[1] + 64;
        p += 2;
    }

    // get previous packet in chunk
    if (r->in_channels[chunk_id]) {
        pkt = r->in_channels[chunk_id];
    } else {
        if(!(pkt = malloc(sizeof(rtmp_packet)))) {
            fprintf(stderr, "Failed to malloc space for packet!\n");
        return RTMPERR(ENOMEM);
        }
        memset(pkt, 0, sizeof(rtmp_packet)); // zero out
        pkt->chunk_id = chunk_id;
        r->in_channels[chunk_id] = pkt;
    }
    pkt->chunk_type = header_type;

    // NB:  we intentionally fallthrough here
    switch (header_type) {
    case CHUNK_LARGE:
        if ((pe - p) < CHUNK_SIZE_LARGE) goto parse_pkt_fail;
        pkt->msg_id = amf_read_i32(&p[7]);
        to_increment += 4;
    case CHUNK_MEDIUM:
        if ((pe - p) < CHUNK_SIZE_MEDIUM ) goto parse_pkt_fail;
        pkt->msg_type = p[6];
        pkt->size = amf_read_i24(&p[3]); // size exclusive of header
        pkt->read = 0;
        to_increment += 4;
    case CHUNK_SMALL: {
        uint32_t ts;
        if ((pe - p) < CHUNK_SIZE_SMALL) goto parse_pkt_fail; // XXX error out
        ts = amf_read_i24(p);
        to_increment += 3;
        if (0xffffff == ts) {
            // read in extended timestamp
            static const int header_sizes[] = { CHUNK_SIZE_LARGE,
                                                CHUNK_SIZE_MEDIUM,
                                                CHUNK_SIZE_SMALL };
            int hsize = header_sizes[header_type];
            if (p + hsize + 4 > pe) goto parse_pkt_fail;

            ts = amf_read_i32(p+hsize);
            to_increment += 4;
        }
        if (!header_type)
            pkt->timestamp = ts; // abs timestamp
        else
            pkt->timestamp += ts; // timestamp delta
    }
    case 3:
        break;
    }
    p += to_increment;

    // enlarge packet body if needed
    if (!pkt->read && pkt->alloc_size < pkt->size) {
        // allocate packet body
        if (pkt->body) {
            free(pkt->body);
            pkt->body = NULL;
            pkt->alloc_size = 0;
        }
        if (!(pkt->body = malloc(pkt->size))) {
            fprintf(stderr, "Out of memory when allocating packet!\n");
            return RTMPERR(ENOMEM);
        }
        pkt->alloc_size = pkt->size;
    }

    // copy packet data
    chunk_size = r->chunk_size < (pkt->size - pkt->read) ?
                 r->chunk_size : (pkt->size - pkt->read);

        // copy over any data leftover from header buffer
        int leftover = r->hdr_bytes - (p - r->hdr);
        chunk_size -= leftover;
        if (chunk_size < 0) {
            // we fucked up and overread into the next packet
            leftover += chunk_size;
            r->hdr_bytes = -chunk_size;
            chunk_size = 0;
            copy_header = 1;
        }

        // candidate for synthetic microbenchmarking against a while loop
        memcpy(pkt->body + pkt->read, p, leftover);
        p         += leftover;
        pkt->read += leftover;
    } else {
        chunk_size = r->chunk_alignment;
	    r->chunk_alignment = 0;
    }

    if (chunk_size) {
        int len;
        if ((len = read_bytes(r, pkt->body + pkt->read, chunk_size)) <= 0) {
	        if (errno == EAGAIN){
	            len = 0;
            } else {
                fprintf(stderr, "Error reading bytes!\n");
                return RTMPERR(errno);
            }
        }

        // chunk was split across TCP packets
        if (len != chunk_size) {
            pkt->read += len;
            r->chunk_alignment = chunk_size - len;
            r->prev_pkt = pkt;
            return RTMPERR(EAGAIN);
	    }
        r->hdr_bytes = 0; // we've completed our chunk
    } else if (copy_header) {
        // we copied way too much in the header and spilled over
        // into the next packet; save the leftover leftover bytes
        // into a temp buffer
        // XXX probably should verify size of write_buf!
        assert(r->hdr_bytes <= sizeof(r->hdr));
        memmove(r->hdr, p, r->hdr_bytes);
    } else {
        // this condition is triggered when we have:
        // a) chunk body (or remainder thereof) that fits into header buf
        // b) no overflow that spills over to the next chunk
        // (in short, the chunk terminates on a TCP packet boundary)
        r->hdr_bytes = 0;
    }
    r->prev_pkt = NULL;
    pkt->read += chunk_size;

   /*
        fprintf(stdout, "Packet/Chunk parameters:\n"
                        "%15s %d\n%15s %d\n%15s %u\n"
                        "%15s %d\n%15s %d\n%15s 0x%x\n"
                        "%15s %d\n%15s %d\n",
                        "header type", header_type,
                        "chunk id",    chunk_id,
                        "timestamp",   pkt->timestamp,
                        "body size",   pkt->size,
                        "read",        pkt->read,
                        "msg type",    pkt->msg_type,
                        "msg id",      pkt->msg_id,
                        "chunksize",   chunk_size);
    */
    if (pkt->read == pkt->size) {
        handle_msg(r, pkt, io);
        pkt->read = 0;
    }
    return 1;

parse_pkt_fail:
    return RTMPERR(EAGAIN);
}

void rtmp_read(struct ev_loop *loop, ev_io *io, int revents)
{
    rtmp *r = get_rtmp(io);
    srv_ctx *ctx = io->data;
    int bytes_read;

    switch (r->state) {
    case UNINIT:
        bytes_read = init_handshake(io);
        if (RTMPERR(EAGAIN) != bytes_read) r->state = HANDSHAKE;
        break;
    case HANDSHAKE:
        bytes_read = handshake2(io);
        if (RTMPERR(EAGAIN) != bytes_read) r->state = READ;
        break;
    case READ:
        bytes_read = process_packet(io);
        break;
    }
    if (bytes_read <= 0 && bytes_read != RTMPERR(EAGAIN)) goto read_error;

    return;

read_error:
    if (bytes_read == RTMPERR(INVALIDDATA))
        fprintf(stderr, "Invalid data\n");
    fprintf(stderr, "Error %d, disconnecting fd %d \n", bytes_read, r->fd);
    ev_io_stop(ctx->loop, io);
    close(r->fd);
}
