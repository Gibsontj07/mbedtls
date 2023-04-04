#ifndef SPX_SHA2_H
#define SPX_SHA2_H

#include "pq/spx_params.h"

#define SPX_SHA256_BLOCK_BYTES 64
#define SPX_SHA256_OUTPUT_BYTES 32  /* This does not necessarily equal SPX_N */

#define SPX_SHA512_BLOCK_BYTES 128
#define SPX_SHA512_OUTPUT_BYTES 64

#if SPX_SHA256_OUTPUT_BYTES < SPX_N
    #error Linking against SHA-256 with N larger than 32 bytes is not supported
#endif

#define SPX_SHA256_ADDR_BYTES 22

#include <stddef.h>
#include <stdint.h>

void sha256_inc_init(unsigned char *state);
void sha256_inc_blocks(unsigned char *state, const unsigned char *in, size_t inblocks);
void sha256_inc_finalize(unsigned char *out, unsigned char *state, const unsigned char *in, size_t inlen);
void sha256(unsigned char *out, const unsigned char *in, size_t inlen);

void sha512_inc_init(unsigned char *state);
void sha512_inc_blocks(unsigned char *state, const unsigned char *in, size_t inblocks);
void sha512_inc_finalize(unsigned char *out, unsigned char *state, const unsigned char *in, size_t inlen);
void sha512(unsigned char *out, const unsigned char *in, size_t inlen);

//#define mgf1_256 SPX_NAMESPACE(mgf1_256)
void mgf1_256(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen);

//#define mgf1_512 SPX_NAMESPACE(mgf1_512)
void mgf1_512(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen);

//#define seed_state SPX_NAMESPACE(seed_state)
void seed_state(spx_ctx *ctx);


#endif
