#include <stdint.h>
#include <string.h>

#include "pq/spx_thash.h"
#include "pq/spx_hash_address.h"
#include "pq/spx_params.h"
#include "pq/spx_utils.h"
#include "mbedtls/sha2.h"

#if SPX_SHA512
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8]);
#endif

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
#if SPX_SHA512
    if (inblocks > 1) {
	thash_512(out, in, inblocks, ctx, addr);
        return;
    }
#endif
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    SPX_VLA(unsigned char, bitmask, inblocks * SPX_N);
    SPX_VLA(unsigned char, buf, SPX_N + SPX_SHA256_OUTPUT_BYTES + inblocks*SPX_N);
    unsigned char sha2_state[40];
    unsigned int i;

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SHA256_ADDR_BYTES);
    mgf1_256(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded, 40 * sizeof(unsigned char));

    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_N + SPX_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    sha256_inc_finalize(outbuf, sha2_state, buf + SPX_N,
                        SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    memcpy(out, outbuf, SPX_N);
    mbedtls_free(buf);
    mbedtls_free(bitmask);
}

#if SPX_SHA512
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char outbuf[SPX_SHA512_OUTPUT_BYTES];
    SPX_VLA(unsigned char, bitmask, inblocks * SPX_N);
    SPX_VLA(unsigned char, buf, SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    unsigned char sha2_state[72];
    unsigned int i;

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SHA256_ADDR_BYTES);
    mgf1_512(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded_512, 72 * sizeof(unsigned char));

    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_N + SPX_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    sha512_inc_finalize(outbuf, sha2_state, buf + SPX_N,
                        SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    memcpy(out, outbuf, SPX_N);
    mbedtls_free(buf);
    mbedtls_free(bitmask);
}
#endif
