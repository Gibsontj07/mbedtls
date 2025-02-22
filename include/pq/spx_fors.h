#ifndef SPX_FORS_H
#define SPX_FORS_H

#include <stdint.h>

#include "pq/spx_params.h"
#include "pq/spx_hash.h"
#include "pq/spx_thash.h"
#include "pq/spx_context.h"

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
// Round 1
// void fors_sign(const sphincs_md_info_t *md, unsigned char *sig, unsigned char *pk,
//                const unsigned char *m,
//                const unsigned char *sk_seed, const unsigned char *pub_seed,
//                const uint32_t fors_addr[8]);

// Round 4
void fors_sign(unsigned char *sig, unsigned char *pk,
               const unsigned char *m,
               const spx_ctx* ctx,
               const uint32_t fors_addr[8]);

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
// Round 1
// void fors_pk_from_sig(const sphincs_md_info_t *md, unsigned char *pk,
//                       const unsigned char *sig, const unsigned char *m,
//                       const unsigned char *pub_seed,
//                       const uint32_t fors_addr[8]);

// #endif

// Round 4
void fors_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *m,
                      const spx_ctx* ctx,
                      const uint32_t fors_addr[8]);

#endif
