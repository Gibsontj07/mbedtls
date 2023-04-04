#ifndef SPX_WOTS_H
#define SPX_WOTS_H

#include <stdint.h>
#include "pq/spx_hash.h"
#include "pq/spx_thash.h"
#include "pq/spx_params.h"
#include "pq/spx_context.h"

// /**  Removed by R4 
//  * WOTS key generation. Takes a 32 byte seed for the private key, expands it to
//  * a full WOTS private key and computes the corresponding public key.
//  * It requires the seed pub_seed (used to generate bitmasks and hash keys)
//  * and the address of this WOTS key pair.
//  *
//  * Writes the computed public key to 'pk'.
//  */
// void wots_gen_pk(const sphincs_md_info_t *md, unsigned char *pk, const unsigned char *seed,
//                  const unsigned char *pub_seed, uint32_t addr[8]);

// /**  Removed by R4 
//  * Takes a n-byte message and the 32-byte seed for the private key to compute a
//  * signature that is placed at 'sig'.
//  */
// void wots_sign(const sphincs_md_info_t *md, unsigned char *sig, const unsigned char *msg,
//                const unsigned char *seed, const unsigned char *pub_seed,
//                uint32_t addr[8]);

// /** Round 1
//  * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
//  *
//  * Writes the computed public key to 'pk'.
//  */
// void wots_pk_from_sig(const sphincs_md_info_t *md, unsigned char *pk,
//                       const unsigned char *sig, const unsigned char *msg,
//                       const unsigned char *pub_seed, uint32_t addr[8]);


/** Round 4
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const spx_ctx *ctx, uint32_t addr[8]);

/* Round 4
 * Compute the chain lengths needed for a given message hash
 */
void chain_lengths(unsigned int *lengths, const unsigned char *msg);

#endif
