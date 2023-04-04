#ifndef SPX_FIPS202_H
#define SPX_FIPS202_H

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE  72

// void shake128(unsigned char *output, unsigned long long outlen, const unsigned char *input,  unsigned long long inlen);
// //void shake128_init(keccak_state *state);
void shake128_absorb(uint64_t *s, const unsigned char *input, unsigned int inputByteLen);
// void shake128_squeezeblocks(unsigned char *output, unsigned long long nblocks, uint64_t *s);

// void sha3_256(unsigned char *output, const unsigned char *input, unsigned long long inlen);
// void sha3_512(unsigned char *output, const unsigned char *input, unsigned long long inlen);

// /* Evaluates SHAKE-128 on `inlen' bytes in `in', according to FIPS-202.
//  * Writes the first `outlen` bytes of output to `out`.
//  */
// void shake128(unsigned char *out, unsigned long long outlen,
//               const unsigned char *in, unsigned long long inlen);

// /* Evaluates SHAKE-256 on `inlen' bytes in `in', according to FIPS-202.
//  * Writes the first `outlen` bytes of output to `out`.
//  */
// void shake256(unsigned char *out, unsigned long long outlen,
//               const unsigned char *in, unsigned long long inlen);

//Round 4
//void shake128_absorb(uint64_t *s, const uint8_t *input, size_t inlen);

void shake128_squeezeblocks(uint8_t *output, size_t nblocks, uint64_t *s);

void shake128_inc_init(uint64_t *s_inc);
void shake128_inc_absorb(uint64_t *s_inc, const uint8_t *input, size_t inlen);
void shake128_inc_finalize(uint64_t *s_inc);
void shake128_inc_squeeze(uint8_t *output, size_t outlen, uint64_t *s_inc);

void shake256_absorb(uint64_t *s, const uint8_t *input, size_t inlen);
void shake256_squeezeblocks(uint8_t *output, size_t nblocks, uint64_t *s);

void shake256_inc_init(uint64_t *s_inc);
void shake256_inc_absorb(uint64_t *s_inc, const unsigned char *input, size_t inlen);
void shake256_inc_finalize(uint64_t *s_inc);
void shake256_inc_squeeze(unsigned char *output, size_t outlen, uint64_t *s_inc);

void shake128(unsigned char *output, size_t outlen,
              const unsigned char *input, size_t inlen);

void shake256(unsigned char *output, size_t outlen,
              const unsigned char *input, size_t inlen);

void sha3_256_inc_init(uint64_t *s_inc);
void sha3_256_inc_absorb(uint64_t *s_inc, const unsigned char *input, size_t inlen);
void sha3_256_inc_finalize(unsigned char *output, uint64_t *s_inc);

void sha3_256(unsigned char *output, const unsigned char *input, size_t inlen);

void sha3_512_inc_init(uint64_t *s_inc);
void sha3_512_inc_absorb(uint64_t *s_inc, const unsigned char *input, size_t inlen);
void sha3_512_inc_finalize(unsigned char *output, uint64_t *s_inc);

void sha3_512(unsigned char *output, const unsigned char *input, size_t inlen);


#endif
