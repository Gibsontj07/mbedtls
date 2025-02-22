#ifndef POLY_D_H
#define POLY_D_H

#include <stdint.h>
#include "pq/dilithium_params.h"

typedef struct {
  int32_t coeffs[N_D];
} poly;

//#define poly_reduce DILITHIUM_NAMESPACE(poly_reduce)
void poly_reduce_D(poly *a);
//#define poly_caddq DILITHIUM_NAMESPACE(poly_caddq)
void poly_caddq(poly *a);

//#define poly_add_D DILITHIUM_NAMESPACE(poly_add_D)
void poly_add_D(poly *c, const poly *a, const poly *b);
//#define poly_sub_D DILITHIUM_NAMESPACE(poly_sub_D)
void poly_sub_D(poly *c, const poly *a, const poly *b);
//#define poly_shiftl DILITHIUM_NAMESPACE(poly_shiftl)
void poly_shiftl(poly *a);

//#define poly_ntt_D DILITHIUM_NAMESPACE(poly_ntt_D)
void poly_ntt_D(poly *a);
//#define poly_invntt_tomont DILITHIUM_NAMESPACE(poly_invntt_tomont)
void poly_invntt_tomont_D(poly *a);
//#define poly_pointwise_montgomery DILITHIUM_NAMESPACE(poly_pointwise_montgomery)
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);

//#define poly_power2round DILITHIUM_NAMESPACE(poly_power2round)
void poly_power2round(poly *a1, poly *a0, const poly *a);
//#define poly_decompose DILITHIUM_NAMESPACE(poly_decompose)
void poly_decompose(poly *a1, poly *a0, const poly *a);
//#define poly_make_hint DILITHIUM_NAMESPACE(poly_make_hint)
unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1);
//#define poly_use_hint DILITHIUM_NAMESPACE(poly_use_hint)
void poly_use_hint(poly *b, const poly *a, const poly *h);

//#define poly_chknorm DILITHIUM_NAMESPACE(poly_chknorm)
int poly_chknorm(const poly *a, int32_t B);
//#define poly_uniform DILITHIUM_NAMESPACE(poly_uniform)
void poly_uniform(poly *a,
                  const unsigned char seed[SEEDBYTES_D],
                  uint16_t nonce);
//#define poly_uniform_eta DILITHIUM_NAMESPACE(poly_uniform_eta)
void poly_uniform_eta(poly *a,
                      const unsigned char seed[CRHBYTES],
                      uint16_t nonce);
//#define poly_uniform_gamma1 DILITHIUM_NAMESPACE(poly_uniform_gamma1)
void poly_uniform_gamma1(poly *a,
                         const unsigned char seed[CRHBYTES],
                         uint16_t nonce);
//#define poly_challenge DILITHIUM_NAMESPACE(poly_challenge)
void poly_challenge(poly *c, const unsigned char seed[SEEDBYTES_D]);

//#define polyeta_pack DILITHIUM_NAMESPACE(polyeta_pack)
void polyeta_pack(unsigned char *r, const poly *a);
//#define polyeta_unpack DILITHIUM_NAMESPACE(polyeta_unpack)
void polyeta_unpack(poly *r, const unsigned char *a);

//#define polyt1_pack DILITHIUM_NAMESPACE(polyt1_pack)
void polyt1_pack(unsigned char *r, const poly *a);
//#define polyt1_unpack DILITHIUM_NAMESPACE(polyt1_unpack)
void polyt1_unpack(poly *r, const unsigned char *a);

//#define polyt0_pack DILITHIUM_NAMESPACE(polyt0_pack)
void polyt0_pack(unsigned char *r, const poly *a);
//#define polyt0_unpack DILITHIUM_NAMESPACE(polyt0_unpack)
void polyt0_unpack(poly *r, const unsigned char *a);

//#define polyz_pack DILITHIUM_NAMESPACE(polyz_pack)
void polyz_pack(unsigned char *r, const poly *a);
//#define polyz_unpack DILITHIUM_NAMESPACE(polyz_unpack)
void polyz_unpack(poly *r, const unsigned char *a);

//#define polyw1_pack DILITHIUM_NAMESPACE(polyw1_pack)
void polyw1_pack(unsigned char *r, const poly *a);

#endif
