#include <stdint.h>
#include "pq/dilithium_params.h"
#include "pq/dilithium_polyvec.h"
#include "pq/dilithium_poly.h"

/*************************************************
* Name:        expand_mat
*
* Description: Implementation of ExpandA. Generates matrix A with uniformly
*              random coefficients a_{i,j} by performing rejection
*              sampling on the output stream of SHAKE128(rho|j|i)
*              or AES256CTR(rho,j|i).
*
* Arguments:   - polyvecl mat[K_D]: output matrix
*              - const unsigned char rho[]: byte array containing seed rho
**************************************************/
void polyvec_matrix_expand(polyvecl mat[K_D], const unsigned char rho[SEEDBYTES_D]) {
  unsigned int i, j;

  for(i = 0; i < K_D; ++i)
    for(j = 0; j < L_D; ++j)
      poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
}

void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K_D], const polyvecl *v) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
}

/**************************************************************/
/************ Vectors of polynomials of length L_D **************/
/**************************************************************/

void polyvecl_uniform_eta(polyvecl *v, const unsigned char seed[CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < L_D; ++i)
    poly_uniform_eta(&v->vec[i], seed, nonce++);
}

void polyvecl_uniform_gamma1(polyvecl *v, const unsigned char seed[CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < L_D; ++i)
    poly_uniform_gamma1(&v->vec[i], seed, L_D*nonce + i);
}

void polyvecl_reduce(polyvecl *v) {
  unsigned int i;

  for(i = 0; i < L_D; ++i)
    poly_reduce_D(&v->vec[i]);
}

/*************************************************
* Name:        polyvecl_add
*
* Description: Add vectors of polynomials of length L_D.
*              No modular reduction is performed.
*
* Arguments:   - polyvecl *w: pointer to output vector
*              - const polyvecl *u: pointer to first summand
*              - const polyvecl *v: pointer to second summand
**************************************************/
void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v) {
  unsigned int i;

  for(i = 0; i < L_D; ++i)
    poly_add_D(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyvecl_ntt
*
* Description: Forward NTT of all polynomials in vector of length L_D. Output
*              coefficients can be up to 16*Q_D larger than input coefficients.
*
* Arguments:   - polyvecl *v: pointer to input/output vector
**************************************************/
void polyvecl_ntt(polyvecl *v) {
  unsigned int i;

  for(i = 0; i < L_D; ++i)
    poly_ntt_D(&v->vec[i]);
}

void polyvecl_invntt_tomont(polyvecl *v) {
  unsigned int i;

  for(i = 0; i < L_D; ++i)
    poly_invntt_tomont_D(&v->vec[i]);
}

void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v) {
  unsigned int i;

  for(i = 0; i < L_D; ++i)
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

/*************************************************
* Name:        polyvecl_pointwise_acc_montgomery
*
* Description: Pointwise multiply vectors of polynomials of length L_D, multiply
*              resulting vector by 2^{-32} and add (accumulate) polynomials
*              in it. Input/output vectors are in NTT domain representation.
*
* Arguments:   - poly *w: output polynomial
*              - const polyvecl *u: pointer to first input vector
*              - const polyvecl *v: pointer to second input vector
**************************************************/
void polyvecl_pointwise_acc_montgomery(poly *w,
                                       const polyvecl *u,
                                       const polyvecl *v)
{
  unsigned int i;
  poly t;

  poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
  for(i = 1; i < L_D; ++i) {
    poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
    poly_add_D(w, w, &t);
  }
}

/*************************************************
* Name:        polyvecl_chknorm
*
* Description: Check infinity norm of polynomials in vector of length L_D.
*              Assumes input polyvecl to be reduced by polyvecl_reduce().
*
* Arguments:   - const polyvecl *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials is strictly smaller than B <= (Q_D-1)/8
* and 1 otherwise.
**************************************************/
int polyvecl_chknorm(const polyvecl *v, int32_t bound)  {
  unsigned int i;

  for(i = 0; i < L_D; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}

/**************************************************************/
/************ Vectors of polynomials of length K_D **************/
/**************************************************************/

void polyveck_uniform_eta(polyveck *v, const unsigned char seed[CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    poly_uniform_eta(&v->vec[i], seed, nonce++);
}

/*************************************************
* Name:        polyveck_reduce
*
* Description: Reduce coefficients of polynomials in vector of length K_D
*              to representatives in [-6283009,6283007].
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_reduce(polyveck *v) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    poly_reduce_D(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_caddq
*
* Description: For all coefficients of polynomials in vector of length K_D
*              add Q_D if coefficient is negative.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_caddq(polyveck *v) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    poly_caddq(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_add
*
* Description: Add vectors of polynomials of length K_D.
*              No modular reduction is performed.
*
* Arguments:   - polyveck *w: pointer to output vector
*              - const polyveck *u: pointer to first summand
*              - const polyveck *v: pointer to second summand
**************************************************/
void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    poly_add_D(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_sub
*
* Description: Subtract vectors of polynomials of length K_D.
*              No modular reduction is performed.
*
* Arguments:   - polyveck *w: pointer to output vector
*              - const polyveck *u: pointer to first input vector
*              - const polyveck *v: pointer to second input vector to be
*                                   subtracted from first input vector
**************************************************/
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    poly_sub_D(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_shiftl
*
* Description: Multiply vector of polynomials of Length K_D by 2^D_D without modular
*              reduction. Assumes input coefficients to be less than 2^{31-D_D}.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_shiftl(polyveck *v) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    poly_shiftl(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_ntt
*
* Description: Forward NTT of all polynomials in vector of length K_D. Output
*              coefficients can be up to 16*Q_D larger than input coefficients.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_ntt(polyveck *v) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    poly_ntt_D(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_invntt_tomont
*
* Description: Inverse NTT and multiplication by 2^{32} of polynomials
*              in vector of length K_D. Input coefficients need to be less
*              than 2*Q_D.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_invntt_tomont(polyveck *v) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    poly_invntt_tomont_D(&v->vec[i]);
}

void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}


/*************************************************
* Name:        polyveck_chknorm
*
* Description: Check infinity norm of polynomials in vector of length K_D.
*              Assumes input polyveck to be reduced by polyveck_reduce().
*
* Arguments:   - const polyveck *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials are strictly smaller than B <= (Q_D-1)/8
* and 1 otherwise.
**************************************************/
int polyveck_chknorm(const polyveck *v, int32_t bound) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}

/*************************************************
* Name:        polyveck_power2round
*
* Description: For all coefficients a of polynomials in vector of length K_D,
*              compute a0, a1 such that a mod^+ Q_D = a1*2^D_D + a0
*              with -2^{D_D-1} < a0 <= 2^{D_D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyveck *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const polyveck *v: pointer to input vector
**************************************************/
void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_decompose
*
* Description: For all coefficients a of polynomials in vector of length K_D,
*              compute high and low bits a0, a1 such a mod^+ Q_D = a1*ALPHA + a0
*              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q_D-1)/ALPHA where we
*              set a1 = 0 and -ALPHA/2 <= a0 = a mod Q_D - Q_D < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyveck *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const polyveck *v: pointer to input vector
**************************************************/
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_make_hint
*
* Description: Compute hint vector.
*
* Arguments:   - polyveck *h: pointer to output vector
*              - const polyveck *v0: pointer to low part of input vector
*              - const polyveck *v1: pointer to high part of input vector
*
* Returns number of 1 bits.
**************************************************/
unsigned int polyveck_make_hint(polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1)
{
  unsigned int i, s = 0;

  for(i = 0; i < K_D; ++i)
    s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);

  return s;
}

/*************************************************
* Name:        polyveck_use_hint
*
* Description: Use hint vector to correct the high bits of input vector.
*
* Arguments:   - polyveck *w: pointer to output vector of polynomials with
*                             corrected high bits
*              - const polyveck *u: pointer to input vector
*              - const polyveck *h: pointer to input hint vector
**************************************************/
void polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
}

void polyveck_pack_w1(unsigned char r[K_D*POLYW1_PACKEDBYTES], const polyveck *w1) {
  unsigned int i;

  for(i = 0; i < K_D; ++i)
    polyw1_pack(&r[i*POLYW1_PACKEDBYTES], &w1->vec[i]);
}
