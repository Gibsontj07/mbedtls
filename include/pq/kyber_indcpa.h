#ifndef KYBER_INDCPA_H
#define KYBER_INDCPA_H
#include "pq/kyber_params.h"
#include "pq/kyber_polyvec.h"
#include <stdint.h>
#include <stddef.h>

void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);
void indcpa_keypair(unsigned char *pk, 
                    unsigned char *sk,
		    int(*f_rng)(void *, unsigned char *, size_t), 
	            void *p_rng);

void indcpa_enc(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk,
               const unsigned char *coins);

void indcpa_dec(unsigned char *m,
               const unsigned char *c,
               const unsigned char *sk);

#endif
