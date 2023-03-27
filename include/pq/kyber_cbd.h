#ifndef KYBER_CBD_H
#define KYBER_CBD_H

#include <stdint.h>
#include "pq/kyber_params.h"
#include "pq/kyber_poly.h"

void poly_cbd_eta1(poly *r, const uint8_t buf[KYBER_ETA1 * KYBER_N / 4]);

void poly_cbd_eta2(poly *r, const uint8_t buf[KYBER_ETA2 * KYBER_N / 4]);

#endif
