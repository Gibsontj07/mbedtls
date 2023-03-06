#ifndef SABER_VERIFY_H
#define SABER_VERIFY_H

#include <stddef.h>
#include <stdint.h>
#include "pq/saber_params.h"

int saber_verify(const unsigned char *a, const unsigned char *b, size_t len);

void saber_cmov(unsigned char *r, const unsigned char *x, size_t len, unsigned char b);

#endif
