#ifndef KYBER_REDUCE_H
#define KYBER_REDUCE_H

#include "pq/kyber_params.h"
#include <stdint.h>

#define MONT (-1044) // 2^16 mod q
#define QINV (-3327) // q^-1 mod 2^16

int16_t montgomery_reduce(int32_t a);

int16_t barrett_reduce(int16_t a);

#endif
