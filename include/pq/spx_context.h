#ifndef SPX_CONTEXT_H
#define SPX_CONTEXT_H

#include <stdint.h>

#include "pq/spx_params.h"

typedef struct {
    unsigned char pub_seed[SPX_N];
    unsigned char sk_seed[SPX_N];

//#ifdef SPX_SHA2
    // sha256 state that absorbed pub_seed
    unsigned char state_seeded[40];

//# if SPX_SHA512
    // sha512 state that absorbed pub_seed
    unsigned char state_seeded_512[72];
//# endif
//#endif

//#ifdef SPX_HARAKA
    uint64_t tweaked512_rc64[10][8];
    uint32_t tweaked256_rc32[10][8];
//#endif
} spx_ctx;

#endif
