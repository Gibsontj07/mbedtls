
/* Based on the public domain implementation in
 * crypto_hash/keccakc512/simple/ from http://bench.cr.yp.to/supercop.html
 * by Ronny Van Keer 
 * and the public domain "TweetFips202" implementation
 * from https://twitter.com/tweetfips202
 * by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe */

#include "pq/fips202.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/timing.h"
HASH_INIT

#define NROUNDS 24
#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))

static uint64_t load64(const unsigned char *x)
{
    unsigned long long r = 0, i;

    for (i = 0; i < 8; ++i) {
        r |= (unsigned long long)x[i] << 8 * i;
    }
    return r;
}

static void store64(unsigned char *x, uint64_t u)
{
    unsigned int i;

    for (i = 0; i < 8; ++i) {
        x[i] = u;
        u >>= 8;
    }
}

static const uint64_t KeccakF_RoundConstants[NROUNDS] = 
{
    (uint64_t)0x0000000000000001ULL,
    (uint64_t)0x0000000000008082ULL,
    (uint64_t)0x800000000000808aULL,
    (uint64_t)0x8000000080008000ULL,
    (uint64_t)0x000000000000808bULL,
    (uint64_t)0x0000000080000001ULL,
    (uint64_t)0x8000000080008081ULL,
    (uint64_t)0x8000000000008009ULL,
    (uint64_t)0x000000000000008aULL,
    (uint64_t)0x0000000000000088ULL,
    (uint64_t)0x0000000080008009ULL,
    (uint64_t)0x000000008000000aULL,
    (uint64_t)0x000000008000808bULL,
    (uint64_t)0x800000000000008bULL,
    (uint64_t)0x8000000000008089ULL,
    (uint64_t)0x8000000000008003ULL,
    (uint64_t)0x8000000000008002ULL,
    (uint64_t)0x8000000000000080ULL,
    (uint64_t)0x000000000000800aULL,
    (uint64_t)0x800000008000000aULL,
    (uint64_t)0x8000000080008081ULL,
    (uint64_t)0x8000000000008080ULL,
    (uint64_t)0x0000000080000001ULL,
    (uint64_t)0x8000000080008008ULL
};

void KeccakF1600_StatePermute(uint64_t * state)
{
    int round;

    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;
    uint64_t BCa, BCe, BCi, BCo, BCu;
    uint64_t Da, De, Di, Do, Du;
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    //copyFromState(A, state)
    Aba = state[ 0];
    Abe = state[ 1];
    Abi = state[ 2];
    Abo = state[ 3];
    Abu = state[ 4];
    Aga = state[ 5];
    Age = state[ 6];
    Agi = state[ 7];
    Ago = state[ 8];
    Agu = state[ 9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

    for (round = 0; round < NROUNDS; round += 2) {
        //    prepareTheta
        BCa = Aba^Aga^Aka^Ama^Asa;
        BCe = Abe^Age^Ake^Ame^Ase;
        BCi = Abi^Agi^Aki^Ami^Asi;
        BCo = Abo^Ago^Ako^Amo^Aso;
        BCu = Abu^Agu^Aku^Amu^Asu;

        //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
        Da = BCu^ROL(BCe, 1);
        De = BCa^ROL(BCi, 1);
        Di = BCe^ROL(BCo, 1);
        Do = BCi^ROL(BCu, 1);
        Du = BCo^ROL(BCa, 1);

        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = ROL(Age, 44);
        Aki ^= Di;
        BCi = ROL(Aki, 43);
        Amo ^= Do;
        BCo = ROL(Amo, 21);
        Asu ^= Du;
        BCu = ROL(Asu, 14);
        Eba = BCa ^((~BCe)&  BCi );
        Eba ^= (uint64_t)KeccakF_RoundConstants[round];
        Ebe = BCe ^((~BCi)&  BCo );
        Ebi = BCi ^((~BCo)&  BCu );
        Ebo = BCo ^((~BCu)&  BCa );
        Ebu = BCu ^((~BCa)&  BCe );

        Abo ^= Do;
        BCa = ROL(Abo, 28);
        Agu ^= Du;
        BCe = ROL(Agu, 20);
        Aka ^= Da;
        BCi = ROL(Aka,  3);
        Ame ^= De;
        BCo = ROL(Ame, 45);
        Asi ^= Di;
        BCu = ROL(Asi, 61);
        Ega = BCa ^((~BCe)&  BCi );
        Ege = BCe ^((~BCi)&  BCo );
        Egi = BCi ^((~BCo)&  BCu );
        Ego = BCo ^((~BCu)&  BCa );
        Egu = BCu ^((~BCa)&  BCe );

        Abe ^= De;
        BCa = ROL(Abe,  1);
        Agi ^= Di;
        BCe = ROL(Agi,  6);
        Ako ^= Do;
        BCi = ROL(Ako, 25);
        Amu ^= Du;
        BCo = ROL(Amu,  8);
        Asa ^= Da;
        BCu = ROL(Asa, 18);
        Eka = BCa ^((~BCe)&  BCi );
        Eke = BCe ^((~BCi)&  BCo );
        Eki = BCi ^((~BCo)&  BCu );
        Eko = BCo ^((~BCu)&  BCa );
        Eku = BCu ^((~BCa)&  BCe );

        Abu ^= Du;
        BCa = ROL(Abu, 27);
        Aga ^= Da;
        BCe = ROL(Aga, 36);
        Ake ^= De;
        BCi = ROL(Ake, 10);
        Ami ^= Di;
        BCo = ROL(Ami, 15);
        Aso ^= Do;
        BCu = ROL(Aso, 56);
        Ema = BCa ^((~BCe)&  BCi );
        Eme = BCe ^((~BCi)&  BCo );
        Emi = BCi ^((~BCo)&  BCu );
        Emo = BCo ^((~BCu)&  BCa );
        Emu = BCu ^((~BCa)&  BCe );

        Abi ^= Di;
        BCa = ROL(Abi, 62);
        Ago ^= Do;
        BCe = ROL(Ago, 55);
        Aku ^= Du;
        BCi = ROL(Aku, 39);
        Ama ^= Da;
        BCo = ROL(Ama, 41);
        Ase ^= De;
        BCu = ROL(Ase,  2);
        Esa = BCa ^((~BCe)&  BCi );
        Ese = BCe ^((~BCi)&  BCo );
        Esi = BCi ^((~BCo)&  BCu );
        Eso = BCo ^((~BCu)&  BCa );
        Esu = BCu ^((~BCa)&  BCe );

        //    prepareTheta
        BCa = Eba^Ega^Eka^Ema^Esa;
        BCe = Ebe^Ege^Eke^Eme^Ese;
        BCi = Ebi^Egi^Eki^Emi^Esi;
        BCo = Ebo^Ego^Eko^Emo^Eso;
        BCu = Ebu^Egu^Eku^Emu^Esu;

        //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        Da = BCu^ROL(BCe, 1);
        De = BCa^ROL(BCi, 1);
        Di = BCe^ROL(BCo, 1);
        Do = BCi^ROL(BCu, 1);
        Du = BCo^ROL(BCa, 1);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = ROL(Ege, 44);
        Eki ^= Di;
        BCi = ROL(Eki, 43);
        Emo ^= Do;
        BCo = ROL(Emo, 21);
        Esu ^= Du;
        BCu = ROL(Esu, 14);
        Aba = BCa ^((~BCe)&  BCi );
        Aba ^= (uint64_t)KeccakF_RoundConstants[round+1];
        Abe = BCe ^((~BCi)&  BCo );
        Abi = BCi ^((~BCo)&  BCu );
        Abo = BCo ^((~BCu)&  BCa );
        Abu = BCu ^((~BCa)&  BCe );

        Ebo ^= Do;
        BCa = ROL(Ebo, 28);
        Egu ^= Du;
        BCe = ROL(Egu, 20);
        Eka ^= Da;
        BCi = ROL(Eka, 3);
        Eme ^= De;
        BCo = ROL(Eme, 45);
        Esi ^= Di;
        BCu = ROL(Esi, 61);
        Aga = BCa ^((~BCe)&  BCi );
        Age = BCe ^((~BCi)&  BCo );
        Agi = BCi ^((~BCo)&  BCu );
        Ago = BCo ^((~BCu)&  BCa );
        Agu = BCu ^((~BCa)&  BCe );

        Ebe ^= De;
        BCa = ROL(Ebe, 1);
        Egi ^= Di;
        BCe = ROL(Egi, 6);
        Eko ^= Do;
        BCi = ROL(Eko, 25);
        Emu ^= Du;
        BCo = ROL(Emu, 8);
        Esa ^= Da;
        BCu = ROL(Esa, 18);
        Aka = BCa ^((~BCe)&  BCi );
        Ake = BCe ^((~BCi)&  BCo );
        Aki = BCi ^((~BCo)&  BCu );
        Ako = BCo ^((~BCu)&  BCa );
        Aku = BCu ^((~BCa)&  BCe );

        Ebu ^= Du;
        BCa = ROL(Ebu, 27);
        Ega ^= Da;
        BCe = ROL(Ega, 36);
        Eke ^= De;
        BCi = ROL(Eke, 10);
        Emi ^= Di;
        BCo = ROL(Emi, 15);
        Eso ^= Do;
        BCu = ROL(Eso, 56);
        Ama = BCa ^((~BCe)&  BCi );
        Ame = BCe ^((~BCi)&  BCo );
        Ami = BCi ^((~BCo)&  BCu );
        Amo = BCo ^((~BCu)&  BCa );
        Amu = BCu ^((~BCa)&  BCe );

        Ebi ^= Di;
        BCa = ROL(Ebi, 62);
        Ego ^= Do;
        BCe = ROL(Ego, 55);
        Eku ^= Du;
        BCi = ROL(Eku, 39);
        Ema ^= Da;
        BCo = ROL(Ema, 41);
        Ese ^= De;
        BCu = ROL(Ese, 2);
        Asa = BCa ^((~BCe)&  BCi );
        Ase = BCe ^((~BCi)&  BCo );
        Asi = BCi ^((~BCo)&  BCu );
        Aso = BCo ^((~BCu)&  BCa );
        Asu = BCu ^((~BCa)&  BCe );
    }

    //copyToState(state, A)
    state[ 0] = Aba;
    state[ 1] = Abe;
    state[ 2] = Abi;
    state[ 3] = Abo;
    state[ 4] = Abu;
    state[ 5] = Aga;
    state[ 6] = Age;
    state[ 7] = Agi;
    state[ 8] = Ago;
    state[ 9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}

static void keccak_absorb(uint64_t *s, unsigned int r,
                          const unsigned char *m, size_t mlen,
                          unsigned char p)
{
    size_t i;
	//unsigned char *t [200];
    unsigned char t[r];

	// Zero state
	for (i = 0; i < 25; ++i)
		s[i] = 0;

    while (mlen >= r) {
        for (i = 0; i < r / 8; ++i) {
            s[i] ^= load64(m + 8 * i);
        }
        KeccakF1600_StatePermute(s);
        mlen -= r;
        m += r;
    }

    for (i = 0; i < r; ++i) {
        t[i] = 0;
    }
    for (i = 0; i < mlen; ++i) {
        t[i] = m[i];
    }
    t[i] = p;
    t[r - 1] |= 128;
    for (i = 0; i < r / 8; ++i) {
        s[i] ^= load64(t + 8 * i);
    }
	//mbedtls_free(t);
}

static void keccak_squeezeblocks(unsigned char *h, size_t nblocks,
                                 uint64_t *s, uint32_t  r)
{

    while (nblocks > 0) {
        KeccakF1600_StatePermute(s);
        for (size_t i = 0; i < (r >> 3); i++) {
            store64(h + 8 * i, s[i]);
        }
        h += r;
        nblocks--;
    }
}


/*************************************************
 * Name:        keccak_inc_init
 *
 * Description: Initializes the incremental Keccak state to zero.
 *
 * Arguments:   - uint64_t *s_inc: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 **************************************************/
static void keccak_inc_init(uint64_t *s_inc) {
    size_t i;

    for (i = 0; i < 25; ++i) {
        s_inc[i] = 0;
    }
    s_inc[25] = 0;
}

/*************************************************
 * Name:        keccak_inc_absorb
 *
 * Description: Incremental keccak absorb
 *              Preceded by keccak_inc_init, succeeded by keccak_inc_finalize
 *
 * Arguments:   - uint64_t *s_inc: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *              - const unsigned char *m: pointer to input to be absorbed into s
 *              - size_t mlen: length of input in bytes
 **************************************************/
static void keccak_inc_absorb(uint64_t *s_inc, uint32_t r, const unsigned char *m,
                              size_t mlen) {
    size_t i;

    /* Recall that s_inc[25] is the non-absorbed bytes xored into the state */
    while (mlen + s_inc[25] >= r) {
        for (i = 0; i < r - s_inc[25]; i++) {
            /* Take the i'th byte from message
               xor with the s_inc[25] + i'th byte of the state; little-endian */
            s_inc[(s_inc[25] + i) >> 3] ^= (uint64_t)m[i] << (8 * ((s_inc[25] + i) & 0x07));
        }
        mlen -= (size_t)(r - s_inc[25]);
        m += r - s_inc[25];
        s_inc[25] = 0;

        KeccakF1600_StatePermute(s_inc);
    }

    for (i = 0; i < mlen; i++) {
        s_inc[(s_inc[25] + i) >> 3] ^= (uint64_t)m[i] << (8 * ((s_inc[25] + i) & 0x07));
    }
    s_inc[25] += mlen;
}

/*************************************************
 * Name:        keccak_inc_finalize
 *
 * Description: Finalizes Keccak absorb phase, prepares for squeezing
 *
 * Arguments:   - uint64_t *s_inc: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *              - unsigned char p: domain-separation byte for different
 *                                 Keccak-derived functions
 **************************************************/
static void keccak_inc_finalize(uint64_t *s_inc, uint32_t r, unsigned char p) {
    /* After keccak_inc_absorb, we are guaranteed that s_inc[25] < r,
       so we can always use one more byte for p in the current state. */
    s_inc[s_inc[25] >> 3] ^= (uint64_t)p << (8 * (s_inc[25] & 0x07));
    s_inc[(r - 1) >> 3] ^= (uint64_t)128 << (8 * ((r - 1) & 0x07));
    s_inc[25] = 0;
}

/*************************************************
 * Name:        keccak_inc_squeeze
 *
 * Description: Incremental Keccak squeeze; can be called on byte-level
 *
 * Arguments:   - unsigned char *h: pointer to output bytes
 *              - size_t outlen: number of bytes to be squeezed
 *              - uint64_t *s_inc: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 **************************************************/
static void keccak_inc_squeeze(unsigned char *h, size_t outlen,
                               uint64_t *s_inc, uint32_t r) {
    size_t i;

    /* First consume any bytes we still have sitting around */
    for (i = 0; i < outlen && i < s_inc[25]; i++) {
        /* There are s_inc[25] bytes left, so r - s_inc[25] is the first
           available byte. We consume from there, i.e., up to r. */
        h[i] = (unsigned char)(s_inc[(r - s_inc[25] + i) >> 3] >> (8 * ((r - s_inc[25] + i) & 0x07)));
    }
    h += i;
    outlen -= i;
    s_inc[25] -= i;

    /* Then squeeze the remaining necessary blocks */
    while (outlen > 0) {
        KeccakF1600_StatePermute(s_inc);

        for (i = 0; i < outlen && i < r; i++) {
            h[i] = (unsigned char)(s_inc[i >> 3] >> (8 * (i & 0x07)));
        }
        h += i;
        outlen -= i;
        s_inc[25] = r - i;
    }
}

void shake128_inc_init(uint64_t *s_inc) {
    keccak_inc_init(s_inc);
}

void shake128_inc_absorb(uint64_t *s_inc, const unsigned char *input, size_t inlen) {
    keccak_inc_absorb(s_inc, SHAKE128_RATE, input, inlen);
}

void shake128_inc_finalize(uint64_t *s_inc) {
    keccak_inc_finalize(s_inc, SHAKE128_RATE, 0x1F);
}

void shake128_inc_squeeze(unsigned char *output, size_t outlen, uint64_t *s_inc) {
    keccak_inc_squeeze(output, outlen, s_inc, SHAKE128_RATE);
}

void shake256_inc_init(uint64_t *s_inc) {
    keccak_inc_init(s_inc);
}

void shake256_inc_absorb(uint64_t *s_inc, const unsigned char *input, size_t inlen) {
    keccak_inc_absorb(s_inc, SHAKE256_RATE, input, inlen);
}

void shake256_inc_finalize(uint64_t *s_inc) {
    keccak_inc_finalize(s_inc, SHAKE256_RATE, 0x1F);
}

void shake256_inc_squeeze(unsigned char *output, size_t outlen, uint64_t *s_inc) {
    keccak_inc_squeeze(output, outlen, s_inc, SHAKE256_RATE);
}

/*************************************************
 * Name:        shake128
 *
 * Description: SHAKE128 XOF with non-incremental API
 *
 * Arguments:   - unsigned char *output: pointer to output
 *              - size_t outlen: requested output length in bytes
 *              - const unsigned char *input: pointer to input
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake128(unsigned char *out, unsigned long long outlen,
              const unsigned char *in, unsigned long long inlen)
{
    unsigned long long i;
    uint64_t s[25];
    unsigned char d[SHAKE128_RATE];

    keccak_absorb(s, SHAKE128_RATE, in, inlen, 0x1F);

    keccak_squeezeblocks(out, outlen / SHAKE128_RATE, s, SHAKE128_RATE);
    out += (outlen / SHAKE128_RATE) * SHAKE128_RATE;

    if (outlen % SHAKE128_RATE) {
        keccak_squeezeblocks(d, 1, s, SHAKE128_RATE);
        for (i = 0; i < outlen % SHAKE128_RATE; i++) {
            out[i] = d[i];
        }
    }
}
/*************************************************
* Name:        shake128_absorb
*
* Description: Absorb step of the SHAKE128 XOF.
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - uint64_t *s:                     pointer to (uninitialized) output Keccak state
*              - const unsigned char *input:      pointer to input to be absorbed into s
*              - unsigned long long inputByteLen: length of input in bytes
**************************************************/
void shake128_absorb(uint64_t *s, const unsigned char *input, unsigned int inputByteLen)
{
	keccak_absorb(s, SHAKE128_RATE, input, inputByteLen, 0x1F);
}

/*************************************************
* Name:        shake128_squeezeblocks
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of SHAKE128_RATE bytes each.
*              Modifies the state. Can be called multiple times to keep squeezing,
*              i.e., is incremental.
*
* Arguments:   - unsigned char *output:      pointer to output blocks
*              - unsigned long long nblocks: number of blocks to be squeezed (written to output)
*              - uint64_t *s:                pointer to in/output Keccak state
**************************************************/
void shake128_squeezeblocks(unsigned char *output, size_t nblocks, uint64_t *s)
{
	keccak_squeezeblocks(output, nblocks, s, SHAKE128_RATE);
}

/*************************************************
 * Name:        shake256_absorb
 *
 * Description: Absorb step of the SHAKE256 XOF.
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
 *              - const unsigned char *input: pointer to input to be absorbed
 *                                            into s
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake256_absorb(uint64_t *s, const unsigned char *input, size_t inlen) {
    keccak_absorb(s, SHAKE256_RATE, input, inlen, 0x1F);
}

/*************************************************
 * Name:        shake256_squeezeblocks
 *
 * Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
 *              SHAKE256_RATE bytes each. Modifies the state. Can be called
 *              multiple times to keep squeezing, i.e., is incremental.
 *
 * Arguments:   - unsigned char *output: pointer to output blocks
 *              - size_t nblocks: number of blocks to be squeezed
 *                                (written to output)
 *              - uint64_t *s: pointer to input/output Keccak state
 **************************************************/
void shake256_squeezeblocks(unsigned char *output, size_t nblocks, uint64_t *s) {
    keccak_squeezeblocks(output, nblocks, s, SHAKE256_RATE);
}


/*************************************************
* Name:        shake256
*
* Description: SHAKE256 XOF with non-incremental API
*
* Arguments:   - unsigned char *output:      pointer to output
*              - size_t outlen:  requested output length in bytes
- const unsigned char *input: pointer to input
- size_t inlen:   length of input in bytes
**************************************************/
void shake256(unsigned char *output, size_t outlen,
	const unsigned char *input, size_t inlen)
{
    HASH_ADD
	uint64_t s[25];
	unsigned char t[SHAKE256_RATE];
	size_t nblocks = outlen / SHAKE256_RATE;
	size_t i;

	/* Absorb input */
	keccak_absorb(s, SHAKE256_RATE, input, inlen, 0x1F);

	/* Squeeze output */
	keccak_squeezeblocks(output, nblocks, s, SHAKE256_RATE);

	output += nblocks*SHAKE256_RATE;
	outlen -= nblocks*SHAKE256_RATE;

	if (outlen)
	{
		keccak_squeezeblocks(t, 1, s, SHAKE256_RATE);
		for (i = 0; i<outlen; i++)
			output[i] = t[i];
	}
}

void sha3_256_inc_init(uint64_t *s_inc) {
    keccak_inc_init(s_inc);
}

void sha3_256_inc_absorb(uint64_t *s_inc, const unsigned char *input, size_t inlen) {
    keccak_inc_absorb(s_inc, SHA3_256_RATE, input, inlen);
}

void sha3_256_inc_finalize(unsigned char *output, uint64_t *s_inc) {
    unsigned char t[SHA3_256_RATE];
    keccak_inc_finalize(s_inc, SHA3_256_RATE, 0x06);

    keccak_squeezeblocks(t, 1, s_inc, SHA3_256_RATE);

    for (size_t i = 0; i < 32; i++) {
        output[i] = t[i];
    }
}

/*************************************************
* Name:        sha3_256
*
* Description: SHA3-256 with non-incremental API
*
* Arguments:   - unsigned char *output:      pointer to output
*              - const unsigned char *input: pointer to input
*              - size_t inlen:   length of input in bytes
**************************************************/
void sha3_256(unsigned char *output, const unsigned char *input, size_t inlen)
{
	uint64_t s[25];
	unsigned char t[SHA3_256_RATE];
	size_t i;

	/* Absorb input */
	keccak_absorb(s, SHA3_256_RATE, input, inlen, 0x06);

	/* Squeeze output */
	keccak_squeezeblocks(t, 1, s, SHA3_256_RATE);

	for (i = 0; i<32; i++)
		output[i] = t[i];
}

void sha3_512_inc_init(uint64_t *s_inc) {
    keccak_inc_init(s_inc);
}

void sha3_512_inc_absorb(uint64_t *s_inc, const unsigned char *input, size_t inlen) {
    keccak_inc_absorb(s_inc, SHA3_512_RATE, input, inlen);
}

void sha3_512_inc_finalize(unsigned char *output, uint64_t *s_inc) {
    unsigned char t[SHA3_512_RATE];
    keccak_inc_finalize(s_inc, SHA3_512_RATE, 0x06);

    keccak_squeezeblocks(t, 1, s_inc, SHA3_512_RATE);

    for (size_t i = 0; i < 32; i++) {
        output[i] = t[i];
    }
}

/*************************************************
* Name:        sha3_512
*
* Description: SHA3-512 with non-incremental API
*
* Arguments:   - unsigned char *output:      pointer to output
*              - const unsigned char *input: pointer to input
*              - size_t inlen:   length of input in bytes
**************************************************/
void sha3_512(unsigned char *output, const unsigned char *input, size_t inlen)
{
	uint64_t s[25];
	unsigned char t[SHA3_512_RATE];
	size_t i;

	/* Absorb input */
	keccak_absorb(s, SHA3_512_RATE, input, inlen, 0x06);

	/* Squeeze output */
	keccak_squeezeblocks(t, 1, s, SHA3_512_RATE);

	for (i = 0; i<64; i++)
		output[i] = t[i];
}
