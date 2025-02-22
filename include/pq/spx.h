#ifndef SPX_H
#define SPX_H

#include "mbedtls/bignum.h"
#include "mbedtls/md.h"
#include "pq/spx_hash.h"
#include "pq/spx_thash.h"
#include "pq/spx_params.h"

#define CRYPTO_ALGNAME_SPX "SPHINCS+"

#define CRYPTO_SECRETKEYBYTES_SPX SPX_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES_SPX SPX_PK_BYTES
#define CRYPTO_BYTES_SPX SPX_BYTES
#define CRYPTO_SEEDBYTES_SPX 3*SPX_N

typedef struct
{
	unsigned int tree_height;
	unsigned int fors_height;
	unsigned int fors_trees;
	unsigned int wots_w;
}
mbedtls_sphincs_params;


typedef struct
{
	mbedtls_mpi sk_prf;
	mbedtls_mpi sk_seed;
	mbedtls_mpi root;
	mbedtls_mpi pk_seed;
	mbedtls_md_type_t md_alg;
	size_t bitlen;
}
mbedtls_sphincs_keypair;


typedef struct
{
	mbedtls_sphincs_params params;
	mbedtls_sphincs_keypair key;
}
mbedtls_sphincs_context;

/*
* mbedTLS API
*/

void mbedtls_sphincs_init(mbedtls_sphincs_context *ctx);

void mbedtls_sphincs_free(mbedtls_sphincs_context *ctx);

int mbedtls_sphincs_check_pub_priv(const mbedtls_sphincs_context *pub, const mbedtls_sphincs_context *prv);

/**
* \brief          This function generates an SPHINCS+ keypair.
*
* \param ctx      The SPHINCS context to store the keypair in.
*
* \return         \c 0 on success
*				  or an error code on failure.
*/
int mbedtls_sphincs_genkey(mbedtls_md_type_t md_alg, mbedtls_sphincs_context *ctx,
	int(*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
* \brief           This function computes the SPHINCS+ signature and writes it
*                  to a buffer.
*
* \warning         It is not thread-safe to use the same context in
*                  multiple threads.
*
* \param ctx       The SPHINCS context.
* \param hash      The message hash.
* \param hlen      The length of the hash.
* \param sig       The buffer that holds the signature.
* \param slen      The length of the signature written.
*
* \return          \c 0 on success
*                  or an error code on failure.
*/
int mbedtls_sphincs_write_signature(mbedtls_sphincs_context *ctx,
	//mbedtls_md_type_t md_alg,
	const unsigned char *hash, size_t hlen,
	unsigned char *sig, size_t *slen,
	int(*f_rng)(void *, unsigned char *, size_t), void *p_rng
	);

/**
* \brief           This function reads and verifies an SPHINCS+ signature.
*
* \param ctx       The SPHINCS context.
* \param hash      The message hash.
* \param hlen      The size of the hash.
* \param sig       The signature to read and verify.
* \param slen      The size of \p sig.
*
* \return          \c 0 on success
*					or an error code on failure.
*/
int mbedtls_sphincs_read_signature(mbedtls_sphincs_context *ctx,
	//mbedtls_md_type_t md_alg,
	const unsigned char *hash, size_t hlen,
	const unsigned char *sig, size_t slen);

/*
* Referenzimplementierung API
*/

//Round 1

// /*
// * Generates a SPHINCS+ key pair.
// * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
// * Format pk: [root || PUB_SEED]
// */
// int crypto_sign_keypair(const sphincs_md_info_t *md, unsigned char *pk, unsigned char *sk);


// /**
// * Returns an array containing the signature followed by the message.
// */
// int crypto_sign(const sphincs_md_info_t *md, unsigned char *sm, unsigned long long *smlen,
// 	const unsigned char *m, unsigned long long mlen,
// 	const unsigned char *sk, unsigned char *optrand);

// /**
// * Verifies a given signature-message pair under a given public key.
// */
// int crypto_sign_open(const sphincs_md_info_t *md, unsigned char *m, unsigned long long mlen,
// 	const unsigned char *sm, unsigned long long smlen,
// 	const unsigned char *pk);
// #endif


//Round 4

/*
 * Returns the length of a secret key, in bytes
 */
unsigned long long crypto_sign_secretkeybytes(void);

/*
 * Returns the length of a public key, in bytes
 */
unsigned long long crypto_sign_publickeybytes(void);

/*
 * Returns the length of a signature, in bytes
 */
unsigned long long crypto_sign_bytes(void);

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
unsigned long long crypto_sign_seedbytes(void);

/*
 * Generates a SPHINCS+ key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int crypto_sign_seed_keypair(const sphincs_md_info_t *md, unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed);

/*
 * Generates a SPHINCS+ key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int crypto_sign_keypair(const sphincs_md_info_t *md, unsigned char *pk, unsigned char *sk,
				int(*f_rng)(void *, unsigned char *, size_t), 
				void *p_rng);

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(unsigned char *sig, size_t *siglen,
                          const unsigned char *m, size_t mlen, const unsigned char *sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(const unsigned char *sig, size_t siglen,
                       const unsigned char *m, size_t mlen, const unsigned char *pk);

/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk);

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

#endif

