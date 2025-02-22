#include <string.h>
#include <stdint.h>

#include "pq/spx.h"
#include "pq/spx_params.h"
#include "pq/spx_wots.h"
#include "pq/spx_fors.h"
#include "pq/spx_hash.h"
#include "pq/spx_thash.h"
#include "pq/spx_hash_address.h"
#include "pq/spx_utils.h"
#include "pq/spx_merkle.h"

#include "mbedtls/md.h"

// /** Round 1 function
//  * Computes the leaf at a given address. First generates the WOTS key pair,
//  * then computes leaf by hashing horizontally.
//  */
// static void wots_gen_leaf(const sphincs_md_info_t *md, unsigned char *leaf, const unsigned char *sk_seed,
//                           const unsigned char *pub_seed,
//                           uint32_t addr_idx, const uint32_t tree_addr[8])
// {
//     unsigned char pk[SPX_WOTS_BYTES];
//     uint32_t wots_addr[8] = {0};
//     uint32_t wots_pk_addr[8] = {0};

//     set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
//     set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

//     copy_subtree_addr(wots_addr, tree_addr);
//     set_keypair_addr(wots_addr, addr_idx);
//     wots_gen_pk(md, pk, sk_seed, pub_seed, wots_addr);

//     copy_keypair_addr(wots_pk_addr, wots_addr);
// 	md->thash(leaf, pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);
// }


/* Round 4
 * Returns the length of a secret key, in bytes
 */
unsigned long long crypto_sign_secretkeybytes(void)
{
    return CRYPTO_SECRETKEYBYTES_SPX;
}

/*
 * Returns the length of a public key, in bytes
 */
unsigned long long crypto_sign_publickeybytes(void)
{
    return CRYPTO_PUBLICKEYBYTES_SPX;
}

/* Round 4
 * Returns the length of a signature, in bytes
 */
unsigned long long crypto_sign_bytes(void)
{
    return CRYPTO_BYTES_SPX;
}

/* Round 4
 * Returns the length of the seed required to generate a key pair, in bytes
 */
unsigned long long crypto_sign_seedbytes(void)
{
    return CRYPTO_SEEDBYTES_SPX;
}


// /* Round 1 vesion
//  * Generates an SPX key pair.
//  * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
//  * Format pk: [PUB_SEED || root]
//  */
// int crypto_sign_keypair(const sphincs_md_info_t *md, unsigned char *pk, unsigned char *sk)
// {
//     /* We do not need the auth path in key generation, but it simplifies the
//        code to have just one treehash routine that computes both root and path
//        in one function. */
//     unsigned char auth_path[SPX_TREE_HEIGHT * SPX_N];
//     uint32_t top_tree_addr[8] = {0};

//     set_layer_addr(top_tree_addr, SPX_D - 1);
//     set_type(top_tree_addr, SPX_ADDR_TYPE_HASHTREE);

//     /* Initialize SK_SEED, SK_PRF and PUB_SEED. */
//     //randombytes(sk, 3 * SPX_N);

//     memcpy(pk, sk + 2*SPX_N, SPX_N);

//     /* This hook allows the hash function instantiation to do whatever
//        preparation or computation it needs, based on the public seed. */
// 	md->initialize_hash_function(pk, sk);

//     /* Compute root node of the top-most subtree. */
    // treehash(md, sk + 3*SPX_N, auth_path, sk, sk + 2*SPX_N, 0, 0, SPX_TREE_HEIGHT,
//              wots_gen_leaf, top_tree_addr);

//     memcpy(pk + SPX_N, sk + 3*SPX_N, SPX_N);

//     return 0;
// }


/* Round 4 vesion
 * Generates an SPX key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_seed_keypair(const sphincs_md_info_t *md, unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed)
{
    spx_ctx ctx;
    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, CRYPTO_SEEDBYTES_SPX);

    memcpy(pk, sk + 2*SPX_N, SPX_N);

    memcpy(ctx.pub_seed, pk, SPX_N);
    memcpy(ctx.sk_seed, sk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    /* Compute root node of the top-most subtree. */
    merkle_gen_root(sk + 3*SPX_N, &ctx);

    memcpy(pk + SPX_N, sk + 3*SPX_N, SPX_N);

    return 0;
}

/*Round 4 vesion
 * Generates an SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_keypair(const sphincs_md_info_t *md, unsigned char *pk, unsigned char *sk,
				int(*f_rng)(void *, unsigned char *, size_t), 
				void *p_rng)
{
  unsigned char seed[CRYPTO_SEEDBYTES_SPX];
  // randombytes(seed, CRYPTO_SEEDBYTES_SPX);
  f_rng(p_rng, seed, CRYPTO_SEEDBYTES_SPX);
  
  crypto_sign_seed_keypair(md, pk, sk, seed);

  return 0;
}



// /** Round 1 vesion
//  * Returns an array containing the signature followed by the message.
//  */
// int crypto_sign(const sphincs_md_info_t *md, unsigned char *sm, unsigned long long *smlen,
//                 const unsigned char *m, unsigned long long mlen,
//                 const unsigned char *sk, unsigned char *optrand)
// {
//     const unsigned char *sk_seed = sk;
//     const unsigned char *sk_prf = sk + SPX_N;
//     const unsigned char *pk = sk + 2*SPX_N;
//     const unsigned char *pub_seed = pk;

//     //unsigned char optrand[SPX_N];
//     unsigned char mhash[SPX_FORS_MSG_BYTES];
//     unsigned char root[SPX_N];
//     unsigned long long i;
//     uint64_t tree;
//     uint32_t idx_leaf;
//     uint32_t wots_addr[8] = {0};
//     uint32_t tree_addr[8] = {0};

//     /* This hook allows the hash function instantiation to do whatever
//        preparation or computation it needs, based on the public seed. */
// 	md->initialize_hash_function(pub_seed, sk_seed);

//     set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
//     set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

//     /* Already put the message in the right place, to make it easier to prepend
//      * things when computing the hash over the message. */
//     /* We need to do this from back to front, so that it works when sm = m */
// 	//int spx_bytes = SPX_BYTES;
// 	//mbedtls_printf("%i", spx_bytes);
//     for (i = mlen; i > 0; i--) {
//         sm[SPX_BYTES + i - 1] = m[i - 1];
//     }
//     *smlen = SPX_BYTES + mlen;

//     /* Optionally, signing can be made non-deterministic using optrand.
//        This can help counter side-channel attacks that would benefit from
//        getting a large number of traces when the signer uses the same nodes. */
//     //randombytes(optrand, SPX_N);
//     /* Compute the digest randomization value. */
// 	md->gen_message_random(sm, sk_prf, optrand, sm + SPX_BYTES, mlen);

//     /* Derive the message digest and leaf index from R, PK and M. */
//     md->hash_message(mhash, &tree, &idx_leaf, sm, pk, sm + SPX_BYTES, mlen);
//     sm += SPX_N;

//     set_tree_addr(wots_addr, tree);
//     set_keypair_addr(wots_addr, idx_leaf);

//     /* Sign the message hash using FORS. */
//     fors_sign(md, sm, root, mhash, sk_seed, pub_seed, wots_addr);
//     sm += SPX_FORS_BYTES;

//     for (i = 0; i < SPX_D; i++) {
//         set_layer_addr(tree_addr, i);
//         set_tree_addr(tree_addr, tree);

//         copy_subtree_addr(wots_addr, tree_addr);
//         set_keypair_addr(wots_addr, idx_leaf);

//         /* Compute a WOTS signature. */
//         wots_sign(md, sm, root, sk_seed, pub_seed, wots_addr);
//         sm += SPX_WOTS_BYTES;

//         /* Compute the authentication path for the used WOTS leaf. */
//         treehash(md, root, sm, sk_seed, pub_seed, idx_leaf, 0,
//                  SPX_TREE_HEIGHT, wots_gen_leaf, tree_addr);
//         sm += SPX_TREE_HEIGHT * SPX_N;

//         /* Update the indices for the next layer. */
//         idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
//         tree = tree >> SPX_TREE_HEIGHT;
//     }

//     return 0;
// }


/** Round 4 vesion
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(unsigned char *sig, size_t *siglen,
                          const unsigned char *m, size_t mlen, const unsigned char *sk)
{
    spx_ctx ctx;

    const unsigned char *sk_prf = sk + SPX_N;
    const unsigned char *pk = sk + 2*SPX_N;

    unsigned char optrand[SPX_N];
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char root[SPX_N];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    //randombytes(optrand, SPX_N);
    /* Compute the digest randomization value. */
    gen_message_random(sig, sk_prf, optrand, m, mlen, &ctx);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    *siglen = SPX_BYTES;

    return 0;
}



/** Round 4 vesion
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk)
{
    size_t siglen;

    crypto_sign_signature(sm, &siglen, m, (size_t)mlen, sk);

    memmove(sm + SPX_BYTES, m, mlen);
    *smlen = siglen + mlen;

    return 0;
}



// /** Round 1
//  * Verifies a given signature-message pair under a given public key.
//  */
// int crypto_sign_open(const sphincs_md_info_t *md, unsigned char *m, unsigned long long mlen,
//                      const unsigned char *sm, unsigned long long smlen,
//                      const unsigned char *pk)
// {
//     const unsigned char *pub_seed = pk;
//     const unsigned char *pub_root = pk + SPX_N;
//     unsigned char mhash[SPX_FORS_MSG_BYTES];
//     unsigned char wots_pk[SPX_WOTS_BYTES];
//     unsigned char root[SPX_N];
//     unsigned char leaf[SPX_N];
//     unsigned char sig[SPX_BYTES];
//     unsigned char *sigptr = sig;
//     unsigned int i;
//     uint64_t tree;
//     uint32_t idx_leaf;
//     uint32_t wots_addr[8] = {0};
//     uint32_t tree_addr[8] = {0};
//     uint32_t wots_pk_addr[8] = {0};

//     /* This hook allows the hash function instantiation to do whatever
//        preparation or computation it needs, based on the public seed. */
// 	md->initialize_hash_function(pub_seed, NULL);

//     set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
//     set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
//     set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

//     //*mlen = smlen - SPX_BYTES;

//     /* Put the message all the way at the end of the m buffer, so that we can
//      * prepend the required other inputs for the hash function. */
//     //memcpy(m + SPX_BYTES, sm + SPX_BYTES, mlen);

//     /* Create a copy of the signature so that m = sm is not an issue */
//     memcpy(sig, sm, SPX_BYTES);

//     /* Derive the message digest and leaf index from R || PK || M. */
//     /* The additional SPX_N is a result of the hash domain separator. */
// 	md->hash_message(mhash, &tree, &idx_leaf, sigptr, pk, m, mlen);// + SPX_BYTES, mlen);
//     sigptr += SPX_N;

//     /* Layer correctly defaults to 0, so no need to set_layer_addr */
//     set_tree_addr(wots_addr, tree);
//     set_keypair_addr(wots_addr, idx_leaf);

//     fors_pk_from_sig(md, root, sigptr, mhash, pub_seed, wots_addr);
//     sigptr += SPX_FORS_BYTES;

//     /* For each subtree.. */
//     for (i = 0; i < SPX_D; i++) {
//         set_layer_addr(tree_addr, i);
//         set_tree_addr(tree_addr, tree);

//         copy_subtree_addr(wots_addr, tree_addr);
//         set_keypair_addr(wots_addr, idx_leaf);

//         copy_keypair_addr(wots_pk_addr, wots_addr);

//         /* The WOTS public key is only correct if the signature was correct. */
//         /* Initially, root is the FORS pk, but on subsequent iterations it is
//            the root of the subtree below the currently processed subtree. */
//         wots_pk_from_sig(md, wots_pk, sigptr, root, pub_seed, wots_addr);
//         sigptr += SPX_WOTS_BYTES;

//         /* Compute the leaf node using the WOTS public key. */
// 		md->thash(leaf, wots_pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);

//         /* Compute the root node of this subtree. */
//         compute_root(md, root, leaf, idx_leaf, 0, sigptr, SPX_TREE_HEIGHT,
//                      pub_seed, tree_addr);
//         sigptr += SPX_TREE_HEIGHT * SPX_N;

//         /* Update the indices for the next layer. */
//         idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
//         tree = tree >> SPX_TREE_HEIGHT;
//     }

//     /* Check if the root node equals the root node in the public key. */
//     if (memcmp(root, pub_root, SPX_N)) {
//         /* If not, zero the message */
//         memset(m, 0, mlen);
//         mlen = 0;
//         return -1;
//     }

//     return 0;
// }


/** Round 4
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(const unsigned char *sig, size_t siglen,
                       const unsigned char *m, size_t mlen, const unsigned char *pk)
{
    spx_ctx ctx;
    const unsigned char *pub_root = pk + SPX_N;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned char leaf[SPX_N];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    if (siglen != SPX_BYTES) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);
 
    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr);
        sig += SPX_WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                     &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N)) {
        return -1;
    }

    return 0;
}


/** Round 4
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    /* The API caller does not necessarily know what size a signature should be
       but SPHINCS+ signatures are always exactly SPX_BYTES. */
    if (smlen < SPX_BYTES) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    //*mlen = smlen - SPX_BYTES;
    size_t alt_mlen = smlen - SPX_BYTES;
    if (crypto_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, alt_mlen, pk)) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }
    /*if (crypto_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, (size_t)*mlen, pk)) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }*/

    /* If verification was successful, move the message to the right place. */
    //memmove(m, sm + SPX_BYTES, *mlen);

    return 0;
}


int mbedtls_sphincs_check_pub_priv(const mbedtls_sphincs_context *pub, const mbedtls_sphincs_context *prv)
{
	if (mbedtls_mpi_cmp_mpi(&pub->key.pk_seed, &prv->key.pk_seed) ||
		mbedtls_mpi_cmp_mpi(&pub->key.root, &prv->key.root))
	{
		return -1;
	}
	return 0;
}

int mbedtls_sphincs_genkey(mbedtls_md_type_t md_alg, mbedtls_sphincs_context *ctx,
							int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	int ret;
	unsigned char pk[SPX_PK_BYTES];
	unsigned char sk[SPX_SK_BYTES];

	sphincs_md_info_t *md;
	if (md_alg == MBEDTLS_MD_SHA256)
	{
		md = &sphincs_sha256_info;
	}
	else
	{
		md = &sphincs_shake256_info;
	}

	/* Initialize with random data */
	do {
		MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&ctx->key.sk_seed, SPX_N, f_rng, p_rng));
	} while (mbedtls_mpi_bitlen(&ctx->key.sk_seed) == 0);
	do {
		MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&ctx->key.sk_prf, SPX_N, f_rng, p_rng));
	} while (mbedtls_mpi_bitlen(&ctx->key.sk_seed) == 0);
	do {
		MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&ctx->key.pk_seed, SPX_N, f_rng, p_rng));
	} while (mbedtls_mpi_bitlen(&ctx->key.sk_seed) == 0);

	mbedtls_mpi_write_binary(&ctx->key.sk_seed, sk + 0 * SPX_N, SPX_N);
	mbedtls_mpi_write_binary(&ctx->key.sk_prf, sk + 1 * SPX_N, SPX_N);
	mbedtls_mpi_write_binary(&ctx->key.pk_seed, sk + 2 * SPX_N, SPX_N);

	if (crypto_sign_keypair(md, pk, sk, f_rng, p_rng)) {
		return -1;
	}
	mbedtls_mpi_read_binary(&ctx->key.sk_seed, sk + 0 * SPX_N, SPX_N);
	mbedtls_mpi_read_binary(&ctx->key.sk_prf, sk + 1 * SPX_N, SPX_N);
	mbedtls_mpi_read_binary(&ctx->key.pk_seed, sk + 2 * SPX_N, SPX_N);
	mbedtls_mpi_read_binary(&ctx->key.root, sk + 3 * SPX_N, SPX_N);
	ctx->key.md_alg = md_alg;
	ctx->key.bitlen = SPX_N * 8; 

cleanup:
	if (ret != 0)
		return(ret);

	return ( 0 );
}

int mbedtls_sphincs_write_signature(mbedtls_sphincs_context *ctx,
	//mbedtls_md_type_t md_alg,
	const unsigned char *hash, size_t hlen,
	unsigned char *sig, size_t *slen,
	int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	int ret = 0;
	unsigned char sk[SPX_SK_BYTES];
	unsigned char optrand[SPX_N];
	unsigned long long ull_slen = 0;

	mbedtls_mpi_write_binary(&ctx->key.sk_seed, sk + 0 * SPX_N, SPX_N);
	mbedtls_mpi_write_binary(&ctx->key.sk_prf, sk + 1 * SPX_N, SPX_N);
	mbedtls_mpi_write_binary(&ctx->key.pk_seed, sk + 2 * SPX_N, SPX_N);
	mbedtls_mpi_write_binary(&ctx->key.root, sk + 3 * SPX_N, SPX_N);

	sphincs_md_info_t *md;
	if (ctx->key.md_alg == MBEDTLS_MD_SHA256)
	{
		md = &sphincs_sha256_info;
	}
	else
	{
		md = &sphincs_shake256_info;
	}
	
	if ((ret = f_rng(p_rng, optrand, SPX_N)) != 0)
		return ret;

	ret = crypto_sign(sig, &ull_slen, hash, hlen, sk);
	*slen = (size_t)ull_slen;

	return (0);
}

int mbedtls_sphincs_read_signature(mbedtls_sphincs_context *ctx,
	//mbedtls_md_type_t md_alg,
	const unsigned char *hash, size_t hlen,
	const unsigned char *sig, size_t slen)
{
	unsigned char pk[SPX_PK_BYTES];
 
	mbedtls_mpi_write_binary(&ctx->key.pk_seed, pk + 0 * SPX_N, SPX_N);
	mbedtls_mpi_write_binary(&ctx->key.root, pk + 1 * SPX_N, SPX_N);

	//mbedtls_mpi_write_file("Root:    ", &ctx->key.root, 16, NULL);
	//mbedtls_mpi_write_file("PK_Seed: ", &ctx->key.pk_seed, 16, NULL);

	sphincs_md_info_t *md;
	if (ctx->key.md_alg == MBEDTLS_MD_SHA256)
	{
		md = &sphincs_sha256_info;
	}
	else
	{
		md = &sphincs_shake256_info;
	}

	return crypto_sign_open(hash, hlen, sig, slen, pk);
}

/*
* Initialize context
*/
void mbedtls_sphincs_init(mbedtls_sphincs_context *ctx)
{
	mbedtls_mpi_init(&ctx->key.root);
	mbedtls_mpi_init(&ctx->key.pk_seed);
	mbedtls_mpi_init(&ctx->key.sk_seed);
	mbedtls_mpi_init(&ctx->key.sk_prf);
}


/*
* Free context
*/
void mbedtls_sphincs_free(mbedtls_sphincs_context *ctx)
{
	mbedtls_mpi_free(&ctx->key.root);
	mbedtls_mpi_free(&ctx->key.pk_seed);
	mbedtls_mpi_free(&ctx->key.sk_seed);
	mbedtls_mpi_free(&ctx->key.sk_prf);
}

