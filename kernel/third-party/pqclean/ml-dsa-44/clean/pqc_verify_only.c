// SPDX-License-Identifier: MIT
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "params.h"
#include "packing.h"
#include "poly.h"
#include "polyvec.h"
#include "pqc_verify_only.h"
#include "keccak_kern.h"

/*
 * ML-DSA-44 verification (verification context version).
 * This version is kernel-safe:
 *  - no incremental SHAKE calls
 *  - no fips202.c / symmetric-shake.c
 *  - no signing/keygen code
 *  - no giant stack frames
 */
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(
        const uint8_t *sig,
        size_t siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *pk)
{
    unsigned int i;
    uint8_t buf[K * POLYW1_PACKEDBYTES];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[CRHBYTES];
    uint8_t c[CTILDEBYTES];
    uint8_t c2[CTILDEBYTES];
    poly cp;
    
    polyvecl *mat = kmalloc_array(K, sizeof(*mat), GFP_KERNEL);
    polyvecl *pz  = kmalloc(sizeof(*pz), GFP_KERNEL);
    polyveck *pt1 = kmalloc(sizeof(*pt1), GFP_KERNEL);
    polyveck *pw1 = kmalloc(sizeof(*pw1), GFP_KERNEL);
    polyveck *ph  = kmalloc(sizeof(*ph), GFP_KERNEL);
    if (!mat || !pz || !pt1 || !pw1 || !ph) { /* free & return -1 */ }

    /* Basic bounds as in PQClean (return -1 on failure) */
    if (ctxlen > 255 || siglen != PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES) {
        return -1;
    }

    /* Unpack pk and signature; quick norm check on z */
    PQCLEAN_MLDSA44_CLEAN_unpack_pk(rho, pt1, pk);
    if (PQCLEAN_MLDSA44_CLEAN_unpack_sig(c, pz, ph, sig)) {
        return -1;
    }
    if (PQCLEAN_MLDSA44_CLEAN_polyvecl_chknorm(pz, GAMMA1 - BETA)) {
        return -1;
    }

    /*
     * ---- Compute mu = CRH( H(pk, TRBYTES), 0x00 || ctxlen || ctx || m ) ----
     * PQClean uses incremental SHAKE here; we do an equivalent one-shot:
     *   h1 = SHAKE256(pk, TRBYTES)
     *   mu = SHAKE256( h1 || 0x00 || ctxlen || ctx || m, CRHBYTES )
     */
    {
        uint8_t h1[TRBYTES];
        uint8_t len_tag[2] = { 0x00, (uint8_t)ctxlen };
        size_t total = TRBYTES + sizeof(len_tag) + ctxlen + mlen;
        uint8_t *tmp = NULL;
        size_t off = 0;

        /* h1 = SHAKE256(pk, TRBYTES) */
        shake256(h1, TRBYTES, pk, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES);

        tmp = kmalloc(total, GFP_KERNEL);
        if (!tmp) {
            return -1;
        }

        memcpy(tmp + off, h1, TRBYTES);               off += TRBYTES;
        memcpy(tmp + off, len_tag, sizeof(len_tag));  off += sizeof(len_tag);
        if (ctxlen) { memcpy(tmp + off, ctx, ctxlen); off += ctxlen; }
        if (mlen)  { memcpy(tmp + off, m,   mlen);    off += mlen;  }

        shake256(mu, CRHBYTES, tmp, total);
        kfree(tmp);
    }

    /* Matrix-vector multiplication; compute w1 = A*z - c * (t1<<D) */
    PQCLEAN_MLDSA44_CLEAN_poly_challenge(&cp, c);
    PQCLEAN_MLDSA44_CLEAN_polyvec_matrix_expand(mat, rho);

    PQCLEAN_MLDSA44_CLEAN_polyvecl_ntt(pz);
    PQCLEAN_MLDSA44_CLEAN_polyvec_matrix_pointwise_montgomery(pw1, mat, pz);

    PQCLEAN_MLDSA44_CLEAN_poly_ntt(&cp);
    PQCLEAN_MLDSA44_CLEAN_polyveck_shiftl(pt1);
    PQCLEAN_MLDSA44_CLEAN_polyveck_ntt(pt1);
    PQCLEAN_MLDSA44_CLEAN_polyveck_pointwise_poly_montgomery(pt1, &cp, pt1);

    PQCLEAN_MLDSA44_CLEAN_polyveck_sub(pw1, pw1, pt1);
    PQCLEAN_MLDSA44_CLEAN_polyveck_reduce(pw1);
    PQCLEAN_MLDSA44_CLEAN_polyveck_invntt_tomont(pw1);

    /* Reconstruct w1 and pack */
    PQCLEAN_MLDSA44_CLEAN_polyveck_caddq(pw1);
    PQCLEAN_MLDSA44_CLEAN_polyveck_use_hint(pw1, pw1, ph);
    PQCLEAN_MLDSA44_CLEAN_polyveck_pack_w1(buf, pw1);

    /*
     * ---- Compute c2 = SHAKE256( mu || buf, CTILDEBYTES ) ----
     * Replaces incremental SHAKE used by PQClean.
     */
    {
        size_t total = CRHBYTES + K * POLYW1_PACKEDBYTES;
        uint8_t *tmp = kmalloc(total, GFP_KERNEL);
        if (!tmp) {
            return -1;
        }
        memcpy(tmp, mu, CRHBYTES);
        memcpy(tmp + CRHBYTES, buf, K * POLYW1_PACKEDBYTES);

        shake256(c2, CTILDEBYTES, tmp, total);
        kfree(tmp);
    }

    /* Check challenge */
    for (i = 0; i < CTILDEBYTES; ++i) {
        if (c[i] != c2[i]) {
            return -1;
        }
    }

    return 0;
}

/* Thin wrapper: verify(message) without context */
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
        const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk)
{
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(
        sig, siglen,
        m, mlen,
        NULL, 0,
        pk
    );
}