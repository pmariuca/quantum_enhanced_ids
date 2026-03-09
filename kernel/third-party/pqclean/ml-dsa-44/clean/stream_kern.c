// SPDX-License-Identifier: GPL-2.0
#include <linux/string.h>
#include "params.h"
#include "symmetric.h"   /* stream128/256 prototypes + typedefs */
#include "fips202.h"     /* inc ctx API */

/* LE helper */
static inline void put_le16(uint8_t b[2], uint16_t v)
{
    b[0] = (uint8_t)(v & 0xff);
    b[1] = (uint8_t)(v >> 8);
}

/* ---- PQClean stream init helpers ---- */
void PQCLEAN_MLDSA44_CLEAN_dilithium_shake128_stream_init(
    stream128_state *st, const uint8_t seed[SEEDBYTES], uint16_t nonce)
{
    uint8_t n[2]; put_le16(n, nonce);
    shake128_inc_init(st);
    shake128_inc_absorb(st, seed, SEEDBYTES);
    shake128_inc_absorb(st, n, 2);
    shake128_inc_finalize(st);
}

void PQCLEAN_MLDSA44_CLEAN_dilithium_shake256_stream_init(
    stream256_state *st, const uint8_t seed[CRHBYTES], uint16_t nonce)
{
    uint8_t n[2]; put_le16(n, nonce);
    shake256_inc_init(st);
    shake256_inc_absorb(st, seed, CRHBYTES);
    shake256_inc_absorb(st, n, 2);
    shake256_inc_finalize(st);
}

/* ---- PQClean stream128 API ---- */
void stream128_init(stream128_state *st, const uint8_t seed[SEEDBYTES], uint16_t nonce)
{
    PQCLEAN_MLDSA44_CLEAN_dilithium_shake128_stream_init(st, seed, nonce);
}
void stream128_squeezeblocks(uint8_t *out, size_t nblocks, stream128_state *st)
{
    while (nblocks--) {
        shake128_inc_squeeze(out, STREAM128_BLOCKBYTES, st);
        out += STREAM128_BLOCKBYTES;
    }
}
void stream128_release(stream128_state *st) { shake128_inc_ctx_release(st); }

/* ---- PQClean stream256 API ---- */
void stream256_init(stream256_state *st, const uint8_t seed[CRHBYTES], uint16_t nonce)
{
    PQCLEAN_MLDSA44_CLEAN_dilithium_shake256_stream_init(st, seed, nonce);
}
void stream256_squeezeblocks(uint8_t *out, size_t nblocks, stream256_state *st)
{
    while (nblocks--) {
        shake256_inc_squeeze(out, STREAM256_BLOCKBYTES, st);
        out += STREAM256_BLOCKBYTES;
    }
}
void stream256_release(stream256_state *st) { shake256_inc_ctx_release(st); }