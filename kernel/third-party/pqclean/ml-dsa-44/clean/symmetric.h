// SPDX-License-Identifier: GPL-2.0
#pragma once
#include <linux/types.h>
#include <linux/stddef.h>
#include "params.h"
#include "fips202.h"  /* for shake128incctx/shake256incctx + prototypes */

/* ---- SHAKE rates (bytes per block) ---- */
#ifndef SHAKE128_RATE
#define SHAKE128_RATE 168
#endif
#ifndef SHAKE256_RATE
#define SHAKE256_RATE 136
#endif

/* PQClean uses these for block sizes in stream squeezes */
#ifndef STREAM128_BLOCKBYTES
#define STREAM128_BLOCKBYTES SHAKE128_RATE
#endif
#ifndef STREAM256_BLOCKBYTES
#define STREAM256_BLOCKBYTES SHAKE256_RATE
#endif

/* ---- PQClean aliases for stream state ----
 * In PQClean, stream states are typedeffed to incremental contexts.
 */
typedef shake128incctx stream128_state;
typedef shake256incctx stream256_state;

/* ---- PQClean “symmetric” helpers used by poly/polyvec/matrix expansion ----
 * Implemented in stream_kern.c
 */
void PQCLEAN_MLDSA44_CLEAN_dilithium_shake128_stream_init(
    stream128_state *st, const uint8_t seed[SEEDBYTES], uint16_t nonce);

void PQCLEAN_MLDSA44_CLEAN_dilithium_shake256_stream_init(
    stream256_state *st, const uint8_t seed[CRHBYTES], uint16_t nonce);

void stream128_init(stream128_state *st, const uint8_t seed[SEEDBYTES], uint16_t nonce);
void stream128_squeezeblocks(uint8_t *out, size_t nblocks, stream128_state *st);
void stream128_release(stream128_state *st);

void stream256_init(stream256_state *st, const uint8_t seed[CRHBYTES], uint16_t nonce);
void stream256_squeezeblocks(uint8_t *out, size_t nblocks, stream256_state *st);
void stream256_release(stream256_state *st);