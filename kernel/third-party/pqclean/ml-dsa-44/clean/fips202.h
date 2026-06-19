// SPDX-License-Identifier: GPL-2.0
#pragma once
#include <linux/types.h>
#include <linux/stddef.h>

/* ---- One-shot SHAKE (implemented in keccak_kern.c) ---- */
void shake128(uint8_t *out, size_t outlen,
              const uint8_t *in, size_t inlen);
void shake256(uint8_t *out, size_t outlen,
              const uint8_t *in, size_t inlen);

/* ---- Incremental SHAKE contexts (kernel-safe buffer shims) ----
 * We don't expose internal members anywhere else; only the API is used.
 */
typedef struct {
    uint8_t *buf;
    size_t   len;
    size_t   cap;
    size_t   squeeze_pos;
} shake128incctx;

typedef struct {
    uint8_t *buf;
    size_t   len;
    size_t   cap;
    size_t   squeeze_pos;
} shake256incctx;

/* ---- Incremental SHAKE API (implemented in shake_inc_kern.c) ---- */
void shake128_inc_init(shake128incctx *state);
void shake128_inc_absorb(shake128incctx *state, const uint8_t *input, size_t inlen);
void shake128_inc_finalize(shake128incctx *state);
void shake128_inc_squeeze(uint8_t *output, size_t outlen, shake128incctx *state);
void shake128_inc_ctx_release(shake128incctx *state);

void shake256_inc_init(shake256incctx *state);
void shake256_inc_absorb(shake256incctx *state, const uint8_t *input, size_t inlen);
void shake256_inc_finalize(shake256incctx *state);
void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *state);
void shake256_inc_ctx_release(shake256incctx *state);
