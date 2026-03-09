#pragma once
#include <linux/types.h>

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
        const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(
        const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);

/* one-shot SHAKE256 for kernel */
void shake256(uint8_t *out, size_t outlen,
              const uint8_t *in, size_t inlen);