// SPDX-License-Identifier: GPL-2.0
#include "third-party/compat/stddef.h"
#include "third-party/compat/stdint.h"
#include "third-party/compat/string.h"
#include "third-party/compat/stdlib.h"
#include "third-party/pqclean/ml-dsa-44/clean/api.h"
#include "qks_pqc_glue.h"


extern int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m,   size_t mlen,
    const uint8_t *pk);

bool qks_mldsa44_verify_wrapper(const uint8_t *recv_hash,
                                const uint8_t *sig, size_t siglen,
                                const uint8_t *pk1952)
{
    if (!recv_hash || !sig || !pk1952)
        return false;
        
    int rc = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, recv_hash, 32, pk1952);
    return rc == 0;
}