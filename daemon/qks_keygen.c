#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <oqs/oqs.h>

int main(void) {
    // REQUEST ML‑DSA‑44 EXACTLY — no fallbacks, no aliases
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (!sig) {
        fprintf(stderr, "ERROR: ML‑DSA‑44 not supported by your liboqs!\n");
        return 1;
    }

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    if (!pk || !sk) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "keypair generation failed\n");
        return 1;
    }

    FILE *f = fopen("qks_pk.bin", "wb");
    fwrite(pk, 1, sig->length_public_key, f);
    fclose(f);

    f = fopen("qks_sk.bin", "wb");
    fwrite(sk, 1, sig->length_secret_key, f);
    fclose(f);

    printf("Generated ML‑DSA‑44 keypair:\n");
    printf("  public : qks_pk.bin (%zu bytes)\n", sig->length_public_key);
    printf("  private: qks_sk.bin (%zu bytes)\n", sig->length_secret_key);

    OQS_SIG_free(sig);
    free(pk);
    free(sk);
    return 0;
}