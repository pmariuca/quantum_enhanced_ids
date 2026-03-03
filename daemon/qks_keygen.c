// qks_keygen.c — generate ML‑DSA‑65 (Dilithium‑5) keypair with liboqs
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <oqs/oqs.h>

#ifndef OQS_SIG_alg_ml_dsa_65
#define OQS_SIG_alg_ml_dsa_65 OQS_SIG_alg_dilithium_5
#endif

static int write_bin(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }
    if (fwrite(buf, 1, len, f) != len) { perror("fwrite"); fclose(f); return -1; }
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    const char *pk_path = (argc >= 2) ? argv[1] : "qks_pk.bin";
    const char *sk_path = (argc >= 3) ? argv[2] : "qks_sk.bin";

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) {
        fprintf(stderr, "OQS_SIG_new failed\n");
        return 1;
    }

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    if (!pk || !sk) {
        fprintf(stderr, "malloc failed\n");
        OQS_SIG_free(sig);
        free(pk); free(sk);
        return 1;
    }

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "OQS_SIG_keypair failed\n");
        OQS_SIG_free(sig); free(pk); free(sk);
        return 1;
    }

    if (write_bin(pk_path, pk, sig->length_public_key) != 0 ||
        write_bin(sk_path, sk, sig->length_secret_key) != 0) {
        fprintf(stderr, "write_bin failed\n");
        OQS_SIG_free(sig); free(pk); free(sk);
        return 1;
    }

    printf("Generated ML‑DSA‑65 keypair:\n");
    printf("  public : %s (%zu bytes)\n", pk_path, sig->length_public_key);
    printf("  private: %s (%zu bytes)\n", sk_path, sig->length_secret_key);

    OQS_SIG_free(sig);
    free(pk); free(sk);
    return 0;
}