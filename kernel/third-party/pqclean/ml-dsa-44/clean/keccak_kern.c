// SPDX-License-Identifier: MIT
#include "keccak_kern.h"
#include <linux/slab.h>

/*
 * Minimal kernel-safe SHAKE128 / SHAKE256 implementation.
 * No VLAs, no recursion, const-time, matches PQClean output.
 */

typedef u64 uint64_t;

/* ---- Keccak round constants, rotations, permutations ---- */
static const uint64_t keccakf_rndc[24] = {
  0x0000000000000001ULL, 0x0000000000008082ULL,
  0x800000000000808aULL, 0x8000000080008000ULL,
  0x000000000000808bULL, 0x0000000080000001ULL,
  0x8000000080008081ULL, 0x8000000000008009ULL,
  0x000000000000008aULL, 0x0000000000000088ULL,
  0x0000000080008009ULL, 0x000000008000000aULL,
  0x000000008000808bULL, 0x800000000000008bULL,
  0x8000000000008089ULL, 0x8000000000008003ULL,
  0x8000000000008002ULL, 0x8000000000000080ULL,
  0x000000000000800aULL, 0x800000008000000aULL,
  0x8000000080008081ULL, 0x8000000000008080ULL,
  0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccakf_rotc[24] = {
  1,3,6,10,15,21,28,36,45,55, 2,14,27,41,56, 8,25,43,62,18,39,61,20,44
};

static const int keccakf_piln[24] = {
 10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1
};

static inline void keccakf(uint64_t st[25])
{
    int round, i, j;
    uint64_t bc[5], t, tmp;

    for (round = 0; round < 24; round++) {

        /* Theta */
        for (i = 0; i < 5; i++)
            bc[i] = st[i]^st[i+5]^st[i+10]^st[i+15]^st[i+20];

        for (i = 0; i < 5; i++) {
            t = bc[(i+4)%5] ^ ((bc[(i+1)%5]<<1) | (bc[(i+1)%5]>>63));
            for (j = 0; j < 25; j += 5)
                st[j+i] ^= t;
        }

        /* Rho + Pi */
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            tmp = st[j];
            st[j] = (t << keccakf_rotc[i]) | (t >> (64 - keccakf_rotc[i]));
            t = tmp;
        }

        /* Chi */
        for (j = 0; j < 25; j += 5) {
            uint64_t a0 = st[j+0], a1 = st[j+1], a2 = st[j+2];
            uint64_t a3 = st[j+3], a4 = st[j+4];
            st[j+0] ^= (~a1) & a2;
            st[j+1] ^= (~a2) & a3;
            st[j+2] ^= (~a3) & a4;
            st[j+3] ^= (~a4) & a0;
            st[j+4] ^= (~a0) & a1;
        }

        /* Iota */
        st[0] ^= keccakf_rndc[round];
    }
}

/* ---- Absorb phase ---- */
static void shake_absorb(uint64_t st[25],
                         const uint8_t *in, size_t inlen,
                         size_t rate)
{
    size_t i;

    memset(st, 0, 25 * sizeof(uint64_t));

    /* Absorb full blocks */
    while (inlen >= rate) {
        for (i = 0; i < rate/8; i++) {
            uint64_t t;
            memcpy(&t, in + 8*i, 8);
            st[i] ^= t;
        }
        keccakf(st);
        in += rate;
        inlen -= rate;
    }

    /* Pad & absorb last block */
    {
        uint8_t tmp[200]; /* Enough for SHAKE128 (rate 168) */
        memset(tmp, 0, sizeof tmp);
        memcpy(tmp, in, inlen);
        tmp[inlen] = 0x1F;       /* SHAKE domain sep */
        tmp[rate - 1] |= 0x80;   /* final bit */

        for (i = 0; i < rate/8; i++) {
            uint64_t t;
            memcpy(&t, tmp + 8*i, 8);
            st[i] ^= t;
        }
    }
}

/* ---- Squeeze phase ---- */
static void shake_squeeze(uint64_t st[25],
                          uint8_t *out, size_t outlen,
                          size_t rate)
{
    while (outlen > 0) {
        keccakf(st);
        if (outlen >= rate) {
            memcpy(out, st, rate);
            out += rate;
            outlen -= rate;
        } else {
            memcpy(out, st, outlen);
            return;
        }
    }
}

/* ---- Public API ---- */
void shake128(uint8_t *out, size_t outlen,
              const uint8_t *in, size_t inlen)
{
    uint64_t st[25];
    shake_absorb(st, in, inlen, 168);
    shake_squeeze(st, out, outlen, 168);
}

void shake256(uint8_t *out, size_t outlen,
              const uint8_t *in, size_t inlen)
{
    uint64_t st[25];
    shake_absorb(st, in, inlen, 136);
    shake_squeeze(st, out, outlen, 136);
}