// SPDX-License-Identifier: GPL-2.0
#include <linux/slab.h>
#include <linux/string.h>
#include "fips202.h"
#include "keccak_kern.h" /* shake128(), shake256() */

static uint8_t *buf_grow(uint8_t *buf, size_t *cap, size_t need)
{
    if (need <= *cap) return buf;
    size_t ncap = (*cap == 0 ? 256 : *cap * 2);
    while (ncap < need) ncap *= 2;
    return krealloc(buf, ncap, GFP_KERNEL);
}

/* ---- SHAKE128 ---- */
void shake128_inc_init(shake128incctx *st)
{
    st->buf = NULL; st->len = 0; st->cap = 0; st->squeeze_pos = 0;
}
void shake128_inc_absorb(shake128incctx *st, const uint8_t *in, size_t inlen)
{
    if (!inlen) return;
    size_t need = st->len + inlen;
    uint8_t *nb = buf_grow(st->buf, &st->cap, need);
    if (!nb) return;
    st->buf = nb;
    memcpy(st->buf + st->len, in, inlen);
    st->len += inlen;
}
void shake128_inc_finalize(shake128incctx *st) { (void)st; }
void shake128_inc_squeeze(uint8_t *out, size_t outlen, shake128incctx *st)
{
    size_t need = st->squeeze_pos + outlen;
    uint8_t *tmp = kmalloc(need, GFP_KERNEL);
    if (!tmp) { memset(out, 0, outlen); return; }
    shake128(tmp, need, st->buf ? st->buf : (const uint8_t*)"", st->len);
    memcpy(out, tmp + st->squeeze_pos, outlen);
    st->squeeze_pos += outlen;
    kfree(tmp);
}
void shake128_inc_ctx_release(shake128incctx *st)
{
    if (st->buf) kfree(st->buf);
    st->buf = NULL; st->len = st->cap = st->squeeze_pos = 0;
}

/* ---- SHAKE256 ---- */
void shake256_inc_init(shake256incctx *st)
{
    st->buf = NULL; st->len = 0; st->cap = 0; st->squeeze_pos = 0;
}
void shake256_inc_absorb(shake256incctx *st, const uint8_t *in, size_t inlen)
{
    if (!inlen) return;
    size_t need = st->len + inlen;
    uint8_t *nb = buf_grow(st->buf, &st->cap, need);
    if (!nb) return;
    st->buf = nb;
    memcpy(st->buf + st->len, in, inlen);
    st->len += inlen;
}
void shake256_inc_finalize(shake256incctx *st) { (void)st; }
void shake256_inc_squeeze(uint8_t *out, size_t outlen, shake256incctx *st)
{
    size_t need = st->squeeze_pos + outlen;
    uint8_t *tmp = kmalloc(need, GFP_KERNEL);
    if (!tmp) { memset(out, 0, outlen); return; }
    shake256(tmp, need, st->buf ? st->buf : (const uint8_t*)"", st->len);
    memcpy(out, tmp + st->squeeze_pos, outlen);
    st->squeeze_pos += outlen;
    kfree(tmp);
}
void shake256_inc_ctx_release(shake256incctx *st)
{
    if (st->buf) kfree(st->buf);
    st->buf = NULL; st->len = st->cap = st->squeeze_pos = 0;
}