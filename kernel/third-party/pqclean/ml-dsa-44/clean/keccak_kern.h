// SPDX-License-Identifier: MIT
#pragma once
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>

/* One-shot SHAKE interface */
void shake128(uint8_t *out, size_t outlen,
              const uint8_t *in, size_t inlen);

void shake256(uint8_t *out, size_t outlen,
              const uint8_t *in, size_t inlen);