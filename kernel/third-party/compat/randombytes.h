#pragma once
#include <linux/types.h>

static inline void randombytes(uint8_t *buf, size_t len) {
    while (len--) *buf++ = 0;
}