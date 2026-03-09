#pragma once

/* Kernel-safe replacement for <stddef.h>, <stdint.h>, <string.h>
 * used by PQClean (ml-dsa-44 clean implementation).
 */

#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/kernel.h>


#ifndef QKS_PQCLEAN_COMPAT_H
#define QKS_PQCLEAN_COMPAT_H

#define exit(code) do { pr_err("exit(%d) called\n", code); BUG(); } while(0)


#define malloc(x) kmalloc((x), GFP_KERNEL)
#define calloc(n,x) kzalloc((n)*(x), GFP_KERNEL)
#define free(x) kfree((x))

#endif


/* ---- <stddef.h> replacements ---- */

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef size_t
typedef __kernel_size_t size_t;
#endif

#ifndef ptrdiff_t
typedef long ptrdiff_t;
#endif

/* ---- <stdint.h> replacements ---- */

typedef __u8  uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;

typedef __s8  int8_t;
typedef __s16 int16_t;
typedef __s32 int32_t;
typedef __s64 int64_t;

/* PQClean sometimes uses restrict */
#ifndef restrict
#define restrict __restrict
#endif
