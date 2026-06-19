#pragma once
#include <linux/types.h>
#include <linux/atomic.h>

extern atomic64_t qks_evt_id;

static inline u64 qks_next_id(void)
{
    return atomic64_inc_return(&qks_evt_id);
}
