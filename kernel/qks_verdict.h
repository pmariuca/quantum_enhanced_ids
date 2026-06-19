#pragma once
#include <linux/types.h>

#define QKS_SIG_LEN        2420
#define QKS_HASH_LEN       32

#define QKS_DENY  0
#define QKS_ALLOW 1

struct qks_verdict_msg {
    u32 event_id;
    u8  verdict;                    // 0 = deny, 1 = allow
    u8  hash[QKS_HASH_LEN];
    u8  signature[QKS_SIG_LEN];
    u32 signature_len;
    uint64_t daemon_ts_sec;
    uint32_t daemon_ts_nsec;
    char reason[64];
};