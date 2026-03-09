#pragma once
#include <stdint.h>

#define QKS_SIG_LEN 2420

#define QKS_DENY  0
#define QKS_ALLOW 1

typedef struct qks_verdict_msg {
    uint32_t event_id;
    uint8_t  verdict;
    uint8_t  hash[32];
    uint8_t  signature[QKS_SIG_LEN];
    uint32_t signature_len;
    uint64_t daemon_ts_sec;
    uint32_t daemon_ts_nsec;
    char reason[64];
} qks_verdict_msg;