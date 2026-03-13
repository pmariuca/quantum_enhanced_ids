#pragma once

#include <linux/types.h>
#include "qks_message.h"
#include "qks_verdict.h"

#define QKS_SIG_LEN        2420
#define QKS_EVENT_HASH_LEN 32

int qks_hash_event(const struct qks_event_msg *ev,
                   u8 out[QKS_EVENT_HASH_LEN]);

bool qks_verify_signature(const struct qks_verdict_msg *v,
                          const u8 *recv_hash,
                          const u8 *signature,
                          u32 sig_len);