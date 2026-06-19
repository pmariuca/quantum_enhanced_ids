#pragma once
#include <linux/types.h>
#include <linux/printk.h>
#include "qks_message.h"

/* Exported function for all QKS modules to log */
void qks_log(const char *fmt, ...);
void qks_dump_event(const struct qks_event_msg *m);

/* Structured logging helpers */
#define qks_log_event_in(eid, etype) \
    qks_log("[KERNEL] Intercepted %s: event_id=%llu", (etype), (u64)(eid))

#define qks_log_event_sent(eid) \
    qks_log("[KERNEL] Event ID: %llu | Sent to userspace | Waiting for verdict...", (u64)(eid))

#define qks_log_hash_verified(eid) \
    qks_log("[KERNEL] Event hash verified: event_id=%llu", (u64)(eid))

#define qks_log_sig_valid(eid) \
    qks_log("[KERNEL] ML-DSA signature VALID: event_id=%llu", (u64)(eid))

#define qks_log_sig_invalid(eid, reason) \
    qks_log("[KERNEL] ML-DSA signature INVALID: event_id=%llu | Reason: %s", (u64)(eid), (reason))

#define qks_log_enforcement(eid, action, reason) \
    qks_log("[KERNEL] Enforcement: %s | event_id=%llu | reason=%s", (action), (u64)(eid), (reason))

/* Initialization and cleanup */
int  qks_log_init(void);
void qks_log_exit(void);