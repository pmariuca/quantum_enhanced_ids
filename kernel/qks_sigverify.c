// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/string.h>

#include "qks_log.h"
#include "qks_message.h"
#include "qks_sigverify.h"
#include "qks_pubkey.h"
#include "qks_verdict.h"
#include "qks_pqc_glue.h"

#define QKS_VERDICT_DOMAIN "QKS:verdict:v1"

static inline __u64 cpu_to_be64_u(__u64 x) {
    return (((__u64)cpu_to_be32((__u32)(x >> 32))) |
           (((__u64)cpu_to_be32((__u32)(x & 0xffffffff))) << 32));
}


int qks_hash_verdict_tuple(const struct qks_verdict_msg *v, u8 out[32])
{
    static const char domain[] = QKS_VERDICT_DOMAIN;
    __u64 be_eid  = cpu_to_be64_u((__u64)v->event_id);
    __u64 be_sec  = cpu_to_be64_u((__u64)v->daemon_ts_sec);
    __u32 be_nsec = cpu_to_be32((__u32)v->daemon_ts_nsec);

    struct crypto_shash *tfm = crypto_alloc_shash("sha256", 0, 0);
    struct shash_desc *desc;
    int ret;

    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    desc->tfm = tfm;

    ret = crypto_shash_init(desc);
    if (ret) goto out;

    // domain separation
    ret = crypto_shash_update(desc, (const u8 *)domain, sizeof(domain) - 1);
    if (ret) goto out;

    // bytes in canonical order
    ret = crypto_shash_update(desc, (const u8 *)&be_eid,  sizeof(be_eid));  if (ret) goto out;
    ret = crypto_shash_update(desc, (const u8 *)&v->verdict, 1);             if (ret) goto out;
    ret = crypto_shash_update(desc, (const u8 *)&be_sec,  sizeof(be_sec));  if (ret) goto out;
    ret = crypto_shash_update(desc, (const u8 *)&be_nsec, sizeof(be_nsec)); if (ret) goto out;

    ret = crypto_shash_final(desc, out);

out:
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

bool qks_verify_signature(const struct qks_verdict_msg *v,
                          const u8 *recv_hash,
                          const u8 *signature,
                          u32 sig_len)
{
    u8 local_hash[QKS_EVENT_HASH_LEN];
    int ret;

    if (sig_len != QKS_SIG_LEN) {
        qks_log("qks: bad signature length %u\n", sig_len);
        return false;
    }

    if (qks_pqc_pubkey_len != 1312) {
        qks_log("qks: pubkey length mismatch (%u)\n", qks_pqc_pubkey_len);
        return false;
    }

    ret = qks_hash_verdict_tuple(v, local_hash);
    
    if (ret != 0) {
        qks_log("qks: hashing failed\n");
        return false;
    }

    if (memcmp(local_hash, recv_hash, QKS_EVENT_HASH_LEN) != 0) {
        qks_log("qks: event hash mismatch (event_id=%u)\n", v->event_id);
        return false;
    }

    if (!signature) {
        qks_log("qks: NULL signature\n");
        return false;
    }

    bool ok = qks_mldsa44_verify_wrapper(recv_hash, signature, sig_len, qks_pqc_pubkey);
    if (!ok) {
        qks_log("qks: signature verify FAILED for event %u\n", v->event_id);
    } else {
        qks_log("Signature OK for id=%u", v->event_id);
    }
    return ok;
}

EXPORT_SYMBOL_GPL(qks_verify_signature);