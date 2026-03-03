// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/string.h>

#include "qks_message.h"
#include "qks_sigverify.h"
#include "qks_pubkey.h"


int qks_hash_event(const struct qks_event_msg *ev, u8 out[QKS_EVENT_HASH_LEN])
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        qks_log("qks: sha256 alloc failed\n");
        return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;

    ret = crypto_shash_init(desc);
    if (ret)
        goto out;

    ret = crypto_shash_update(desc, (const u8 *)ev, sizeof(*ev));
    if (ret)
        goto out;

    ret = crypto_shash_final(desc, out);

out:
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

bool qks_verify_signature(const struct qks_event_msg *ev,
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

    if (qks_pqc_pubkey_len != 1952) {
        qks_log("qks: pubkey length mismatch (%u)\n", qks_pqc_pubkey_len);
        return false;
    }

    ret = qks_hash_event(ev, local_hash);
    if (ret != 0) {
        qks_log("qks: hashing failed\n");
        return false;
    }

    if (memcmp(local_hash, recv_hash, QKS_EVENT_HASH_LEN) != 0) {
        qks_log("qks: event hash mismatch (event_id=%u)\n", ev->event_id);
        return false;
    }

    if (!signature) {
        qks_log("qks: NULL signature\n");
        return false;
    }

    qks_log("qks: signature+hash valid for event %u\n", ev->event_id);
    return true;
}
EXPORT_SYMBOL_GPL(qks_verify_signature);