// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <net/genetlink.h>

#include "qks_genl.h"
#include "qks_message.h"
#include "qks_verdict.h"
#include "qks_sigverify.h"

/* -------------------- Pending map -------------------- */
static DEFINE_XARRAY(qks_pending);

static int qks_store_pending_event(const struct qks_event_msg *msg)
{
    struct qks_event_msg *copy;
    void *old;
    int err;

    copy = kmemdup(msg, sizeof(*msg), GFP_ATOMIC);
    if (!copy)
        return -ENOMEM;

    old = xa_store(&qks_pending, msg->event_id, copy, GFP_ATOMIC);
    err = xa_err(old);
    if (err) {
        kfree(copy);
        return err;
    }

    return 0;
}

static struct qks_event_msg *qks_take_pending_event(u32 id)
{
    return xa_erase(&qks_pending, id);
}

/* Forward declaration so compiler knows signature */
void qks_apply_verdict(const struct qks_event_msg *ev, u8 verdict);

/* -------------------- Netlink Policy -------------------- */
static const struct nla_policy qks_policy[QKS_ATTR_MAX + 1] = {
    [QKS_ATTR_UNSPEC]  = { .type = NLA_UNSPEC },
    [QKS_ATTR_MSG]     = { .type = NLA_BINARY, .len = sizeof(struct qks_event_msg) },
    [QKS_ATTR_VERDICT] = { .type = NLA_BINARY, .len = sizeof(struct qks_verdict_msg) },
};

/* -------------------- Verdict Command Handler -------------------- */
static int qks_cmd_verdict(struct sk_buff *skb, struct genl_info *info)
{
    const struct qks_verdict_msg *v;
    struct qks_event_msg *ev;
    bool ok;

    if (!info->attrs[QKS_ATTR_VERDICT])
        return -EINVAL;
    if (nla_len(info->attrs[QKS_ATTR_VERDICT]) < sizeof(*v))
        return -EINVAL;

    v = nla_data(info->attrs[QKS_ATTR_VERDICT]);

    ev = qks_take_pending_event(v->event_id);
    if (!ev) {
        qks_log("[QKS] Verdict for unknown event_id=%u\n", v->event_id);
        return 0;
    }

    ok = qks_verify_signature(ev, v->hash, v->signature, v->signature_len);
    if (!ok) {
        qks_log("[QKS] Signature/hash invalid for id=%u -> DENY\n", v->event_id);
        qks_apply_verdict(ev, QKS_DENY);
        kfree(ev);
        return 0;
    }

    qks_apply_verdict(ev, v->verdict ? QKS_ALLOW : QKS_DENY);
    kfree(ev);
    return 0;
}

/* -------------------- GENL Ops -------------------- */
static const struct genl_ops qks_ops[] = {
    {
        .cmd = QKS_CMD_VERDICT,
        .flags = 0,
        .doit = qks_cmd_verdict,
        // .validate = GENL_DONT_VALIDATE_STRICT,
        .policy = qks_policy,
        .maxattr = QKS_ATTR_MAX,
    },
};

/* -------------------- GENL Family -------------------- */
static const struct genl_multicast_group qks_mcgrps[] = {
    { .name = QKS_GENL_MCGRP },
};

static struct genl_family qks_family = {
    .name = QKS_GENL_FAMILY,
    .version = QKS_GENL_VERSION,
    .hdrsize = 0,
    .maxattr = QKS_ATTR_MAX,
    .policy = qks_policy,

    .ops = qks_ops,
    .n_ops = ARRAY_SIZE(qks_ops),

    .mcgrps = qks_mcgrps,
    .n_mcgrps = ARRAY_SIZE(qks_mcgrps),

    .netnsok = true,
};

/* -------------------- Netlink Registration -------------------- */
int qks_netlink_init(void)
{
    BUILD_BUG_ON(QKS_ATTR_UNSPEC != 0);
    BUILD_BUG_ON(QKS_CMD_VERDICT <= 0);

    
    qks_log("[QKS] GENL: fam.name=%s fam.maxattr=%u ops.maxattr=%u cmd=%u\n",
            qks_family.name, qks_family.maxattr, qks_ops[0].maxattr, QKS_CMD_VERDICT);
    return genl_register_family(&qks_family);
}

void qks_netlink_exit(void)
{
    genl_unregister_family(&qks_family);
}

/* -------------------- Weak Verbict Hook -------------------- */
__weak void qks_apply_verdict(const struct qks_event_msg *ev, u8 verdict)
{
    qks_log("[QKS] (weak) verdict=%u for id=%u\n",
            verdict, ev ? ev->event_id : 0);
}
EXPORT_SYMBOL_GPL(qks_apply_verdict);

/* -------------------- Event Multicast Sender -------------------- */
int qks_send_msg(struct qks_event_msg *msg)
{
    struct sk_buff *skb;
    void *hdr;
    int ret;

    if (!msg)
        return -EINVAL;

    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;

    hdr = genlmsg_put(skb, 0, 0, &qks_family, 0, QKS_CMD_EVENT);
    if (!hdr) {
        nlmsg_free(skb);
        return -ENOMEM;
    }

    ret = nla_put(skb, QKS_ATTR_MSG, sizeof(*msg), msg);
    if (ret) {
        nlmsg_free(skb);
        return ret;
    }

    genlmsg_end(skb, hdr);

    ret = genlmsg_multicast(&qks_family, skb, 0, 0, GFP_ATOMIC);
    if (ret == -ESRCH)      /* no listeners — not fatal */
        return 0;
    if (ret)
        return ret;

    qks_store_pending_event(msg);
    return 0;
}
EXPORT_SYMBOL(qks_send_msg);