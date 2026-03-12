// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <net/genetlink.h>

#include <linux/atomic.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/param.h>

#include "qks_genl.h"
#include "qks_message.h"
#include "qks_verdict.h"
#include "qks_sigverify.h"
#include "qks_log.h"

/* -------------------- Daemon Fallback -------------------- */
static uint verdict_timeout_ms = 500;
module_param(verdict_timeout_ms, uint, 0644);
MODULE_PARM_DESC(verdict_timeout_ms, "Timeout in ms to wait for daemon verdict; on expiry -> DENY");


struct qks_pending {
    struct qks_event_msg *ev;
    struct timer_list     tmo;
    atomic_t              done;   /* 0=pending, 1=handled */
    u64                   id;
};

static void qks_verdict_timeout(struct timer_list *t);


/* -------------------- Pending map -------------------- */
static DEFINE_XARRAY(qks_pending);

static int qks_store_pending_event(const struct qks_event_msg *msg)
{
    struct qks_pending *p;
    struct qks_event_msg *copy;
    void *old;
    int err;

    p = kmalloc(sizeof(*p), GFP_ATOMIC);
    if (!p)
        return -ENOMEM;

    copy = kmemdup(msg, sizeof(*msg), GFP_ATOMIC);
    if (!copy) {
        kfree(p);
        return -ENOMEM;
    }

    p->ev = copy;
    p->id = copy->event_id;
    atomic_set(&p->done, 0);

    /* Setup deadline timer */
    timer_setup(&p->tmo, qks_verdict_timeout, 0);
    mod_timer(&p->tmo, jiffies + msecs_to_jiffies(verdict_timeout_ms));

    /* Store into XArray. Overwrites are freed to avoid leaks. */
    old = xa_store(&qks_pending, (unsigned long)p->id, p, GFP_ATOMIC);
    err = xa_err(old);
    if (err) {
        timer_shutdown_sync(&p->tmo);
        kfree(copy);
        kfree(p);
        return err;
    }
    if (old && !IS_ERR(old)) {
        struct qks_pending *prev = old;
        timer_shutdown_sync(&prev->tmo);
        kfree(prev->ev);
        kfree(prev);
    }

    return 0;
}

static struct qks_pending *qks_take_pending(u64 id)
{
    return xa_erase(&qks_pending, (unsigned long)id);
}

/* Forward declaration so compiler knows signature */
void qks_apply_verdict(const struct qks_event_msg *ev, u8 verdict, const char *reason);

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
    struct qks_pending *p;
    struct qks_event_msg *ev;
    bool ok;

    if (!info->attrs[QKS_ATTR_VERDICT])
        return -EINVAL;
    if (nla_len(info->attrs[QKS_ATTR_VERDICT]) < sizeof(*v))
        return -EINVAL;

    v = nla_data(info->attrs[QKS_ATTR_VERDICT]);

    p = qks_take_pending(v->event_id);
    if (!p) {
        qks_log("Verdict for unknown event_id=%llu (maybe timed out)", (u64)v->event_id);
        return 0;
    }

    /* Ensure timer cannot fire after proceed */
    timer_shutdown_sync(&p->tmo);

    /* First handler wins; if timer already handled, drop quietly */
    if (atomic_xchg(&p->done, 1) != 0) {
        kfree(p->ev);
        kfree(p);
        return 0;
    }

    ev = p->ev;
    // print event
    qks_dump_event(ev);

    ok = qks_verify_signature(ev, v->hash, v->signature, v->signature_len);
    if (!ok) {
        qks_log("Signature/hash INVALID for id=%llu -> DENY", ev->event_id);
        qks_apply_verdict(ev, QKS_DENY, "invalid_signature");
        kfree(ev);
        kfree(p);
        return 0;
    }

    qks_apply_verdict(ev, v->verdict, v->reason);

    kfree(ev);
    kfree(p);
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

/* -------------------- Daemon Fallback -------------------- */
static void qks_verdict_timeout(struct timer_list *t)
{
    struct qks_pending *p = container_of(t, struct qks_pending, tmo);

    if (atomic_xchg(&p->done, 1) != 0)
        return;

    /* Remove from map (ok if already gone) */
    xa_erase(&qks_pending, (unsigned long)p->id);

    qks_log("FALLBACK: verdict timeout -> DENY id=%llu", p->id);
    // qks_dump_event(p->ev);
    // qks_apply_verdict(p->ev, QKS_DENY, "timeout");

    kfree(p->ev);
    kfree(p);
}

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
    
    
    if (ret == -ESRCH) { /* no listeners */
        qks_log("FALLBACK: no listeners -> ALLOW id=%llu", msg->event_id);
        return 0;
    }

    if (ret)
        return ret;

    qks_store_pending_event(msg);
    return 0;
}
EXPORT_SYMBOL(qks_send_msg);