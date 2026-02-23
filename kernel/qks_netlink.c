// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <net/genetlink.h>
#include "qks_message.h"

MODULE_LICENSE("GPL");

enum {
    QKS_CMD_UNSPEC,
    QKS_CMD_EVENT,
    __QKS_CMD_MAX,
};
#define QKS_CMD_MAX (__QKS_CMD_MAX - 1)

static const struct genl_ops qks_ops[] = { };

// One multicast group named "QKS_MC"
static const struct genl_multicast_group qks_mcgrps[] = {
    { .name = "QKS_MC", },
};

static struct genl_family qks_family = {
    .name       = "QKS_GENL",
    .version    = 1,
    .maxattr    = QKS_ATTR_MSG,
    .netnsok    = true,

    .ops        = qks_ops,
    .n_ops      = ARRAY_SIZE(qks_ops),

    .mcgrps     = qks_mcgrps,
    .n_mcgrps   = ARRAY_SIZE(qks_mcgrps),
};

int qks_send_msg(struct qks_event_msg *msg)
{
    struct sk_buff *skb;
    void *hdr;
    int ret;

    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;

    // Use a single command for all events, switch by msg->event_type in userspace
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
    return genlmsg_multicast(&qks_family, skb, 0, 0, GFP_ATOMIC);
}
EXPORT_SYMBOL(qks_send_msg);

static int __init qks_netlink_init(void)
{
    int ret = genl_register_family(&qks_family);
    if (ret) {
        pr_err("[QKS] genl_register_family failed: %d\n", ret);
        return ret;
    }

    pr_info("[QKS] Netlink initialized (family=%s, groups=%u)\n",
            qks_family.name, qks_family.n_mcgrps);
    return 0;
}

static void __exit qks_netlink_exit(void)
{
    genl_unregister_family(&qks_family);
    pr_info("[QKS] Netlink shutdown\n");
}

module_init(qks_netlink_init);
module_exit(qks_netlink_exit);