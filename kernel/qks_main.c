#include <linux/module.h>
#include <linux/init.h>
#include "qks_log.h"

extern int qks_netlink_init(void);
extern void qks_netlink_exit(void);

extern int qks_netfilter_init(void);
extern void qks_netfilter_exit(void);

extern int qks_syscalls_init(void);
extern void qks_syscalls_exit(void);

static int __init qks_init(void)
{
    int ret;

    ret = qks_log_init();
    if (ret)
        return ret;

    ret = qks_netlink_init();
    if (ret) return ret;

    ret = qks_netfilter_init();
    if (ret) {
        qks_netlink_exit();
        return ret;
    }

    ret = qks_syscalls_init();
    if (ret) {
        qks_netfilter_exit();
        qks_netlink_exit();
        return ret;
    }

    return 0;
}

static void __exit qks_exit(void)
{
    qks_log_exit();
    qks_syscalls_exit();
    qks_netfilter_exit();
    qks_netlink_exit();
}

module_init(qks_init);
module_exit(qks_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Quantum IDS kernel module");