#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("QKS");
MODULE_DESCRIPTION("Quantum Kernel Sentinel - Basic Skeleton");
MODULE_VERSION("0.1");

static int __init qks_init(void)
{
    pr_info("[QKS] Kernel module loaded.\n");
    return 0;   // success
}

static void __exit qks_exit(void)
{
    pr_info("[QKS] Kernel module unloaded.\n");
}

module_init(qks_init);
module_exit(qks_exit);