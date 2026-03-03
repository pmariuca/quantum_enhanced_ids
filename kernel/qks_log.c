// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/printk.h>

#include "qks_log.h"

#define QKS_LOG_BUF_SIZE   (64 * 1024)   /* 64 KB ring buffer */
#define QKS_LOG_LINE_MAX   512           /* max per-log message */

static char *qks_logbuf;
static size_t qks_log_head;
static DEFINE_SPINLOCK(qks_log_lock);

/* Write formatted log line into ring buffer */
void qks_log(const char *fmt, ...)
{
    char tmp[QKS_LOG_LINE_MAX];
    va_list args;
    int len;
    unsigned long flags;

    va_start(args, fmt);
    len = vsnprintf(tmp, sizeof(tmp), fmt, args);
    va_end(args);

    if (len <= 0)
        return;

    /* Write into ring buffer */
    spin_lock_irqsave(&qks_log_lock, flags);

    /* If message is larger than buffer, discard */
    if (len >= QKS_LOG_BUF_SIZE) {
        spin_unlock_irqrestore(&qks_log_lock, flags);
        return;
    }

    /* If wrap needed */
    if (qks_log_head + len >= QKS_LOG_BUF_SIZE)
        qks_log_head = 0;

    memcpy(qks_logbuf + qks_log_head, tmp, len);
    qks_log_head += len;

    spin_unlock_irqrestore(&qks_log_lock, flags);
}

/* /proc read: dump the entire buffer sequentially */
static int qks_log_proc_show(struct seq_file *m, void *v)
{
    size_t i;

    spin_lock(&qks_log_lock);
    seq_puts(m, "=== QKS Kernel Log ===\n");

    for (i = 0; i < QKS_LOG_BUF_SIZE; i++) {
        char c = qks_logbuf[i];
        if (c)
            seq_putc(m, c);
    }

    spin_unlock(&qks_log_lock);
    return 0;
}

static int qks_log_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, qks_log_proc_show, NULL);
}

static const struct proc_ops qks_log_proc_ops = {
    .proc_open    = qks_log_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* Init */
int qks_log_init(void)
{
    qks_logbuf = vzalloc(QKS_LOG_BUF_SIZE);
    if (!qks_logbuf)
        return -ENOMEM;

    if (!proc_create("qks/log", 0444, NULL, &qks_log_proc_ops)) {
        vfree(qks_logbuf);
        return -ENOMEM;
    }

    qks_log("[QKS-LOG] Log system initialized. Buffer=%u bytes\n",
            QKS_LOG_BUF_SIZE);

    return 0;
}

/* Exit */
void qks_log_exit(void)
{
    remove_proc_entry("qks/log", NULL);
    if (qks_logbuf)
        vfree(qks_logbuf);
}