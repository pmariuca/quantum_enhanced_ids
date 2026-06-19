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
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/moduleparam.h>
#include <linux/stdarg.h>

#include "qks_log.h"
#include "qks_message.h"

#define QKS_LOG_BUF_SIZE   (16 * 1024)   /* 64 KB ring buffer */
#define QKS_LOG_LINE_MAX   512           /* max per-log message */

static char *qks_logbuf;
static size_t qks_log_head;
static DEFINE_SPINLOCK(qks_log_lock);

/* Write formatted log line into ring buffer AND printk */
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

    /* Print immediately to kernel log (live) */
    printk(KERN_INFO "[QKS] %s", tmp);

    /* Also store in ring buffer */
    spin_lock_irqsave(&qks_log_lock, flags);

    if (len < QKS_LOG_BUF_SIZE) {
        if (qks_log_head + len >= QKS_LOG_BUF_SIZE)
            qks_log_head = 0;

        memcpy(qks_logbuf + qks_log_head, tmp, len);
        qks_log_head += len;
    }

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

static struct proc_dir_entry *qks_proc_dir;

static const char *qks_event_type_str(u8 t)
{
    switch (t) {
    case QKS_EVENT_EXEC:    return "EXEC";
    case QKS_EVENT_PACKET:  return "PACKET";
    case QKS_EVENT_DNS:     return "DNS";
    case QKS_EVENT_SYSCALL: return "SYSCALL";
    default:                return "UNKNOWN";
    }
}

void qks_dump_event(const struct qks_event_msg *m)
{
    if (!m) {
        qks_log("EVENT: (null)\n");
        return;
    }

    qks_log("EVENT id=%llu type=%s ts=%llu ns pid=%u ppid=%u uid=%u",
            m->event_id,
            qks_event_type_str(m->event_type),
            m->timestamp_ns,
            m->pid, m->ppid, m->uid);

    switch (m->event_type) {

    case QKS_EVENT_EXEC:
        qks_log("EXEC path=%s", m->exec_path);
        break;

    case QKS_EVENT_PACKET:
        qks_log("PACKET src=%pI4:%u dst=%pI4:%u proto=%u len=%u pkt_pid=%u exec=%s",
                &m->packet_src_ip,
                m->packet_src_port,
                &m->packet_dst_ip,
                m->packet_dst_port,
                m->packet_protocol,
                m->packet_len,
                m->pkt_pid,
                m->pkt_exec_path);
        break;

    case QKS_EVENT_DNS:
        qks_log("DNS src=%pI4 dst=%pI4 qname=%s qtype=%u",
                &m->packet_src_ip,
                &m->packet_dst_ip,
                m->dns_qname,
                m->dns_qtype);
        break;

    case QKS_EVENT_SYSCALL:
        qks_log("SYSCALL nr=%u subtype=%u addr=0x%llx len=%llu flags=0x%llx prot=0x%x arg0=%u arg1=%u arg2=%u str=%s",
                m->sc_nr,
                m->sc_subtype,
                m->sc_addr,
                m->sc_len,
                m->sc_flags,
                m->sc_prot,
                m->sc_arg0_u32,
                m->sc_arg1_u32,
                m->sc_arg2_u32,
                m->sc_str);
        break;

    default:
        qks_log("UNKNOWN EVENT TYPE=%u", m->event_type);
        break;
    }
}
EXPORT_SYMBOL(qks_dump_event);

/* Init log system */
int qks_log_init(void)
{
    qks_logbuf = vzalloc(QKS_LOG_BUF_SIZE);
    if (!qks_logbuf)
        return -ENOMEM;

    qks_proc_dir = proc_mkdir("qks", NULL);    // create /proc/qks
    if (!qks_proc_dir) {
        vfree(qks_logbuf);
        return -ENOMEM;
    }

    if (!proc_create("log", 0444, qks_proc_dir, &qks_log_proc_ops)) {
        remove_proc_entry("qks", NULL);
        vfree(qks_logbuf);
        return -ENOMEM;
    }

    qks_log("[QKS-LOG] Log system initialized. Buffer=%u bytes\n", QKS_LOG_BUF_SIZE);

    return 0;
}

void qks_log_exit(void)
{
    remove_proc_entry("log", qks_proc_dir);
    remove_proc_entry("qks", NULL);
    if (qks_logbuf)
        vfree(qks_logbuf);
}