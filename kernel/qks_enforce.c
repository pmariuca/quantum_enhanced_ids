// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/rcupdate.h>
#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/byteorder/generic.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/cred.h>

#include "qks_message.h"
#include "qks_verdict.h"
#include "qks_log.h"

#ifndef QKS_DENY
#define QKS_DENY  0
#endif
#ifndef QKS_ALLOW
#define QKS_ALLOW 1
#endif

/* ===================== Process kill helper ===================== */
static int qks_kill_tgid(pid_t tgid, int sig)
{
    int ret = -ESRCH;

    rcu_read_lock();
    {
        struct pid *pid = find_get_pid(tgid);
        if (pid) {
            struct task_struct *task = get_pid_task(pid, PIDTYPE_TGID);
            if (task) {
                ret = send_sig_info(sig, SEND_SIG_PRIV, task);
                put_task_struct(task);
            }
            put_pid(pid);
        }
    }
    rcu_read_unlock();

    return ret;
}

static bool qks_should_not_kill(const struct qks_event_msg *ev)
{
    if (!ev)
        return true;

    /* NEVER kill PID 1 */
    if (ev->pid == 1)
        return true;

    /* NEVER kill kernel threads */
    if (current->flags & PF_KTHREAD)
        return true;

    /* NEVER kill root-owned processes for now (safety) */
    if (ev->uid == 0)
        return true;

    return false;
}

/* ===================== Packet drop-list (TTL) ================== */
/* Maintain a small in-kernel cache for (pid, dst_ip, dst_port, proto)
 * so the Netfilter hook can drop subsequent outbound packets for a while
 * after a DENY verdict arrives asynchronously.
 */

struct qks_drop_key {
    u32 pid;
    u32 ip;     /* host-order IPv4 (matches your event struct) */
    u16 port;   /* host-order */
    u8  proto;  /* IPPROTO_TCP/UDP/... */
};

struct qks_drop_ent {
    struct hlist_node  node;
    struct qks_drop_key key;
    unsigned long       expires;
};

#define QKS_DROP_BITS 10  /* 1024 buckets */
static DEFINE_HASHTABLE(qks_drop_ht, QKS_DROP_BITS);
static DEFINE_SPINLOCK(qks_drop_lock);

static u32 qks_drop_hash(const struct qks_drop_key *k)
{
    return (k->pid ^ k->ip ^ (k->port << 16) ^ k->proto);
}

static void qks_drop_purge_expired_locked(void)
{
    unsigned int bkt;
    struct qks_drop_ent *e;
    struct hlist_node *tmp;
    unsigned long now = jiffies;

    hash_for_each_safe(qks_drop_ht, bkt, tmp, e, node) {
        if (time_after_eq(now, e->expires)) {
            hash_del(&e->node);
            kfree(e);
        }
    }
}

/* Add/refresh a drop entry with TTL in milliseconds */
static void qks_drop_add(u32 pid, u32 ip, u16 port, u8 proto, unsigned long ttl_ms)
{
    struct qks_drop_key key = { .pid = pid, .ip = ip, .port = port, .proto = proto };
    struct qks_drop_ent *e;
    unsigned long flags;
    u32 h = qks_drop_hash(&key);

    spin_lock_irqsave(&qks_drop_lock, flags);

    /* purge old */
    qks_drop_purge_expired_locked();

    /* try to find existing */
    hash_for_each_possible(qks_drop_ht, e, node, h) {
        if (e->key.pid == key.pid &&
            e->key.ip  == key.ip &&
            e->key.port== key.port &&
            e->key.proto== key.proto) {
            e->expires = jiffies + msecs_to_jiffies(ttl_ms);
            spin_unlock_irqrestore(&qks_drop_lock, flags);
            return;
        }
    }

    /* insert new */
    e = kzalloc(sizeof(*e), GFP_ATOMIC);
    if (e) {
        e->key = key;
        e->expires = jiffies + msecs_to_jiffies(ttl_ms);
        hash_add(qks_drop_ht, &e->node, h);
    }

    spin_unlock_irqrestore(&qks_drop_lock, flags);
}

/* Query from Netfilter (LOCAL_OUT) before allowing a packet out. */
bool qks_drop_should_block(u32 pid, u32 ip, u16 port, u8 proto)
{
    struct qks_drop_key key = { .pid = pid, .ip = ip, .port = port, .proto = proto };
    struct qks_drop_ent *e;
    unsigned long flags;
    bool block = false;
    u32 h = qks_drop_hash(&key);

    spin_lock_irqsave(&qks_drop_lock, flags);

    /* purge expired entries opportunistically */
    qks_drop_purge_expired_locked();

    hash_for_each_possible(qks_drop_ht, e, node, h) {
        if (e->key.pid == key.pid &&
            e->key.ip  == key.ip &&
            e->key.port== key.port &&
            e->key.proto== key.proto) {
            if (time_before(jiffies, e->expires)) {
                block = true;
            } else {
                hash_del(&e->node);
                kfree(e);
            }
            break;
        }
    }

    spin_unlock_irqrestore(&qks_drop_lock, flags);
    return block;
}
EXPORT_SYMBOL_GPL(qks_drop_should_block);

/* ===================== Verdict enforcement ===================== */
static void qks_enforce_exec_deny(const struct qks_event_msg *ev, const char *reason)
{
    if (qks_should_not_kill(ev)) {
        qks_log_enforcement(ev->event_id, "SIGKILL", reason);
        qks_log("EXEC DENY applied: id=%llu pid=%u reason='%s'",
                (u64)ev->event_id, ev->pid, reason);
        return;
    }

    int rc = qks_kill_tgid(ev->pid, SIGKILL);
    qks_log_enforcement(ev->event_id, "SIGKILL", reason);
    qks_log("EXEC DENY applied: id=%llu pid=%u reason='%s' path='%s' kill_rc=%d",
            (u64)ev->event_id, ev->pid, reason, ev->exec_path, rc);

}

static void qks_enforce_syscall_deny(const struct qks_event_msg *ev, const char *reason)
{
    if (qks_should_not_kill(ev)) {
        qks_log_enforcement(ev->event_id, "SIGKILL", reason);
        qks_log("SYSCALL DENY applied: id=%llu pid=%u reason='%s' (protected process)",
                (u64)ev->event_id, ev->pid, reason);
        return;
    }
    
    int rc = qks_kill_tgid(ev->pid, SIGKILL);
    qks_log_enforcement(ev->event_id, "SIGKILL", reason);
    qks_log("SYSCALL DENY applied: id=%llu pid=%u reason='%s' subtype=%u kill_rc=%d",
            (u64)ev->event_id, ev->pid, reason, ev->sc_subtype, rc);
}

static void qks_enforce_packet_deny(const struct qks_event_msg *ev, const char *reason)
{
    __be32 dip_be = htonl(ev->packet_dst_ip);
    qks_drop_add(ev->pkt_pid, ev->packet_dst_ip, ev->packet_dst_port, ev->packet_protocol, 30000);

    qks_log_enforcement(ev->event_id, "DROP_PACKET", reason);
    qks_log("PACKET DENY applied: id=%llu pid=%u reason='%s' proto=%u dst_ip=%pI4 dst_port=%u (ttl=30s)",
            (u64)ev->event_id, ev->pkt_pid, reason,
            ev->packet_protocol, &dip_be, ev->packet_dst_port);
}

static void qks_enforce_dns_deny(const struct qks_event_msg *ev, const char *reason)
{
    qks_drop_add(ev->pkt_pid, ev->packet_dst_ip, 53, IPPROTO_UDP, 30000);

    qks_log_enforcement(ev->event_id, "DROP_DNS", reason);
    qks_log("DNS DENY applied: id=%llu pid=%u reason='%s' qname='%s' qtype=%u (block udp/53 for 30s)",
            (u64)ev->event_id, ev->pkt_pid, reason, ev->dns_qname, ev->dns_qtype);
}

/* Strong definition overrides the weak one in netlink module */
void qks_apply_verdict(const struct qks_event_msg *ev, u8 verdict, const char *reason)
{
    if (!ev) return;

    if (verdict != QKS_DENY) {
        /* ALLOW or UNKNOWN: policy-only phase - no kernel action */
        qks_log_enforcement(ev->event_id, "ALLOW", reason);
        pr_debug("QKS ALLOW/UNKNOWN: id=%llu type=%u\n",
                 (u64)ev->event_id, ev->event_type);
        return;
    }

    /* DENY */
    switch (ev->event_type) {
    case QKS_EVENT_EXEC:
        qks_enforce_exec_deny(ev, reason);
        break;

    case QKS_EVENT_SYSCALL:
        qks_enforce_syscall_deny(ev, reason);
        break;

    case QKS_EVENT_PACKET:
        qks_enforce_packet_deny(ev, reason);
        break;

    case QKS_EVENT_DNS:
        qks_enforce_dns_deny(ev, reason);
        break;

    default:
        qks_log("DENY (unknown type): id=%llu type=%u", (u64)ev->event_id, ev->event_type);
        break;
    }
}
EXPORT_SYMBOL_GPL(qks_apply_verdict);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("QKS enforcement (policy-only phase)");