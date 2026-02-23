// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/fs.h>

#include "qks_message.h"

MODULE_LICENSE("GPL");

extern int qks_send_msg(struct qks_event_msg *msg);

static atomic_t qks_pkt_evt_id = ATOMIC_INIT(1);

// suspicious ports
static bool is_suspicious_port(u16 p)
{
    return (
        p == 22   || p == 23   || p == 80   || p == 443 ||
        p == 445  || p == 3389 || p == 5353 || p == 1900
    );
}

// get executable path from current process
static void qks_get_exec_path_from_socket(const struct sk_buff *skb,
                                          char *buf,
                                          size_t buflen)
{
    struct mm_struct *mm = current->mm;
    char *path;
    char tmp_buf[256];

    if (!mm || !mm->exe_file) {
        strscpy(buf, "", buflen);
        return;
    }

    path = d_path(&mm->exe_file->f_path, tmp_buf, sizeof(tmp_buf));
    if (!IS_ERR(path))
        strscpy(buf, path, buflen);
    else
        strscpy(buf, "", buflen);
}


// Parse DNS Question Name (QNAME) from raw UDP payload.
// Returns number of bytes consumed or 0 on failure.
static int qks_dns_parse_qname(const unsigned char *buf, int len, char *out, int outlen)
{
    int i = 0;
    int o = 0;

    if (len <= 0)
        return 0;

    while (i < len) {
        unsigned char labellen = buf[i++];
        if (labellen == 0)
            break;

        if (labellen > 63 || i + labellen > len)
            return 0;

        if (o != 0) {
            if (o >= outlen - 1)
                return 0;
            out[o++] = '.';
        }

        if (o + labellen >= outlen - 1)
            return 0;

        memcpy(out + o, buf + i, labellen);
        o += labellen;
        i += labellen;
    }

    out[o] = '\0';
    return i + 4; // Skip QTYPE (2 bytes) + QCLASS (2 bytes)
}

static struct nf_hook_ops qks_nf_ops[2];

// Hook: outbound SYN only
static unsigned int qks_nf_hook(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    if (!skb)
        return NF_ACCEPT;

    // only outbound
    if (state->hook != NF_INET_LOCAL_OUT)
        return NF_ACCEPT;

    const struct iphdr *iph = ip_hdr(skb);
    if (!iph || iph->version != 4)
        return NF_ACCEPT;

    // TCP only
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    const struct tcphdr *tcph =
        (const struct tcphdr *)((u8 *)iph + iph->ihl * 4);

    if (!tcph)
        return NF_ACCEPT;

    // SYN only (no ACK)
    if (!(tcph->syn) || tcph->ack)
        return NF_ACCEPT;

    u16 srcp = ntohs(tcph->source);
    u16 dstp = ntohs(tcph->dest);

    // suspicious ports only
    if (!is_suspicious_port(srcp) && !is_suspicious_port(dstp))
        return NF_ACCEPT;

    // build message
    struct qks_event_msg msg = {0};

    msg.schema_version = QKS_SCHEMA_V1;
    msg.event_type     = QKS_EVENT_PACKET;
    msg.timestamp_ns   = ktime_get_ns();
    msg.event_id       = atomic_inc_return(&qks_pkt_evt_id);

    msg.packet_src_ip   = ntohl(iph->saddr);
    msg.packet_dst_ip   = ntohl(iph->daddr);
    msg.packet_src_port = srcp;
    msg.packet_dst_port = dstp;
    msg.packet_protocol = iph->protocol;
    msg.packet_len      = ntohs(iph->tot_len);

    msg.pkt_pid = current->pid;
    msg.pkt_uid = current_uid().val;
    qks_get_exec_path_from_socket(skb, msg.pkt_exec_path, sizeof(msg.pkt_exec_path));

    qks_send_msg(&msg);
    return NF_ACCEPT;
}


// DNS outbound detection
static unsigned int qks_dns_hook(void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state)
{
    if (!skb)
        return NF_ACCEPT;

    if (state->hook != NF_INET_LOCAL_OUT)
        return NF_ACCEPT;

    const struct iphdr *iph = ip_hdr(skb);
    if (!iph || iph->version != 4)
        return NF_ACCEPT;

    if (iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    const struct udphdr *udph =
        (const struct udphdr *)((u8 *)iph + iph->ihl * 4);

    if (!udph)
        return NF_ACCEPT;

    u16 dstp = ntohs(udph->dest);
    if (dstp != 53)
        return NF_ACCEPT; // only DNS queries

    // Extract DNS payload
    unsigned char *dns = (unsigned char *)udph + sizeof(struct udphdr);
    int dns_len = ntohs(udph->len) - sizeof(struct udphdr);

    if (dns_len < 12)
        return NF_ACCEPT;

    // DNS header format: first 12 bytes
    // QDCOUNT is bytes 4-5
    u16 qdcount = (dns[4] << 8) | dns[5];
    if (qdcount == 0)
        return NF_ACCEPT;

    // Parse QNAME
    struct qks_event_msg msg = {0};

    char qname[256];
    memset(qname, 0, sizeof(qname));

    int consumed = qks_dns_parse_qname(dns + 12, dns_len - 12, qname, sizeof(qname));
    if (consumed <= 0)
        return NF_ACCEPT;

    // After QNAME, next 2 bytes = QTYPE
    if (12 + consumed > dns_len)
        return NF_ACCEPT;

    u16 qtype = (dns[12 + consumed - 4] << 8) | dns[12 + consumed - 3];

    // Build DNS event
    msg.schema_version = QKS_SCHEMA_V1;
    msg.event_type     = QKS_EVENT_DNS;
    msg.timestamp_ns   = ktime_get_ns();
    msg.event_id       = atomic_inc_return(&qks_pkt_evt_id);

    msg.packet_src_ip = ntohl(iph->saddr);
    msg.packet_dst_ip = ntohl(iph->daddr);
    msg.packet_src_port = ntohs(udph->source);
    msg.packet_dst_port = dstp;
    msg.packet_protocol = IPPROTO_UDP;
    msg.packet_len      = ntohs(udph->len);

    msg.pkt_pid = current->pid;
    msg.pkt_uid = current_uid().val;

    qks_get_exec_path_from_socket(skb, msg.pkt_exec_path, sizeof(msg.pkt_exec_path));

    strscpy(msg.dns_qname, qname, sizeof(msg.dns_qname));
    msg.dns_qtype = qtype;

    qks_send_msg(&msg);

    return NF_ACCEPT;
}

static int __init qks_netfilter_init(void)
{
    qks_nf_ops[0].hook     = qks_nf_hook;   // TCP SYN sensor
    qks_nf_ops[0].pf       = NFPROTO_IPV4;
    qks_nf_ops[0].hooknum  = NF_INET_LOCAL_OUT;
    qks_nf_ops[0].priority = NF_IP_PRI_FIRST;

    qks_nf_ops[1].hook     = qks_dns_hook;  // DNS sensor
    qks_nf_ops[1].pf       = NFPROTO_IPV4;
    qks_nf_ops[1].hooknum  = NF_INET_LOCAL_OUT;
    qks_nf_ops[1].priority = NF_IP_PRI_FIRST;


    nf_register_net_hooks(&init_net, qks_nf_ops, 2);
    pr_info("[QKS] Packet PID/UID/EXE monitor loaded.\n");
    return 0;
}

static void __exit qks_netfilter_exit(void)
{
    nf_unregister_net_hooks(&init_net, qks_nf_ops, 2);
    pr_info("[QKS] Packet PID/UID/EXE monitor unloaded.\n");
}

module_init(qks_netfilter_init);
module_exit(qks_netfilter_exit);