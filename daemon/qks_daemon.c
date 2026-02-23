#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>

#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "../kernel/qks_message.h"

static volatile bool g_running = true;

// signal header
static void on_sigint(int signo) {
    (void)signo;
    g_running = false;
}

// ------------------------- HELPERS -------------------------
static const char* evt_type_str(uint8_t t) {
    switch (t) {
        case QKS_EVENT_EXEC:    return "EXEC";
        case QKS_EVENT_SYSCALL: return "SYSCALL";
        case QKS_EVENT_PACKET:  return "PACKET";
        default:                return "UNKNOWN";
    }
}

static void print_exec_event(const struct qks_event_msg* m) {
    unsigned long sec = (unsigned long)(m->timestamp_ns / 1000000000ULL);
    unsigned long ns  = (unsigned long)(m->timestamp_ns % 1000000000ULL);

    printf("[DAEMON] EXEC id=%u ts=%lu.%09lu pid=%u ppid=%u uid=%u path=\"%s\"\n",
           m->event_id,
           sec, ns,
           m->pid, m->ppid, m->uid,
           m->exec_path[0] ? m->exec_path : "(unknown)");
    fflush(stdout);
}

static void print_packet_event(const struct qks_event_msg* m) {
    printf("[DAEMON] PACKET id=%u pid=%u uid=%u exe=\"%s\" "
       "src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u proto=%u len=%u\n",
       m->event_id,
       m->pkt_pid,
       m->pkt_uid,
       m->pkt_exec_path,


        (m->packet_src_ip >> 24) & 0xFF,
        (m->packet_src_ip >> 16) & 0xFF,
        (m->packet_src_ip >>  8) & 0xFF,
        (m->packet_src_ip      ) & 0xFF,
        m->packet_src_port,

        (m->packet_dst_ip >> 24) & 0xFF,
        (m->packet_dst_ip >> 16) & 0xFF,
        (m->packet_dst_ip >>  8) & 0xFF,
        (m->packet_dst_ip      ) & 0xFF,
        m->packet_dst_port,

        m->packet_protocol,
        m->packet_len
    );
    fflush(stdout);
}


static const char* sc_subtype_str(uint32_t st) {
    switch (st) {
        case QKS_SC_MEMFD_CREATE: return "MEMFD_CREATE";
        case QKS_SC_MPROTECT_X:   return "MPROTECT_X";
        case QKS_SC_MMAP_X:       return "MMAP_X";
        case QKS_SC_PRIV_CHANGE:  return "PRIV_CHANGE";
        case QKS_SC_CLONE_FAMILY: return "CLONE_FAMILY";
        case QKS_SC_UNSHARE:      return "UNSHARE";
        case QKS_SC_SETNS:        return "SETNS";
        default:                  return "UNKNOWN";
    }
}

static void print_syscall_event(const struct qks_event_msg* m) {
    printf("[DAEMON] SYSCALL id=%u subtype=%s pid=%u ppid=%u uid=%u "
           "nr=%u addr=0x%llx len=%llu prot=0x%x flags=0x%llx "
           "a0=%u a1=%u a2=%u str=\"%s\"\n",

           m->event_id,
           sc_subtype_str(m->sc_subtype),
           m->pid, m->ppid, m->uid,
           m->sc_nr,

           (unsigned long long)m->sc_addr,
           (unsigned long long)m->sc_len,
           (unsigned int)m->sc_prot,
           (unsigned long long)m->sc_flags,

           m->sc_arg0_u32,
           m->sc_arg1_u32,
           m->sc_arg2_u32,
           m->sc_str
    );

    fflush(stdout);
}

static void print_packet_event_dns(const struct qks_event_msg* m) {
    printf("[DAEMON] DNS id=%u pid=%u uid=%u exe=\"%s\" qname=\"%s\" type=%u src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u\n",
           m->event_id,
           m->pkt_pid,
           m->pkt_uid,
           m->pkt_exec_path,
           m->dns_qname,
           m->dns_qtype,

           (m->packet_src_ip >> 24)&255,
           (m->packet_src_ip >> 16)&255,
           (m->packet_src_ip >> 8)&255,
           (m->packet_src_ip)&255,
           m->packet_src_port,

           (m->packet_dst_ip >> 24)&255,
           (m->packet_dst_ip >> 16)&255,
           (m->packet_dst_ip >> 8)&255,
           (m->packet_dst_ip)&255,
           m->packet_dst_port
    );
    fflush(stdout);

}

// ------------------------- NETLINK CALLBACK -------------------------
static int on_qks_msg(struct nl_msg *msg, void *arg) {
    (void)arg;

    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gh = (struct genlmsghdr *)nlmsg_data(nlh);

    struct nlattr *attrs[QKS_ATTR_MSG + 1];
    memset(attrs, 0, sizeof(attrs));

    nla_parse(attrs, QKS_ATTR_MSG,
              genlmsg_attrdata(gh, 0),
              genlmsg_attrlen(gh, 0),
              NULL);

    if (!attrs[QKS_ATTR_MSG]) {
        fprintf(stderr, "[DAEMON] Missing QKS_ATTR_MSG\n");
        return NL_OK;
    }

    if (nla_len(attrs[QKS_ATTR_MSG]) < (int)sizeof(struct qks_event_msg)) {
        fprintf(stderr, "[DAEMON] Short message\n");
        return NL_OK;
    }

    const struct qks_event_msg *m =
        (const struct qks_event_msg *)nla_data(attrs[QKS_ATTR_MSG]);

    switch (m->event_type) {
        case QKS_EVENT_EXEC:
            print_exec_event(m);
            break;

        case QKS_EVENT_PACKET:
            print_packet_event(m);
            break;

        case QKS_EVENT_DNS:
            print_packet_event_dns(m);
            break;

        
        case QKS_EVENT_SYSCALL:
            print_syscall_event(m);
            break;

        default:
            printf("[DAEMON] UNKNOWN id=%u type=%s\n",
                   m->event_id, evt_type_str(m->event_type));
            fflush(stdout);
            break;
    }

    return NL_OK;
}

int main(void) {
    struct nl_sock *sk = NULL;
    int fam_id, grp_id;
    int rc;

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    sk = nl_socket_alloc();
    if (!sk) {
        fprintf(stderr, "nl_socket_alloc failed\n");
        return 1;
    }

    // Disable sequence & ACK checking for multicast events
    nl_socket_disable_seq_check(sk);
    nl_socket_disable_auto_ack(sk);

    if ((rc = genl_connect(sk)) != 0) {
        fprintf(stderr, "genl_connect failed: %s\n", nl_geterror(rc));
        nl_socket_free(sk);
        return 1;
    }

    fam_id = genl_ctrl_resolve(sk, "QKS_GENL");
    if (fam_id < 0) {
        fprintf(stderr, "resolve family failed: %s\n", nl_geterror(fam_id));
        nl_socket_free(sk);
        return 1;
    }

    grp_id = genl_ctrl_resolve_grp(sk, "QKS_GENL", "QKS_MC");
    if (grp_id < 0) {
        fprintf(stderr, "resolve group failed: %s\n", nl_geterror(grp_id));
        nl_socket_free(sk);
        return 1;
    }

    if ((rc = nl_socket_add_membership(sk, grp_id)) != 0) {
        fprintf(stderr, "membership failed: %s\n", nl_geterror(rc));
        nl_socket_free(sk);
        return 1;
    }

    nl_socket_modify_cb(sk, NL_CB_VALID,  NL_CB_CUSTOM, on_qks_msg, NULL);

    printf("[DAEMON] Listening... (Ctrl+C to exit)\n");

    while (g_running) {
        rc = nl_recvmsgs_default(sk);
        if (rc < 0 && g_running) {
            fprintf(stderr, "[DAEMON] recv error: %s\n", nl_geterror(rc));
            usleep(100000);
        }
    }

    nl_socket_free(sk);
    printf("[DAEMON] Stopped.\n");
    return 0;
}