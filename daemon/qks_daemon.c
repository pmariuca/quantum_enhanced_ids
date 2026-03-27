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
#include <openssl/sha.h>


#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <arpa/inet.h>
#include <netinet/tcp.h>   // TCP flags
#include <netinet/ip.h>

#include "pqclean/ml-dsa-44/clean/api.h"
#include "qks_message_user.h"
#include "qks_verdict_user.h"
#include "qks_consts_user.h"
#include "../kernel/qks_genl.h"
#include "queue.h"
#include "syscalls.h"
#include "policy.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>


// Globals
static volatile bool g_running = true;

struct qks_queue g_queue;
static pthread_t g_worker;

static void qks_now_iso8601(char *buf, size_t len) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);

    snprintf(buf, len,
             "%04d-%02d-%02dT%02d:%02d:%02d.%09ldZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             ts.tv_nsec);
}

// Private key data
static uint8_t qks_sk[5000];
static size_t  qks_sk_len = 0;

static uint8_t g_pk[1312];
static size_t  g_pk_len = 0;

static bool load_public_key(void) {
    FILE *f = fopen("qks_pk.bin", "rb");
    if (!f) {
        fprintf(stderr, "[DAEMON] ERROR: cannot open qks_pk.bin\n");
        return false;
    }
    g_pk_len = fread(g_pk, 1, sizeof(g_pk), f);
    fclose(f);
    if (g_pk_len != 1312) {
        fprintf(stderr, "[DAEMON] ERROR: bad public key length %zu (want 1312)\n", g_pk_len);
        return false;
    }
    printf("[DAEMON] pk[0..15]=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
           g_pk[0],g_pk[1],g_pk[2],g_pk[3],g_pk[4],g_pk[5],g_pk[6],g_pk[7],
           g_pk[8],g_pk[9],g_pk[10],g_pk[11],g_pk[12],g_pk[13],g_pk[14],g_pk[15]);
    return true;
}

// ------------------------- SIGNAL -------------------------
static void on_sigint(int signo) {
    (void)signo;
    g_running = false;
}

// ------------------------- PRINTING -------------------------
static const char* evt_type_str(uint8_t t) {
    switch (t) {
        case QKS_EVENT_EXEC:      return "EXEC";
        case QKS_EVENT_SYSCALL:   return "SYSCALL";
        case QKS_EVENT_PACKET:    return "PACKET";
        case QKS_EVENT_DNS:       return "DNS";
        case QKS_EVENT_PACKET_IN: return "PACKET_IN";
        default:                  return "UNKNOWN";
    }
}

// ------------------------- HELPERS -------------------------
static void to_hex(const uint8_t *in, size_t len, char *out, size_t out_len)
{
    static const char *hex = "0123456789abcdef";

    if (out_len < len * 2 + 1) {
        if (out_len > 0) out[0] = '\0';
        return;
    }

    for (size_t i = 0; i < len; i++) {
        out[i*2]   = hex[(in[i] >> 4) & 0xF];
        out[i*2+1] = hex[in[i] & 0xF];
    }
    out[len * 2] = '\0';
}


static void qks_write_event_jsonl(const struct qks_event_msg *ev,
                                  enum qks_policy_result pol,
                                  const char *reason,
                                  const char *sig_status,
                                  size_t sig_len,
                                  const uint8_t hash[32],
                                  const char *sig_scheme)
{
    FILE *f = fopen("policy/events.jsonl", "a");
    if (!f) {
        fprintf(stderr, "[DAEMON] ERROR: cannot open events.jsonl for append\n");
        return;
    }

    char ts[64];
    qks_now_iso8601(ts, sizeof(ts));

    // start object
    fprintf(f, "{");

    // top-level fields
    fprintf(f, "\"ts_daemon\":\"%s\",", ts);
    fprintf(f, "\"event_id\":%lu,", ev->event_id);
    fprintf(f, "\"type\":\"%s\",", evt_type_str(ev->event_type));
    fprintf(f, "\"policy\":\"%s\",",
             pol == QKS_POLICY_ALLOW ? "ALLOW" :
             pol == QKS_POLICY_DENY  ? "DENY"  : "UNKNOWN");
    fprintf(f, "\"reason\":\"%s\",", reason ? reason : "none");
    
    // --- Signature metadata block ---
    {
        char hash_hex[65] = {0};
        if (hash) {
            to_hex(hash, 32, hash_hex, sizeof(hash_hex));
        }

        fprintf(f, "\"sig\":{");
        fprintf(f, "\"status\":\"%s\",", sig_status ? sig_status : "n/a");
        fprintf(f, "\"len\":%zu,", sig_len);
        fprintf(f, "\"scheme\":\"%s\",", sig_scheme ? sig_scheme : "verdict_tuple_v1");
        if (hash) {
            fprintf(f, "\"hash\":\"%s\"", hash_hex);
        } else {
            fprintf(f, "\"hash\":null");
        }
        fprintf(f, "},");
    }

    // structured event fields
    if (ev->event_type == QKS_EVENT_EXEC) {
        fprintf(f, "\"exec\":{");
        fprintf(f, "\"path\":\"%s\"", ev->exec_path);
        fprintf(f, "}");
    }

    if (ev->event_type == QKS_EVENT_PACKET) {
        char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ev->packet_src_ip, sip, sizeof(sip));
        inet_ntop(AF_INET, &ev->packet_dst_ip, dip, sizeof(dip));

        fprintf(f, "\"packet\":{");
        fprintf(f, "\"src_ip\":\"%s\",", sip);
        fprintf(f, "\"src_port\":%u,", ev->packet_src_port);
        fprintf(f, "\"dst_ip\":\"%s\",", dip);
        fprintf(f, "\"dst_port\":%u,", ev->packet_dst_port);
        fprintf(f, "\"protocol\":%u,", ev->packet_protocol);
        fprintf(f, "\"len\":%u", ev->packet_len);
        fprintf(f, "}");
    }

    if (ev->event_type == QKS_EVENT_PACKET_IN) {
        char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
        uint32_t src_be = htonl(ev->packet_src_ip);
        uint32_t dst_be = htonl(ev->packet_dst_ip);
        inet_ntop(AF_INET, &src_be, sip, sizeof(sip));
        inet_ntop(AF_INET, &dst_be, dip, sizeof(dip));

        fprintf(f, "\"packet_in\":{");
        fprintf(f, "\"src_ip\":\"%s\",", sip);
        fprintf(f, "\"src_port\":%u,", ev->packet_src_port);
        fprintf(f, "\"dst_ip\":\"%s\",", dip);
        fprintf(f, "\"dst_port\":%u,", ev->packet_dst_port);
        fprintf(f, "\"protocol\":%u,", ev->packet_protocol);
        fprintf(f, "\"tcp_flags\":\"0x%02x\",", ev->reserved1);
        fprintf(f, "\"len\":%u", ev->packet_len);
        fprintf(f, "}");
    }

    if (ev->event_type == QKS_EVENT_DNS) {
        char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ev->packet_src_ip, sip, sizeof(sip));
        inet_ntop(AF_INET, &ev->packet_dst_ip, dip, sizeof(dip));

        fprintf(f, "\"dns\":{");
        fprintf(f, "\"src_ip\":\"%s\",", sip);
        fprintf(f, "\"dst_ip\":\"%s\",", dip);
        fprintf(f, "\"qname\":\"%s\",", ev->dns_qname);
        fprintf(f, "\"qtype\":%u", ev->dns_qtype);
        fprintf(f, "}");
    }

    if (ev->event_type == QKS_EVENT_SYSCALL) {
        uint32_t sock_type = ev->sc_arg1_u32 & 0x0f;
        fprintf(f, "\"syscall\":{");
        fprintf(f, "\"nr\":%u,", ev->sc_nr);
        fprintf(f, "\"subtype\":%u,", ev->sc_subtype);
        fprintf(f, "\"flags\":\"0x%lx\",", ev->sc_flags);
        fprintf(f, "\"prot\":\"0x%x\",", ev->sc_prot);
        fprintf(f, "\"arg0\":%u,", ev->sc_arg0_u32);
        fprintf(f, "\"arg1\":%u,", ev->sc_arg1_u32);
        fprintf(f, "\"arg2\":%u,", ev->sc_arg2_u32);
        fprintf(f, "\"arg_str\":\"%s\",", ev->sc_str);
        fprintf(f, "\"sock_domain\":%u,", ev->sc_arg0_u32);
        fprintf(f, "\"sock_type\":%u,", sock_type);
        fprintf(f, "\"sock_type_with_flags\":%u,", ev->sc_arg1_u32);
        fprintf(f, "\"sock_protocol\":%u", ev->sc_arg2_u32);
        fprintf(f, "}");
    }

    // end object
    fprintf(f, "}\n");

    fclose(f);
}

static bool load_private_key(void) {
    FILE *f = fopen("qks_sk.bin", "rb");
    if (!f) {
        fprintf(stderr, "[DAEMON] ERROR: cannot open qks_sk.bin\n");
        return false;
    }
    qks_sk_len = fread(qks_sk, 1, sizeof(qks_sk), f);
    fclose(f);

    if (qks_sk_len == 0) {
        fprintf(stderr, "[DAEMON] ERROR: private key empty\n");
        return false;
    }

    printf("[DAEMON] Loaded ML‑DSA‑44 private key (%zu bytes)\n", qks_sk_len);
    return true;
}

static inline uint64_t to_be64(uint64_t x) {
    // portable htonll (not in POSIX)
    return ((uint64_t)htonl((uint32_t)(x >> 32))) |
           ((uint64_t)htonl((uint32_t)(x & 0xffffffff)) << 32);
}

static void qks_hash_verdict_tuple(uint64_t event_id,
                                   uint8_t verdict,
                                   uint64_t ts_sec,
                                   uint32_t ts_nsec,
                                   uint8_t out_hash[32])
{
    // Domain separation tag to prevent cross-protocol confusion
    static const char domain[] = "QKS:verdict:v1";
    uint8_t buf[ sizeof(domain) - 1 + 8 + 1 + 8 + 4 ];
    size_t  off = 0;

    memcpy(buf + off, domain, sizeof(domain) - 1);
    off += sizeof(domain) - 1;

    uint64_t be_eid   = to_be64(event_id);
    uint64_t be_sec   = to_be64(ts_sec);
    uint32_t be_nsec  = htonl(ts_nsec);

    memcpy(buf + off, &be_eid, 8); off += 8;
    buf[off++] = verdict;
    memcpy(buf + off, &be_sec, 8); off += 8;
    memcpy(buf + off, &be_nsec, 4); off += 4;

    // Hash
    SHA256(buf, off, out_hash);
}

static bool sign_hash(const uint8_t hash[32], uint8_t sig_out[2420], size_t *sig_len)
{
    int rc = PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(
                    sig_out, sig_len,
                    hash, 32,
                    qks_sk);
    
    if (rc != 0) {
            fprintf(stderr, "[DAEMON] PQClean sign (ctx) FAILED\n");
            return false;
        }

    return true;
}

static void send_verdict(struct nl_sock *sk, int fam_id,
                         const struct qks_verdict_msg *v)
{
    struct nl_msg *reply = nlmsg_alloc();
    if (!reply) {
        fprintf(stderr, "[DAEMON] nlmsg_alloc failed\n");
        return;
    }

    genlmsg_put(reply,
                NL_AUTO_PORT,
                NL_AUTO_SEQ,
                fam_id,
                0,
                0,
                QKS_CMD_VERDICT,
                QKS_GENL_VERSION);

    nla_put(reply, QKS_ATTR_VERDICT, sizeof(*v), v);
    nl_send_auto(sk, reply);
    nlmsg_free(reply);
}

static const char *proto_name(uint8_t p) {
    switch (p) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default: return "OTHER";
    }
}

static void print_tcp_flags(uint8_t flags) {
    printf("        flags = 0x%02x [", flags);
    if (flags & TH_FIN)  printf(" FIN");
    if (flags & TH_SYN)  printf(" SYN");
    if (flags & TH_RST)  printf(" RST");
    if (flags & TH_PUSH) printf(" PSH");
    if (flags & TH_ACK)  printf(" ACK");
    if (flags & TH_URG)  printf(" URG");
    printf(" ]\n");
}

static void normalize_packet(const struct qks_event_msg *ev) {
    // ---- Convert IPs ----
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ev->packet_src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ev->packet_dst_ip, dst_ip, sizeof(dst_ip));

    // ---- Convert ports to host byte order ----
    uint16_t sport = ntohs(ev->packet_src_port);
    uint16_t dport = ntohs(ev->packet_dst_port);

    // ---- Print normalized packet metadata ----
    printf("    PACKET: %s:%u -> %s:%u\n", src_ip, sport, dst_ip, dport);
    printf("        proto = %u (%s)\n", ev->packet_protocol, proto_name(ev->packet_protocol));
    printf("        len   = %u bytes\n", ev->packet_len);

    // ---- TCP flags (valid only for TCP) ----
    if (ev->event_type == QKS_EVENT_PACKET &&
        ev->packet_protocol == IPPROTO_TCP)
    {
        printf("    TCP flags = 0x%02x [", ev->reserved1);
        if (ev->reserved1 & TH_FIN) printf(" FIN");
        if (ev->reserved1 & TH_SYN) printf(" SYN");
        if (ev->reserved1 & TH_RST) printf(" RST");
        if (ev->reserved1 & TH_PUSH) printf(" PSH");
        if (ev->reserved1 & TH_ACK) printf(" ACK");
        if (ev->reserved1 & TH_URG) printf(" URG");
        printf(" ]\n");
    }

    // ---- Process information ----
    printf("        pkt_pid = %u\n", ev->pkt_pid);
    printf("        pkt_uid = %u\n", ev->pkt_uid);
    printf("        pkt_exec_path = %s\n", ev->pkt_exec_path);
}

// ------------------------- CONTEXT FOR CALLBACK -------------------------
struct qks_ctx {
    struct nl_sock *sk;
    int fam_id;
};

// ------------------------- NETLINK CALLBACK -------------------------
static int on_qks_msg(struct nl_msg *msg, void *arg) {
    struct qks_ctx *ctx = (struct qks_ctx *)arg;

    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gh = (struct genlmsghdr *)nlmsg_data(nlh);

    
    struct nlattr *attrs[QKS_ATTR_MAX + 1] = {0};
    if (nla_parse(attrs, QKS_ATTR_MAX,
                genlmsg_attrdata(gh, 0),
                genlmsg_attrlen(gh, 0),
                NULL) < 0) {
        fprintf(stderr, "[DAEMON] nla_parse failed\n");
        return NL_OK;
    }

    if (!attrs[QKS_ATTR_MSG]) {
        fprintf(stderr, "[DAEMON] Missing QKS_ATTR_MSG\n");
        return NL_OK;
    }
    if (nla_len(attrs[QKS_ATTR_MSG]) < (int)sizeof(qks_event_msg)) {
        fprintf(stderr, "[DAEMON] Short event message\n");
        return NL_OK;
    }

    const qks_event_msg *m = nla_data(attrs[QKS_ATTR_MSG]);
    printf("[DAEMON] EVENT id=%lu type=%s (queued)\n",
           m->event_id,
           evt_type_str(m->event_type));

    struct qks_event_msg *cpy = malloc(sizeof(*cpy));
    memcpy(cpy, m, sizeof(*cpy));

    // Push into FIFO queue
    queue_push(&g_queue, cpy);

    return NL_OK;
}

static void *worker_thread_main(void *arg)
{
    struct qks_ctx *ctx = arg;

    while (g_running) {
        struct qks_event_msg *ev = queue_pop(&g_queue);

        if (ev->event_type == QKS_EVENT_SYSCALL) {
            printf("SYSCALL: %s (%u)\n",
                syscall_name_or_unknown(ev->sc_nr),
                ev->sc_nr);
            printf("      subtype = %u\n", ev->sc_subtype);
            printf("      addr    = 0x%lx\n", ev->sc_addr);
            printf("      len     = %lu\n", ev->sc_len);
            printf("      flags   = 0x%lx\n", ev->sc_flags);
            printf("      prot    = 0x%x\n", ev->sc_prot);
            printf("      arg0    = %u\n", ev->sc_arg0_u32);
            printf("      arg1    = %u\n", ev->sc_arg1_u32);
            printf("      arg2    = %u\n", ev->sc_arg2_u32);
            printf("      str     = '%s'\n", ev->sc_str);
        }

        if (ev->event_type == QKS_EVENT_PACKET) {
            normalize_packet(ev);
        }

        const char *pol_reason = NULL;
        bool suppress_log = false;
        enum qks_policy_result pol = qks_policy_eval(ev, &pol_reason, &suppress_log);

        // ---- Sign ----
        struct qks_verdict_msg v = {0};
        v.event_id = ev->event_id;
        v.verdict = QKS_ALLOW;

        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        v.daemon_ts_sec  = (uint64_t)now.tv_sec;
        v.daemon_ts_nsec = (uint32_t)now.tv_nsec;

        strncpy(v.reason, pol_reason ? pol_reason : "none", sizeof(v.reason)-1);
        v.reason[sizeof(v.reason)-1] = '\0';
        
        qks_hash_verdict_tuple(v.event_id, v.verdict, v.daemon_ts_sec, v.daemon_ts_nsec, v.hash);   

        size_t sig_len = 0;
        const char *sig_status = "ok";
        
        if (!sign_hash(v.hash, v.signature, &sig_len)) {
            sig_status = "fail_sign";
            fprintf(stderr, "[DAEMON] Sign failed for %lu → DENY\n", ev->event_id);
            v.verdict = QKS_DENY;
            v.signature_len = 0;
        } else {
            int rc = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
                        v.signature, sig_len, v.hash, 32, g_pk);
            if (rc == 0)
                v.signature_len = sig_len;
            else {
                v.verdict = QKS_DENY;
                v.signature_len = 0;
            }
        }

        if (!suppress_log) {
            printf("[DAEMON] policy = %s (reason=%s)\n",
                pol == QKS_POLICY_ALLOW ? "ALLOW" :
                pol == QKS_POLICY_DENY  ? "DENY"  : "UNKNOWN",
                pol_reason ? pol_reason : "n/a");

            qks_write_event_jsonl(ev, pol, pol_reason,
                                    sig_status, v.signature_len,
                                    v.hash, "verdict_tuple_v1");

            if (pol == QKS_POLICY_DENY) {
                struct qks_verdict_msg v = {0};
                v.event_id = ev->event_id;
                v.verdict  = QKS_DENY;

                // timestamp
                struct timespec now;
                clock_gettime(CLOCK_REALTIME, &now);
                v.daemon_ts_sec  = (uint64_t)now.tv_sec;
                v.daemon_ts_nsec = (uint32_t)now.tv_nsec;

                strncpy(v.reason, pol_reason ? pol_reason : "none", sizeof(v.reason)-1);

                qks_hash_verdict_tuple(v.event_id, v.verdict, v.daemon_ts_sec, v.daemon_ts_nsec, v.hash);
                
                size_t sig_len = 0;
                if (!sign_hash(v.hash, v.signature, &sig_len)) {
                    v.signature_len = 0;
                } else {
                    v.signature_len = sig_len;
                }

                send_verdict(ctx->sk, ctx->fam_id, &v);
                free(ev);
                continue;
            }
        }

        // ---- Send verdict ----
        send_verdict(ctx->sk, ctx->fam_id, &v);

        free(ev);
    }

    return NULL;
}

// ------------------------- MAIN -------------------------
int main(void) {
    if (!load_private_key())
        return 1;

    if (!load_public_key())  return 1;
    
    if (!qks_policy_load("policy/policy.json")) {
        fprintf(stderr, "[DAEMON] Failed to load policy.json\n");
        return 1;
    }
    qks_policy_merge_local("policy/policy.local.json");

    struct nl_sock *sk = nl_socket_alloc();
    if (!sk) {
        fprintf(stderr, "nl_socket_alloc failed\n");
        return 1;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    nl_socket_disable_seq_check(sk);
    nl_socket_disable_auto_ack(sk);

    int rc;
    if ((rc = genl_connect(sk)) != 0) {
        fprintf(stderr, "genl_connect failed: %s\n", nl_geterror(rc));
        nl_socket_free(sk);
        return 1;
    }

    int fam_id = genl_ctrl_resolve(sk, QKS_GENL_FAMILY);
    if (fam_id < 0) {
        fprintf(stderr, "[DAEMON] resolve family failed: %s\n", nl_geterror(fam_id));
        return 1;
    }
    printf("[DAEMON] family id = %d\n", fam_id);

    int grp_id = genl_ctrl_resolve_grp(sk, QKS_GENL_FAMILY, QKS_GENL_MCGRP);
    if (grp_id < 0) {
        fprintf(stderr, "[DAEMON] resolve group failed: %s\n", nl_geterror(grp_id));
        return 1;
    }
    printf("[DAEMON] group id   = %d\n", grp_id);

    rc = nl_socket_add_membership(sk, grp_id);
    if (rc != 0) {
        fprintf(stderr, "[DAEMON] add_membership failed: %s\n", nl_geterror(rc));
        return 1;
    } else {
        printf("[DAEMON] joined multicast group OK\n");
    }

    nl_socket_add_membership(sk, grp_id);

    struct qks_ctx ctx = { .sk = sk, .fam_id = fam_id };
    queue_init(&g_queue);
    pthread_create(&g_worker, NULL, worker_thread_main, &ctx);
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, on_qks_msg, &ctx);

    printf("[DAEMON] Ready. Listening for QKS events…\n");

    while (g_running) {
        rc = nl_recvmsgs_default(sk);
        if (rc < 0 && g_running)
            fprintf(stderr, "[DAEMON] recv error: %s\n", nl_geterror(rc));
    }

    nl_socket_free(sk);
    
    g_running = false;
    pthread_cond_broadcast(&g_queue.cond);
    pthread_join(g_worker, NULL);

    printf("[DAEMON] Shutdown.\n");
    return 0;
}