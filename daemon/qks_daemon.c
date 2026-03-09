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

#include "pqclean/ml-dsa-44/clean/api.h"

#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>


#include "qks_message_user.h"
#include "qks_verdict_user.h"
#include "qks_consts_user.h"
#include "../kernel/qks_genl.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


// Globals
static volatile bool g_running = true;

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

// ------------------------- HELPERS -------------------------
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

static void hash_event(const struct qks_event_msg *m, uint8_t out[32]) {
    SHA256((const uint8_t *)m, sizeof(*m), out);
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


// ------------------------- PRINTING -------------------------
static const char* evt_type_str(uint8_t t) {
    switch (t) {
        case QKS_EVENT_EXEC:    return "EXEC";
        case QKS_EVENT_SYSCALL: return "SYSCALL";
        case QKS_EVENT_PACKET:  return "PACKET";
        case QKS_EVENT_DNS:     return "DNS";
        default:                return "UNKNOWN";
    }
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
    const qks_event_msg *m = (const qks_event_msg *)nla_data(attrs[QKS_ATTR_MSG]);


    // ===== Print event =====
    printf("[DAEMON] EVENT id=%lu type=%s\n", m->event_id, evt_type_str(m->event_type));

    // ===== Hash =====
    uint8_t hash[32];
    hash_event(m, hash);


    // ===== Sign =====
    struct qks_verdict_msg v = {0};
    v.event_id = m->event_id;
    v.verdict  = QKS_ALLOW;  // Default allow (add detection logic later)
    memcpy(v.hash, hash, 32);

    
    size_t sig_len = 0;

    if (!sign_hash(hash, v.signature, &sig_len)) {
        fprintf(stderr, "[DAEMON] Sign failed for event_id=%lu → DENY\n", m->event_id);
        v.verdict = QKS_DENY;
        v.signature_len = 0;
    } else {
        // Self-verify with non-ctx API using the PUBLIC key and the actual signature length
        int rc = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
                    v.signature, sig_len,
                    hash, 32,
                    g_pk);
        printf("[DAEMON] self-verify non-ctx = %s for id=%lu\n", rc==0 ? "OK" : "FAIL", m->event_id);

        if (rc != 0) {
            v.verdict = QKS_DENY;
            v.signature_len = 0;
        } else {
            v.signature_len = (uint32_t)sig_len;
        }
    }

    // ===== Send verdict back to kernel =====
    struct nl_msg *reply = nlmsg_alloc();
    if (!reply) {
        fprintf(stderr, "[DAEMON] nlmsg_alloc failed\n");
        return NL_OK;
    }

    genlmsg_put(reply,
                NL_AUTO_PORT,
                NL_AUTO_SEQ,
                ctx->fam_id,
                0,
                0,
                QKS_CMD_VERDICT,
                QKS_GENL_VERSION);

    nla_put(reply, QKS_ATTR_VERDICT, sizeof(v), &v);

    nl_send_auto(ctx->sk, reply);
    nlmsg_free(reply);

    return NL_OK;
}

// ------------------------- MAIN -------------------------
int main(void) {
    if (!load_private_key())
        return 1;

    if (!load_public_key())  return 1;
    printf("[DAEMON] signing_variant = non-ctx\n");

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
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, on_qks_msg, &ctx);

    printf("[DAEMON] Ready. Listening for QKS events…\n");

    while (g_running) {
        rc = nl_recvmsgs_default(sk);
        if (rc < 0 && g_running)
            fprintf(stderr, "[DAEMON] recv error: %s\n", nl_geterror(rc));
    }

    nl_socket_free(sk);
    printf("[DAEMON] Shutdown.\n");
    return 0;
}