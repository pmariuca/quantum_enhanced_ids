#include "policy.h"
#include "qks_message_user.h"   // event types & syscall subtypes
#include "qks_consts_user.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <arpa/inet.h>          // inet_ntop
#include <netinet/in.h>         // IPPROTO_*
#include <netinet/tcp.h>        // TH_SYN, TH_ACK, ...
#include <sys/mman.h>           // PROT_EXEC, PROT_WRITE
#include <sched.h>              // CLONE_* (for clone/setns flags)
#include <fnmatch.h>


#ifndef TH_FIN
#define TH_FIN  0x01
#endif
#ifndef TH_SYN
#define TH_SYN  0x02
#endif
#ifndef TH_RST
#define TH_RST  0x04
#endif
#ifndef TH_PUSH
#define TH_PUSH 0x08
#endif
#ifndef TH_ACK
#define TH_ACK  0x10
#endif
#ifndef TH_URG
#define TH_URG  0x20
#endif


#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif

#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif


/* ====================== State ====================== */
static cJSON *policy_root = NULL;

/* ====================== Load ======================= */
bool qks_policy_load(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[POLICY] cannot open %s\n", path);
        return false;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    char *buf = (char *)malloc((size_t)size + 1);
    if (!buf) { fclose(f); return false; }

    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        fclose(f);
        free(buf);
        fprintf(stderr, "[POLICY] read error for %s\n", path);
        return false;
    }
    buf[size] = '\0';
    fclose(f);

    policy_root = cJSON_Parse(buf);
    free(buf);

    if (!policy_root) {
        fprintf(stderr, "[POLICY] invalid JSON in %s\n", path);
        return false;
    }

    printf("[POLICY] Loaded policy file OK\n");
    return true;
}

bool qks_policy_merge_local(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[POLICY] no local override %s\n", path);
        return false;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    char *buf = malloc(size + 1);
    fread(buf, 1, size, f);
    buf[size] = '\0';
    fclose(f);

    cJSON *local = cJSON_Parse(buf);
    free(buf);

    if (!local) {
        fprintf(stderr, "[POLICY] invalid JSON in %s\n", path);
        return false;
    }

    /* merge keys */
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, local) {
        cJSON *existing = cJSON_GetObjectItem(policy_root, item->string);
        if (existing) {
            /* recursively merge arrays/objects */
            if (cJSON_IsObject(item)) {
                cJSON *sub = NULL;
                cJSON_ArrayForEach(sub, item) {
                    cJSON_ReplaceItemInObject(existing, sub->string, cJSON_Duplicate(sub, 1));
                }
            } else {
                cJSON_ReplaceItemInObject(policy_root, item->string, cJSON_Duplicate(item, 1));
            }
        } else {
            /* new key */
            cJSON_AddItemToObject(policy_root, item->string, cJSON_Duplicate(item, 1));
        }
    }

    cJSON_Delete(local);
    printf("[POLICY] merged local overrides from %s\n", path);
    return true;
}

/* ===================== Helpers ===================== */
static inline bool str_startswith(const char *s, const char *prefix) {
    return s && prefix && strncmp(s, prefix, strlen(prefix)) == 0;
}
static inline bool str_contains(const char *s, const char *sub) {
    return (s && sub && strstr(s, sub) != NULL);
}
static inline bool str_endswith(const char *s, const char *suffix) {
    if (!s || !suffix) return false;
    size_t sl = strlen(s), su = strlen(suffix);
    if (sl < su) return false;
    return strcmp(s + sl - su, suffix) == 0;
}

static bool get_any_bool(const cJSON *rule) {
    const cJSON *any = cJSON_GetObjectItemCaseSensitive(rule, "any");
    return (any && cJSON_IsBool(any) && cJSON_IsTrue(any));
}

static inline bool json_suppress_log(const cJSON *rule) {
    const cJSON *sl = cJSON_GetObjectItemCaseSensitive(rule, "suppress_log");
    return (sl && cJSON_IsBool(sl) && cJSON_IsTrue(sl));
}

/* UID constraints:
 * - "uid_in": [ints]
 * - "uid_not": int
 * For EXEC/SYSCALL → ev->uid. For PACKET/DNS/PACKET_IN → ev->pkt_uid.
 */
static bool match_uid_constraints(const cJSON *rule, const struct qks_event_msg *ev)
{
    uint32_t uid = 0;
    if (ev->event_type == QKS_EVENT_PACKET || ev->event_type == QKS_EVENT_DNS ||
        ev->event_type == QKS_EVENT_PACKET_IN)
        uid = ev->pkt_uid;
    else
        uid = ev->uid;

    /* uid_not */
    const cJSON *uid_not = cJSON_GetObjectItemCaseSensitive(rule, "uid_not");
    if (uid_not && cJSON_IsNumber(uid_not)) {
        if ((uint32_t)uid_not->valuedouble == uid)
            return false;
    }

    /* uid_in */
    const cJSON *uid_in = cJSON_GetObjectItemCaseSensitive(rule, "uid_in");
    if (uid_in && cJSON_IsArray(uid_in)) {
        bool ok = false;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, uid_in) {
            if (cJSON_IsNumber(it) && (uint32_t)it->valuedouble == uid) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }

    return true;
}

/* ===================== EXEC match ===================== */
static bool match_exec_rule(const cJSON *rule, const struct qks_event_msg *ev)
{
    const char *p = ev->exec_path ? ev->exec_path : "";

    /* Optional any:true shortcut (still honor UID constraints). */
    if (get_any_bool(rule)) {
        return match_uid_constraints(rule, ev);
    }

    /* UID constraints (common) */
    if (!match_uid_constraints(rule, ev)) return false;

    /* path_prefix */
    const cJSON *pp = cJSON_GetObjectItemCaseSensitive(rule, "path_prefix");
    if (pp && cJSON_IsString(pp)) {
        if (!str_startswith(p, pp->valuestring))
            return false;
    }

    /* path_suffix */
    const cJSON *ps = cJSON_GetObjectItemCaseSensitive(rule, "path_suffix");
    if (ps && cJSON_IsString(ps)) {
        if (!str_endswith(p, ps->valuestring))
            return false;
    }

    /* path_contains */
    const cJSON *pc = cJSON_GetObjectItemCaseSensitive(rule, "path_contains");
    if (pc && cJSON_IsString(pc)) {
        if (!str_contains(p, pc->valuestring))
            return false;
    }

    /* path_contains_any */
    const cJSON *pca = cJSON_GetObjectItemCaseSensitive(rule, "path_contains_any");
    if (pca && cJSON_IsArray(pca)) {
        bool ok = false;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, pca) {
            if (cJSON_IsString(it) && str_contains(p, it->valuestring)) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }

    /* path_prefix_any */
    const cJSON *ppa = cJSON_GetObjectItemCaseSensitive(rule, "path_prefix_any");
    if (ppa && cJSON_IsArray(ppa)) {
        bool ok = false;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, ppa) {
            if (cJSON_IsString(it) && str_startswith(p, it->valuestring)) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }

    /* file_suffix_any */
    const cJSON *fsa = cJSON_GetObjectItemCaseSensitive(rule, "file_suffix_any");
    if (fsa && cJSON_IsArray(fsa)) {
        bool ok = false;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, fsa) {
            if (cJSON_IsString(it) && str_endswith(p, it->valuestring)) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }

    /* exec_paths_any */
    const cJSON *epa = cJSON_GetObjectItemCaseSensitive(rule, "exec_paths_any");
    if (epa && cJSON_IsArray(epa)) {
        bool ok = false;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, epa) {
            if (cJSON_IsString(it) && str_startswith(p, it->valuestring)) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }

    /* path_glob */
    const cJSON *pg = cJSON_GetObjectItemCaseSensitive(rule, "path_glob");
    if (pg && cJSON_IsString(pg)) {
        if (fnmatch(pg->valuestring, p, 0) != 0)
            return false;
    }

    return true;
}

/* =============== PACKET match (fast) ================= */
static bool ip_to_str(uint32_t host_be, char out[INET_ADDRSTRLEN]) {
    /* Note: ev->packet_*_ip already in host order (your kernel did ntohl). */
    uint32_t be = htonl(host_be);
    return inet_ntop(AF_INET, &be, out, INET_ADDRSTRLEN) != NULL;
}

static bool match_packet_rule(const cJSON *rule, const struct qks_event_msg *ev)
{
    if (ev->event_type != QKS_EVENT_PACKET)
        return false;

    if (!match_uid_constraints(rule, ev)) return false;

    /* Optional any:true */
    if (get_any_bool(rule)) return true;

    /* proto */
    const cJSON *proto = cJSON_GetObjectItemCaseSensitive(rule, "proto");
    if (proto && cJSON_IsString(proto)) {
        if ((strcmp(proto->valuestring, "tcp") == 0 && ev->packet_protocol != IPPROTO_TCP) ||
            (strcmp(proto->valuestring, "udp") == 0 && ev->packet_protocol != IPPROTO_UDP) ||
            (strcmp(proto->valuestring, "icmp") == 0 && ev->packet_protocol != IPPROTO_ICMP))
            return false;
    }

    /* dst_ports_any */
    const cJSON *dpa = cJSON_GetObjectItemCaseSensitive(rule, "dst_ports_any");
    if (dpa && cJSON_IsArray(dpa)) {
        bool ok = false;
        uint16_t d = ev->packet_dst_port;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, dpa) {
            if (cJSON_IsNumber(it) && (uint16_t)it->valuedouble == d) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }

    /* tcp_flags_any */
    const cJSON *tfa = cJSON_GetObjectItemCaseSensitive(rule, "tcp_flags_any");
    if (tfa && cJSON_IsArray(tfa)) {
        if (ev->packet_protocol != IPPROTO_TCP) return false;
        uint8_t f = ev->reserved1;
        bool ok = false;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, tfa) {
            if (!cJSON_IsString(it)) continue;
            if (strcmp(it->valuestring, "syn") == 0 && (f & TH_SYN)) ok = true;
            if (strcmp(it->valuestring, "ack") == 0 && (f & TH_ACK)) ok = true;
            if (strcmp(it->valuestring, "rst") == 0 && (f & TH_RST)) ok = true;
            if (strcmp(it->valuestring, "fin") == 0 && (f & TH_FIN)) ok = true;
            if (ok) break;
        }
        if (!ok) return false;
    }

    /* dst_ip_prefix_any (strings like "10.0.0." or "192.168.") */
    const cJSON *dip = cJSON_GetObjectItemCaseSensitive(rule, "dst_ip_prefix_any");
    if (dip && cJSON_IsArray(dip)) {
        char ipstr[INET_ADDRSTRLEN];
        if (!ip_to_str(ev->packet_dst_ip, ipstr)) return false;

        bool ok = false;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, dip) {
            if (cJSON_IsString(it) && str_startswith(ipstr, it->valuestring)) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }

    return true;
}

/* =============== PACKET_IN match (incoming) ================= */
static bool match_packet_in_rule(const cJSON *rule, const struct qks_event_msg *ev)
{
    if (ev->event_type != QKS_EVENT_PACKET_IN)
        return false;

    /* No UID constraints for incoming packets (pkt_uid is 0) */

    /* Optional any:true */
    if (get_any_bool(rule)) return true;

    /* proto */
    const cJSON *proto = cJSON_GetObjectItemCaseSensitive(rule, "proto");
    if (proto && cJSON_IsString(proto)) {
        if ((strcmp(proto->valuestring, "tcp") == 0 && ev->packet_protocol != IPPROTO_TCP) ||
            (strcmp(proto->valuestring, "udp") == 0 && ev->packet_protocol != IPPROTO_UDP) ||
            (strcmp(proto->valuestring, "icmp") == 0 && ev->packet_protocol != IPPROTO_ICMP))
            return false;
    }

    /* src_ports_any (for incoming, source port from remote) */
    const cJSON *spa = cJSON_GetObjectItemCaseSensitive(rule, "src_ports_any");
    if (spa && cJSON_IsArray(spa)) {
        bool ok = false;
        uint16_t s = ev->packet_src_port;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, spa) {
            if (cJSON_IsNumber(it) && (uint16_t)it->valuedouble == s) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }

    /* dst_ports_any (local listening port) */
    const cJSON *dpa = cJSON_GetObjectItemCaseSensitive(rule, "dst_ports_any");
    if (dpa && cJSON_IsArray(dpa)) {
        bool ok = false;
        uint16_t d = ev->packet_dst_port;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, dpa) {
            if (cJSON_IsNumber(it) && (uint16_t)it->valuedouble == d) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }

    /* tcp_flags_any */
    const cJSON *tfa = cJSON_GetObjectItemCaseSensitive(rule, "tcp_flags_any");
    if (tfa && cJSON_IsArray(tfa)) {
        if (ev->packet_protocol != IPPROTO_TCP) return false;
        uint8_t f = ev->reserved1;
        bool ok = false;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, tfa) {
            if (!cJSON_IsString(it)) continue;
            if (strcmp(it->valuestring, "syn") == 0 && (f & TH_SYN)) ok = true;
            if (strcmp(it->valuestring, "ack") == 0 && (f & TH_ACK)) ok = true;
            if (strcmp(it->valuestring, "rst") == 0 && (f & TH_RST)) ok = true;
            if (strcmp(it->valuestring, "fin") == 0 && (f & TH_FIN)) ok = true;
            if (ok) break;
        }
        if (!ok) return false;
    }

    /* src_ip_prefix_any (remote IP prefix) */
    const cJSON *sip = cJSON_GetObjectItemCaseSensitive(rule, "src_ip_prefix_any");
    if (sip && cJSON_IsArray(sip)) {
        char ipstr[INET_ADDRSTRLEN];
        if (!ip_to_str(ev->packet_src_ip, ipstr)) return false;

        bool ok = false;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, sip) {
            if (cJSON_IsString(it) && str_startswith(ipstr, it->valuestring)) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }

    return true;
}

/* ====================== DNS match ====================== */
static bool match_dns_rule(const cJSON *rule, const struct qks_event_msg *ev)
{
    if (ev->event_type != QKS_EVENT_DNS)
        return false;

    if (!match_uid_constraints(rule, ev)) return false;

    if (get_any_bool(rule)) return true;

    const char *q = ev->dns_qname ? ev->dns_qname : "";

    /* qname_suffixes_any */
    const cJSON *qs = cJSON_GetObjectItemCaseSensitive(rule, "qname_suffixes_any");
    if (qs && cJSON_IsArray(qs)) {
        bool ok = false;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, qs) {
            if (cJSON_IsString(it) && str_endswith(q, it->valuestring)) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }

    /* qname_contains_any */
    const cJSON *qc = cJSON_GetObjectItemCaseSensitive(rule, "qname_contains_any");
    if (qc && cJSON_IsArray(qc)) {
        bool ok = false;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, qc) {
            if (cJSON_IsString(it) && str_contains(q, it->valuestring)) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }

    /* qname_length_greater */
    const cJSON *qlg = cJSON_GetObjectItemCaseSensitive(rule, "qname_length_greater");
    if (qlg && cJSON_IsNumber(qlg)) {
        if (strlen(q) <= (size_t)qlg->valuedouble)
            return false;
    }

    return true;
}

/* ===================== SYSCALL match ==================== */
static bool match_syscall_rule(const cJSON *rule, const struct qks_event_msg *ev)
{
    if (ev->event_type != QKS_EVENT_SYSCALL)
        return false;

    if (!match_uid_constraints(rule, ev)) return false;

    if (get_any_bool(rule)) return true;

    /* subtype string → numeric compare */
    const cJSON *sub = cJSON_GetObjectItemCaseSensitive(rule, "subtype");
    if (sub && cJSON_IsString(sub)) {
        if (strcmp(sub->valuestring, "CLONE_FAMILY") == 0 && ev->sc_subtype != QKS_SC_CLONE_FAMILY)
            return false;
        if (strcmp(sub->valuestring, "MPROTECT_X") == 0 && ev->sc_subtype != QKS_SC_MPROTECT_X)
            return false;
        if (strcmp(sub->valuestring, "MMAP_X") == 0     && ev->sc_subtype != QKS_SC_MMAP_X)
            return false;
        if (strcmp(sub->valuestring, "PRIV_CHANGE") == 0 && ev->sc_subtype != QKS_SC_PRIV_CHANGE)
            return false;
        if (strcmp(sub->valuestring, "UNSHARE") == 0    && ev->sc_subtype != QKS_SC_UNSHARE)
            return false;
        if (strcmp(sub->valuestring, "SETNS") == 0      && ev->sc_subtype != QKS_SC_SETNS)
            return false;
    }

    /* prot_any: ["PROT_EXEC","PROT_WRITE"] */
    const cJSON *pa = cJSON_GetObjectItemCaseSensitive(rule, "prot_any");
    if (pa && cJSON_IsArray(pa)) {
        bool ok = false;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, pa) {
            if (!cJSON_IsString(it)) continue;
            if (strcmp(it->valuestring, "PROT_EXEC") == 0 && (ev->sc_prot & PROT_EXEC))
                ok = true;
            if (strcmp(it->valuestring, "PROT_WRITE") == 0 && (ev->sc_prot & PROT_WRITE))
                ok = true;
            if (ok) break;
        }
        if (!ok) return false;
    }

    /* flags_any: supports a few common flags without heavy mapping */
    const cJSON *fa = cJSON_GetObjectItemCaseSensitive(rule, "flags_any");
    if (fa && cJSON_IsArray(fa)) {
        bool ok = false;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, fa) {
            if (!cJSON_IsString(it)) continue;
            /* Clone namespace flags (subset) */
            if (strcmp(it->valuestring, "CLONE_NEWUSER") == 0 && (ev->sc_flags & CLONE_NEWUSER))
                ok = true;
#ifdef CLONE_NEWNS
            if (strcmp(it->valuestring, "CLONE_NEWNS") == 0 && (ev->sc_flags & CLONE_NEWNS))
                ok = true;
#endif
#ifdef CLONE_NEWNET
            if (strcmp(it->valuestring, "CLONE_NEWNET") == 0 && (ev->sc_flags & CLONE_NEWNET))
                ok = true;
#endif
#ifdef MAP_ANONYMOUS
            /* mmap flags subset */
            if (strcmp(it->valuestring, "MAP_ANONYMOUS") == 0 && (ev->sc_flags & MAP_ANONYMOUS))
                ok = true;
#endif
            if (ok) break;
        }
        if (!ok) return false;
    }

    /* flags_none: ensure none of the named bits are present */
    const cJSON *fn = cJSON_GetObjectItemCaseSensitive(rule, "flags_none");
    if (fn && cJSON_IsArray(fn)) {
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, fn) {
            if (!cJSON_IsString(it)) continue;
            if (strcmp(it->valuestring, "CLONE_NEWUSER") == 0 && (ev->sc_flags & CLONE_NEWUSER))
                return false;
#ifdef CLONE_NEWNS
            if (strcmp(it->valuestring, "CLONE_NEWNS") == 0 && (ev->sc_flags & CLONE_NEWNS))
                return false;
#endif
#ifdef CLONE_NEWNET
            if (strcmp(it->valuestring, "CLONE_NEWNET") == 0 && (ev->sc_flags & CLONE_NEWNET))
                return false;
#endif
#ifdef MAP_ANONYMOUS
            if (strcmp(it->valuestring, "MAP_ANONYMOUS") == 0 && (ev->sc_flags & MAP_ANONYMOUS))
                return false;
#endif
        }
    }

    /* setns special: nstype_not_in: ["CLONE_NEWNS","CLONE_NEWNET",...] */
    const cJSON *nni = cJSON_GetObjectItemCaseSensitive(rule, "nstype_not_in");
    if (nni && cJSON_IsArray(nni)) {
        /* Kernel encodes nstype using CLONE_NEW* values; user-space event uses sc_arg1_u32 */
        uint32_t ns = ev->sc_arg1_u32;
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, nni) {
            if (!cJSON_IsString(it)) continue;
#ifdef CLONE_NEWNS
            if (strcmp(it->valuestring, "CLONE_NEWNS") == 0 && ns == CLONE_NEWNS) return false;
#endif
#ifdef CLONE_NEWNET
            if (strcmp(it->valuestring, "CLONE_NEWNET") == 0 && ns == CLONE_NEWNET) return false;
#endif
#ifdef CLONE_NEWUSER
            if (strcmp(it->valuestring, "CLONE_NEWUSER") == 0 && ns == CLONE_NEWUSER) return false;
#endif
        }
    }

    return true;
}

/* ============== GLOBAL section (simple) ============== */
static bool match_global_rule(const cJSON *rule, const struct qks_event_msg *ev)
{
    /* UID constraints are allowed here */
    if (!match_uid_constraints(rule, ev)) return false;

    /* Exec path-based checks if event is EXEC and rule has path* keys */
    if (ev->event_type == QKS_EVENT_EXEC) {
        /* Reuse exec matcher behavior */
        return match_exec_rule(rule, ev);
    }

    /* Otherwise, if rule has only any:true or uid constraints, we matched above. */
    if (get_any_bool(rule)) return true;

    /* If rule contains path conditions but event isn't EXEC, don't match. */
    return false;
}

/* -------------- Evaluate section (deny/allow/ml) -------------- */
static inline const char *get_reason(const cJSON *rule, const char *fallback) {
    const cJSON *r = cJSON_GetObjectItemCaseSensitive(rule, "reason");
    return (r && cJSON_IsString(r)) ? r->valuestring : fallback;
}

static enum qks_policy_result eval_section(const cJSON *section,
                                           const struct qks_event_msg *ev,
                                           const char **reason_out,
                                           bool *suppress_out)
{
    if (suppress_out) *suppress_out = false;
    if (!section) return QKS_POLICY_UNKNOWN;

    /* 1) deny */
    const cJSON *deny = cJSON_GetObjectItemCaseSensitive(section, "deny");
    if (deny && cJSON_IsArray(deny)) {
        const cJSON *rule = NULL;
        cJSON_ArrayForEach(rule, deny) {
            bool match = false;
            switch (ev->event_type) {
                case QKS_EVENT_EXEC:      match = match_exec_rule(rule, ev);      break;
                case QKS_EVENT_PACKET:    match = match_packet_rule(rule, ev);    break;
                case QKS_EVENT_PACKET_IN: match = match_packet_in_rule(rule, ev); break;
                case QKS_EVENT_DNS:       match = match_dns_rule(rule, ev);       break;
                case QKS_EVENT_SYSCALL:   match = match_syscall_rule(rule, ev);   break;
                default: break;
            }
            if (match) {
                *reason_out = get_reason(rule, "deny_rule");
                if (suppress_out) *suppress_out = json_suppress_log(rule);

                return QKS_POLICY_DENY;
            }
        }
    }

    /* 2) allow */
    const cJSON *allow = cJSON_GetObjectItemCaseSensitive(section, "allow");
    if (allow && cJSON_IsArray(allow)) {
        const cJSON *rule = NULL;
        cJSON_ArrayForEach(rule, allow) {
            bool match = false;
            switch (ev->event_type) {
                case QKS_EVENT_EXEC:      match = match_exec_rule(rule, ev);      break;
                case QKS_EVENT_PACKET:    match = match_packet_rule(rule, ev);    break;
                case QKS_EVENT_PACKET_IN: match = match_packet_in_rule(rule, ev); break;
                case QKS_EVENT_DNS:       match = match_dns_rule(rule, ev);       break;
                case QKS_EVENT_SYSCALL:   match = match_syscall_rule(rule, ev);   break;
                default: break;
            }
            if (match) {
                *reason_out = get_reason(rule, "allow_rule");
                if (suppress_out) *suppress_out = json_suppress_log(rule);

                return QKS_POLICY_ALLOW;
            }
        }
    }

    /* 3) ml → UNKNOWN */
    const cJSON *ml = cJSON_GetObjectItemCaseSensitive(section, "ml");
    if (ml && cJSON_IsArray(ml)) {
        const cJSON *rule = NULL;
        cJSON_ArrayForEach(rule, ml) {
            bool match = false;
            switch (ev->event_type) {
                case QKS_EVENT_EXEC:      match = match_exec_rule(rule, ev);      break;
                case QKS_EVENT_PACKET:    match = match_packet_rule(rule, ev);    break;
                case QKS_EVENT_PACKET_IN: match = match_packet_in_rule(rule, ev); break;
                case QKS_EVENT_DNS:       match = match_dns_rule(rule, ev);       break;
                case QKS_EVENT_SYSCALL:   match = match_syscall_rule(rule, ev);   break;
                default: break;
            }
            if (match) {
                *reason_out = get_reason(rule, "ml_rule");
                if (suppress_out) *suppress_out = json_suppress_log(rule);
                    
                return QKS_POLICY_UNKNOWN;
            }
        }
    }

    return QKS_POLICY_UNKNOWN;
}

/* ===================== Main API ===================== */
enum qks_policy_result qks_policy_eval(const struct qks_event_msg *ev,
                                       const char **reason_out,
                                       bool *suppress_log_out)
{
    if (!policy_root) {
        *reason_out = "policy_not_loaded";
        return QKS_POLICY_UNKNOWN;
    }

    /* Global section first: deny/allow */
    const cJSON *global = cJSON_GetObjectItemCaseSensitive(policy_root, "global");
    if (global && cJSON_IsObject(global)) {
        /* deny */
        const cJSON *deny = cJSON_GetObjectItemCaseSensitive(global, "deny");
        if (deny && cJSON_IsArray(deny)) {
            const cJSON *rule = NULL;
            cJSON_ArrayForEach(rule, deny) {
                if (match_global_rule(rule, ev)) {
                    *reason_out = get_reason(rule, "global_deny");
                    if (suppress_log_out) *suppress_log_out = json_suppress_log(rule);

                    return QKS_POLICY_DENY;
                }
            }
        }
        /* allow */
        const cJSON *allow = cJSON_GetObjectItemCaseSensitive(global, "allow");
        if (allow && cJSON_IsArray(allow)) {
            const cJSON *rule = NULL;
            cJSON_ArrayForEach(rule, allow) {
                if (match_global_rule(rule, ev)) {
                    *reason_out = get_reason(rule, "global_allow");
                    if (suppress_log_out) *suppress_log_out = json_suppress_log(rule);

                    return QKS_POLICY_ALLOW;
                }
            }
        }
    }

    /* Section by event_type */
    const cJSON *section = NULL;
    switch (ev->event_type) {
        case QKS_EVENT_EXEC:      section = cJSON_GetObjectItemCaseSensitive(policy_root, "exec");      break;
        case QKS_EVENT_PACKET:    section = cJSON_GetObjectItemCaseSensitive(policy_root, "packet");    break;
        case QKS_EVENT_PACKET_IN: section = cJSON_GetObjectItemCaseSensitive(policy_root, "packet_in"); break;
        case QKS_EVENT_DNS:       section = cJSON_GetObjectItemCaseSensitive(policy_root, "dns");       break;
        case QKS_EVENT_SYSCALL:   section = cJSON_GetObjectItemCaseSensitive(policy_root, "syscall");   break;
        default: section = NULL; break;
    }

    enum qks_policy_result r = eval_section(section, ev, reason_out, suppress_log_out);
    if (r != QKS_POLICY_UNKNOWN) return r;

    /* Fallback to default_action at root */
    const cJSON *da = cJSON_GetObjectItemCaseSensitive(policy_root, "default_action");
    if (da && cJSON_IsString(da)) {
        if (strcmp(da->valuestring, "allow") == 0) {
            *reason_out = "default_allow";
            return QKS_POLICY_ALLOW;
        } else if (strcmp(da->valuestring, "deny") == 0) {
            *reason_out = "default_deny";
            return QKS_POLICY_DENY;
        } else { /* "ml" or unknown - UNKNOWN */
            *reason_out = "default_ml";
            return QKS_POLICY_UNKNOWN;
        }
    }

    *reason_out = "no_match_no_default";
    return QKS_POLICY_UNKNOWN;
}