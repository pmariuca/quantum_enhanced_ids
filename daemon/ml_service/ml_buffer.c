#include "ml_buffer.h"
#include "../qks_message_user.h"
#include "../qks_consts_user.h"
#include <string.h>

#include <netinet/in.h>

static ml_pid_buffer_t g_bufs[ML_MAX_PIDS];

ml_pid_buffer_t *ml_buf_get(uint32_t pid, uint64_t ts_ns) {
    // find existing slot
    for (int i = 0; i < ML_MAX_PIDS; i++) {
        if (g_bufs[i].active && g_bufs[i].pid == pid) {
            // expire window if needed
            if (ts_ns - g_bufs[i].window_start_ns > ML_WINDOW_NS) {
                memset(&g_bufs[i], 0, sizeof(g_bufs[i]));
                g_bufs[i].pid = pid;
                g_bufs[i].active = 1;
                g_bufs[i].window_start_ns = ts_ns;
            }
            return &g_bufs[i];
        }
    }
    // allocate new slot
    for (int i = 0; i < ML_MAX_PIDS; i++) {
        if (!g_bufs[i].active) {
            memset(&g_bufs[i], 0, sizeof(g_bufs[i]));
            g_bufs[i].pid = pid;
            g_bufs[i].active = 1;
            g_bufs[i].window_start_ns = ts_ns;
            return &g_bufs[i];
        }
    }
    return NULL;  // table full
}

void ml_buf_update(ml_pid_buffer_t *buf, const struct qks_event_msg *ev) {
    if (!buf) return;

    if (ev->event_type == QKS_EVENT_EXEC) {
        buf->sc_exec_count++;
    }

    if (ev->event_type == QKS_EVENT_SYSCALL) {
        switch (ev->sc_subtype) {
            case QKS_SC_MEMFD_CREATE:  buf->sc_memfd_count++;      break;
            case QKS_SC_MPROTECT_X:    buf->sc_mprotect_x_count++; break;
            case QKS_SC_MMAP_X:        buf->sc_mmap_x_count++;     break;
            case QKS_SC_PRIV_CHANGE:   buf->sc_priv_change_count++; break;
            case QKS_SC_CLONE_FAMILY:  buf->sc_clone_count++;       break;
            case QKS_SC_UNSHARE:       buf->sc_namespace_count++;   break;
            case QKS_SC_SETNS:         buf->sc_namespace_count++;   break;
            case QKS_SC_SOCKET_CREATE: buf->sc_socket_create_count++; break;
        }
    }

    if (ev->event_type == QKS_EVENT_PACKET) {
        buf->net_packet_out_count++;
        buf->net_total_packet_len += ev->packet_len;
        buf->net_unique_dst_ips++;    // simplified (no dedup)
        buf->net_unique_dst_ports++;

        // SYN without ACK = suspicious
        if (ev->packet_protocol == IPPROTO_TCP &&
            (ev->reserved1 & 0x02) && !(ev->reserved1 & 0x10))
            buf->net_tcp_flags_anomaly++;

        uint16_t dport = ntohs(ev->packet_dst_port);
        if (dport < 1024 || dport == 4444 || dport == 1337 || dport == 31337)
            buf->net_suspicious_port_count++;
    }

    if (ev->event_type == QKS_EVENT_PACKET_IN) {
        buf->net_packet_in_count++;
    }

    if (ev->event_type == QKS_EVENT_DNS) {
        buf->net_dns_count++;
    }
}