#pragma once
#include <stdint.h>
#include <time.h>
#include "../qks_message_user.h"

#define ML_WINDOW_NS 1000000000ULL  // 1 second
#define ML_MAX_PIDS  1024

typedef struct {
    uint32_t pid;
    uint64_t window_start_ns;
    int      active;

    // Syscall features
    uint32_t sc_exec_count;
    uint32_t sc_memfd_count;
    uint32_t sc_mprotect_x_count;
    uint32_t sc_mmap_x_count;
    uint32_t sc_priv_change_count;
    uint32_t sc_clone_count;
    uint32_t sc_namespace_count;
    uint32_t sc_socket_create_count;

    // Network features
    uint32_t net_packet_out_count;
    uint32_t net_packet_in_count;
    uint32_t net_dns_count;
    uint32_t net_suspicious_port_count;
    uint32_t net_unique_dst_ips;    // simple counter
    uint32_t net_unique_dst_ports;
    uint64_t net_total_packet_len;  // for mean
    uint32_t net_tcp_flags_anomaly; // SYN flood etc
} ml_pid_buffer_t;

ml_pid_buffer_t *ml_buf_get(uint32_t pid, uint64_t ts_ns);
void ml_buf_update(ml_pid_buffer_t *buf, const struct qks_event_msg *ev);