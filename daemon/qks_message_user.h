#pragma once
#include <stdint.h>

/*
 * User-space mirror of kernel struct qks_event_msg.
 */

typedef struct qks_event_msg {
    uint8_t  schema_version;
    uint8_t  event_type;
    uint16_t reserved0;

    uint64_t event_id;
    uint64_t timestamp_ns;

    /* EXEC fields */
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    char     exec_path[256];

    /* PACKET fields */
    uint32_t packet_src_ip;
    uint32_t packet_dst_ip;
    uint16_t packet_src_port;
    uint16_t packet_dst_port;
    uint8_t  packet_protocol;
    uint8_t  reserved1;
    uint16_t packet_len;

    /* PACKET process info */
    uint32_t pkt_pid;
    uint32_t pkt_uid;
    char     pkt_exec_path[256];

    /* DNS fields */
    char     dns_qname[256];
    uint16_t dns_qtype;
    uint16_t dns_reserved;

    /* SYSCALL fields */
    uint32_t sc_nr;
    uint32_t sc_subtype;
    uint64_t sc_addr;
    uint64_t sc_len;
    uint64_t sc_flags;
    uint32_t sc_prot;
    uint32_t sc_arg0_u32;
    uint32_t sc_arg1_u32;
    uint32_t sc_arg2_u32;
    char     sc_str[64];
} qks_event_msg;