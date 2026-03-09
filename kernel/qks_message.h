#ifndef QKS_MESSAGE_H
#define QKS_MESSAGE_H

#include <linux/types.h>

#define QKS_SCHEMA_V1        1

// Event types
#define QKS_EVENT_EXEC       1
#define QKS_EVENT_SYSCALL    2
#define QKS_EVENT_PACKET     3
#define QKS_EVENT_DNS        4

// Netlink attribute blob
#define QKS_ATTR_MSG         1

// ---- SYSCALL subtypes (sc_subtype) ----
#define QKS_SC_MEMFD_CREATE   1
#define QKS_SC_MPROTECT_X     2
#define QKS_SC_MMAP_X         3
#define QKS_SC_PRIV_CHANGE    4   // setuid/setgid/setres*/capset
#define QKS_SC_CLONE_FAMILY   5   // clone / clone3
#define QKS_SC_UNSHARE        6
#define QKS_SC_SETNS          7

struct qks_event_msg {
    __u8  schema_version;
    __u8  event_type;
    __u16 reserved0;

    __u64 event_id;
    __u64 timestamp_ns;

    // EXEC fields
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char  exec_path[256];

    // PACKET fields
    __u32 packet_src_ip;
    __u32 packet_dst_ip;
    __u16 packet_src_port;
    __u16 packet_dst_port;
    __u8  packet_protocol;
    __u8  reserved1;
    __u16 packet_len;

    // PACKET process info
    __u32 pkt_pid;
    __u32 pkt_uid;
    char  pkt_exec_path[256];

    // DNS fields
    char  dns_qname[256];
    __u16 dns_qtype;
    __u16 dns_reserved;

    __u32 sc_nr;
    __u32 sc_subtype;
    __u64 sc_addr;
    __u64 sc_len;
    __u64 sc_flags;
    __u32 sc_prot;
    __u32 sc_arg0_u32;
    __u32 sc_arg1_u32;
    __u32 sc_arg2_u32;
    char  sc_str[64];
};

#endif