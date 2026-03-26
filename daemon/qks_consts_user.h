#pragma once

/* Event types */
#define QKS_EVENT_EXEC       1
#define QKS_EVENT_SYSCALL    2
#define QKS_EVENT_PACKET     3
#define QKS_EVENT_DNS        4
#define QKS_EVENT_PACKET_IN  5

/* Syscall subtypes */
/* Keep in sync with kernel */
#define QKS_SC_MEMFD_CREATE  1
#define QKS_SC_MPROTECT_X    2
#define QKS_SC_MMAP_X        3
#define QKS_SC_PRIV_CHANGE   4
#define QKS_SC_CLONE_FAMILY  5
#define QKS_SC_UNSHARE       6
#define QKS_SC_SETNS         7