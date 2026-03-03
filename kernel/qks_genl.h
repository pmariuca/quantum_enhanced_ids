#pragma once

#define QKS_GENL_FAMILY   "QKS_GENL"
#define QKS_GENL_MCGRP    "QKS_MC"
#define QKS_GENL_VERSION  1

/* Commands */
enum qks_cmd {
    QKS_CMD_UNSPEC = 0,
    QKS_CMD_EVENT,    /* kernel -> userspace multicast (struct qks_event_msg) */
    QKS_CMD_VERDICT,  /* userspace -> kernel unicast (struct qks_verdict_msg) */
    __QKS_CMD_MAX,
};
#define QKS_CMD_MAX (__QKS_CMD_MAX - 1)

/* Attributes */
enum qks_attr {
    QKS_ATTR_UNSPEC = 0,
    QKS_ATTR_MSG,       /* struct qks_event_msg   (binary) */
    QKS_ATTR_VERDICT,   /* struct qks_verdict_msg (binary) */
    __QKS_ATTR_MAX,
};
#define QKS_ATTR_MAX (__QKS_ATTR_MAX - 1)

/* Verdict constants */
#define QKS_DENY   0u
#define QKS_ALLOW  1u