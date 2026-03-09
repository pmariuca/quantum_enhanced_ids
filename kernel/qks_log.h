#pragma once
#include <linux/types.h>
#include <linux/printk.h>
#include "qks_message.h"

/* Exported function for all QKS modules to log */
void qks_log(const char *fmt, ...);
void qks_dump_event(const struct qks_event_msg *m);

/* Initialization and cleanup */
int  qks_log_init(void);
void qks_log_exit(void);