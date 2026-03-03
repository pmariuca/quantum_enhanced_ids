#pragma once
#include <linux/types.h>
#include <linux/printk.h>

/* Exported function for all QKS modules to log */
void qks_log(const char *fmt, ...);

/* Initialization and cleanup */
int  qks_log_init(void);
void qks_log_exit(void);