// SPDX-License-Identifier: GPL-2.0
#pragma once
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/stdbool.h>

/* Ask if an outbound packet should be dropped. 
 * Provide (pid, dst_ip host-order, dst_port host-order, proto).
 */
bool qks_drop_should_block(u32 pid, u32 ip, u16 port, u8 proto);
``