// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/uidgid.h>
#include <linux/uaccess.h>
#include <linux/mman.h>       // PROT_*
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <asm/unistd.h>

#include "qks_message.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("QKS");
MODULE_DESCRIPTION("QKS Exec & Syscall Sensors (memfd/mprotect/mmap/priv/ns)");
MODULE_VERSION("1.1");

extern int qks_send_msg(struct qks_event_msg *msg);

// ---- Event counter (syscalls) ----
static atomic_t qks_sys_evt_id = ATOMIC_INIT(1);

// ---- x86_64 syscall argument mapping (kprobe on __x64_sys_*) ----
#if defined(CONFIG_X86_64)
# define ARG0(regs) ((regs)->di)
# define ARG1(regs) ((regs)->si)
# define ARG2(regs) ((regs)->dx)
# define ARG3(regs) ((regs)->r10)
# define ARG4(regs) ((regs)->r8)
# define ARG5(regs) ((regs)->r9)
#else
# error "This file currently targets x86_64 only. Ask me for ARM64 mappings if needed."
#endif

// ---- Helpers ----
static void qks_fill_common(struct qks_event_msg *m, __u8 subtype, __u32 sc_nr)
{
    memset(m, 0, sizeof(*m));
    m->schema_version = QKS_SCHEMA_V1;
    m->event_type     = QKS_EVENT_SYSCALL;
    m->timestamp_ns   = ktime_get_ns();
    m->event_id       = atomic_inc_return(&qks_sys_evt_id);

    m->pid  = current->pid;
    m->ppid = task_ppid_nr(current);
    m->uid  = __kuid_val(current_uid());

    m->sc_subtype = subtype;
    m->sc_nr      = sc_nr;
}

static void qks_copy_user_str(char *dst, size_t dst_len, const char __user *uptr)
{
    long n = strncpy_from_user(dst, uptr, dst_len - 1);
    if (n < 0) {
        dst[0] = '\0';
    } else {
        dst[dst_len - 1] = '\0';
    }
}

static struct kprobe kp_execve   = { .symbol_name = "__x64_sys_execve"   };
static struct kprobe kp_execveat = { .symbol_name = "__x64_sys_execveat" };

static int handler_pre_exec(struct kprobe *p, struct pt_regs *regs)
{
    char buf[512];
    struct mm_struct *mm = current->mm;
    struct qks_event_msg msg;

    if (!mm || !mm->exe_file) {
        memset(&msg, 0, sizeof(msg));
        msg.schema_version = QKS_SCHEMA_V1;
        msg.event_type     = QKS_EVENT_EXEC;
        msg.timestamp_ns   = ktime_get_ns();
        msg.event_id       = atomic_inc_return(&qks_sys_evt_id);
        msg.pid            = current->pid;
        msg.ppid           = task_ppid_nr(current);
        msg.uid            = __kuid_val(current_uid());
        msg.exec_path[0]   = '\0';
        qks_send_msg(&msg);
        return 0;
    }

    {
        char *path = d_path(&mm->exe_file->f_path, buf, sizeof(buf));
        memset(&msg, 0, sizeof(msg));
        msg.schema_version = QKS_SCHEMA_V1;
        msg.event_type     = QKS_EVENT_EXEC;
        msg.timestamp_ns   = ktime_get_ns();
        msg.event_id       = atomic_inc_return(&qks_sys_evt_id);
        msg.pid            = current->pid;
        msg.ppid           = task_ppid_nr(current);
        msg.uid            = __kuid_val(current_uid());

        if (!IS_ERR(path))
            strscpy(msg.exec_path, path, sizeof(msg.exec_path));

        qks_send_msg(&msg);
    }

    return 0;
}

// ---- 1) memfd_create(name, flags) ----
static struct kprobe kp_memfd_create = { .symbol_name = "__x64_sys_memfd_create" };

static int handler_pre_memfd(struct kprobe *p, struct pt_regs *regs)
{
    struct qks_event_msg msg;
    const char __user *uname = (const char __user *)ARG0(regs);
    __u64 flags = (__u64)ARG1(regs);

    qks_fill_common(&msg, QKS_SC_MEMFD_CREATE, __NR_memfd_create);
    msg.sc_flags = flags;
    if (uname)
        qks_copy_user_str(msg.sc_str, sizeof(msg.sc_str), uname);

    qks_send_msg(&msg);
    return 0;
}

// ---- 2) mprotect(addr, len, prot)  — log only when PROT_EXEC ----
static struct kprobe kp_mprotect = { .symbol_name = "__x64_sys_mprotect" };

static int handler_pre_mprotect(struct kprobe *p, struct pt_regs *regs)
{
    __u64 addr = (__u64)ARG0(regs);
    __u64 len  = (__u64)ARG1(regs);
    __u32 prot = (__u32)ARG2(regs);

    if (!(prot & PROT_EXEC))
        return 0;

    struct qks_event_msg msg;
    qks_fill_common(&msg, QKS_SC_MPROTECT_X, __NR_mprotect);
    msg.sc_addr = addr;
    msg.sc_len  = len;
    msg.sc_prot = prot;

    qks_send_msg(&msg);
    return 0;
}

// ---- 3) mmap(addr, len, prot, flags, fd, off) — log only when PROT_EXEC ----
static struct kprobe kp_mmap = { .symbol_name = "__x64_sys_mmap" };

static int handler_pre_mmap(struct kprobe *p, struct pt_regs *regs)
{
    __u64 addr  = (__u64)ARG0(regs);
    __u64 len   = (__u64)ARG1(regs);
    __u32 prot  = (__u32)ARG2(regs);
    __u64 flags = (__u64)ARG3(regs);
    // (__u64)ARG4(regs) fd; (__u64)ARG5(regs) off

    if (!(prot & PROT_EXEC))
        return 0;

    struct qks_event_msg msg;
    qks_fill_common(&msg, QKS_SC_MMAP_X, __NR_mmap);
    msg.sc_addr  = addr;
    msg.sc_len   = len;
    msg.sc_prot  = prot;
    msg.sc_flags = flags;

    qks_send_msg(&msg);
    return 0;
}

// ---- 4) Priv/identity changes: setuid/setgid/setres* + capset ----
static struct kprobe kp_setuid     = { .symbol_name = "__x64_sys_setuid" };
static struct kprobe kp_setgid     = { .symbol_name = "__x64_sys_setgid" };
static struct kprobe kp_setresuid  = { .symbol_name = "__x64_sys_setresuid" };
static struct kprobe kp_setresgid  = { .symbol_name = "__x64_sys_setresgid" };
static struct kprobe kp_capset     = { .symbol_name = "__x64_sys_capset" };

static int handler_pre_setuid(struct kprobe *p, struct pt_regs *regs)
{
    struct qks_event_msg msg;
    qks_fill_common(&msg, QKS_SC_PRIV_CHANGE, __NR_setuid);
    msg.sc_arg0_u32 = (__u32)ARG0(regs); // new uid
    qks_send_msg(&msg);
    return 0;
}
static int handler_pre_setgid(struct kprobe *p, struct pt_regs *regs)
{
    struct qks_event_msg msg;
    qks_fill_common(&msg, QKS_SC_PRIV_CHANGE, __NR_setgid);
    msg.sc_arg0_u32 = (__u32)ARG0(regs); // new gid
    qks_send_msg(&msg);
    return 0;
}
static int handler_pre_setresuid(struct kprobe *p, struct pt_regs *regs)
{
    struct qks_event_msg msg;
    qks_fill_common(&msg, QKS_SC_PRIV_CHANGE, __NR_setresuid);
    msg.sc_arg0_u32 = (__u32)ARG0(regs); // ruid
    msg.sc_arg1_u32 = (__u32)ARG1(regs); // euid
    msg.sc_arg2_u32 = (__u32)ARG2(regs); // suid
    qks_send_msg(&msg);
    return 0;
}
static int handler_pre_setresgid(struct kprobe *p, struct pt_regs *regs)
{
    struct qks_event_msg msg;
    qks_fill_common(&msg, QKS_SC_PRIV_CHANGE, __NR_setresgid);
    msg.sc_arg0_u32 = (__u32)ARG0(regs); // rgid
    msg.sc_arg1_u32 = (__u32)ARG1(regs); // egid
    msg.sc_arg2_u32 = (__u32)ARG2(regs); // sgid
    qks_send_msg(&msg);
    return 0;
}
static int handler_pre_capset(struct kprobe *p, struct pt_regs *regs)
{
    struct qks_event_msg msg;
    qks_fill_common(&msg, QKS_SC_PRIV_CHANGE, __NR_capset);
    qks_send_msg(&msg);
    return 0;
}

// ---- 5) Namespaces / process creation: clone/clone3/unshare/setns ----
static struct kprobe kp_clone   = { .symbol_name = "__x64_sys_clone" };
static struct kprobe kp_clone3  = { .symbol_name = "__x64_sys_clone3" };
static struct kprobe kp_unshare = { .symbol_name = "__x64_sys_unshare" };
static struct kprobe kp_setns   = { .symbol_name = "__x64_sys_setns" };

static int handler_pre_clone(struct kprobe *p, struct pt_regs *regs)
{
    struct qks_event_msg msg;
    __u64 flags = (__u64)ARG0(regs);

    qks_fill_common(&msg, QKS_SC_CLONE_FAMILY, __NR_clone);
    msg.sc_flags = flags;
    qks_send_msg(&msg);
    return 0;
}

static int handler_pre_clone3(struct kprobe *p, struct pt_regs *regs)
{
    struct qks_event_msg msg;
    __u64 __user *uargs = (__u64 __user *)ARG0(regs);
    __u64 size = (__u64)ARG1(regs);
    __u64 flags = 0;

    if (uargs && size >= sizeof(__u64)) {
        if (copy_from_user(&flags, uargs, sizeof(__u64)))
            flags = 0;
    }

    qks_fill_common(&msg, QKS_SC_CLONE_FAMILY, __NR_clone3);
    msg.sc_flags    = flags;
    msg.sc_arg0_u32 = (size > 0xFFFFFFFFULL) ? 0xFFFFFFFFU : (unsigned int)size; // low 32
    qks_send_msg(&msg);
    return 0;
}

static int handler_pre_unshare(struct kprobe *p, struct pt_regs *regs)
{
    struct qks_event_msg msg;
    __u64 flags = (__u64)ARG0(regs);

    qks_fill_common(&msg, QKS_SC_UNSHARE, __NR_unshare);
    msg.sc_flags = flags;
    qks_send_msg(&msg);
    return 0;
}

static int handler_pre_setns(struct kprobe *p, struct pt_regs *regs)
{
    struct qks_event_msg msg;
    __u32 fd     = (__u32)ARG0(regs);
    __u32 nstype = (__u32)ARG1(regs);

    qks_fill_common(&msg, QKS_SC_SETNS, __NR_setns);
    msg.sc_arg0_u32 = fd;
    msg.sc_arg1_u32 = nstype;
    qks_send_msg(&msg);
    return 0;
}

// ---- Module init/exit: register all hooks ----
int qks_syscalls_init(void)
{
    int ret;

    // execve / execveat
    kp_execve.pre_handler   = handler_pre_exec;
    kp_execveat.pre_handler = handler_pre_exec;

    if ((ret = register_kprobe(&kp_execve))   != 0) return ret;
    (void)register_kprobe(&kp_execveat);

    // memfd_create
    kp_memfd_create.pre_handler = handler_pre_memfd;
    if ((ret = register_kprobe(&kp_memfd_create)) != 0) goto fail;

    // mprotect (PROT_EXEC)
    kp_mprotect.pre_handler = handler_pre_mprotect;
    if ((ret = register_kprobe(&kp_mprotect)) != 0) goto fail;

    // mmap (PROT_EXEC)
    kp_mmap.pre_handler = handler_pre_mmap;
    if ((ret = register_kprobe(&kp_mmap)) != 0) goto fail;

    // priv/identity
    kp_setuid.pre_handler    = handler_pre_setuid;
    kp_setgid.pre_handler    = handler_pre_setgid;
    kp_setresuid.pre_handler = handler_pre_setresuid;
    kp_setresgid.pre_handler = handler_pre_setresgid;
    kp_capset.pre_handler    = handler_pre_capset;

    if ((ret = register_kprobe(&kp_setuid))    != 0) goto fail;
    if ((ret = register_kprobe(&kp_setgid))    != 0) goto fail;
    if ((ret = register_kprobe(&kp_setresuid)) != 0) goto fail;
    if ((ret = register_kprobe(&kp_setresgid)) != 0) goto fail;
    (void)register_kprobe(&kp_capset);

    // ns/process
    kp_clone.pre_handler   = handler_pre_clone;
    kp_clone3.pre_handler  = handler_pre_clone3;
    kp_unshare.pre_handler = handler_pre_unshare;
    kp_setns.pre_handler   = handler_pre_setns;

    if ((ret = register_kprobe(&kp_clone))   != 0) goto fail;
    (void)register_kprobe(&kp_clone3);
    if ((ret = register_kprobe(&kp_unshare)) != 0) goto fail;
    if ((ret = register_kprobe(&kp_setns))   != 0) goto fail;

    return 0;

fail:
    qks_log("[QKS] Failed to register a syscall kprobe: %d\n", ret);
    return ret;
}

void qks_syscalls_exit(void)
{
    // Unregister everything
    unregister_kprobe(&kp_execve);
    unregister_kprobe(&kp_execveat);

    unregister_kprobe(&kp_memfd_create);
    unregister_kprobe(&kp_mprotect);
    unregister_kprobe(&kp_mmap);

    unregister_kprobe(&kp_setuid);
    unregister_kprobe(&kp_setgid);
    unregister_kprobe(&kp_setresuid);
    unregister_kprobe(&kp_setresgid);
    unregister_kprobe(&kp_capset);

    unregister_kprobe(&kp_clone);
    unregister_kprobe(&kp_clone3);
    unregister_kprobe(&kp_unshare);
    unregister_kprobe(&kp_setns);
}