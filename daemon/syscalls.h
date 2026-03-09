#ifndef QKS_SYSCALLS_H
#define QKS_SYSCALLS_H

// Minimal syscall table
static const char *linux_syscalls[] = {
    [9] = "mmap",
    [10] = "mprotect",
    [56] = "clone",
    [59]  = "execve",
    [105] = "setuid",
    [106] = "setgid",
    [117] = "setresuid",
    [119] = "setresgid",
    [319] = "memfd_create",
    [126] = "capset",
    [272] = "unshare",
    [308] = "setns",
    [322] = "execveat",
    [435] = "clone3", 
};

static inline const char *syscall_name_or_unknown(uint32_t nr) {
    if (nr < sizeof(linux_syscalls) / sizeof(linux_syscalls[0])
        && linux_syscalls[nr])
        return linux_syscalls[nr];
    return "unknown_syscall";
}

#endif