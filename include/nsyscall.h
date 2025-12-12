/**
 * @file nsyscall.h
 * @brief aarch64 linux syscall interface
 * @date 2025-12-12
 *
 * inlined syscall stub s for position-independent exec
 */


#ifndef _NEBULA_SYSCALL_H
#define _NEBULA_SYSCALL_H


#include "ntypes.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * syscall nums
 * ───────────────────────────────────────────────────────────────────────────── */


#define __NR_read               63
#define __NR_write              64
#define __NR_openat             56
#define __NR_close              57
#define __NR_mmap               222
#define __NR_mprotect           226
#define __NR_munmap             215
#define __NR_exit               93
#define __NR_exit_group         94
#define __NR_getpid             172


/* ─────────────────────────────────────────────────────────────────────────────
 * constants
 * ───────────────────────────────────────────────────────────────────────────── */


#define AT_FDCWD                (-100)
#define O_RDONLY                0

#define PROT_READ               0x1
#define PROT_WRITE              0x2
#define PROT_EXEC               0x4

#define MAP_PRIVATE             0x02
#define MAP_ANONYMOUS           0x20
#define MAP_FAILED              ((void *)-1)

#define STDIN_FILENO            0
#define STDOUT_FILENO           1
#define STDERR_FILENO           2


/* ─────────────────────────────────────────────────────────────────────────────
 * syscall macros
 * ───────────────────────────────────────────────────────────────────────────── */


#define _syscall0(nr) ({                          \
    register i64 _x0 __asm__("x0");               \
    register i64 _x8 __asm__("x8") = (nr);        \
    __asm__ __volatile__(                         \
        "svc #0"                                  \
        : "=r"(_x0)                               \
        : "r" (_x8)                               \
        : "memory"                                \
    );                                            \
    _x0;                                          \
})
#define _syscall1(nr, a0) ({                      \
    register i64 _x0 __asm__("x0") = (i64)(a0);   \
    register i64 _x8 __asm__("x8") = (nr);        \
    __asm__ __volatile__(                         \
        "svc #0"                                  \
        : "+r"(_x0)                               \
        : "r" (_x8)                               \
        : "memory"                                \
    );                                            \
    _x0;                                          \
})
#define _syscall2(nr, a0, a1) ({                  \
    register i64 _x0 __asm__("x0") = (i64)(a0);   \
    register i64 _x1 __asm__("x1") = (i64)(a1);   \
    register i64 _x8 __asm__("x8") = (nr);        \
    __asm__ __volatile__(                         \
        "svc #0"                                  \
        : "+r"(_x0)                               \
        : "r" (_x1), "r"(_x8)                     \
        : "memory"                                \
    );                                            \
    _x0;                                          \
})
#define _syscall3(nr, a0, a1, a2) ({              \
    register i64 _x0 __asm__("x0") = (i64)(a0);   \
    register i64 _x1 __asm__("x1") = (i64)(a1);   \
    register i64 _x2 __asm__("x2") = (i64)(a2);   \
    register i64 _x8 __asm__("x8") = (nr);        \
    __asm__ __volatile__(                         \
        "svc #0"                                  \
        : "+r"(_x0)                               \
        : "r" (_x1), "r"(_x2), "r"(_x8)           \
        : "memory"                                \
    );                                            \
    _x0;                                          \
})
#define _syscall6(nr, a0, a1, a2, a3, a4, a5) ({  \
    register i64 _x0 __asm__("x0") = (i64)(a0);   \
    register i64 _x1 __asm__("x1") = (i64)(a1);   \
    register i64 _x2 __asm__("x2") = (i64)(a2);   \
    register i64 _x3 __asm__("x3") = (i64)(a3);   \
    register i64 _x4 __asm__("x4") = (i64)(a4);   \
    register i64 _x5 __asm__("x5") = (i64)(a5);   \
    register i64 _x8 __asm__("x8") = (nr);        \
    __asm__ __volatile__(                         \
        "svc #0"                                  \
        : "+r"(_x0)                               \
        : "r"(_x1), "r"(_x2), "r"(_x3),           \
          "r"(_x4), "r"(_x5), "r"(_x8)            \
        : "memory"                                \
    );                                            \
    _x0;                                          \
})


/* ─────────────────────────────────────────────────────────────────────────────
 * syscall wrappers
 * ───────────────────────────────────────────────────────────────────────────── */


static __always_inline i64 sys_read(i32 fd, void *buf, size_t len)
{
    return _syscall3(__NR_read, fd, buf, len);
}

static __always_inline i64 sys_write(i32 fd, const void *buf, size_t len)
{
    return _syscall3(__NR_write, fd, buf, len);
}

static __always_inline i64 sys_openat(i32 dfd, const char *path, i32 flags)
{
    return _syscall3(__NR_openat, dfd, path, flags);
}

static __always_inline i64 sys_close(i32 fd)
{
    return _syscall1(__NR_close, fd);
}

static __always_inline void *sys_mmap(void *addr, size_t len, i32 prot,
                                    i32 flags, i32 fd, i64 off)
{
    return (void *)_syscall6(__NR_mmap, addr, len, prot, flags, fd, off);
}

static __always_inline i32 sys_mprotect(void *addr, size_t len, i32 prot)
{
    return (i32)_syscall3(__NR_mprotect, addr, len, prot);
}

static __always_inline i32 sys_munmap(void *addr, size_t len)
{
    return (i32)_syscall2(__NR_munmap, addr, len);
}

static __always_inline i32 sys_getpid(void)
{
    return (i32)_syscall0(__NR_getpid);
}

static __always_inline __noreturn void sys_exit(i32 code)
{
    _syscall1(__NR_exit_group, code);
    unreachable();
}


#endif /* _NEBULA_SYSCALL_H */
