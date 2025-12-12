/**
 * @file ntypes.h
 * @brief type defs for position-independent code
 * @date 2025-12-12
 *
 * core primitive types, compiler attribs,  & static analysis hints
 * for aarch64 linux shellcoding
 */


#ifndef _NEBULA_TYPES_H
#define _NEBULA_TYPES_H


/* ─────────────────────────────────────────────────────────────────────────────
 * prim types
 * ───────────────────────────────────────────────────────────────────────────── */


typedef unsigned char           u8;
typedef unsigned short          u16;
typedef unsigned int            u32;
typedef unsigned long long      u64;

typedef signed char             i8;
typedef signed short            i16;
typedef signed int              i32;
typedef signed long long        i64;

typedef u64                     uptr;
typedef i64                     iptr;
typedef u64                     size_t;

typedef _Bool                   bool;
#define true                    ((bool)1)
#define false                   ((bool)0)
#define NULL                    ((void *)0)


/* ─────────────────────────────────────────────────────────────────────────────
 * compiler attribs
 * ───────────────────────────────────────────────────────────────────────────── */


#define __packed                __attribute__((packed))
#define __aligned(x)            __attribute__((aligned(x)))
#define __section(s)            __attribute__((section(s)))
#define __used                  __attribute__((used))
#define __unused                __attribute__((unused))
#define __noinline              __attribute__((noinline))
#define __always_inline         __attribute__((always_inline)) inline
#define __noreturn              __attribute__((noreturn))
#define __visible               __attribute__((externally_visible, used))
#define __hidden                __attribute__((visibility("hidden")))


/* ─────────────────────────────────────────────────────────────────────────────
 * static analysis
 * ───────────────────────────────────────────────────────────────────────────── */


#define likely(x)               __builtin_expect(!!(x), 1)
#define unlikely(x)             __builtin_expect(!!(x), 0)
#define unreachable()           __builtin_unreachable()

#define ARRAY_SIZE(a)           (sizeof(a) / sizeof((a)[0]))
#define ALIGN(x, a)             (((x) + ((a) - 1)) & ~((a) - 1))

#define offsetof(type, member)  __builtin_offsetof(type, member)


/* ─────────────────────────────────────────────────────────────────────────────
 * bound & assert
 * ───────────────────────────────────────────────────────────────────────────── */


#define ITER_MAX                4096
#define ASSERT(c)               do { if (unlikely(!(c))) __builtin_trap(); } while (0)


/* ─────────────────────────────────────────────────────────────────────────────
 * mem barrier
 * ───────────────────────────────────────────────────────────────────────────── */


#define barrier()               __asm__ __volatile__("" : :: "memory")


#endif /* _NEBULA_TYPES_H */
