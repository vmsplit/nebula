/**
 * @file nebula.h
 * @brief core implant defs & ctx structs
 * @date 2025-12-12
 *
 * primary header
 */


#ifndef _NEBULA_H
#define _NEBULA_H


#include "ntypes.h"
#include "nelf.h"
#include "nsyscall.h"
#include "nhash.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * version
 * ───────────────────────────────────────────────────────────────────────────── */


#define NEBULA_VERSION_MAJOR    1
#define NEBULA_VERSION_MINOR    0
#define NEBULA_VERSION_PATCH    0

#define NEBULA_VERSION          ((NEBULA_VERSION_MAJOR << 16) | \
                                 (NEBULA_VERSION_MINOR << 8)  | \
                                 (NEBULA_VERSION_PATCH))


/* ─────────────────────────────────────────────────────────────────────────────
 * sect markers
 * ───────────────────────────────────────────────────────────────────────────── */


extern u8 __start[];
extern u8 __end[];


/* ─────────────────────────────────────────────────────────────────────────────
 * func types
 * ───────────────────────────────────────────────────────────────────────────── */


typedef i64   (*fn_write_t)    (i32, const void *, size_t);
typedef i64   (*fn_read_t)     (i32, void *, size_t);
typedef void *(*fn_mmap_t)     (void *, size_t, i32, i32, i32, i64);
typedef i32   (*fn_mprotect_t) (void *, size_t, i32);
typedef i32   (*fn_munmap_t)   (void *, size_t);
typedef void  (*fn_exit_t)     (i32) __noreturn;


/* ─────────────────────────────────────────────────────────────────────────────
 * module info
 * ───────────────────────────────────────────────────────────────────────────── */


#define MAX_MODULES     32
#define MAX_PATH_LEN    128


/**
 * struct _nebula_mod : loaded mod info
 */
typedef struct _nebula_mod
{
    uptr    base;
    uptr    end;
    u32     hash;
    u8      perms;
    char    path[MAX_PATH_LEN];
} nebula_mod_t;


/* ─────────────────────────────────────────────────────────────────────────────
 * cpu info
 * ───────────────────────────────────────────────────────────────────────────── */


/**
 * struct _nebula_cpu : aarch64 cpu featurs
 */
typedef struct _nebula_cpu
{
    u64     midr;
    u64     revidr;
    u64     id_aa64pfr0;
    u64     id_aa64isar0;
    u64     id_aa64mmfr0;
    u8      impl;
    u8      variant;
    u16     part;
    u8      rev;
} nebula_cpu_t;


/* ─────────────────────────────────────────────────────────────────────────────
 * runtime ctx
 * ───────────────────────────────────────────────────────────────────────────── */


/**
 * struct _nebula_libc : resolved libc funct ptrs
 */
typedef struct _nebula_libc
{
    uptr            base;
    fn_write_t      write;
    fn_read_t       read;
    fn_mmap_t       mmap;
    fn_mprotect_t   mprotect;
    fn_munmap_t     munmap;
    fn_exit_t       exit;
} nebula_libc_t;


/**
 * struct _nebula_self : shellcode self-info
 */
typedef struct _nebula_self
{
    uptr    base;
    size_t  size;
    u32     crc;
} nebula_self_t;


/**
 * struct _nebula_proc : proc info
 */
typedef struct _nebula_proc
{
    i32     pid;
    i32     ppid;
    i32     uid;
    i32     gid;
    char    comm[16];
} nebula_proc_t;


/**
 * struct _nebula_ctx : implant runtime ctx
 */
typedef struct _nebula_ctx
{
    nebula_self_t   self;
    nebula_proc_t   proc;
    nebula_cpu_t    cpu;
    nebula_libc_t   libc;
    nebula_mod_t    mods[MAX_MODULES];
    u32             mod_cnt;
    bool            ready;
} nebula_ctx_t;


/* ─────────────────────────────────────────────────────────────────────────────
 * core API
 * ───────────────────────────────────────────────────────────────────────────── */


/**
 * nebula_init() : initialise implant ctx
 * @ctx:  ctx to initialise
 * @base: load shellcode addr
 *
 * Return: true on success
 */
bool nebula_init(nebula_ctx_t *ctx, uptr base);


/**
 * nebula_exec() : exec implant payload
 * @ctx: initialised ctx
 */
void nebula_exec(nebula_ctx_t *ctx);


/**
 * nebula_entry() : c entrypoint from asm stub
 * @base: shellcode base addr
 * @arg:  opt arg from loader
 */
void nebula_entry(uptr base, void *arg);


/* ─────────────────────────────────────────────────────────────────────────────
 * resolution API
 * ───────────────────────────────────────────────────────────────────────────── */


/**
 * resolve_mod() : find loaded mod by name hash
 * @hash:  djb2 hash of mod fname
 *
 * Return: mod base addr or 0
 */
uptr resolve_mod(u32 hash);


/**
 * resolve_sym() : resolve sym from mod
 * @base: mod base addr
 * @hash: djb2 hash of sym name
 *
 * Return: sym addr or 0
 */
uptr resolve_sym(uptr base, u32 hash);


/* ─────────────────────────────────────────────────────────────────────────────
 * utility API
 * ───────────────────────────────────────────────────────────────────────────── */


/**
 * crc32() : hashing util
 * @data: data to hash
 * @len: len of data
 *
 * Return: hash
 */
u32 crc32(const void *data, size_t len);


#endif /* _NEBULA_H */
