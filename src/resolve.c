/**
 * @file resolve.c
 * @brief runtime elf sym res
 * @date 2025-12-12
 *
 * locate loaded mods via /proc/self/maps & resolves
 * syms by walking elf dynamic sect
 */


#include "../include/nebula.h"


#define MAPS_PATH               "/proc/self/maps"
#define MAPS_BUFSZ              4096
#define MAX_ENTRIES             64


static const u8 _elf_magic[] = { 0x7f, 'E', 'L', 'F' };


/* ─────────────────────────────────────────────────────────────────────────────
 * internal helpers
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
    const elf64_ehdr_t *e = (const elf64_ehdr_t *)  base;
    const elf64_phdr_t *p = (const elf64_phdr_t *) (base + e->e_phoff);

    for (u32 i = 0; i < e->e_phnum && i < ITER_MAX; i++)
    {
        if (p[i].p_type == PT_DYNAMIC)
            return (elf64_dyn_t *)(base + p[i].p_vaddr);
    }

    return NULL;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * public API
 * ───────────────────────────────────────────────────────────────────────────── */


uptr resolve_mod(u32 hash)
{
    char buf[MAPS_BUFSZ];
    i64 fd, n;
    const char *line;
    u32 cnt = 0;

    fd = sys_openat(AT_FDCWD, MAPS_PATH, O_RDONLY);
    if (fd < 0)
        return 0;

    n = sys_read((i32) fd, buf, sizeof(buf) - 1);
    sys_close((i32) fd);

    if (n <= 0)
        return 0;

    buf[n] = '\0';
    line = buf;

    while (*line && cnt++ < MAX_ENTRIES)
    {
        uptr base = _hex2u64(line, 16);
        const char *path = line;

        while (*path && *path != '\n' && *path != '/')
            path++;

        if (*path == '/')
        {
            const char *name = path;
            const char *p = path;

            while (*p && *p != '\n')
            {
                if (*p == '/')
                    name = p + 1;
                p++;
            }

            size_t len = 0;
            for (const char *q = name; *q && *q != '\n'; q++)
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
    elf64_dyn_t *dyn;
    elf64_sym_t *symtab = NULL;
    const char *strtab = NULL;
    u64 strsz = 0;
    u32 cnt = 0;

    if (!base || !hash || !_is_elf(base))
        return 0;

    dyn = _find_dyn(base);
    if (!dyn)
        return 0;

    while (dyn->d_tag != DT_NULL && cnt++ < ITER_MAX)
    {
        switch (dyn->d_tag)
        {
        case DT_SYMTAB:
            symtab = (elf64_sym_t *) dyn->d_un.d_ptr;
            break;
        case DT_STRTAB:
            strtab = (const char *)  dyn->d_un.d_ptr;
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
