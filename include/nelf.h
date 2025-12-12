/**
 * @file nelf.h
 * @brief elf64 struct defs for dynamic res
 * @date 2025-12-12
 *
 * elf structs required for runtime symbol res
 * without glibc dep
 */


#ifndef _NEBULA_ELF_H
#define _NEBULA_ELF_H


/* ─────────────────────────────────────────────────────────────────────────────
 * elf constants
 * ───────────────────────────────────────────────────────────────────────────── */


#define EI_NIDENT               16
#define EI_CLASS                4
#define ELFCLASS64              2

#define PT_NULL                 0
#define PT_LOAD                 1
#define PT_DYNAMIC              2

#define DT_NULL                 0
#define DT_STRTAB               5
#define DT_SYMTAB               6
#define DT_STRSZ                10

#define STT_NOTYPE              0
#define STT_OBJECT              1
#define STT_FUNC                2

#define ELF64_ST_TYPE(i)        ((i) & 0xf)
#define ELF64_ST_BIND(i)        ((i) >> 4)


/* ─────────────────────────────────────────────────────────────────────────────
 * elf structs
 * ───────────────────────────────────────────────────────────────────────────── */

/**
 * struct _elf64_ehdr : elf64 file headr
 */
typedef struct _elf64_ehdr
{
    u8      e_ident[EI_NIDENT];
    u16     e_type;
    u16     e_machine;
    u32     e_version;
    u64     e_entry;
    u64     e_phoff;
    u64     e_shoff;
    u32     e_flags;
    u16     e_ehsize;
    u16     e_phentsize;
    u16     e_phnum;
    u16     e_shentsize;
    u16     e_shnum;
    u16     e_shstrndx;
} __packed elf64_ehdr_t;


/**
 * struct _elf64_phdr : elf64 prog header
 */
typedef struct _elf64_phdr
{
    u32     p_type;
    u32     p_flags;
    u64     p_offset;
    u64     p_vaddr;
    u64     p_paddr;
    u64     p_filesz;
    u64     p_memsz;
    u64     p_align;
} __packed elf64_phdr_t;


/**
 * struct _elf64_dyn : elf64 dynamic sect entry
 */
typedef struct _elf64_dyn
{
    i64     d_tag;
    union
    {
        u64 d_val;
        u64 d_ptr;
    } d_un;
} __packed elf64_dyn_t;


/**
 * struct _elf64_sym : elf64 sym table entry
 */
typedef struct _elf64_sym
{
    u32     st_name;
    u8      st_info;
    u8      st_other;
    u16     st_shndx;
    u64     st_value;
    u64     st_size;
} __packed elf64_sym_t;


#endif /* _NEBULA_ELF_H_ */
