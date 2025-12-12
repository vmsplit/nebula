/**
 * @file ntypes.h
 * @brief DJB2 string hashing for sym resolution
 * @date 2025-12-12
 */


#ifndef _NEBULA_HASH_H
#define _NEBULA_HASH_H


#include "ntypes.h"


#define HASH_FNV1A_SEED     0x811c9dc5u
#define HASH_FNV1A_PRIME    0x01000193u

#define HASH_DJB2_SEED      5381u


/* ─────────────────────────────────────────────────────────────────────────────
 * comp-time fnv1a
 * ───────────────────────────────────────────────────────────────────────────── */


#define _CT_HASH_BYTE(h, b) (((h) ^ (u8)(b)) * HASH_FNV1A_PRIME)

#define H1(s,i,h)  _CT_HASH_BYTE(h,  (s)[i])
#define H2(s,i,h)  H1(s,i, H1(s,(i)  +1,h))
#define H4(s,i,h)  H2(s,i, H2(s,(i)  +2,h))
#define H8(s,i,h)  H4(s,i, H4(s,(i)  +4,h))
#define H16(s,i,h) H8(s,i, H8(s,(i)  +8,h))
#define H32(s,i,h) H16(s,i,H16(s,(i) +16,h))


/**
 * H() : comp-time string hash  (32 char lim)
 * @s: string lit
 *
 * usage: H("libc.o.6")
 */
#define H(s) ((u32)(sizeof(s) > 1  ?  H32(s, 0, HASH_FNV1A_SEED) : HASH_FNV1A_SEED))



/**
 * djb2() : hash null-termed string
 * @s: input string
 *
 * Return:  32-bit hash val
 */
static __always_inline u32 djb2(const char *s)
{
    u32 h = HASH_DJB2_SEED;
    u8 c;

    while ((c = (u8) *s++))
        h = ((h << 5) + h) + c;

    return h;
}



/**
 * djb2n() : hash string with explicit len
 * @s: input buff
 * @n: len bytes
 *
 * Return:  32-bit hash val
 */
static __always_inline u32 djb2n(const char *s, size_t n)
{
    u32 h = HASH_DJB2_SEED;

    for (size_t i = 0; i < n; i++)
        h = ((h << 5) + h) + (u8) s[i];

    return h;
}


/**
 * fnv1a() : runtime fnv1a hash
 * @s: input string
 *
 * Return: 32-bit hash val
 */
static __always_inline u32 fnv1a(const char *s)
{
    u32 h = HASH_FNV1A_SEED;

    while (*s)
        h = (h ^ (u8) *s++) * HASH_FNV1A_PRIME;

    return h;
}


/**
 * fnv1an() : runtime fnv1a with len
 * @s: input buff
 * @n: len bytes
 *
 * Return:  32-bit hash val
 */
static __always_inline u32 fnv1an(const char *s, size_t n)
{
    u32 h = HASH_FNV1A_SEED;

    for (size_t i = 0; i < n; i++)
        h = (h ^ (u8) s[i]) * HASH_FNV1A_PRIME;

    return h;
}


#endif /* _NEBULA_HASH_H */
