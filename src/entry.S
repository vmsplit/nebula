/**
 * @file entry.S
 * @brief position-independent entry stub for arm64 linux
 * @date 2025-12-12
 *
 * !!! must be linked first to ensure __start is at offset 0
 */


    .section .text.head, "ax", @progbits
    .align 4


/* ─────────────────────────────────────────────────────────────────────────────
 * shellcode boundary
 * ───────────────────────────────────────────────────────────────────────────── */


    .globl __start
    .type __start, @object
__start:


/* ─────────────────────────────────────────────────────────────────────────────
 * entrypoit
 * ───────────────────────────────────────────────────────────────────────────── */


    .globl _start
    .type _start, @function
_start:
    mov     x19, x0
    adr     x20, __start

    mov     x29, sp
    mov     x9, sp
    and     x9, x9, #~0xf
    mov     sp, x9

    mov     x0, x20
    mov     x1, x19
    bl      nebula_entry

    mov     x0, #0
    b       _exit
    .size _start, . - _start


/* ─────────────────────────────────────────────────────────────────────────────
 * exit stub
 * ───────────────────────────────────────────────────────────────────────────── */


    .globl _exit
    .type _exit, @function
_exit:
    mov     x8, #94
    svc     #0
    brk     #0x1
    .size _exit, . - _exit


/* ─────────────────────────────────────────────────────────────────────────────
 * end markr
 * ───────────────────────────────────────────────────────────────────────────── */


    .section .text.tail, "ax", @progbits
    .align 4

    .globl __end
    .type __end, @object
__end:
    .size __end, 0
