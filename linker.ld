OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

SECTIONS
{
    . = 0;

    .text : {
        *(.text.head)
        *(.text)
        *(.text.*)
        *(.text.tail)
    }

    . = ALIGN(8);

    .rodata : {
        *(.rodata)
        *(.rodata.*)
    }

    . = ALIGN(8);

    .got : { *(.got) }
    .got.plt : { *(.got.plt) }

    . = ALIGN(8);

    .data : {
        *(.data)
        *(.data.*)
    }

    . = ALIGN(8);

    .bss : {
        *(.bss)
        *(.bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
        *(.dynsym)
        *(.dynstr)
        *(.dynamic)
        *(.gnu.*)
        *(.ARM.*)
        *(.interp)
        *(.rela.*)
        *(.plt)
    }
}
