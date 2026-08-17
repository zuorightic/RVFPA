OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x20000000, LENGTH = 512K
    RAM   (rwx) : ORIGIN = 0x80000000, LENGTH = 256K
}

SECTIONS
{
    .text : ALIGN(16)
    {
        KEEP(*(.text.startup))
        *(.text .text.*)
        . = ALIGN(16);
    } > FLASH

    .rodata : ALIGN(16)
    {
        *(.srodata .srodata.*)
        *(.rodata .rodata.*)
        . = ALIGN(16);
    } > FLASH

    .data : ALIGN(16)
    {
        __data_start = .;
        *(.sdata .sdata.*)
        *(.data .data.*)
        . = ALIGN(16);
        __data_end = .;
    } > RAM AT > FLASH
    __data_load = LOADADDR(.data);

    .bss (NOLOAD) : ALIGN(16)
    {
        __bss_start = .;
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    } > RAM

    .noinit (NOLOAD) : ALIGN(16)
    {
        *(.noinit .noinit.*)
    } > RAM

    __global_pointer$ = __data_start + 0x800;
    __heap_start = ALIGN(16);
    __stack_top = ORIGIN(RAM) + LENGTH(RAM);
    __heap_end = __stack_top - 16K;

    /DISCARD/ :
    {
        *(.eh_frame .eh_frame.*)
        *(.comment)
    }
}
