/* Linker script for the SIMT amplification kernel on Vortex rtlsim (RAM at 0x80000000, result_buf at 0x8001F000)
   Authors: Dillibabu Shanmugam and Patrick Schaumont
   Affiliation: Worcester Polytechnic Institute */
OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 0x40000  /* 256 KB */
}

SECTIONS
{
    . = 0x80000000;
    .text.init : { KEEP(*(.text.init)) } > RAM
    .text      : { *(.text*) } > RAM
    .rodata    : { *(.rodata*) } > RAM
    .data      : ALIGN(16) { *(.data*) } > RAM
    .sdata     : { *(.sdata*) } > RAM
    .result_buf 0x8001F000 : { KEEP(*(.result_buf)) } > RAM
    .bss       : { *(.bss*) *(COMMON) } > RAM
    _stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
