/* Linker script for the bare-metal AES-128 kernel on Vortex SimX (RAM at 0x80000000, fixed fault_ctrl and result_buf sections)
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

    .data : ALIGN(16) { *(.data*) } > RAM
    .sdata : { *(.sdata*) } > RAM

    /* Fault control region at fixed offset */
    .fault_ctrl 0x8001E000 : { KEEP(*(.fault_ctrl)) } > RAM

    /* Result buffer at fixed offset (visible to host SimX) */
    .result_buf 0x8001F000 : { KEEP(*(.result_buf)) } > RAM

    .bss : { *(.bss*) *(COMMON) } > RAM

    /* Stack grows down from end of RAM */
    _stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
