/* Linker script for the SIMT AES-128 kernel on Vortex SimX (fixed lane_done, fault_ctrl and result_buf sections)
   Authors: Dillibabu Shanmugam and Patrick Schaumont
   Affiliation: Worcester Polytechnic Institute */
OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 0x40000
}

SECTIONS
{
    . = 0x80000000;

    .text.init : { KEEP(*(.text.init)) } > RAM
    .text      : { *(.text*) } > RAM
    .rodata    : { *(.rodata*) } > RAM

    .data : ALIGN(16) { *(.data*) } > RAM
    .sdata : { *(.sdata*) } > RAM

    .lane_done 0x8001D000 : { KEEP(*(.lane_done)) } > RAM
    .fault_ctrl 0x8001E000 : { KEEP(*(.fault_ctrl)) } > RAM
    .result_buf 0x8001F000 : { KEEP(*(.result_buf)) } > RAM

    .bss : { *(.bss*) *(COMMON) } > RAM

    _stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
