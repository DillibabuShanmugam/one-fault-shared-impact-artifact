# Bare-metal startup for Vortex SimX: entry at STARTUP_ADDR 0x80000000, set sp/gp, call main, exit via ebreak
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute
.section .text.init
.globl _start
_start:
    // Set up stack pointer (top of memory area)
    li      sp, 0x80020000
    li      gp, 0x80010000
    // Clear all general purpose registers
    li      x1, 0
    li      x5, 0
    li      x6, 0
    li      x7, 0
    li      x28, 0
    li      x29, 0
    li      x30, 0
    li      x31, 0
    // Call main
    call    main
    // Vortex SimX exits when ebreak is executed (deactivates warps)
1:  ebreak
    j       1b
