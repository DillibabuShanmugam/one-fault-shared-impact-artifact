# Bare-metal startup for Vortex rtlsim (entry at STARTUP_ADDR 0x80000000) used by the C reference kernel
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute
.section .text.init
.globl _start
_start:
    li      sp, 0x8001C000
    li      gp, 0x80010000
    call    main
1:  ebreak            // Vortex exits when all warps ebreak
    j       1b
