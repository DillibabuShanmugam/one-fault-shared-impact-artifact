# Hand-written SIMT amplification kernel for Vortex rtlsim: four lanes compute 0xA5A50000|tid; the or a5,a5,a0 write-back is the commit-stage fault target
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute
# RISCV_CUSTOM0 = 0x0B (tmc encoding .insn r 0x0B,0,0,x0,<mask>,x0); VX_CSR_THREAD_ID = 0xCC0 (per-lane thread id)

.section .text.init
.globl _start
_start:
    li      a1, 0xF
    .insn r 0x0B, 0, 0, x0, a1, x0      // vx_tmc(0xF): activate 4 lanes -> tmask=1111
    csrr    a0, 0xCC0                    // a0 = thread id (per-lane 0,1,2,3)
    lui     a5, 0xa5a50                  // a5 = 0xA5A50000 (uniform)
    or      a5, a5, a0                   // a5 = 0xA5A50000 | tid  <-- TARGET write-back (rd=15, tmask=1111)
    lui     a2, 0x8001f                  // a2 = 0x8001F000 (RESULT base)
    slli    a3, a0, 2                    // a3 = tid*4
    add     a2, a2, a3                   // a2 = &RESULT[tid]
    sw      a5, 0(a2)                    // RESULT[tid] = a5
    fence                                // ensure the store drains to memory
    .insn r 0x0B, 0, 0, x0, x0, x0      // vx_tmc(x0): deactivate all lanes -> warp/program done
1:  j       1b
