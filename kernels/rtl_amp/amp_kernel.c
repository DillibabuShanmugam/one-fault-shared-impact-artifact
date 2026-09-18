// C reference of the SIMT amplification kernel for Vortex rtlsim: four lanes store RESULT[tid] = 0xA5A50000 | tid; the value write-back is the fault target
// Authors: Dillibabu Shanmugam and Patrick Schaumont
// Affiliation: Worcester Polytechnic Institute

#define VX_CSR_THREAD_ID  0xCC0
#define RISCV_CUSTOM0     0x0B

// Result buffer, one 32-bit word per lane, visible to the host after the run.
volatile unsigned* const RESULT = (volatile unsigned*)0x8001F000;

static inline void vx_tmc(int mask) {
    __asm__ volatile (".insn r %0, 0, 0, x0, %1, x0" :: "i"(RISCV_CUSTOM0), "r"(mask));
}

static inline int vx_thread_id(void) {
    int r;
    __asm__ volatile ("csrr %0, %1" : "=r"(r) : "i"(VX_CSR_THREAD_ID));
    return r;
}

int main(void) {
    // Enable 4 threads (lanes) in this warp: tmask = 0b1111.
    vx_tmc(0xF);

    // Per-lane distinct value: the CSR read differs per lane, so the write-back bus carries four words under a full tmask
    int tid = vx_thread_id();
    volatile unsigned val = 0xA5A50000u | (unsigned)tid;   // <-- targeted register write-back

    // Publish to memory so the corruption is observable downstream.
    RESULT[tid] = val;

    // Collapse back to a single lane and exit.
    vx_tmc(0x1);
    return 0;
}
