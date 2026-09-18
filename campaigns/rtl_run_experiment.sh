#!/usr/bin/env bash
# Reproduce the RTL commit-stage fault experiment (Table II, "SIMT, Verilator RTL") on a patched Vortex checkout.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute
# Requires VORTEX set to a Vortex checkout (commit in patches/VORTEX_COMMIT.txt) with patches/rtl_commit_fault.patch applied and rtlsim built.
set -euo pipefail

: "${VORTEX:?set VORTEX to a Vortex checkout patched with patches/rtl_commit_fault.patch and built}"
ART=$(cd "$(dirname "$0")/.." && pwd)
BIN=$VORTEX/build/sim/rtlsim/rtlsim
KDIR=$ART/kernels/rtl_amp
KBIN=$KDIR/amp_kernel.bin
OUT=${OUT:-$ART/traces/rtl/rerun}   # archived raw outputs in traces/rtl/ are left untouched
mkdir -p "$OUT"

# 1. Build the four-lane test kernel (per-lane value 0xA5A50000|tid), or use the shipped binary.
make -C "$KDIR"

# 2. Golden run: hook armed for tracing only (mask 0 never injects); enumerates every warp-0 write-back with per-lane data.
"$BIN" "$KBIN" +fi_enable=1 +fi_warp=0 +fi_instr=99999 +fi_mask=00000000 \
    2>&1 | tee "$OUT/golden_enum_raw.txt" | grep -E '\[FI\]|\[RESULT\]'

echo "----------------------------------------------------------------"

# 3. Faulty run: inject once at write-back index 3 ('or a5,a5,a0', tmask=1111), XOR mask 0xFF into every active lane.
"$BIN" "$KBIN" +fi_enable=1 +fi_warp=0 +fi_instr=3 +fi_mask=000000FF \
    2>&1 | tee "$OUT/faulty_run_raw.txt" | grep -E '\[FI\]|\[RESULT\]'
