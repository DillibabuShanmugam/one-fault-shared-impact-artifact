#!/usr/bin/env python3
# Single-bit (power-of-two mask) fault campaign on Vortex SimX with concrete DFA recovery on the resulting traces.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute

import subprocess
import sys
import csv
import re
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SIMX = PROJECT_ROOT / "vortex" / "build" / "sim" / "simx" / "simx"
AES_BIN = Path(__file__).resolve().parent / "aes.bin"
RESULTS_DIR = PROJECT_ROOT / "experiments" / "results"
RESULTS_DIR.mkdir(exist_ok=True, parents=True)

DIAG_TO_COL = {
    frozenset({0, 7, 10, 13}): 0,
    frozenset({1, 4, 11, 14}): 1,
    frozenset({2, 5, 8, 15}):  2,
    frozenset({3, 6, 9, 12}):  3,
}


def run(instr=-1, mask=0, timeout=15):
    cmd = [str(SIMX)]
    if instr >= 0:
        cmd += ["-i", str(instr), "-x", f"0x{mask:02x}"]
    cmd += [str(AES_BIN)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"done": 0}
    res = {}
    for line in proc.stdout.splitlines():
        if line.startswith("PT="):    res["pt"]  = line[3:].strip()
        elif line.startswith("KEY="): res["key"] = line[4:].strip()
        elif line.startswith("CT="):  res["ct"]  = line[3:].strip()
        elif line.startswith("DONE="): res["done"] = int(line[5:].strip())
    return res


def main():
    if not SIMX.exists() or not AES_BIN.exists():
        print("ERROR: build simx and aes.bin first", file=sys.stderr); sys.exit(1)

    print("=== Golden Run ===")
    golden = run()
    if golden.get("done") != 1:
        print(f"FATAL: golden failed: {golden}"); sys.exit(1)
    print(f"  CT = {golden['ct']}")
    g_bytes = bytes.fromhex(golden["ct"])

    # Single-bit masks only
    masks = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]

    # Sweep round-9 window
    instrs = list(range(3700, 4011, 4))  # 78 instructions

    print(f"\n=== Single-bit Sweep ({len(instrs)} instr * {len(masks)} masks "
          f"= {len(instrs) * len(masks)} runs) ===")
    rows = []
    rows.append({
        "trial": "golden", "instr": -1, "mask": 0,
        "golden_ct": golden["ct"], "faulty_ct": golden["ct"],
        "diff_count": 0, "diff_positions": "", "dfa_column": -1,
    })

    t0 = time.time()
    n_dfa = 0
    for instr in instrs:
        for mask in masks:
            r = run(instr=instr, mask=mask)
            if r.get("done") != 1:
                continue
            f_bytes = bytes.fromhex(r["ct"])
            dpos = [i for i in range(16) if g_bytes[i] != f_bytes[i]]
            dc = len(dpos)
            col = -1
            if dc == 4:
                col = DIAG_TO_COL.get(frozenset(dpos), -1)
                if col >= 0:
                    n_dfa += 1
            rows.append({
                "trial": f"i{instr}_m{mask:02x}",
                "instr": instr, "mask": mask,
                "golden_ct": golden["ct"], "faulty_ct": r["ct"],
                "diff_count": dc,
                "diff_positions": ",".join(str(p) for p in dpos),
                "dfa_column": col,
            })
    elapsed = time.time() - t0

    csv_path = RESULTS_DIR / "real_singlebit_campaign.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\nSaved {len(rows)} rows to {csv_path}")

    # Statistics
    from collections import Counter
    diff_dist = Counter(r["diff_count"] for r in rows[1:])
    col_dist = Counter(r["dfa_column"] for r in rows[1:] if r["dfa_column"] >= 0)
    print(f"\nDiff-count distribution: {dict(diff_dist)}")
    print(f"DFA column distribution (single-bit only): {dict(col_dist)}")
    print(f"Total round-9 4-byte diagonals: {n_dfa}")
    print(f"Wall-clock time: {elapsed:.1f}s")

    # Run DFA solver
    print("\n=== Running concrete DFA solver on single-bit traces ===")
    sys.path.insert(0, str(PROJECT_ROOT))
    from smt_attack.dfa_solver import recover_key
    from aes_kernel.aes128 import key_expansion, get_round_key

    pairs_by_col = {0: [], 1: [], 2: [], 3: []}
    for r in rows[1:]:
        if r["dfa_column"] < 0:
            continue
        g = list(bytes.fromhex(r["golden_ct"]))
        f = list(bytes.fromhex(r["faulty_ct"]))
        pairs_by_col[r["dfa_column"]].append((g, f))

    print("Per-column single-bit pair counts:")
    for c in range(4):
        print(f"  col {c}: {len(pairs_by_col[c])}")

    nist_key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]

    for n_per in [1, 2, 3, 4, 5]:
        subset = []
        for c in range(4):
            subset.extend(pairs_by_col[c][:n_per])
        if not subset:
            continue
        t0 = time.time()
        k0_list, _ = recover_key(subset, verbose=False)
        t = time.time() - t0
        found = any(k == nist_key for k in k0_list)
        print(f"  {n_per} pair/col ({len(subset)} total): "
              f"{len(k0_list)} candidates, "
              f"correct={'Y' if found else 'N'}, "
              f"time={t*1000:.1f}ms")

    # Comparison summary
    summary_path = RESULTS_DIR / "singlebit_summary.md"
    with open(summary_path, "w") as f:
        f.write("# Single-Bit Fault Campaign Summary\n\n")
        f.write("Restricted to single-bit XOR masks (powers of two only) "
                "as a more conservative physical fault model than the "
                "arbitrary 8-bit masks of the main campaign.\n\n")
        f.write(f"## Numbers\n")
        f.write(f"- Total runs: {len(rows)-1}\n")
        f.write(f"- Round-9 4-byte diagonal hits: {n_dfa}\n")
        f.write(f"- Diff distribution: {dict(diff_dist)}\n")
        f.write(f"- Column distribution: {dict(col_dist)}\n")
        f.write(f"- Wall time: {elapsed:.1f}s\n\n")
        f.write(f"## Comparison vs multi-bit campaign\n\n")
        f.write(f"- Multi-bit (5 masks: 0xff,0x80,0x55,0x2a,0x01): "
                f"669 round-9 hits across instr 3700..4010\n")
        f.write(f"- Single-bit (8 masks: 0x01..0x80): {n_dfa} round-9 hits\n")
        f.write(f"- The single-bit primitive is strictly more constrained "
                f"and corresponds to the standard CPU DFA bit-flip model "
                f"(Biham-Shamir 1997, Piret 2003).\n")
    print(f"\nSummary written to {summary_path}")


if __name__ == "__main__":
    main()
