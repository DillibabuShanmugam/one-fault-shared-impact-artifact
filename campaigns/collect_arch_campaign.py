#!/usr/bin/env python3
# Architectural register-writeback fault campaign on Vortex SimX: round-9, round-10 and SIMT-scoped sweeps.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute

import subprocess
import sys
import os
import csv
import argparse
import random
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SIMX = PROJECT_ROOT / "vortex" / "build" / "sim" / "simx" / "simx"
AES_BIN = Path(__file__).resolve().parent / "aes.bin"


def run_simx(instr=-1, mask=0, warp=-1, thread=-1, rd=-1, timeout=15):
    cmd = [str(SIMX)]
    if instr >= 0:
        cmd += ["-i", str(instr), "-x", f"0x{mask:02x}"]
        if warp   >= 0: cmd += ["-W", str(warp)]
        if thread >= 0: cmd += ["-T", str(thread)]
        if rd     >= 0: cmd += ["-R", str(rd)]
    cmd += [str(AES_BIN)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"done": 0, "stderr": "timeout", "pt": "", "key": "", "ct": ""}
    res = {"stderr": proc.stderr}
    for line in proc.stdout.splitlines():
        if line.startswith("PT="):    res["pt"]  = line[3:].strip()
        elif line.startswith("KEY="): res["key"] = line[4:].strip()
        elif line.startswith("CT="):  res["ct"]  = line[3:].strip()
        elif line.startswith("DONE="): res["done"] = int(line[5:].strip())
    return res


def diff_info(golden_hex, faulty_hex):
    g = bytes.fromhex(golden_hex); f = bytes.fromhex(faulty_hex)
    pos = [i for i in range(16) if g[i] != f[i]]
    return len(pos), pos


def run_golden():
    g = run_simx()
    if g.get("done") != 1:
        print(f"FATAL: golden run failed: {g}", file=sys.stderr); sys.exit(1)
    print(f"  Golden CT: {g['ct']}")
    return g


def case1_round9_sweep(golden, args):
    """Case 1: Round-9 fault region - produces 4-byte DFA diagonal pattern."""
    print("\n" + "="*60)
    print("CASE 1: Round-9 architectural fault sweep")
    print("="*60)
    print(f"Range: instr {args.r9_start}..{args.r9_end} step {args.r9_step}")
    print(f"Masks: {args.masks}")

    rows = []
    col_count = defaultdict(int)
    for ic in range(args.r9_start, args.r9_end + 1, args.r9_step):
        for mask in args.masks:
            r = run_simx(instr=ic, mask=mask)
            if r.get("done") != 1:
                continue
            dc, dpos = diff_info(golden["ct"], r["ct"])
            if dc == 4:
                # Determine DFA column from diagonal pattern
                col = _detect_col(dpos)
                if col is not None:
                    col_count[col] += 1
                    rows.append({
                        "case": "round9", "instr": ic, "mask": mask,
                        "warp": -1, "thread": -1,
                        "golden_ct": golden["ct"], "faulty_ct": r["ct"],
                        "diff_count": dc, "diff_positions": ",".join(str(p) for p in dpos),
                        "fault_column": col,
                    })

    print(f"Collected {len(rows)} round-9 DFA pairs")
    print(f"Per-column distribution: {dict(col_count)}")
    return rows


def case2_round10_sweep(golden, args):
    """Case 2: Round-10 fault region - produces 1-byte (no DFA diagonal)."""
    print("\n" + "="*60)
    print("CASE 2: Round-10 architectural fault sweep (NOT DFA-effective)")
    print("="*60)
    print(f"Range: instr {args.r10_start}..{args.r10_end} step {args.r10_step}")

    rows = []
    for ic in range(args.r10_start, args.r10_end + 1, args.r10_step):
        for mask in args.masks:
            r = run_simx(instr=ic, mask=mask)
            if r.get("done") != 1:
                continue
            dc, dpos = diff_info(golden["ct"], r["ct"])
            if 0 < dc <= 2:
                rows.append({
                    "case": "round10", "instr": ic, "mask": mask,
                    "warp": -1, "thread": -1,
                    "golden_ct": golden["ct"], "faulty_ct": r["ct"],
                    "diff_count": dc, "diff_positions": ",".join(str(p) for p in dpos),
                    "fault_column": -1,
                })
    print(f"Collected {len(rows)} round-10 single-byte faults (cannot mount DFA)")
    return rows


def case3_simt_scoping(golden, args, instr_pool):
    """Case 3: SIMT scoping - vary (warp, thread) targets."""
    print("\n" + "="*60)
    print("CASE 3: SIMT fault scoping (warp/thread targeted)")
    print("="*60)
    if not instr_pool:
        print("No round-9 instructions available for SIMT test")
        return []

    rows = []
    # Test for each warp/thread on a small set of round-9 instructions
    test_instrs = instr_pool[:args.simt_count]
    print(f"Testing {len(test_instrs)} instructions x {args.warps} warps x {args.threads_per_warp} threads")

    for ic in test_instrs:
        for w in range(args.warps):
            for t in range(args.threads_per_warp):
                r = run_simx(instr=ic, mask=0xff, warp=w, thread=t)
                if r.get("done") != 1:
                    continue
                dc, dpos = diff_info(golden["ct"], r["ct"])
                fault_done = "fault_done=yes" in r.get("stderr", "")
                rows.append({
                    "case": "simt", "instr": ic, "mask": 0xff,
                    "warp": w, "thread": t,
                    "golden_ct": golden["ct"], "faulty_ct": r["ct"],
                    "diff_count": dc,
                    "diff_positions": ",".join(str(p) for p in dpos),
                    "fault_column": _detect_col(dpos) if dc == 4 else -1,
                    "fault_done": int(fault_done),
                })

    triggered = sum(1 for r in rows if r.get("fault_done"))
    print(f"Collected {len(rows)} SIMT scoping samples ({triggered} faults triggered)")
    return rows


# DFA column detection (matches dfa_solver.py)
_DIAGS = {
    frozenset({0, 7, 10, 13}): 0,
    frozenset({1, 4, 11, 14}): 1,
    frozenset({2, 5, 8, 15}):  2,
    frozenset({3, 6, 9, 12}):  3,
}
def _detect_col(dpos):
    return _DIAGS.get(frozenset(dpos))


def main():
    parser = argparse.ArgumentParser(
        description="Architectural fault campaign on Vortex SimX")
    parser.add_argument("--r9-start", type=int, default=3700)
    parser.add_argument("--r9-end",   type=int, default=4010)
    parser.add_argument("--r9-step",  type=int, default=2)
    parser.add_argument("--r10-start", type=int, default=4020)
    parser.add_argument("--r10-end",   type=int, default=4400)
    parser.add_argument("--r10-step",  type=int, default=4)
    parser.add_argument("--masks", type=str, default="0xff,0x80,0x55,0x2a,0x01",
                        help="Comma-separated fault masks")
    parser.add_argument("--simt-count", type=int, default=4,
                        help="Number of instructions for SIMT scoping test")
    parser.add_argument("--warps", type=int, default=4)
    parser.add_argument("--threads-per-warp", type=int, default=4)
    parser.add_argument("--output", type=str, default="real_arch_campaign.csv")
    args = parser.parse_args()

    args.masks = [int(m, 0) for m in args.masks.split(",")]

    if not AES_BIN.exists():
        print(f"ERROR: {AES_BIN} not found", file=sys.stderr); sys.exit(1)
    if not SIMX.exists():
        print(f"ERROR: {SIMX} not found", file=sys.stderr); sys.exit(1)

    print("="*60)
    print("ARCHITECTURAL FAULT CAMPAIGN - Vortex SimX")
    print("="*60)
    print(f"SimX:   {SIMX}")
    print(f"AES:    {AES_BIN}")

    print("\n=== Golden Run ===")
    golden = run_golden()

    all_rows = []

    case1_rows = case1_round9_sweep(golden, args)
    all_rows.extend(case1_rows)

    case2_rows = case2_round10_sweep(golden, args)
    all_rows.extend(case2_rows)

    instr_pool = sorted(set(r["instr"] for r in case1_rows))
    case3_rows = case3_simt_scoping(golden, args, instr_pool)
    all_rows.extend(case3_rows)

    # Save
    fields = ["case", "instr", "mask", "warp", "thread",
              "golden_ct", "faulty_ct", "diff_count", "diff_positions",
              "fault_column", "fault_done"]
    out_path = Path(args.output)
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in all_rows:
            r.setdefault("fault_done", 1)
            w.writerow(r)

    print("\n" + "="*60)
    print(f"=== FINAL: {len(all_rows)} total entries -> {out_path} ===")
    print(f"  Case 1 (round-9 DFA): {len(case1_rows)}")
    print(f"  Case 2 (round-10 ineffective): {len(case2_rows)}")
    print(f"  Case 3 (SIMT scoping): {len(case3_rows)}")
    print("="*60)


if __name__ == "__main__":
    main()
