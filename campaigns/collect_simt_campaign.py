#!/usr/bin/env python3
# Multi-lane SIMT fault campaign on Vortex SimX: records how many lanes each injected fault corrupts and the per-lane diff pattern.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute

import subprocess
import sys
import csv
import argparse
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SIMX = PROJECT_ROOT / "vortex" / "build" / "sim" / "simx" / "simx"
AES_BIN = Path(__file__).resolve().parent / "aes_simt.bin"
RESULT_BUF_ADDR = "0x80008080"

NUM_LANES = 4

# Detect DFA column from CT diff positions (matches dfa_solver.py)
DIAG_TO_COL = {
    frozenset({0, 7, 10, 13}): 0,
    frozenset({1, 4, 11, 14}): 1,
    frozenset({2, 5, 8, 15}):  2,
    frozenset({3, 6, 9, 12}):  3,
}


def run_simx(instr=-1, mask=0, timeout=15):
    cmd = [str(SIMX), "-S", "-A", RESULT_BUF_ADDR]
    if instr >= 0:
        cmd += ["-i", str(instr), "-x", f"0x{mask:02x}", "-V"]
    cmd += [str(AES_BIN)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    res = {"cts": ["", "", "", ""], "fired_lanes": []}
    for line in proc.stdout.splitlines():
        m = re.match(r"CT(\d+)=(.+)", line)
        if m:
            res["cts"][int(m.group(1))] = m.group(2).strip()
    # Parse stderr for [FI] lines to find which lanes fired
    for line in proc.stderr.splitlines():
        m = re.match(r"\[FI\] winstr#\d+ wid=\d+ tid=(\d+)", line)
        if m:
            res["fired_lanes"].append(int(m.group(1)))
    return res


def detect_col(diff_positions):
    return DIAG_TO_COL.get(frozenset(diff_positions))


def main():
    parser = argparse.ArgumentParser(description="Multi-lane SIMT fault campaign")
    parser.add_argument("--start", type=int, default=4500)
    parser.add_argument("--end", type=int, default=5600)
    parser.add_argument("--step", type=int, default=2)
    parser.add_argument("--mask", type=lambda x: int(x, 0), default=0xff)
    parser.add_argument("--output", type=str, default="real_simt_campaign.csv")
    args = parser.parse_args()

    if not SIMX.exists() or not AES_BIN.exists():
        print("ERROR: build aes_simt.bin and SimX first", file=sys.stderr)
        sys.exit(1)

    print(f"Collecting golden run...")
    golden = run_simx()
    if not golden or any(not c for c in golden["cts"]):
        print(f"FATAL: golden failed: {golden}"); sys.exit(1)
    print(f"  CT0={golden['cts'][0]}")
    print(f"  CT1={golden['cts'][1]}")
    print(f"  CT2={golden['cts'][2]}")
    print(f"  CT3={golden['cts'][3]}")

    rows = []
    rows.append({
        "trial": "golden", "instr": -1, "fired_lanes": "",
        "n_fired": 0,
        **{f"ct{i}": golden["cts"][i] for i in range(NUM_LANES)},
        **{f"diff_count_{i}": 0 for i in range(NUM_LANES)},
        **{f"col_{i}": -1 for i in range(NUM_LANES)},
    })

    print(f"\nSweeping instr {args.start}..{args.end} step {args.step}")
    n_4lane = 0
    for ic in range(args.start, args.end + 1, args.step):
        r = run_simx(instr=ic, mask=args.mask)
        if not r:
            continue
        diff_counts = []
        cols = []
        for lane in range(NUM_LANES):
            try:
                g = bytes.fromhex(golden["cts"][lane])
                f = bytes.fromhex(r["cts"][lane])
                if len(f) != 16 or len(g) != 16:
                    diff_counts.append(-1)
                    cols.append(-1)
                    continue
                dpos = [i for i in range(16) if g[i] != f[i]]
                diff_counts.append(len(dpos))
                cols.append(detect_col(dpos) if len(dpos) == 4 else -1)
            except (ValueError, IndexError):
                diff_counts.append(-1)
                cols.append(-1)

        n_fired = len(r["fired_lanes"])
        if n_fired == 4 and all(d == 4 for d in diff_counts):
            n_4lane += 1

        rows.append({
            "trial": f"i{ic}", "instr": ic,
            "fired_lanes": ",".join(str(t) for t in r["fired_lanes"]),
            "n_fired": n_fired,
            **{f"ct{i}": r["cts"][i] for i in range(NUM_LANES)},
            **{f"diff_count_{i}": diff_counts[i] for i in range(NUM_LANES)},
            **{f"col_{i}": cols[i] for i in range(NUM_LANES)},
        })

        if n_fired >= 2:
            print(f"  instr={ic}: fired_lanes={r['fired_lanes']} "
                  f"diff={diff_counts} col={cols}")

    # Save
    out = Path(args.output)
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"\nSaved {len(rows)} rows to {out}")
    print(f"Instructions firing all 4 lanes simultaneously: {n_4lane}")
    print(f"  -> {n_4lane} fault injections each yield 4 correlated DFA pairs")


if __name__ == "__main__":
    main()
