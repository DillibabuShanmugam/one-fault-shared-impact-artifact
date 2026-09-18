#!/usr/bin/env python3
# Collect architectural register-writeback fault traces from Vortex SimX and sweep for DFA-effective instruction counts.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute

import subprocess
import sys
import os
import csv
import argparse
import random
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SIMX = PROJECT_ROOT / "vortex" / "build" / "sim" / "simx" / "simx"
AES_BIN = Path(__file__).resolve().parent / "aes.bin"


def run_simx_arch(instr_count: int = -1, fault_mask: int = 0,
                  warp: int = -1, thread: int = -1, rd: int = -1,
                  timeout: int = 30) -> dict:
    """Run AES on SimX with architectural fault at instruction `instr_count`."""
    cmd = [str(SIMX)]
    if instr_count >= 0:
        cmd += ["-i", str(instr_count), "-x", f"0x{fault_mask:02x}"]
        if warp >= 0:   cmd += ["-W", str(warp)]
        if thread >= 0: cmd += ["-T", str(thread)]
        if rd >= 0:     cmd += ["-R", str(rd)]
    cmd += [str(AES_BIN)]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"done": 0, "stderr": "timeout", "pt": "", "key": "", "ct": ""}
    result = {"stderr": proc.stderr}
    for line in proc.stdout.splitlines():
        if line.startswith("PT="):  result["pt"]  = line[3:].strip()
        elif line.startswith("KEY="): result["key"] = line[4:].strip()
        elif line.startswith("CT="):  result["ct"]  = line[3:].strip()
        elif line.startswith("DONE="): result["done"] = int(line[5:].strip())
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Collect architectural fault traces from real Vortex SimX")
    parser.add_argument("--scan-start", type=int, default=3500,
                        help="First instruction count to test")
    parser.add_argument("--scan-end", type=int, default=4400,
                        help="Last instruction count to test")
    parser.add_argument("--scan-step", type=int, default=10)
    parser.add_argument("--fault-mask", type=lambda x: int(x, 0), default=0xff)
    parser.add_argument("--multi-mask", action="store_true",
                        help="Sweep multiple fault masks for diversity")
    parser.add_argument("--output", type=str, default="real_arch_traces.csv")
    args = parser.parse_args()

    if not AES_BIN.exists():
        print(f"ERROR: {AES_BIN} not found", file=sys.stderr); sys.exit(1)
    if not SIMX.exists():
        print(f"ERROR: {SIMX} not found", file=sys.stderr); sys.exit(1)

    # 1) Golden run
    print("=== Golden Run ===")
    golden = run_simx_arch()
    if golden.get("done") != 1:
        print(f"Golden failed: {golden}"); sys.exit(1)
    print(f"  PT  = {golden['pt']}")
    print(f"  KEY = {golden['key']}")
    print(f"  CT  = {golden['ct']}")
    g_bytes = bytes.fromhex(golden["ct"])

    # 2) Sweep instruction counts to find DFA-effective faults
    print(f"\n=== Architectural Fault Sweep ===")
    print(f"Range: instr {args.scan_start}..{args.scan_end} step {args.scan_step}")
    print(f"Fault mask: 0x{args.fault_mask:02x}")

    rows = []
    rows.append({
        "trial": "golden", "instr_count": -1, "fault_mask": 0,
        "warp": -1, "thread": -1, "fault_done": 1,
        "plaintext": golden["pt"], "key": golden["key"],
        "golden_ct": golden["ct"], "faulty_ct": golden["ct"],
        "diff_count": 0, "diff_positions": "",
    })

    fault_results = []  # list of (instr_count, diff_count, diff_pos, faulty_ct)
    for ic in range(args.scan_start, args.scan_end + 1, args.scan_step):
        r = run_simx_arch(instr_count=ic, fault_mask=args.fault_mask)
        if r.get("done") != 1:
            continue
        f_bytes = bytes.fromhex(r["ct"])
        diff_pos = [i for i in range(16) if g_bytes[i] != f_bytes[i]]
        dc = len(diff_pos)
        fault_done = "fault_done=yes" in r.get("stderr", "")
        fault_results.append((ic, dc, diff_pos, r["ct"], fault_done))

        if dc > 0:
            print(f"  instr={ic}: diff={dc} bytes at {diff_pos}  "
                  f"({'FI' if fault_done else 'no-FI'})")

        rows.append({
            "trial": f"i{ic}", "instr_count": ic, "fault_mask": args.fault_mask,
            "warp": -1, "thread": -1, "fault_done": int(fault_done),
            "plaintext": r["pt"], "key": r["key"],
            "golden_ct": golden["ct"], "faulty_ct": r["ct"],
            "diff_count": dc, "diff_positions": ",".join(str(p) for p in diff_pos),
        })

    # 3) Statistics
    diff4_pairs = [r for r in fault_results if r[1] == 4]
    print(f"\n=== Summary ===")
    print(f"Tested {len(fault_results)} instruction counts")
    print(f"  No effect (diff=0): {sum(1 for r in fault_results if r[1] == 0)}")
    print(f"  Single byte (diff=1): {sum(1 for r in fault_results if r[1] == 1)}")
    print(f"  Round-9 single-fault pattern (diff=4): {len(diff4_pairs)}")
    print(f"  Multi-byte (diff>4): {sum(1 for r in fault_results if r[1] > 4)}")

    # 4) SIMT scoping demonstration
    print(f"\n=== SIMT Scoping Test ===")
    if diff4_pairs:
        target_ic = diff4_pairs[0][0]
        print(f"Using instruction {target_ic} (gives 4-byte DFA pattern)")
        for w in [-1, 0, 1, 2, 3]:
            for t in [-1, 0]:
                r = run_simx_arch(instr_count=target_ic,
                                  fault_mask=args.fault_mask,
                                  warp=w, thread=t)
                if r.get("done") != 1:
                    continue
                f_bytes = bytes.fromhex(r["ct"])
                dc = sum(1 for i in range(16) if g_bytes[i] != f_bytes[i])
                fdone = "yes" in r.get("stderr", "") and "fault_done=yes" in r.get("stderr", "")
                print(f"  warp={w:2d} thread={t:2d}: diff={dc} fault_done={fdone}")

                rows.append({
                    "trial": f"simt_w{w}_t{t}", "instr_count": target_ic,
                    "fault_mask": args.fault_mask,
                    "warp": w, "thread": t, "fault_done": int(fdone),
                    "plaintext": r["pt"], "key": r["key"],
                    "golden_ct": golden["ct"], "faulty_ct": r["ct"],
                    "diff_count": dc,
                    "diff_positions": ",".join(str(i) for i in range(16) if g_bytes[i] != f_bytes[i]),
                })

    # 5) Save
    out_path = Path(args.output)
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"\n=== Saved {len(rows)} rows to {out_path} ===")
    print(f"All faults injected in SimX execute pipeline (real architectural FI).")


if __name__ == "__main__":
    main()
