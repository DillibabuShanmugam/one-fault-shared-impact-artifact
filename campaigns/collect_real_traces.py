#!/usr/bin/env python3
# Collect golden/faulty AES-128 ciphertext pairs from Vortex SimX using memory-mapped round-9 fault injection.
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


def parse_simx_output(output: str) -> dict:
    """Parse PT/KEY/CT/DONE lines from SimX output."""
    result = {}
    for line in output.splitlines():
        if line.startswith("PT="):
            result["pt"] = line[3:].strip()
        elif line.startswith("KEY="):
            result["key"] = line[4:].strip()
        elif line.startswith("CT="):
            result["ct"] = line[3:].strip()
        elif line.startswith("DONE="):
            result["done"] = int(line[5:].strip())
    return result


def run_simx(plaintext_hex: str = None, key_hex: str = None,
             fault_round: int = 0, fault_byte: int = 0,
             fault_value: int = 0, num_warps: int = 4, num_threads: int = 4,
             timeout: int = 60) -> dict:
    """Run SimX with given parameters, return parsed PT/KEY/CT; SimX has issues with -w 1 -t 1, defaults are 4x4."""
    cmd = [str(SIMX)]
    if num_warps != 4 or num_threads != 4:
        cmd += ["-c", "1", "-w", str(num_warps), "-t", str(num_threads)]
    if fault_round > 0:
        cmd += ["-r", str(fault_round), "-b", str(fault_byte),
                "-x", f"0x{fault_value:02x}"]
    if plaintext_hex:
        cmd += ["-P", plaintext_hex]
    if key_hex:
        cmd += ["-K", key_hex]
    cmd += [str(AES_BIN)]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return parse_simx_output(proc.stdout)
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}


def main():
    parser = argparse.ArgumentParser(description="Collect real DFA traces from Vortex SimX")
    parser.add_argument("--num-faults", type=int, default=20,
                        help="Number of fault injections per column (default 20)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=str, default="real_simx_traces.csv")
    parser.add_argument("--num-warps", type=int, default=1)
    parser.add_argument("--num-threads", type=int, default=1)
    args = parser.parse_args()

    if not AES_BIN.exists():
        print(f"ERROR: {AES_BIN} not found. Run 'make' in simx_aes/ first.", file=sys.stderr)
        sys.exit(1)

    if not SIMX.exists():
        print(f"ERROR: {SIMX} not found.", file=sys.stderr)
        sys.exit(1)

    rng = random.Random(args.seed)

    # NIST AES-128 key
    nist_key = "2b7e151628aed2a6abf7158809cf4f3c"

    # Step 1: collect golden ciphertext (no fault)
    print(f"=== Collecting golden ciphertext ===")
    golden = run_simx(key_hex=nist_key)
    if "error" in golden or golden.get("done") != 1:
        print(f"ERROR: golden run failed: {golden}", file=sys.stderr)
        sys.exit(1)
    print(f"  Golden CT: {golden['ct']}")

    # Step 2: fault campaign on row 0 of each column (bytes 0, 4, 8, 12 -> DFA columns 0..3)
    print(f"\n=== Fault Campaign ({args.num_faults} faults/column) ===")

    rows = []
    rows.append({
        "trial": "golden",
        "fault_round": 0,
        "fault_byte": -1,
        "fault_value": 0,
        "plaintext": golden["pt"],
        "key": golden["key"],
        "golden_ct": golden["ct"],
        "faulty_ct": golden["ct"],
        "diff_count": 0,
        "diff_positions": "",
    })

    col_to_byte = {0: 0, 1: 4, 2: 8, 3: 12}

    for col in range(4):
        for trial in range(args.num_faults):
            fb = col_to_byte[col]
            fv = rng.randint(1, 255)
            faulty = run_simx(key_hex=nist_key, fault_round=9,
                              fault_byte=fb, fault_value=fv)
            if "error" in faulty or faulty.get("done") != 1:
                print(f"  WARN: fault trial col={col} #{trial} failed: {faulty}")
                continue

            g_bytes = bytes.fromhex(golden["ct"])
            f_bytes = bytes.fromhex(faulty["ct"])
            diff_pos = [i for i in range(16) if g_bytes[i] != f_bytes[i]]

            rows.append({
                "trial": f"col{col}_t{trial}",
                "fault_round": 9,
                "fault_byte": fb,
                "fault_value": fv,
                "plaintext": faulty["pt"],
                "key": faulty["key"],
                "golden_ct": golden["ct"],
                "faulty_ct": faulty["ct"],
                "diff_count": len(diff_pos),
                "diff_positions": ",".join(str(p) for p in diff_pos),
            })
            print(f"  col{col} trial{trial}: byte={fb} xor=0x{fv:02x} "
                  f"diff={len(diff_pos)} bytes at {diff_pos}")

    # Save CSV
    out_path = Path(args.output)
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n=== Saved {len(rows)-1} fault pairs to {out_path} ===")
    print(f"All traces from REAL Vortex SimX execution (not Python simulation).")


if __name__ == "__main__":
    main()
