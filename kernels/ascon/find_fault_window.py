#!/usr/bin/env python3
# Sweep instruction counts on Vortex SimX to find the Ascon final-permutation fault window.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute

import subprocess, re, sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
SIMX = PROJECT / "vortex" / "build" / "sim" / "simx" / "simx"
BIN = Path(__file__).resolve().parent / "ascon.bin"


def run(instr=-1, mask=0):
    cmd = [str(SIMX)]
    if instr >= 0:
        cmd += ["-i", str(instr), "-x", f"0x{mask:02x}"]
    cmd += [str(BIN)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return None
    res = {}
    for line in p.stdout.splitlines():
        if line.startswith("CT="):
            res["tag"] = line[3:].strip()
        elif line.startswith("DONE="):
            res["done"] = int(line[5:].strip())
    return res


def main():
    print("Golden run:")
    g = run()
    if not g or g.get("done") != 1:
        print(f"  failed: {g}"); sys.exit(1)
    print(f"  tag = {g['tag']}")
    g_bytes = bytes.fromhex(g["tag"])

    # Sweep 2000..4040 step 50 to find rough fault region
    print(f"\nCoarse sweep (mask=0x80, step=50):")
    n_diff_dist = {}
    candidates = []
    for ic in range(2000, 4040, 50):
        r = run(instr=ic, mask=0x80)
        if not r or r.get("done") != 1:
            continue
        f_bytes = bytes.fromhex(r["tag"])
        diff = sum(1 for i in range(16) if g_bytes[i] != f_bytes[i])
        n_diff_dist[diff] = n_diff_dist.get(diff, 0) + 1
        if 1 <= diff <= 8:
            candidates.append((ic, diff))
            print(f"  instr={ic}: diff={diff} bytes")
    print(f"\n  diff distribution: {n_diff_dist}")
    print(f"  candidates with diff in [1,8]: {len(candidates)}")
    if candidates:
        print(f"  range: {candidates[0][0]}..{candidates[-1][0]}")


if __name__ == "__main__":
    main()
