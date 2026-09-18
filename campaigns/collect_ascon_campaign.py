#!/usr/bin/env python3
# Architectural single-bit fault campaign on Ascon-128 running on Vortex SimX.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute

import subprocess, sys, csv, time
from collections import Counter
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
SIMX = PROJECT / "vortex" / "build" / "sim" / "simx" / "simx"
BIN = Path(__file__).resolve().parent / "ascon.bin"
RESULTS_DIR = PROJECT / "experiments" / "results"
RESULTS_DIR.mkdir(exist_ok=True, parents=True)


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
        if line.startswith("CT="): res["tag"] = line[3:].strip()
        elif line.startswith("DONE="): res["done"] = int(line[5:].strip())
    return res


def main():
    if not SIMX.exists() or not BIN.exists():
        print("ERROR: build simx and ascon.bin first", file=sys.stderr); sys.exit(1)

    print("=== Golden Run ===")
    g = run()
    if not g or g.get("done") != 1:
        print(f"FATAL: golden failed: {g}"); sys.exit(1)
    print(f"  tag = {g['tag']}")
    g_bytes = bytes.fromhex(g["tag"])

    masks = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
    instrs = list(range(3500, 4040, 4))

    print(f"\n=== Single-bit Sweep ({len(instrs)} instr * {len(masks)} masks "
          f"= {len(instrs) * len(masks)} runs) ===")
    rows = []
    rows.append({
        "trial": "golden", "instr": -1, "mask": 0,
        "golden_tag": g["tag"], "faulty_tag": g["tag"],
        "diff_count": 0, "diff_positions": "",
    })

    t0 = time.time()
    diff_dist = Counter()
    n_useful = 0
    for instr in instrs:
        for mask in masks:
            r = run(instr=instr, mask=mask)
            if not r or r.get("done") != 1:
                continue
            f_bytes = bytes.fromhex(r["tag"])
            dpos = [i for i in range(16) if g_bytes[i] != f_bytes[i]]
            dc = len(dpos)
            diff_dist[dc] += 1
            if 1 <= dc <= 8:
                n_useful += 1
            rows.append({
                "trial": f"i{instr}_m{mask:02x}",
                "instr": instr, "mask": mask,
                "golden_tag": g["tag"], "faulty_tag": r["tag"],
                "diff_count": dc,
                "diff_positions": ",".join(str(p) for p in dpos),
            })
    elapsed = time.time() - t0

    csv_path = RESULTS_DIR / "real_ascon_campaign.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"\nSaved {len(rows)} rows to {csv_path}")
    print(f"Diff distribution: {dict(sorted(diff_dist.items()))}")
    print(f"Useful (diff in [1,8]): {n_useful}")
    print(f"Wall time: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
