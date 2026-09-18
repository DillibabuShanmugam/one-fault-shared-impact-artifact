#!/usr/bin/env python3
# Multi-seed AES DFA recovery on real SimX traces: unique-key success rate and solve time per fault-pair count over 20 seeds.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute
import sys, csv
import numpy as np
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "experiments"))

from run_simx_experiments import collect_simx_pairs
from smt_attack.dfa_solver import solve_k10_decomposed, detect_fault_column
from aes_kernel.aes128 import key_expansion, get_round_key

KEY = "2b7e151628aed2a6abf7158809cf4f3c"
SEEDS = list(range(20))          # 20 independent fault-value draws
PER_COL = [1, 2, 3, 4, 5]        # -> 4, 8, 12, 16, 20 total pairs
SOLVE_REPEATS = 5                # intra-seed timing runs, averaged per seed

key = list(bytes.fromhex(KEY))
k10_expected = get_round_key(key_expansion(key), 10)

# per pair-count: lists across seeds
uniq = {n: [] for n in PER_COL}
tmean = {n: [] for n in PER_COL}
min_pairs_for_unique = []

for si, seed in enumerate(SEEDS):
    pairs, _ = collect_simx_pairs(KEY, n_per_col=25, seed=seed)
    grouped = {0: [], 1: [], 2: [], 3: []}
    for g, f in pairs:
        c = detect_fault_column(g, f)
        if c is not None:
            grouped[c].append((g, f))
    seed_min = None
    for n in PER_COL:
        subset = []
        for col in range(4):
            subset.extend(grouped[col][:n])
        ts = []
        u = False
        for r in range(SOLVE_REPEATS):
            k10_list, st = solve_k10_decomposed(subset, verbose=False)
            ts.append(st * 1000.0)
            if r == 0:
                u = (len(k10_list) == 1 and any(k == k10_expected for k in k10_list))
        uniq[n].append(1 if u else 0)
        tmean[n].append(float(np.mean(ts)))
        if u and seed_min is None:
            seed_min = n
    min_pairs_for_unique.append(seed_min if seed_min is not None else -1)
    print(f"seed {seed:2d}: min per-col for unique = {seed_min}  "
          f"(2/col unique={bool(uniq[2][-1])}, t={tmean[2][-1]:.1f} ms)")

print("\n=== Summary over", len(SEEDS), "seeds ===")
rows = []
for n in PER_COL:
    u = np.array(uniq[n]); t = np.array(tmean[n])
    frac = 100.0 * u.mean()
    rows.append(dict(per_col=n, total_pairs=n * 4,
                     unique_success_pct=round(frac, 1),
                     seeds_success=int(u.sum()), seeds_total=len(SEEDS),
                     solve_mean_ms=round(float(t.mean()), 2),
                     solve_std_ms=round(float(t.std(ddof=1)), 2)))
    print(f"  {n}/col ({n*4:2d} pairs): unique {int(u.sum())}/{len(SEEDS)} "
          f"= {frac:.1f}%   solve {t.mean():.1f} +/- {t.std(ddof=1):.1f} ms")

mn = np.array([m for m in min_pairs_for_unique if m > 0])
print(f"\nMinimum pairs-per-column for unique recovery across seeds: "
      f"mode/mean = {int(np.round(mn.mean()))} (min {mn.min()}, max {mn.max()})")
r2 = next(r for r in rows if r["per_col"] == 2)
print(f"HEADLINE (8 pairs = 2/col): {r2['unique_success_pct']}% unique over "
      f"{len(SEEDS)} seeds, {r2['solve_mean_ms']} +/- {r2['solve_std_ms']} ms")

out = PROJECT_ROOT / "experiments/results/multiseed_recovery.csv"
with open(out, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader(); w.writerows(rows)
print("wrote", out)
