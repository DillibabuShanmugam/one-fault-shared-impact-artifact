#!/usr/bin/env python3
# Recompute every Table II value of the paper from the packaged trace sets and print PASS/FAIL per row.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute
import csv, os, re, sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
T = os.path.join(HERE, "traces")
results = []


def check(row, got, want, ok=None):
    ok = (got == want) if ok is None else ok
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {row:<52} recomputed={got!s:<18} paper={want}")


def rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def col_like(r, *keys):
    """Return the value of the first column whose name contains any key."""
    for k in r:
        kl = k.lower()
        if any(x in kl for x in keys):
            return r[k]
    raise KeyError(keys)


# AES 20-seed recovery ----------------------------------------------------
ms = rows(os.path.join(T, "aes_recovery", "multiseed_recovery.csv"))
by = {int(r["per_col"]): r for r in ms}
r1, r2 = by[1], by[2]
check("AES, 1 pair/column (4): unique key, 20 seeds",
      f"{r1['seeds_success']}/{r1['seeds_total']}", "0/20")
check("AES, 2 pairs/column (8): unique key, 20 seeds",
      f"{r2['seeds_success']}/{r2['seeds_total']}", "20/20")
mean, std = float(r2["solve_mean_ms"]), float(r2["solve_std_ms"])
check("AES, 8 pairs: solve time mean +/- std (ms)",
      f"{mean:.1f} +/- {std:.1f}", "43.0 +/- 6.9",
      ok=(round(mean, 1) == 43.0 and round(std, 1) == 6.9))

# AES multi-key -------------------------------------------------------------
mk = rows(os.path.join(T, "aes_recovery", "real_simx_multikey.csv"))[0]
check("AES, 20 random keys: recovered from 8 pairs",
      f"{mk['successes']}/{mk['n_keys']}", "19/20")

# Single-bit (first row is the golden no-fault baseline: trial="golden", mask=0) ---
sb = [r for r in rows(os.path.join(T, "singlebit", "real_singlebit_campaign.csv"))
      if r["trial"] != "golden"]
diag = sum(1 for r in sb if int(r["diff_count"]) == 4)
check("AES, single-bit faults: 4-byte diagonals of 593 (golden row skipped)",
      f"{diag} of {len(sb)}", "531 of 593", ok=(diag == 531 and len(sb) == 593))

# Round selectivity ---------------------------------------------------------
ac = rows(os.path.join(T, "round_selectivity", "real_arch_campaign.csv"))
region_key = list(ac[0].keys())[0]
r9 = [r for r in ac if "9" in r[region_key]]
r10 = [r for r in ac if "10" in r[region_key]]
d9 = Counter(int(col_like(r, "diff_count", "ndiff", "diff")) for r in r9)
d10 = Counter(int(col_like(r, "diff_count", "ndiff", "diff")) for r in r10)
check("Round selectivity: differing bytes, round 9 / round 10",
      f"{sorted(d9)} / {sorted(d10)} over {len(r9)}+{len(r10)}={len(r9)+len(r10)} sites",
      "4 / 1 over 1054 sites",
      ok=(set(d9) == {4} and set(d10) == {1} and len(r9) + len(r10) == 1054))

# SIMT amplification --------------------------------------------------------
st = rows(os.path.join(T, "simt", "real_simt_campaign.csv"))[1:]  # skip golden
alllane = []
usable = nfired = 0
for r in st:
    nf = int(r["n_fired"]); nfired += nf
    dc = [int(r[f"diff_count_{i}"]) for i in range(4)]
    cc = [int(r[f"col_{i}"]) for i in range(4)]
    usable += sum(1 for d in dc if d == 4)
    if nf == 4 and all(d == 4 for d in dc):
        alllane.append(cc)
single_col = sum(1 for cc in alllane if len(set(cc)) == 1)
check("SIMT, 4-lane kernel: all-lane fires of 200",
      f"{len(alllane)} of {len(st)}", "46 of 200",
      ok=(len(alllane) == 46 and len(st) == 200))
check("SIMT: all-lane fires with all four lanes in ONE column",
      f"{single_col} of {len(alllane)}", "46 of 46 (hence 4 injections, one per column)",
      ok=(single_col == len(alllane) == 46))
check("SIMT: mean lanes struck per injection",
      f"{nfired/len(st):.2f}", "3.24", ok=(round(nfired / len(st), 2) == 3.24))
check("SIMT: mean DFA-usable diagonals per injection",
      f"{usable/len(st):.2f}", "about 1 (0.97)", ok=(round(usable / len(st), 2) == 0.97))
check("SIMT: column of the 46 all-lane fires (cols 0..3)",
      [sum(1 for cc in alllane if cc[0] == c) for c in range(4)], [10, 9, 13, 14])

# RTL ----------------------------------------------------------------------
raw = open(os.path.join(T, "rtl", "faulty_run_raw.txt")).read()
lanes = re.findall(r"lane\s+(\d)\s+ACTIVE\s+0x([0-9a-f]+)\s*->\s*0x([0-9a-f]+)", raw)
flipped = sum(1 for _, a, b in lanes if int(a, 16) ^ int(b, 16) == 0xFF)
check("SIMT, Verilator RTL: lanes corrupted by one fault (test kernel)",
      f"{flipped}/{len(lanes)} active lanes XORed with 0xFF", "4/4",
      ok=(flipped == 4 and len(lanes) == 4))

# Ascon --------------------------------------------------------------------
asc = rows(os.path.join(T, "ascon", "real_ascon_campaign.csv"))
eff = sum(1 for r in asc if int(r["diff_count"]) > 0)
check("Ascon: injections (rows minus golden) / tag changed",
      f"{len(asc)-1} / {eff}", "1066 / 778", ok=(len(asc) - 1 == 1066 and eff == 778))

# Ascon modeled recovery (solver/ascon/ascon_key_recovery.py outputs) -----
SA = os.path.join(HERE, "solver", "ascon")
mf = {int(r["masks_per_col"]): r for r in rows(os.path.join(SA, "ascon_minfaults.csv"))}
k1_at = next(int(r["faults_per_key"]) for m, r in sorted(mf.items())
             if float(r["k1_success_rate"]) == 100.0)
full_at = next(int(r["faults_per_key"]) for m, r in sorted(mf.items())
               if float(r["full_success_rate"]) == 100.0)
k1_only_at_128 = float(mf[2]["k1_success_rate"]) == 100.0 and float(mf[2]["full_success_rate"]) == 0.0
check("Ascon, tag only (modeled): faults for K1, full key still 0% there",
      f"K1 at {k1_at} faults (full {mf[2]['full_success_rate']}%)", "128",
      ok=(k1_at == 128 and k1_only_at_128))
check("Ascon, tag + capacity word (modeled): faults for full key",
      f"full key at {full_at} faults", "192", ok=(full_at == 192))
rr = rows(os.path.join(SA, "ascon_recovery_results.csv"))
okk = sum(1 for r in rr if r["success"] == "1" and r["faults_used"] == "192")
check("Ascon (modeled): full key on 20 random keys at 192 faults",
      f"{okk}/{len(rr)}", "20/20", ok=(okk == 20 and len(rr) == 20))
# DFA-usable structural class: one-bit = tag differential of Hamming weight 1; sparse = 2..6 differing tag bytes (disjoint)
def hw(r):
    a, b = bytes.fromhex(r["golden_tag"]), bytes.fromhex(r["faulty_tag"])
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))
effrows = [r for r in asc if int(r["diff_count"]) > 0]
onebit = [r for r in effrows if hw(r) == 1]
sparse = [r for r in effrows if 2 <= int(r["diff_count"]) <= 6]
pats = len(set(r["diff_positions"] for r in sparse))
check("Ascon: one-bit tag differentials (Hamming weight 1)", len(onebit), 163)
check("Ascon: sparse multi-byte differentials (2..6 bytes)", len(sparse), 240)
check("Ascon: distinct positional patterns among the sparse class", pats, 54)
check("Ascon: DFA-usable = one-bit + sparse / remaining diffuse",
      f"{len(onebit)+len(sparse)} / {len(effrows)-len(onebit)-len(sparse)}", "403 / 375",
      ok=(len(onebit) + len(sparse) == 403 and len(effrows) - len(onebit) - len(sparse) == 375))
print("INFO  The 128 / 192 / 20-of-20 rows are a modeled last-round-fault analysis on the"
      " script's own Ascon model (tag only leaves 2^64 candidates for K0). The SimX CSV"
      " lacks lane/column labels and cannot drive that recovery directly; regenerate the"
      " modeled rows with `ascon_key_recovery.py --only minfaults` and `--only multikey`.")

n = len(results)
print(f"\n{sum(results)}/{n} checks passed")
sys.exit(0 if all(results) else 1)
