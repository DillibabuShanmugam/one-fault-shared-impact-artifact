#!/usr/bin/env python3
# Ascon-128 finalization DFA: last-round single-bit fault model, tag-only K1 recovery, and full-key recovery with one unmasked capacity word.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute

import argparse
import csv
import os
import random
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ascon_ref import ascon_round, ROUND_CONSTANTS, MASK64, rotr, IV, ascon128_tag_empty

# Ascon 5-bit S-box (lane 0 = MSB / bit 4, ... lane 4 = LSB / bit 0)
SBOX = [0x4, 0xb, 0x1f, 0x14, 0x1a, 0x15, 0x9, 0x2,
        0x1b, 0x5, 0x8, 0x12, 0x1d, 0x3, 0x6, 0x1c,
        0x1e, 0x13, 0x7, 0xe, 0x0, 0xd, 0x11, 0x18,
        0x10, 0xc, 0x1, 0x19, 0x16, 0xa, 0xf, 0x17]

# per-lane Linear-layer rotations (from ascon_ref)
ROT = {0: (19, 28), 1: (61, 39), 2: (1, 6), 3: (10, 17), 4: (7, 41)}
RC_LAST = ROUND_CONSTANTS[11]         # constant of the 12th (last) round


def build_ddt():
    ddt = [[0] * 32 for _ in range(32)]
    for x in range(32):
        for d in range(32):
            ddt[d][SBOX[x] ^ SBOX[x ^ d]] += 1
    return ddt


DDT = build_ddt()


# Last-round primitives
def sbox_state(s):
    """Bit-sliced Ascon S-box applied across all 64 columns (no AddRC/Linear)."""
    s = list(s)
    s[0] ^= s[4]; s[4] ^= s[3]; s[2] ^= s[1]
    t = [(~s[i]) & MASK64 for i in range(5)]
    t[0] &= s[1]; t[1] &= s[2]; t[2] &= s[3]; t[3] &= s[4]; t[4] &= s[0]
    s[0] ^= t[1]; s[1] ^= t[2]; s[2] ^= t[3]; s[3] ^= t[4]; s[4] ^= t[0]
    s[1] ^= s[0]; s[0] ^= s[4]; s[3] ^= s[2]; s[2] = (~s[2]) & MASK64
    return s


def linear(s):
    s = list(s)
    for i in range(5):
        r1, r2 = ROT[i]
        s[i] = s[i] ^ rotr(s[i], r1) ^ rotr(s[i], r2)
    return s


def linmat(r1, r2):
    """GF(2) matrix of  x -> x ^ rotr(x,r1) ^ rotr(x,r2)  (bit i = coeff)."""
    M = np.zeros((64, 64), dtype=np.uint8)
    for b in range(64):
        x = 1 << b
        y = (x ^ rotr(x, r1) ^ rotr(x, r2)) & MASK64
        for i in range(64):
            if (y >> i) & 1:
                M[i, b] = 1
    return M


def invmat(M):
    """GF(2) inverse via Gauss-Jordan."""
    n = 64
    A = (M.copy() % 2)
    I = np.eye(n, dtype=np.uint8)
    for c in range(n):
        p = next(r for r in range(c, n) if A[r, c])
        A[[c, p]] = A[[p, c]]; I[[c, p]] = I[[p, c]]
        for r in range(n):
            if r != c and A[r, c]:
                A[r] ^= A[c]; I[r] ^= I[c]
    return I % 2


LINV = {i: invmat(linmat(*ROT[i])) for i in (2, 3, 4)}


def apply_mat(M, val):
    bits = np.array([(val >> i) & 1 for i in range(64)], dtype=np.uint8)
    out = M.dot(bits) % 2
    return sum(int(out[i]) << i for i in range(64))


def col_of(state, j):
    """5-bit S-box column value at bit position j (lane0=MSB)."""
    return sum(((state[L] >> j) & 1) << (4 - L) for L in range(5))


def state_from_cols(cols):
    """Inverse of col_of: build 5 lanes from 64 column values."""
    s = [0, 0, 0, 0, 0]
    for j, x in enumerate(cols):
        for L in range(5):
            s[L] |= ((x >> (4 - L)) & 1) << j
    return s


# Oracle (uses the true key; an attacker only sees its outputs)
class AsconOracle:
    """Produces what a fault attacker observes: the correct tag, faulty tags for single-bit last-round faults, and (full-key mode) S_out[2]."""

    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce
        self.K0 = int.from_bytes(key[0:8], "big")
        self.K1 = int.from_bytes(key[8:16], "big")
        self.U = self._state_entering_last_round()
        self.S_out = linear(sbox_state(self._addrc(self.U)))
        self.T0 = self.S_out[3] ^ self.K0
        self.T1 = self.S_out[4] ^ self.K1
        self.n_faults = 0

    def _addrc(self, U):
        s = list(U)
        s[2] ^= RC_LAST
        return s

    def _state_entering_last_round(self):
        K0, K1 = self.K0, self.K1
        N0 = int.from_bytes(self.nonce[0:8], "big")
        N1 = int.from_bytes(self.nonce[8:16], "big")
        s = [IV, K0, K1, N0, N1]
        for i in range(12):
            s = ascon_round(s, ROUND_CONSTANTS[i])
        s[3] ^= K0; s[4] ^= K1; s[4] ^= 1
        s[0] ^= 0x8000000000000000; s[1] ^= K0; s[2] ^= K1
        for i in range(11):                      # 11 rounds -> input to round 12
            s = ascon_round(s, ROUND_CONSTANTS[i])
        return s

    def golden_tag(self):
        return self.T0.to_bytes(8, "big") + self.T1.to_bytes(8, "big")

    def capacity_word(self):
        """Unmasked S_out[2] (needed only to resolve the K0 half)."""
        return self.S_out[2]

    def faulty_tag(self, lane, col):
        """Inject a single-bit flip at U[lane], bit `col`; return faulty tag."""
        self.n_faults += 1
        Uf = list(self.U)
        Uf[lane] ^= (1 << col)
        Sf = linear(sbox_state(self._addrc(Uf)))
        return (Sf[3] ^ self.K0).to_bytes(8, "big") + (Sf[4] ^ self.K1).to_bytes(8, "big")


# Attacker (sees only tags, fault positions, public layers and nonce)
def _obs_bits(golden_tag, faulty_tag):
    """Return (dy3, dy4): clean per-column S-box output differentials, lanes 3,4."""
    g0 = int.from_bytes(golden_tag[0:8], "big"); g1 = int.from_bytes(golden_tag[8:16], "big")
    f0 = int.from_bytes(faulty_tag[0:8], "big"); f1 = int.from_bytes(faulty_tag[8:16], "big")
    dy3 = apply_mat(LINV[3], g0 ^ f0)
    dy4 = apply_mat(LINV[4], g1 ^ f1)
    return dy3, dy4


def ddt_candidates(e, obs3, obs4):
    return set(x for x in range(32)
               if ((SBOX[x] ^ SBOX[x ^ e]) >> 1) & 1 == obs3
               and (SBOX[x] ^ SBOX[x ^ e]) & 1 == obs4)


def recover_columns(golden_tag, faults):
    """faults: list of (lane, col, faulty_tag); returns per-column candidate sets for the 5-bit S-box input x_j."""
    cand = [set(range(32)) for _ in range(64)]
    for lane, col, ftag in faults:
        e = 1 << (4 - lane)               # column XOR-difference from a U[lane] flip
        dy3, dy4 = _obs_bits(golden_tag, ftag)
        obs3 = (dy3 >> col) & 1
        obs4 = (dy4 >> col) & 1
        cand[col] &= ddt_candidates(e, obs3, obs4)
    return cand


def recover_key(golden_tag, faults, capacity_word=None):
    """Returns dict with recovered K0, K1 (bytes or None) and diagnostics; K1 from the tag alone, K0 needs capacity word S_out[2]."""
    T0 = int.from_bytes(golden_tag[0:8], "big")
    T1 = int.from_bytes(golden_tag[8:16], "big")
    cand = recover_columns(golden_tag, faults)

    # classify columns
    resolved_unique = sum(1 for c in cand if len(c) == 1)
    resolved_pair = sum(1 for c in cand
                        if 1 <= len(c) <= 2 and all((a ^ b) in (0, 4) for a in c for b in c))
    k1_ok_cols = sum(1 for c in cand if c and len({SBOX[x] & 1 for x in c}) == 1)

    # ---- K1: use lane-4 output bit, invariant to the lane-2 ambiguity -------
    K1 = None
    if k1_ok_cols == 64:
        y4 = 0
        for j, c in enumerate(cand):
            y4 |= (SBOX[next(iter(c))] & 1) << j          # bit0 identical over the set
        S3out4 = apply_mat(linmat(*ROT[4]), y4)           # S_out[4] = L4(Y4)
        K1 = (S3out4 ^ T1).to_bytes(8, "big")

    # ---- K0: resolve lane-2 per column using the unmasked capacity word -----
    K0 = None
    resolved = None
    if capacity_word is not None:
        y2 = apply_mat(LINV[2], capacity_word)            # Y2 = L2^{-1}(S_out[2])
        cols = []
        ok = True
        for j, c in enumerate(cand):
            want = (y2 >> j) & 1
            match = [x for x in c if (SBOX[x] >> 2) & 1 == want]
            if len(match) != 1:
                ok = False
                break
            cols.append(match[0])
        if ok:
            resolved = cols
            S_out = linear(sbox_state(state_from_cols(cols)))
            K0 = (S_out[3] ^ T0).to_bytes(8, "big")
            K1 = (S_out[4] ^ T1).to_bytes(8, "big")       # reconfirm K1

    return {
        "K0": K0, "K1": K1,
        "candidates": cand,
        "resolved_unique_cols": resolved_unique,
        "resolved_pair_cols": resolved_pair,
        "k1_resolvable_cols": k1_ok_cols,
        "resolved_state_cols": 0 if resolved is None else len(resolved),
    }


# Fault-campaign helper
def run_campaign(oracle, lanes=(0, 1, 3), cols=range(64)):
    """Inject single-bit faults at the given lanes for every column."""
    golden = oracle.golden_tag()
    faults = []
    for col in cols:
        for lane in lanes:
            faults.append((lane, col, oracle.faulty_tag(lane, col)))
    return golden, faults


# 1. Sanity anchor + modeled-fault validator
def sanity_anchor():
    key = bytes(range(16)); nonce = bytes(range(16))
    tag = ascon128_tag_empty(key, nonce).hex()
    exp = "e355159f292911f794cb1432a0103a8a"
    print(f"[anchor] ascon_ref test vector tag = {tag}")
    print(f"[anchor] expected                  = {exp}")
    print(f"[anchor] MATCH: {tag == exp}\n")
    assert tag == exp, "ascon_ref test vector mismatch!"


def demo(seed=1, lanes=(0, 1, 3)):
    rng = random.Random(seed)
    key = bytes(rng.randrange(256) for _ in range(16))
    nonce = bytes(range(16))
    oracle = AsconOracle(key, nonce)

    print("=" * 74)
    print("MODELED-FAULT VALIDATOR  (single random key, fixed nonce)")
    print("=" * 74)
    print(f"true key   = {key.hex()}")
    print(f"nonce      = {nonce.hex()}")
    print(f"golden tag = {oracle.golden_tag().hex()}\n")

    golden, faults = run_campaign(oracle, lanes=lanes)

    # ---- (a) tag-ONLY recovery (honest baseline) ---------------------------
    t0 = time.perf_counter()
    r_tag = recover_key(golden, faults, capacity_word=None)
    dt_tag = (time.perf_counter() - t0) * 1e3
    print("-- tag-only DFA (observes ONLY the 128-bit tag) ------------------")
    print(f"   faults injected            : {len(faults)} "
          f"({len(lanes)} masks x 64 columns)")
    print(f"   columns pinned to {{x,x^4}}  : {r_tag['resolved_pair_cols']}/64")
    print(f"   K1 = key[8:16] recovered   : {r_tag['K1'] is not None and r_tag['K1'] == key[8:16]}"
          f"   ({r_tag['K1'].hex() if r_tag['K1'] else None})")
    print(f"   K0 = key[0:8]  recovered   : False  (irreducible 2^64 residual, tag-only)")
    print(f"   solve time                 : {dt_tag:.1f} ms\n")

    # ---- (b) full-key recovery (adds one unmasked capacity word) -----------
    t0 = time.perf_counter()
    r_full = recover_key(golden, faults, capacity_word=oracle.capacity_word())
    dt_full = (time.perf_counter() - t0) * 1e3
    recovered = (r_full["K0"] or b"") + (r_full["K1"] or b"")
    print("-- full DFA (tag + one unmasked capacity word S_out[2]) ----------")
    print(f"   columns resolved uniquely  : {r_full['resolved_state_cols']}/64")
    print(f"   recovered key              : {recovered.hex()}")
    print(f"   true key                   : {key.hex()}")
    print(f"   solve time                 : {dt_full:.1f} ms")
    print(f"   total faults consumed      : {oracle.n_faults}\n")

    success = (recovered == key)
    print(f"RECOVERED KEY == TRUE KEY: {success}")
    print("=" * 74 + "\n")
    return success


# 2. Multi-key experiment
def multikey(n_keys=20, seed=100, lanes=(0, 1, 3), out_csv=None):
    print("=" * 74)
    print(f"MULTI-KEY EXPERIMENT  ({n_keys} random keys, fixed nonce)")
    print("=" * 74)
    rng = random.Random(seed)
    rows = []
    succ = 0
    min_faults_full = None
    for k in range(n_keys):
        key = bytes(rng.randrange(256) for _ in range(16))
        nonce = bytes(range(16))
        oracle = AsconOracle(key, nonce)
        golden, faults = run_campaign(oracle, lanes=lanes)
        r = recover_key(golden, faults, capacity_word=oracle.capacity_word())
        rec = (r["K0"] or b"") + (r["K1"] or b"")
        ok = (rec == key)
        succ += ok
        cols = r["resolved_state_cols"]
        nf = oracle.n_faults
        if ok:
            min_faults_full = nf if min_faults_full is None else min(min_faults_full, nf)
        rows.append({"key": key.hex(), "faults_used": nf,
                     "columns_resolved": cols, "success": int(ok)})
        print(f"  key {k:2d}: {key.hex()}  faults={nf:3d}  cols={cols:2d}/64  ok={ok}")
    rate = 100.0 * succ / n_keys
    print(f"\n  success rate           : {succ}/{n_keys} = {rate:.1f}%")
    print(f"  faults / key           : {len(lanes)*64} (={len(lanes)} masks x 64 cols)")
    print(f"  minimum faults (full)  : {min_faults_full}")
    if out_csv:
        with open(out_csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["key", "faults_used",
                                              "columns_resolved", "success"])
            w.writeheader(); w.writerows(rows)
        print(f"  wrote {out_csv}")
    print("=" * 74 + "\n")
    return rate, min_faults_full


# 3. Minimal-fault study: which single-bit mask sets per column suffice for K1 (agree on Sbox&1) and the full key ({x, x^4} plus capacity word)
def _masksets_needed():
    from itertools import combinations
    lane_mask = {L: 1 << (4 - L) for L in range(5)}

    def obs(x, e):
        d = SBOX[x] ^ SBOX[x ^ e]
        return ((d >> 1) & 1, d & 1)

    def suffices(lanes, mode):
        sig = {}
        for x in range(32):
            sig.setdefault(tuple(obs(x, lane_mask[L]) for L in lanes), []).append(x)
        for grp in sig.values():
            if mode == "k1" and len({SBOX[x] & 1 for x in grp}) != 1:
                return False
            if mode == "full" and not all((a ^ b) in (0, 4) for a in grp for b in grp):
                return False
        return True

    res = {}
    for mode in ("k1", "full"):
        best = None
        for k in range(1, 6):
            good = [c for c in combinations(range(5), k) if suffices(c, mode)]
            if good:
                best = (k, good[0]); break
        res[mode] = best
    return res


def minfaults(n_keys=20, seed=200, out_csv=None):
    print("=" * 74)
    print("MINIMAL-FAULT STUDY  (sweep #single-bit masks per column)")
    print("=" * 74)
    need = _masksets_needed()
    print(f"  minimal masks/col for K1 (64-bit) : k={need['k1'][0]}  lanes={need['k1'][1]}")
    print(f"  minimal masks/col for full key    : k={need['full'][0]}  lanes={need['full'][1]}")
    print()

    # Empirical sweep: use the first m lanes of a fixed order and measure success.
    order = [0, 1, 3, 2, 4]
    rows = []
    for m in range(1, 6):
        lanes = tuple(order[:m])
        rng = random.Random(seed)
        succ_full = 0
        succ_k1 = 0
        for _ in range(n_keys):
            key = bytes(rng.randrange(256) for _ in range(16))
            oracle = AsconOracle(key, bytes(range(16)))
            golden, faults = run_campaign(oracle, lanes=lanes)
            r = recover_key(golden, faults, capacity_word=oracle.capacity_word())
            rec = (r["K0"] or b"") + (r["K1"] or b"")
            succ_full += (rec == key)
            succ_k1 += (r["K1"] is not None and r["K1"] == key[8:16])
        fpk = m * 64
        rows.append({"masks_per_col": m, "faults_per_key": fpk,
                     "lanes": "|".join(map(str, lanes)),
                     "k1_success_rate": round(100.0 * succ_k1 / n_keys, 1),
                     "full_success_rate": round(100.0 * succ_full / n_keys, 1)})
        print(f"  masks/col={m} ({fpk:3d} faults/key)  lanes={lanes}"
              f"  K1={100.0*succ_k1/n_keys:5.1f}%  full={100.0*succ_full/n_keys:5.1f}%")
    if out_csv:
        with open(out_csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["masks_per_col", "faults_per_key",
                                              "lanes", "k1_success_rate",
                                              "full_success_rate"])
            w.writeheader(); w.writerows(rows)
        print(f"\n  wrote {out_csv}")
    print("=" * 74 + "\n")
    return rows


# 4. Real-SimX-trace connection
def real_trace_report(csv_path=None):
    if csv_path is None:
        csv_path = os.path.join(HERE, "real_ascon_campaign.csv")
    print("=" * 74)
    print("REAL SimX TRACE CONNECTION  (honest status)")
    print("=" * 74)
    if not os.path.exists(csv_path):
        print(f"  {csv_path} not found -- skipping.")
        print("=" * 74 + "\n"); return
    rows = list(csv.DictReader(open(csv_path)))
    eff = [r for r in rows if r["diff_count"] not in ("0", "")]
    from collections import Counter
    dist = Counter(int(r["diff_count"]) for r in eff)
    print(f"  loaded {len(rows)} rows, {len(eff)} effective (non-zero tag diff)")
    print(f"  tag-diff byte-weight distribution: "
          f"{{{', '.join(f'{k}:{dist[k]}' for k in sorted(dist))}}}")
    print()
    print("  BLOCKER: real_ascon_campaign.csv records (instr, mask) of the SimX")
    print("  architectural fault but NOT which state bit/(lane,column) was flipped.")
    print("  The DFA needs the injected difference e_j at a known column, which the")
    print("  trace does not expose. Options to close the gap:")
    print("   (a) instrument sim/simx so each run logs the faulted (lane,column);")
    print("   (b) extend simx_ascon/ascon.c result_buf to also dump s[0..2]")
    print("       (the unmasked capacity words) -- required for the K0 half anyway,")
    print("       since result_buf today exposes ONLY the 16-byte tag (lanes 3,4).")
    print()
    print("  What IS demonstrated on real traces: the SimX campaign produces exactly")
    print("  the structured 2..6 (and full) byte tag differentials this recovery")
    print("  consumes; the modeled last-round fault is the same structural class.")
    print("  What is NOT (yet) demonstrated: an end-to-end recovery driven from the")
    print("  raw CSV, because the (lane,column) label is missing. No faked recovery.")
    print("=" * 74 + "\n")


def main():
    ap = argparse.ArgumentParser(description="Ascon-128 finalization DFA key recovery")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--keys", type=int, default=20, help="#keys for multi-key experiment")
    ap.add_argument("--lanes", type=str, default="0,1,3",
                    help="single-bit fault lanes per column (comma list)")
    ap.add_argument("--only", choices=["demo", "multikey", "minfaults", "real"],
                    default=None, help="run only one stage")
    ap.add_argument("--multikey-csv", default=os.path.join(HERE, "ascon_recovery_results.csv"))
    ap.add_argument("--minfaults-csv", default=os.path.join(HERE, "ascon_minfaults.csv"))
    args = ap.parse_args()
    lanes = tuple(int(x) for x in args.lanes.split(","))

    sanity_anchor()
    stages = [args.only] if args.only else ["demo", "multikey", "minfaults", "real"]
    if "demo" in stages:
        ok = demo(seed=args.seed, lanes=lanes)
    if "multikey" in stages:
        multikey(n_keys=args.keys, lanes=lanes, out_csv=args.multikey_csv)
    if "minfaults" in stages:
        minfaults(n_keys=max(20, args.keys), out_csv=args.minfaults_csv)
    if "real" in stages:
        real_trace_report()


if __name__ == "__main__":
    main()
