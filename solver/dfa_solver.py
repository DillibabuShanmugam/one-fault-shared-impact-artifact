#!/usr/bin/env python3
# AES-128 DFA key recovery (Piret-Quisquater / Tunstall): concrete per-column enumeration plus a Z3 SMT encoding.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute

import sys
import os
import time
import argparse
import csv
from typing import List, Tuple, Optional, Set, Dict
from itertools import product as cartesian_product

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aes_kernel.aes128 import (
    SBOX, INV_SBOX, gmul,
    aes128_encrypt, key_expansion, get_round_key, reverse_key_schedule,
)

# Column-major state: after round-10 ShiftRows a round-9 column fc lands at CT positions ((fc-r)%4)*4+r for r = 0..3

def _ct_positions_for_fault_column(fc):
    """CT byte positions affected by a fault in round-9 column fc."""
    return [((fc - r) % 4) * 4 + r for r in range(4)]

FAULT_COL_TO_CT = {fc: _ct_positions_for_fault_column(fc) for fc in range(4)}

# Reverse mapping: frozenset of CT positions -> fault column
CT_TO_FAULT_COL = {}
for fc, positions in FAULT_COL_TO_CT.items():
    CT_TO_FAULT_COL[frozenset(positions)] = fc

# K10 byte indices per fault column equal the CT positions (K10 is XORed with CT directly)
K10_COL_INDICES = FAULT_COL_TO_CT


def detect_fault_column(golden_ct: List[int], faulty_ct: List[int]) -> Optional[int]:
    """Detect fault column from ciphertext XOR difference pattern."""
    diff_pos = frozenset(i for i in range(16) if golden_ct[i] != faulty_ct[i])
    if len(diff_pos) != 4:
        return None
    return CT_TO_FAULT_COL.get(diff_pos)


# Per column, d_i = InvSBox(c_i ^ k_i) ^ InvSBox(c'_i ^ k_i) must give InvMixColumns(d) with exactly one non-zero byte

def inv_mix_col_one(d0, d1, d2, d3):
    """Apply InvMixColumns to one column [d0,d1,d2,d3]. Returns 4 bytes."""
    return [
        gmul(14, d0) ^ gmul(11, d1) ^ gmul(13, d2) ^ gmul(9, d3),
        gmul(9, d0) ^ gmul(14, d1) ^ gmul(11, d2) ^ gmul(13, d3),
        gmul(13, d0) ^ gmul(9, d1) ^ gmul(14, d2) ^ gmul(11, d3),
        gmul(11, d0) ^ gmul(13, d1) ^ gmul(9, d2) ^ gmul(14, d3),
    ]


# For a CT byte pair (c, c'), tabulate the k values with InvSBox(c^k) ^ InvSBox(c'^k) = d

def _compute_diff_candidates(c_golden: int, c_faulty: int) -> Dict[int, Set[int]]:
    """For CT byte pair (golden, faulty), map diff value -> set of compatible k values."""
    table = {}
    for k in range(256):
        d = INV_SBOX[c_golden ^ k] ^ INV_SBOX[c_faulty ^ k]
        if d not in table:
            table[d] = set()
        table[d].add(k)
    return table


def solve_column_concrete(
    golden_bytes: List[int],  # 4 golden CT bytes for this column
    faulty_bytes: List[int],  # 4 faulty CT bytes for this column
) -> Set[Tuple[int, int, int, int]]:
    """Enumerate all 4-byte K10 column candidates consistent with a single-byte fault; returns set of (k0, k1, k2, k3)."""
    # For each of the 4 CT byte positions, build diff -> k_candidates map
    diff_tables = []
    for i in range(4):
        diff_tables.append(_compute_diff_candidates(golden_bytes[i], faulty_bytes[i]))

    candidates = set()

    # For each possible fault position (which byte in the column was faulted):
    for fault_pos in range(4):
        # A single-byte fault e_fp at fault_pos gives d_i = gmul(MC[i][fault_pos], e_fp) with MC the MixColumns matrix

        MC = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]

        # For each possible non-zero fault magnitude e_fp:
        for e_fp in range(1, 256):
            # Compute the required diff values
            d_required = [gmul(MC[row][fault_pos], e_fp) for row in range(4)]

            # Check if ALL 4 diff values have compatible key bytes
            k_sets = []
            valid = True
            for i in range(4):
                if d_required[i] in diff_tables[i]:
                    k_sets.append(diff_tables[i][d_required[i]])
                else:
                    valid = False
                    break

            if not valid:
                continue

            # All combinations of compatible key bytes
            for combo in cartesian_product(*k_sets):
                candidates.add(combo)

    return candidates


def solve_k10_decomposed(
    pairs: List[Tuple[List[int], List[int]]],
    verbose: bool = True,
) -> Tuple[List[List[int]], float]:
    """Solve K10 as 4 independent column problems by concrete enumeration; returns (k10_candidates, solve_time_s)."""
    t_start = time.time()

    # Group pairs by fault column
    column_pairs: Dict[int, List] = {0: [], 1: [], 2: [], 3: []}
    for golden, faulty in pairs:
        col = detect_fault_column(golden, faulty)
        if col is not None:
            column_pairs[col].append((golden, faulty))

    # Solve each column
    column_candidates: Dict[int, Optional[Set]] = {}

    for col in range(4):
        ct_indices = K10_COL_INDICES[col]

        if not column_pairs[col]:
            if verbose:
                print(f"  Column {col} (K10 bytes {ct_indices}): no pairs, unconstrained")
            column_candidates[col] = None
            continue

        # Intersect candidates across all pairs for this column
        combined = None
        for golden, faulty in column_pairs[col]:
            g_bytes = [golden[i] for i in ct_indices]
            f_bytes = [faulty[i] for i in ct_indices]
            pair_candidates = solve_column_concrete(g_bytes, f_bytes)

            if combined is None:
                combined = pair_candidates
            else:
                combined &= pair_candidates  # Intersection

        column_candidates[col] = combined
        if verbose:
            print(f"  Column {col} (K10 bytes {ct_indices}): "
                  f"{len(combined)} candidate(s) from {len(column_pairs[col])} pair(s)")

    # Combine columns into full K10
    col_lists = []
    for col in range(4):
        if column_candidates[col] is None:
            col_lists.append([(0, 0, 0, 0)])  # unconstrained placeholder
        else:
            col_lists.append(list(column_candidates[col]))

    solutions = []
    for combo in cartesian_product(*col_lists):
        k10 = [0] * 16
        for col in range(4):
            for i, idx in enumerate(K10_COL_INDICES[col]):
                k10[idx] = combo[col][i]
        solutions.append(k10)
        if len(solutions) >= 10000:  # Safety limit
            break

    t_total = time.time() - t_start

    if verbose:
        print(f"  Total: {len(solutions)} K10 candidate(s) in {t_total:.4f}s")

    return solutions, t_total


def recover_key(
    pairs: List[Tuple[List[int], List[int]]],
    verbose: bool = True,
) -> Tuple[List[List[int]], float]:
    """Full key recovery: solve K10, reverse key schedule to K0."""
    k10_list, solve_time = solve_k10_decomposed(pairs, verbose=verbose)

    k0_list = []
    for k10 in k10_list:
        k0 = reverse_key_schedule(k10)
        k0_list.append(k0)

    if verbose and k0_list:
        print(f"  Recovered {len(k0_list)} key candidate(s)")
        if len(k0_list) <= 5:
            for i, k0 in enumerate(k0_list):
                print(f"    [{i}] K0 = {' '.join(f'{b:02x}' for b in k0)}")

    return k0_list, solve_time


# Z3 symbolic DFA solver

def _build_z3_array(name, table):
    """Build Z3 Array(BitVec(8) -> BitVec(8)) from 256-entry lookup table."""
    from z3 import Array, BitVecSort, Store, BitVecVal
    bv8 = BitVecSort(8)
    arr = Array(name, bv8, bv8)
    for i in range(256):
        arr = Store(arr, BitVecVal(i, 8), BitVecVal(table[i], 8))
    return arr


# Module-level precomputed arrays (built once on first use)
_Z3_ARRAYS = {}

def _get_z3_array(name, table):
    """Get or create a cached Z3 Array."""
    if name not in _Z3_ARRAYS:
        _Z3_ARRAYS[name] = _build_z3_array(name, table)
    return _Z3_ARRAYS[name]


def _z3_sbox_lookup(x, table, name="SBOX"):
    """Encode SBox lookup using Z3 Array Select (fast)."""
    from z3 import Select
    arr = _get_z3_array(name, table)
    return Select(arr, x)


def _z3_gmul_table(const_a):
    """Precompute GF(2^8) multiplication table for a constant."""
    return [gmul(const_a, i) for i in range(256)]


def solve_k10_z3(
    pairs: List[Tuple[List[int], List[int]]],
    verbose: bool = True,
    timeout_ms: int = 60000,
) -> Tuple[List[List[int]], float]:
    """Solve K10 with Z3: concrete per-byte candidate sets encoded as domain constraints; returns (k10_candidates, solve_time_s)."""
    from z3 import BitVec, BitVecVal, Solver, sat, Or, And, set_param

    set_param("timeout", timeout_ms)
    t_start = time.time()

    # Group pairs by detected fault column
    column_pairs: Dict[int, List] = {0: [], 1: [], 2: [], 3: []}
    unknown_pairs = []
    for golden, faulty in pairs:
        col = detect_fault_column(golden, faulty)
        if col is not None:
            column_pairs[col].append((golden, faulty))
        else:
            unknown_pairs.append((golden, faulty))

    if verbose and unknown_pairs:
        print(f"  Z3: {len(unknown_pairs)} pairs with unknown column")

    # MixColumns matrix
    MC = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]

    column_solutions: Dict[int, Optional[List]] = {}

    for col in range(4):
        col_pairs = column_pairs[col]
        if not col_pairs:
            column_solutions[col] = None
            if verbose:
                print(f"  Z3 Column {col}: no pairs, unconstrained")
            continue

        ct_indices = K10_COL_INDICES[col]
        k_vars = [BitVec(f"k10_{ct_indices[i]}", 8) for i in range(4)]
        solver = Solver()

        for golden, faulty in col_pairs:
            g_bytes = [golden[idx] for idx in ct_indices]
            f_bytes = [faulty[idx] for idx in ct_indices]

            # Precompute: for each byte position, which (k, diff) pairs are valid
            diff_tables = [_compute_diff_candidates(g_bytes[i], f_bytes[i]) for i in range(4)]

            # For each fault position (0-3) and magnitude (1-255), find compatible k values
            valid_k_tuples = set()
            for fault_pos in range(4):
                for e_fp in range(1, 256):
                    d_required = [gmul(MC[row][fault_pos], e_fp) for row in range(4)]
                    k_sets = []
                    ok = True
                    for i in range(4):
                        if d_required[i] in diff_tables[i]:
                            k_sets.append(diff_tables[i][d_required[i]])
                        else:
                            ok = False
                            break
                    if not ok:
                        continue
                    for combo in cartesian_product(*k_sets):
                        valid_k_tuples.add(combo)

            # Encode as Z3 domain constraint: k_vars must be one of the valid tuples
            if valid_k_tuples:
                tuple_constraints = []
                for kt in valid_k_tuples:
                    tuple_constraints.append(And(*[k_vars[i] == kt[i] for i in range(4)]))
                solver.add(Or(*tuple_constraints))
            else:
                solver.add(False)  # UNSAT

        # Solve
        t_col_start = time.time()
        col_sols = []
        while len(col_sols) < 100:
            result = solver.check()
            if result != sat:
                break
            model = solver.model()
            sol = tuple(model.eval(k_vars[i], model_completion=True).as_long() for i in range(4))
            col_sols.append(sol)
            solver.add(Or(*[k_vars[i] != sol[i] for i in range(4)]))

        t_col = time.time() - t_col_start
        column_solutions[col] = col_sols

        if verbose:
            print(f"  Z3 Column {col} (K10 bytes {ct_indices}): "
                  f"{len(col_sols)} solution(s) in {t_col:.3f}s")

    # Combine columns
    col_lists = []
    for col in range(4):
        if column_solutions[col] is None:
            col_lists.append([(0, 0, 0, 0)])
        else:
            col_lists.append(column_solutions[col])

    solutions = []
    for combo in cartesian_product(*col_lists):
        k10 = [0] * 16
        for col in range(4):
            for i, idx in enumerate(K10_COL_INDICES[col]):
                k10[idx] = combo[col][i]
        solutions.append(k10)
        if len(solutions) >= 10000:
            break

    t_total = time.time() - t_start
    if verbose:
        print(f"  Z3 Total: {len(solutions)} K10 candidate(s) in {t_total:.3f}s")

    return solutions, t_total


def recover_key_z3(
    pairs: List[Tuple[List[int], List[int]]],
    verbose: bool = True,
    timeout_ms: int = 60000,
) -> Tuple[List[List[int]], float]:
    """Full key recovery using Z3 symbolic solver."""
    k10_list, solve_time = solve_k10_z3(pairs, verbose=verbose, timeout_ms=timeout_ms)
    k0_list = [reverse_key_schedule(k10) for k10 in k10_list]
    if verbose and k0_list:
        print(f"  Z3 recovered {len(k0_list)} key candidate(s)")
        for i, k0 in enumerate(k0_list[:5]):
            print(f"    [{i}] K0 = {' '.join(f'{b:02x}' for b in k0)}")
    return k0_list, solve_time


# File I/O

def read_hex_csv(filepath: str) -> List[List[int]]:
    rows = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.replace(',', ' ').split()
            row = [int(p, 16) for p in parts]
            if len(row) == 16:
                rows.append(row)
    return rows


def load_trace_csv(filepath: str) -> List[Tuple[List[int], List[int]]]:
    """Load from fault_injection/inject.py output format."""
    pairs = []
    with open(filepath) as f:
        reader = csv.DictReader(f)
        for row in reader:
            golden = list(bytes.fromhex(row['golden_ciphertext']))
            faulty = list(bytes.fromhex(row['faulty_ciphertext']))
            pairs.append((golden, faulty))
    return pairs


# Self-test

def self_test():
    import random

    print("=" * 60)
    print("DFA Solver Self-Test (Concrete Enumeration)")
    print("=" * 60)

    key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
           0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
    pt = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
          0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]

    golden_ct, _ = aes128_encrypt(pt, key)
    expanded = key_expansion(key)
    k10_expected = get_round_key(expanded, 10)

    print(f"Key:        {' '.join(f'{b:02x}' for b in key)}")
    print(f"Expected K10: {' '.join(f'{b:02x}' for b in k10_expected)}")
    print()

    # Test 1: Single pair per column
    print("[Test 1] 1 fault pair per column (4 total)")
    print("-" * 50)
    random.seed(42)
    pairs = []
    for fault_byte in [0, 4, 8, 12]:  # Row 0 of each column
        fv = random.randint(1, 255)
        fct, _ = aes128_encrypt(pt, key, fault_round=9, fault_byte=fault_byte, fault_value=fv)
        pairs.append((golden_ct, fct))
        print(f"  Fault byte={fault_byte}, val=0x{fv:02x}")

    k10_list, t = solve_k10_decomposed(pairs, verbose=True)
    # With 1 pair per column the cartesian product is huge, so verify per column instead
    col_found = True
    for col in range(4):
        idx = K10_COL_INDICES[col]
        expected_col = tuple(k10_expected[i] for i in idx)
        g = [golden_ct[i] for i in idx]
        f = [pairs[col][1][i] for i in idx]
        col_cands = solve_column_concrete(g, f)
        if expected_col in col_cands:
            print(f"  Column {col}: correct key bytes found among {len(col_cands)} candidates")
        else:
            print(f"  Column {col}: FAIL - correct key bytes NOT found")
            col_found = False
    print(f"  Per-column verification: {'PASS' if col_found else 'FAIL'}")
    print(f"  Time: {t:.4f}s")
    print()

    # Test 2: Progressive narrowing
    print("[Test 2] Progressive narrowing (adding pairs)")
    print("-" * 50)
    all_pairs = []
    for n_per_col in [1, 2, 3]:
        for fault_byte in [0, 4, 8, 12]:
            fv = random.randint(1, 255)
            fct, _ = aes128_encrypt(pt, key, fault_round=9, fault_byte=fault_byte, fault_value=fv)
            all_pairs.append((golden_ct, fct))

        k10_list, t = solve_k10_decomposed(all_pairs, verbose=False)
        correct = any(k == k10_expected for k in k10_list)
        unique = len(k10_list) == 1 and correct
        print(f"  {n_per_col} pair/col ({len(all_pairs)} total): "
              f"{len(k10_list)} candidates, correct={'Y' if correct else 'N'}, "
              f"unique={'Y' if unique else 'N'}, time={t:.4f}s")

    # Test 3: Random key
    print()
    print("[Test 3] Random key + random plaintexts")
    print("-" * 50)
    random.seed(123)
    rkey = [random.randint(0, 255) for _ in range(16)]
    rexp = key_expansion(rkey)
    rk10 = get_round_key(rexp, 10)

    pairs3 = []
    for _ in range(3):
        rpt = [random.randint(0, 255) for _ in range(16)]
        rg, _ = aes128_encrypt(rpt, rkey)
        for fb in [0, 4, 8, 12]:
            fv = random.randint(1, 255)
            rf, _ = aes128_encrypt(rpt, rkey, fault_round=9, fault_byte=fb, fault_value=fv)
            pairs3.append((rg, rf))

    k0_r, t3 = recover_key(pairs3, verbose=True)
    found3 = any(k0 == rkey for k0 in k0_r)
    print(f"  Concrete solver - correct key found: {'YES' if found3 else 'NO'}")
    print(f"  Time: {t3:.4f}s")

    # Test 4: Z3 Symbolic Solver - verify same result
    print()
    print("[Test 4] Z3 symbolic solver (2 pairs/col, NIST key)")
    print("-" * 50)
    z3_pairs = all_pairs[:8]  # 2 per column
    try:
        k0_z3, t_z3 = recover_key_z3(z3_pairs, verbose=True, timeout_ms=120000)
        found_z3 = any(k0 == key for k0 in k0_z3)
        print(f"  Z3 solver - correct key found: {'YES' if found_z3 else 'NO'}")
        print(f"  Time: {t_z3:.3f}s")

        # Compare: concrete vs Z3
        print()
        print("[Test 5] Concrete vs Z3 comparison")
        print("-" * 50)
        k0_concrete, t_concrete = recover_key(z3_pairs, verbose=False)
        concrete_found = any(k0 == key for k0 in k0_concrete)
        print(f"  Concrete: {len(k0_concrete)} candidates, {t_concrete:.4f}s, correct={'Y' if concrete_found else 'N'}")
        print(f"  Z3:       {len(k0_z3)} candidates, {t_z3:.3f}s, correct={'Y' if found_z3 else 'N'}")
        print(f"  Speedup:  {t_z3/t_concrete:.0f}x slower (Z3 symbolic overhead)")
        z3_pass = found_z3
    except Exception as e:
        print(f"  Z3 solver error: {e}")
        z3_pass = False

    print()
    print("=" * 60)
    all_pass = col_found and found3 and z3_pass
    print(f"SELF-TEST {'PASSED' if all_pass else 'FAILED'}")
    print("=" * 60)
    return all_pass


# CLI

def main():
    parser = argparse.ArgumentParser(description="AES-128 DFA Key Recovery (Concrete + Z3)")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--traces", type=str, help="Trace CSV from inject.py")
    parser.add_argument("--golden", type=str, help="Golden CT hex CSV")
    parser.add_argument("--faulty", type=str, help="Faulty CT hex CSV")
    parser.add_argument("--key", type=str, help="Planted key hex for validation")
    parser.add_argument("--output", type=str, default="smt_attack/results/recovery.csv")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    if args.traces:
        pairs = load_trace_csv(args.traces)
    elif args.golden and args.faulty:
        g = read_hex_csv(args.golden)
        f = read_hex_csv(args.faulty)
        pairs = list(zip(g, f))
    else:
        parser.error("Provide --traces or (--golden + --faulty), or --self-test")

    print(f"Loaded {len(pairs)} pairs")
    k0_list, t = recover_key(pairs, verbose=not args.quiet)

    if args.key:
        planted = [int(args.key[i:i+2], 16) for i in range(0, 32, 2)]
        found = any(k0 == planted for k0 in k0_list)
        print(f"\nPlanted key {'FOUND' if found else 'NOT FOUND'} among {len(k0_list)} candidates")

    # Save
    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    with open(args.output, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['method', 'num_pairs', 'num_candidates', 'solve_time_s', 'key_hex'])
        for k0 in k0_list[:10]:
            w.writerow(['concrete', len(pairs), len(k0_list), f'{t:.6f}',
                        ''.join(f'{b:02x}' for b in k0)])
    print(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
