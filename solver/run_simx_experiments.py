#!/usr/bin/env python3
# Real Vortex SimX experiments: key recovery vs fault-pair count, multi-key validation, and warp configuration effect.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute

import subprocess
import sys
import os
import csv
import time
import argparse
import random
import numpy as np
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from smt_attack.dfa_solver import (
    solve_k10_decomposed, recover_key, detect_fault_column,
    K10_COL_INDICES, solve_column_concrete,
)
from aes_kernel.aes128 import key_expansion, get_round_key, reverse_key_schedule

SIMX = PROJECT_ROOT / "vortex" / "build" / "sim" / "simx" / "simx"
AES_BIN = PROJECT_ROOT / "simx_aes" / "aes.bin"


def run_simx_fault(key_hex: str, fault_round: int, fault_byte: int,
                   fault_value: int, num_warps: int = 4, num_threads: int = 4,
                   timeout: int = 30) -> dict:
    """Run AES on real SimX with fault injection. Returns parsed PT/KEY/CT."""
    cmd = [str(SIMX)]
    if num_warps != 4 or num_threads != 4:
        cmd += ["-c", "1", "-w", str(num_warps), "-t", str(num_threads)]
    if fault_round > 0:
        cmd += ["-r", str(fault_round), "-b", str(fault_byte),
                "-x", f"0x{fault_value:02x}"]
    if key_hex:
        cmd += ["-K", key_hex]
    cmd += [str(AES_BIN)]

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    result = {}
    for line in proc.stdout.splitlines():
        if line.startswith("PT="):  result["pt"]  = line[3:].strip()
        elif line.startswith("KEY="): result["key"] = line[4:].strip()
        elif line.startswith("CT="):  result["ct"]  = line[3:].strip()
        elif line.startswith("DONE="): result["done"] = int(line[5:].strip())
    return result


def collect_simx_pairs(key_hex: str, n_per_col: int, seed: int = 42) -> list:
    """Collect (golden, faulty) ciphertext pairs from real SimX."""
    rng = random.Random(seed)
    col_to_byte = {0: 0, 1: 4, 2: 8, 3: 12}

    # Golden run
    golden_run = run_simx_fault(key_hex, 0, 0, 0)
    if golden_run.get("done") != 1:
        raise RuntimeError(f"Golden run failed: {golden_run}")
    golden_ct = list(bytes.fromhex(golden_run["ct"]))

    pairs = []
    for col in range(4):
        for _ in range(n_per_col):
            fv = rng.randint(1, 255)
            faulty_run = run_simx_fault(key_hex, 9, col_to_byte[col], fv)
            if faulty_run.get("done") != 1:
                continue
            faulty_ct = list(bytes.fromhex(faulty_run["ct"]))
            pairs.append((golden_ct, faulty_ct))

    return pairs, golden_ct


def experiment_real_recovery(output_dir, key_hex):
    """Experiment: Key recovery success vs # of real SimX fault pairs."""
    print("\n" + "="*60)
    print("Exp 1 (REAL SimX): Key Recovery vs Fault Pair Count")
    print("="*60)

    key = list(bytes.fromhex(key_hex))
    expanded = key_expansion(key)
    k10_expected = get_round_key(expanded, 10)

    # Collect 25 pairs/column (100 total) from real SimX
    print("Collecting 100 real SimX fault pairs...")
    t0 = time.time()
    pairs, _ = collect_simx_pairs(key_hex, n_per_col=25, seed=42)
    t_collect = time.time() - t0
    print(f"Collected {len(pairs)} REAL SimX pairs in {t_collect:.1f}s")

    # Group by column for progressive narrowing
    grouped = {0: [], 1: [], 2: [], 3: []}
    for g, f in pairs:
        c = detect_fault_column(g, f)
        if c is not None:
            grouped[c].append((g, f))

    results = []
    for n_per_col in [1, 2, 3, 4, 5, 8, 10, 15, 20, 25]:
        subset = []
        for col in range(4):
            subset.extend(grouped[col][:n_per_col])

        t_start = time.perf_counter()
        k10_list, solve_time = solve_k10_decomposed(subset, verbose=False)
        wall = time.perf_counter() - t_start

        correct = any(k == k10_expected for k in k10_list)
        unique = len(k10_list) == 1 and correct

        results.append({
            'pairs_per_col': n_per_col,
            'total_pairs': n_per_col * 4,
            'num_candidates': len(k10_list),
            'correct_found': correct,
            'unique_recovery': unique,
            'solve_time_ms': solve_time * 1000,
        })
        print(f"  {n_per_col:2d}/col ({n_per_col*4:3d} total): "
              f"{len(k10_list):4d} cand, "
              f"correct={'Y' if correct else 'N'}, "
              f"unique={'Y' if unique else 'N'}, "
              f"{solve_time*1000:.1f}ms")

    csv_path = os.path.join(output_dir, 'real_simx_recovery.csv')
    with open(csv_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=results[0].keys())
        w.writeheader()
        w.writerows(results)
    print(f"  Saved to {csv_path}")
    return results


def experiment_multi_key_simx(output_dir, n_keys=20):
    """Multi-key validation: random keys, real SimX, real fault recovery."""
    print("\n" + "="*60)
    print(f"Exp 2 (REAL SimX): Multi-Key Validation ({n_keys} random keys)")
    print("="*60)

    rng = random.Random(42)
    successes = 0
    times = []
    collect_times = []

    for ki in range(n_keys):
        rkey = bytes(rng.randint(0, 255) for _ in range(16))
        rkey_hex = rkey.hex()
        expected = key_expansion(list(rkey))
        k10_exp = get_round_key(expected, 10)

        try:
            t0 = time.time()
            pairs, _ = collect_simx_pairs(rkey_hex, n_per_col=2, seed=ki)
            t_col = time.time() - t0
            collect_times.append(t_col)

            t0 = time.perf_counter()
            k10_list, _ = solve_k10_decomposed(pairs, verbose=False)
            t_solve = time.perf_counter() - t0
            times.append(t_solve)

            if any(k == k10_exp for k in k10_list):
                successes += 1
                status = "OK"
            else:
                status = "FAIL"

            print(f"  Key {ki+1:2d}/{n_keys}: collected {len(pairs)} SimX pairs "
                  f"({t_col:.1f}s), solved in {t_solve*1000:.1f}ms - {status}")
        except Exception as e:
            print(f"  Key {ki+1:2d}/{n_keys}: ERROR - {e}")

    success_rate = successes / n_keys * 100
    print(f"\n  REAL SimX success rate: {successes}/{n_keys} = {success_rate:.0f}%")
    print(f"  Mean solve time: {np.mean(times)*1000:.1f}ms")
    print(f"  Mean SimX collection time: {np.mean(collect_times):.2f}s")

    csv_path = os.path.join(output_dir, 'real_simx_multikey.csv')
    with open(csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['n_keys', 'successes', 'success_rate', 'mean_solve_ms',
                    'mean_collect_s'])
        w.writerow([n_keys, successes, f'{success_rate:.0f}',
                    f'{np.mean(times)*1000:.1f}',
                    f'{np.mean(collect_times):.2f}'])
    print(f"  Saved to {csv_path}")
    return success_rate


def experiment_warp_count_simx(output_dir, key_hex):
    """Vary SimX warp count, measure timing/effect on attack."""
    print("\n" + "="*60)
    print("Exp 3 (REAL SimX): Warp Configuration Effect")
    print("="*60)

    results = []
    # Try valid SimX configs (avoid the -t 1 -w 1 bug)
    for nw, nt in [(2, 4), (4, 4), (4, 8), (8, 4)]:
        # Run a single fault injection at this config
        try:
            t0 = time.time()
            fault_run = run_simx_fault(
                key_hex, fault_round=9, fault_byte=0, fault_value=0xa4,
                num_warps=nw, num_threads=nt
            )
            t_run = time.time() - t0
            success = fault_run.get("done") == 1

            results.append({
                'num_warps': nw,
                'threads_per_warp': nt,
                'total_threads': nw * nt,
                'simx_run_time_s': t_run,
                'fault_success': success,
            })
            print(f"  warps={nw}, threads={nt} (total={nw*nt}): "
                  f"{t_run:.2f}s, success={success}")
        except Exception as e:
            print(f"  warps={nw}, threads={nt}: ERROR - {e}")

    csv_path = os.path.join(output_dir, 'real_simx_warps.csv')
    with open(csv_path, 'w', newline='') as f:
        if results:
            w = csv.DictWriter(f, fieldnames=results[0].keys())
            w.writeheader()
            w.writerows(results)
    print(f"  Saved to {csv_path}")
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Vortex SimX fault injection experiments")
    parser.add_argument("--experiment", choices=["all", "recovery", "multikey", "warp"],
                        default="all")
    parser.add_argument("--output-dir", type=str, default="experiments/results")
    parser.add_argument("--n-keys", type=int, default=20)
    args = parser.parse_args()

    if not SIMX.exists():
        print(f"ERROR: {SIMX} not found. Build SimX first.", file=sys.stderr)
        sys.exit(1)
    if not AES_BIN.exists():
        print(f"ERROR: {AES_BIN} not found. Build aes.bin first.", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    nist_key = "2b7e151628aed2a6abf7158809cf4f3c"
    print("="*60)
    print("VORTEX SIMX FAULT INJECTION EXPERIMENTS")
    print("="*60)
    print(f"SimX:    {SIMX}")
    print(f"AES bin: {AES_BIN}")
    print(f"Key:     {nist_key}")

    if args.experiment in ("all", "recovery"):
        experiment_real_recovery(args.output_dir, nist_key)

    if args.experiment in ("all", "multikey"):
        experiment_multi_key_simx(args.output_dir, args.n_keys)

    if args.experiment in ("all", "warp"):
        experiment_warp_count_simx(args.output_dir, nist_key)

    print("\n" + "="*60)
    print("REAL SimX experiments complete.")
    print("="*60)


if __name__ == "__main__":
    main()
