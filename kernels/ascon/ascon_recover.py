#!/usr/bin/env python3
# Ascon-128 partial state recovery statistics from Vortex SimX architectural fault traces.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute

import csv, sys
from collections import Counter
from pathlib import Path

CSV_PATH = (Path(__file__).resolve().parent.parent
            / "experiments" / "results" / "real_ascon_campaign.csv")


def hexdiff(a_hex, b_hex):
    a = bytes.fromhex(a_hex); b = bytes.fromhex(b_hex)
    return bytes(x ^ y for x, y in zip(a, b))


def hw_byte(x):
    return bin(x).count("1")


def main():
    rows = list(csv.DictReader(open(CSV_PATH)))[1:]
    print(f"Loaded {len(rows)} fault traces")

    bit_hw_dist = Counter()
    byte_hw_dist = Counter()
    for r in rows:
        if int(r['diff_count']) == 0:
            continue
        d = hexdiff(r['golden_tag'], r['faulty_tag'])
        bit_hw_dist[sum(hw_byte(x) for x in d)] += 1
        byte_hw_dist[int(r['diff_count'])] += 1

    print(f"\nByte HW distribution: {dict(sorted(byte_hw_dist.items()))}")

    pure_1bit = [r for r in rows
                 if int(r['diff_count']) == 1
                 and sum(hw_byte(x) for x in hexdiff(r['golden_tag'], r['faulty_tag'])) == 1]
    print(f"\nPure 1-bit tag differentials: {len(pure_1bit)}")
    print(f"  faults that produced exactly 1 flipped bit in the 128-bit tag")
    print(f"  candidates for the post-permutation, pre-K-XOR fault site")

    bit_positions = Counter()
    for r in pure_1bit:
        d = hexdiff(r['golden_tag'], r['faulty_tag'])
        for i, b in enumerate(d):
            if b:
                bit_positions[(i, b.bit_length() - 1)] += 1
    distinct = len(bit_positions)
    print(f"  Distinct (byte, bit) positions covered: {distinct}/128")

    multi = [r for r in rows if 2 <= int(r['diff_count']) <= 6]
    print(f"\nMulti-byte structured diffs (2..6 bytes): {len(multi)}")
    print(f"  Dobraunig-Eichlseder-Mendel DFA inputs")
    print(f"  carry constrained S-box differentials through the last P12 round")

    pattern_counts = Counter()
    for r in multi:
        d = hexdiff(r['golden_tag'], r['faulty_tag'])
        positions = tuple(i for i, b in enumerate(d) if b)
        pattern_counts[positions] += 1
    print(f"  Distinct diff-position patterns: {len(pattern_counts)}")
    print(f"  Top-5 most common patterns:")
    for pat, c in pattern_counts.most_common(5):
        print(f"    {pat}: {c} occurrences")

    print("\n=== Summary ===")
    print(f"Total architectural fault injections: {len(rows)}")
    print(f"Effective faults (non-zero diff): {sum(1 for r in rows if int(r['diff_count']) > 0)}")
    print(f"Pure 1-bit tag diffs: {len(pure_1bit)} (post-permutation fault site)")
    print(f"Multi-byte structured diffs: {len(multi)} (last-round S-box fault site)")
    print(f"Distinct fault patterns: {len(pattern_counts)} (state-recovery basis)")


if __name__ == "__main__":
    main()
