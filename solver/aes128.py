#!/usr/bin/env python3
# AES-128 reference implementation with round/byte fault injection and a behavioral SIMT (warp/thread) fault model.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute

import numpy as np
from typing import Optional, Tuple, List

# AES S-Box
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

INV_SBOX = [0] * 256
for i in range(256):
    INV_SBOX[SBOX[i]] = i

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def xtime(a: int) -> int:
    """Multiply by x in GF(2^8)."""
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def gmul(a: int, b: int) -> int:
    """Galois field multiplication."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def sub_bytes(state: list) -> list:
    return [SBOX[b] for b in state]


def inv_sub_bytes(state: list) -> list:
    return [INV_SBOX[b] for b in state]


def shift_rows(state: list) -> list:
    """State is column-major [s0..s15]; row i shifts left by i positions."""
    s = list(state)
    # Row 1: shift left 1
    s[1], s[5], s[9], s[13] = state[5], state[9], state[13], state[1]
    # Row 2: shift left 2
    s[2], s[6], s[10], s[14] = state[10], state[14], state[2], state[6]
    # Row 3: shift left 3
    s[3], s[7], s[11], s[15] = state[15], state[3], state[7], state[11]
    return s


def inv_shift_rows(state: list) -> list:
    s = list(state)
    s[1], s[5], s[9], s[13] = state[13], state[1], state[5], state[9]
    s[2], s[6], s[10], s[14] = state[10], state[14], state[2], state[6]
    s[3], s[7], s[11], s[15] = state[7], state[11], state[15], state[3]
    return s


def mix_columns(state: list) -> list:
    out = list(state)
    for c in range(4):
        i = c * 4
        s0, s1, s2, s3 = state[i], state[i+1], state[i+2], state[i+3]
        out[i]   = gmul(2, s0) ^ gmul(3, s1) ^ s2 ^ s3
        out[i+1] = s0 ^ gmul(2, s1) ^ gmul(3, s2) ^ s3
        out[i+2] = s0 ^ s1 ^ gmul(2, s2) ^ gmul(3, s3)
        out[i+3] = gmul(3, s0) ^ s1 ^ s2 ^ gmul(2, s3)
    return out


def inv_mix_columns(state: list) -> list:
    out = list(state)
    for c in range(4):
        i = c * 4
        s0, s1, s2, s3 = state[i], state[i+1], state[i+2], state[i+3]
        out[i]   = gmul(14, s0) ^ gmul(11, s1) ^ gmul(13, s2) ^ gmul(9, s3)
        out[i+1] = gmul(9, s0) ^ gmul(14, s1) ^ gmul(11, s2) ^ gmul(13, s3)
        out[i+2] = gmul(13, s0) ^ gmul(9, s1) ^ gmul(14, s2) ^ gmul(11, s3)
        out[i+3] = gmul(11, s0) ^ gmul(13, s1) ^ gmul(9, s2) ^ gmul(14, s3)
    return out


def add_round_key(state: list, round_key: list) -> list:
    return [s ^ k for s, k in zip(state, round_key)]


def key_expansion(key: list) -> list:
    """Expand 16-byte key into 11 round keys (176 bytes)."""
    w = list(key)  # 16 bytes
    for i in range(4, 44):
        temp = w[(i-1)*4:(i-1)*4+4]
        if i % 4 == 0:
            # RotWord + SubWord + Rcon
            temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            temp[0] ^= RCON[i // 4 - 1]
        w.extend([w[(i-4)*4+j] ^ temp[j] for j in range(4)])
    return w


def get_round_key(expanded_key: list, rnd: int) -> list:
    return expanded_key[rnd*16:(rnd+1)*16]


def aes128_encrypt(plaintext: list, key: list,
                   fault_round: int = -1, fault_byte: int = -1,
                   fault_value: int = 0) -> Tuple[list, list]:
    """AES-128 encryption with an optional fault at the input of fault_round; returns (ciphertext, round_states)."""
    expanded_key = key_expansion(key)
    state = add_round_key(list(plaintext), get_round_key(expanded_key, 0))
    round_states = [list(state)]

    for rnd in range(1, 11):
        # Inject fault at input of this round
        if rnd == fault_round and fault_byte >= 0:
            state[fault_byte] ^= fault_value

        state = sub_bytes(state)
        state = shift_rows(state)
        if rnd < 10:
            state = mix_columns(state)
        state = add_round_key(state, get_round_key(expanded_key, rnd))
        round_states.append(list(state))

    return state, round_states


def reverse_key_schedule(k10: list) -> list:
    """Recover K0 from K10 by reversing the AES-128 key schedule."""
    w = [0] * 176
    w[160:176] = list(k10)
    for rnd in range(9, -1, -1):
        for i in range(3, -1, -1):  # word index within round
            wi = rnd * 4 + i  # absolute word index
            if i > 0:
                for j in range(4):
                    w[wi*4+j] = w[(wi+4)*4+j] ^ w[(wi+3)*4+j]
            else:
                # wi is multiple of 4
                next_w = w[(wi+3)*4:(wi+3)*4+4]
                temp = [SBOX[next_w[1]], SBOX[next_w[2]], SBOX[next_w[3]], SBOX[next_w[0]]]
                temp[0] ^= RCON[rnd]
                for j in range(4):
                    w[wi*4+j] = w[(wi+4)*4+j] ^ temp[j]

    return w[0:16]


class SIMTFaultModel:
    """Behavioral model of SIMT fault propagation: lockstep threads share one fault, each yielding its own DFA pair."""

    def __init__(self, num_warps: int = 4, threads_per_warp: int = 4):
        self.num_warps = num_warps
        self.threads_per_warp = threads_per_warp
        self.total_threads = num_warps * threads_per_warp

    def encrypt_batch(self, plaintexts: list, key: list,
                      fault_round: int = -1, fault_byte: int = -1,
                      fault_value: int = 0,
                      fault_warp: int = -1, fault_thread: int = -1,
                      fault_scope: str = "thread") -> list:
        """Encrypt across all threads; fault_scope is thread, warp, memory or global; returns list of (ciphertext, was_faulted)."""
        results = []

        for w in range(self.num_warps):
            for t in range(self.threads_per_warp):
                tid = w * self.threads_per_warp + t
                if tid >= len(plaintexts):
                    break

                # Determine if this thread gets faulted
                inject = False
                if fault_round > 0 and fault_byte >= 0:
                    if fault_scope == "global":
                        inject = True
                    elif fault_scope == "memory" and fault_warp >= 0:
                        inject = True  # All threads affected by shared memory fault
                    elif fault_scope == "warp" and w == fault_warp:
                        inject = True  # All threads in target warp
                    elif fault_scope == "thread" and w == fault_warp and t == fault_thread:
                        inject = True

                fr = fault_round if inject else -1
                fb = fault_byte if inject else -1
                fv = fault_value if inject else 0

                ct, _ = aes128_encrypt(plaintexts[tid], key, fr, fb, fv)
                results.append((ct, inject))

        return results


def generate_random_plaintexts(n: int) -> list:
    """Generate n random 16-byte plaintexts."""
    return [list(np.random.randint(0, 256, 16)) for _ in range(n)]


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AES-128 SIMT Encryption Engine")
    parser.add_argument("--warps", type=int, default=4)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.test:
        # NIST test vector
        key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
        pt  = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
               0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
        expected_ct = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                       0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]

        ct, _ = aes128_encrypt(pt, key)
        assert ct == expected_ct, f"NIST test FAILED: {[hex(b) for b in ct]}"
        print("NIST AES-128 test vector: PASS")

        # Test key schedule reversal
        expanded = key_expansion(key)
        k10 = get_round_key(expanded, 10)
        k0_recovered = reverse_key_schedule(k10)
        assert k0_recovered == key, f"Key reversal FAILED"
        print("Key schedule reversal: PASS")

        # Test fault injection
        ct_golden, _ = aes128_encrypt(pt, key)
        ct_faulty, _ = aes128_encrypt(pt, key, fault_round=9, fault_byte=0, fault_value=0x01)
        diff = [g ^ f for g, f in zip(ct_golden, ct_faulty)]
        nonzero = sum(1 for d in diff if d != 0)
        print(f"Round-9 single byte fault: {nonzero} ciphertext bytes differ")
        assert nonzero == 4, f"Expected 4 differing bytes, got {nonzero}"
        print("Fault propagation test: PASS")

        # Test SIMT engine
        engine = SIMTFaultModel(num_warps=args.warps, threads_per_warp=args.threads)
        pts = generate_random_plaintexts(engine.total_threads)
        results = engine.encrypt_batch(pts, key, fault_round=9, fault_byte=0,
                                       fault_value=0x42, fault_warp=0,
                                       fault_scope="warp")
        faulted = sum(1 for _, f in results if f)
        print(f"SIMT engine: {engine.total_threads} threads, {faulted} faulted (warp 0)")
        print("All tests PASSED")
