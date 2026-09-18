#!/usr/bin/env python3
# Python reference Ascon-128 matching the bare-metal C in ascon.c.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute

ROUND_CONSTANTS = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
                   0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
IV = 0x80400c0600000000
MASK64 = (1 << 64) - 1


def rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK64


def ascon_round(s, C):
    s = list(s)
    s[2] ^= C
    s[0] ^= s[4]; s[4] ^= s[3]; s[2] ^= s[1]
    t = [(~s[i]) & MASK64 for i in range(5)]
    t[0] &= s[1]; t[1] &= s[2]; t[2] &= s[3]; t[3] &= s[4]; t[4] &= s[0]
    s[0] ^= t[1]; s[1] ^= t[2]; s[2] ^= t[3]; s[3] ^= t[4]; s[4] ^= t[0]
    s[1] ^= s[0]; s[0] ^= s[4]; s[3] ^= s[2]; s[2] = (~s[2]) & MASK64
    s[0] = s[0] ^ rotr(s[0], 19) ^ rotr(s[0], 28)
    s[1] = s[1] ^ rotr(s[1], 61) ^ rotr(s[1], 39)
    s[2] = s[2] ^ rotr(s[2],  1) ^ rotr(s[2],  6)
    s[3] = s[3] ^ rotr(s[3], 10) ^ rotr(s[3], 17)
    s[4] = s[4] ^ rotr(s[4],  7) ^ rotr(s[4], 41)
    return s


def P12(s):
    for i in range(12):
        s = ascon_round(s, ROUND_CONSTANTS[i])
    return s


def ascon128_tag_empty(key, nonce):
    K0 = int.from_bytes(key[0:8], 'big')
    K1 = int.from_bytes(key[8:16], 'big')
    N0 = int.from_bytes(nonce[0:8], 'big')
    N1 = int.from_bytes(nonce[8:16], 'big')
    s = [IV, K0, K1, N0, N1]
    s = P12(s)
    s[3] ^= K0
    s[4] ^= K1
    s[4] ^= 0x0000000000000001
    s[0] ^= 0x8000000000000000
    s[1] ^= K0
    s[2] ^= K1
    s = P12(s)
    s[3] ^= K0
    s[4] ^= K1
    return s[3].to_bytes(8, 'big') + s[4].to_bytes(8, 'big')


if __name__ == "__main__":
    key = bytes(range(16))
    nonce = bytes(range(16))
    tag = ascon128_tag_empty(key, nonce)
    print(f"key   = {key.hex()}")
    print(f"nonce = {nonce.hex()}")
    print(f"tag   = {tag.hex()}")
    expected = "e355159f292911f794cb1432a0103a8a"
    print(f"simx  = {expected}")
    print(f"match = {tag.hex() == expected}")
