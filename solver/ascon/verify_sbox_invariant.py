#!/usr/bin/env python3
# Independent verification of the Ascon DFA claims; derives the S-box from first principles instead of importing the constant.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute
import os, sys, numpy as np
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ascon_ref import rotr, MASK64
import ascon_key_recovery as R

# Derive the Ascon 5-bit S-box by running R.sbox_state on single-column inputs (lane0=MSB..lane4=LSB)
def derive_sbox():
    sb = [0]*32
    for x in range(32):
        # place 5-bit value x into column 0 across 5 lanes (lane0=MSB=bit4)
        s = [ ((x >> (4-L)) & 1) for L in range(5) ]
        out = R.sbox_state(s)  # note: no AddRC here
        y = sum(((out[L] & 1) << (4-L)) for L in range(5))
        sb[x] = y
    return sb

DERIVED = derive_sbox()
print("[1] Derived S-box == code SBOX constant:", DERIVED == R.SBOX)
# also compare to canonical published Ascon S-box
CANON = [0x4,0xb,0x1f,0x14,0x1a,0x15,0x9,0x2,0x1b,0x5,0x8,0x12,0x1d,0x3,0x6,0x1c,
         0x1e,0x13,0x7,0xe,0x0,0xd,0x11,0x18,0x10,0xc,0x1,0x19,0x16,0xa,0xf,0x17]
print("    Code SBOX == canonical Ascon S-box :", R.SBOX == CANON)

S = R.SBOX
# bit indexing: output lane L -> bit (4-L). lane3->bit1, lane4->bit0, lane2->bit2
def b(v, lane): return (v >> (4-lane)) & 1

# CLAIM 2: key cancellation, finalization s[3]^=K0; s[4]^=K1 => tag diff cancels K
from ascon_ref import ascon128_tag_empty
import random
rng = random.Random(7)
key = bytes(rng.randrange(256) for _ in range(16)); nonce = bytes(range(16))
orc = R.AsconOracle(key, nonce)
g = orc.golden_tag()
f = orc.faulty_tag(0, 5)
# recompute S_out diff on lanes 3,4 WITHOUT key, from oracle internals
Uf = list(orc.U); Uf[0]^=(1<<5)
Sf = R.linear(R.sbox_state(orc._addrc(Uf)))
d3 = orc.S_out[3]^Sf[3]; d4 = orc.S_out[4]^Sf[4]
tg0=int.from_bytes(g[0:8],'big'); tg1=int.from_bytes(g[8:16],'big')
tf0=int.from_bytes(f[0:8],'big'); tf1=int.from_bytes(f[8:16],'big')
print("[2] tag-diff == S_out-diff (K cancels): lane3", (tg0^tf0)==d3, " lane4", (tg1^tf1)==d4)

# CLAIM 3: LINV inverts forward linear matrix (bijection on GF(2)^64)
ok3 = True
for i in (2,3,4):
    M = R.linmat(*R.ROT[i]); Minv = R.LINV[i]
    prod = (Minv.dot(M) % 2)
    if not np.array_equal(prod, np.eye(64, dtype=np.uint8)): ok3=False
    # also check forward is bijection: full rank == inverse exists (already implied)
print("[3] LINV[i] . M[i] == I  for i in {2,3,4}:", ok3)

# CLAIM 4: ddt_candidates(e,obs3,obs4) must equal exactly {x: bit1(diff)==obs3, bit0==obs4}
ok4 = True
for e in range(1,32):
    for x in range(32):
        d = S[x]^S[x^e]
        cand = R.ddt_candidates(e, (d>>1)&1, d&1)
        if x not in cand: ok4=False
    # cross-check: recovered candidate sets partition all 32
print("[4] ddt_candidates consistent with brute S-box diff:", ok4)

# CLAIM 5a: for every e and x, bits(lane3,lane4) of S(x)^S(x^e) equal those of S(x^4)^S(x^4^e)
inv_34_holds = True
counterex = None
for e in range(32):
    for x in range(32):
        d  = S[x]     ^ S[x^e]
        d4 = S[x^4]   ^ S[x^4^e]
        if (b(d,3), b(d,4)) != (b(d4,3), b(d4,4)):
            inv_34_holds = False; counterex=(e,x); break
    if not inv_34_holds: break
print("[5a] lane3/4 output diff invariant under x->x^4 (ALL e,x):", inv_34_holds, counterex or "")

# (5b) bit2 (lane2 output) ALWAYS differs between x and x^4
bit2_always = all(((S[x]>>2)&1) != ((S[x^4]>>2)&1) for x in range(32))
print("[5b] lane2 output bit always differs x vs x^4 (ALL x):", bit2_always)
# and the code's stated constant S(x)&3 ^ S(x^4)&3 == 0b10
const_low2 = set((S[x]&3) ^ (S[x^4]&3) for x in range(32))
print("    (S(x)&3)^(S(x^4)&3) constant set:", const_low2, "== {2}?", const_low2=={2})

# (5c) lane4 output bit invariant under x->x^4 (K1 independent of the lane-2 input bit)
lane4_inv = all(b(S[x],4)==b(S[x^4],4) for x in range(32))
print("[5c] lane4 output bit invariant under x->x^4 (=> K1 free):", lane4_inv)
# and lane3 out bit FLIPS (=> K0 ambiguous):
lane3_flip = all(b(S[x],3)!=b(S[x^4],3) for x in range(32))
print("    lane3 output bit ALWAYS flips under x->x^4 (=> K0 ambiguous):", lane3_flip)

# (5d) over all 5 single-bit masks, is the residual candidate set exactly {x, x^4}?
lane_mask = {L: 1<<(4-L) for L in range(5)}
def obs(x,e):
    d=S[x]^S[x^e]; return ((d>>1)&1, d&1)
worst=set()
for x0 in range(32):
    # signature over ALL 5 single-bit masks
    sig=tuple(obs(x0, lane_mask[L]) for L in range(5))
    grp=[x for x in range(32) if tuple(obs(x,lane_mask[L]) for L in range(5))==sig]
    worst.add(frozenset(grp))
sizes=set(len(g) for g in worst)
pairs_ok=all(all((a^bb) in (0,4) for a in g for bb in g) for g in worst)
print("[5d] residual group sizes over ALL 5 masks:", sorted(sizes),
      "| all groups == {x,x^4}:", pairs_ok)

# CLAIM 1: data-flow, grep recovery fns for any use of key/K0/K1
import inspect
for fn in (R.recover_columns, R.recover_key, R._obs_bits, R.ddt_candidates):
    src=inspect.getsource(fn)
    hits=[t for t in ("self.key","self.K0","self.K1",".key","oracle.key") if t in src]
    print(f"[1-dataflow] {fn.__name__}: key-refs {hits if hits else 'NONE'}")
