# Architectural fault campaign on Vortex SimX

Every fault here is injected in the SimX execute pipeline (`sim/simx/execute.cpp`) on the
integer register write-back, scoped by warp, thread and retired-instruction index.

## Traces collected

1,118 traces in total:

- 669 in the round-9 window, each giving a four-byte DFA diagonal
- 385 in the round-10 window, each giving a single differing byte
- 64 samples used to check that the fault scoping works

The 669 round-9 traces spread across the four DFA columns as 166, 180, 167 and 156.

## Key recovery

| Pairs per column | Total pairs | Candidates | Unique key | Solve time |
|---|---|---|---|---|
| 1 | 4 | 10000 | no | 368 ms |
| 2 | 8 | 1 | yes | 53.9 ms |
| 3 | 12 | 1 | yes | 79.7 ms |
| 5 | 20 | 1 | yes | 134.2 ms |
| 8 | 32 | 1 | yes | 214.3 ms |
| 10 | 40 | 1 | yes | 269.1 ms |

The recovered key is `2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c`, the FIPS-197 test key.
Two pairs per column is the first setting that pins the key uniquely, which matches the
classical DFA bound.

## Round selectivity

| Region | Traces | Differing ciphertext bytes | DFA-usable |
|---|---|---|---|
| Round 9, instructions 3700 to 4010 | 669 | 4 | yes |
| Round 10, instructions 4020 to 4400 | 385 | 1 | no |

A round-9 fault spreads through MixColumns and reaches four ciphertext bytes. Round 10 has no
MixColumns, so a fault there stays in one byte. The retired-instruction index alone therefore
selects which round is hit.

## Fault scoping

For each round-9 instruction we tried all 16 combinations of warp and thread, over four
instructions, for 64 runs. Exactly four fired, one per instruction, all on warp 0 and thread 0.
That is the expected result for this single-lane AES binary: the fault fires only when the
targeted instruction retires on the targeted lane, so the scoping is genuinely lane-aware.

## Trace classifier

| Traces | Threshold on the differing-byte count | Random forest |
|---|---|---|
| Clean, 1054 | 100.0% | 100.0% |
| With one or two noise bytes | 45.5% | 100.0% |

On clean traces a plain threshold is enough. Once noise bytes are added the threshold collapses
while the classifier holds, because it uses the per-byte Hamming weights and the column
distribution rather than the byte count alone.

## Two solvers

| Solver | Clean, 8 pairs | Outcome |
|---|---|---|
| Concrete | 49.7 ms | unique correct key |
| Z3 | 22.7 s | unique correct key |

On clean data the concrete solver is 456 times faster, so it is the one we use. Z3 earns its
place only when the differential is corrupted and the column is unknown: there the concrete
detector returns nothing on 40 column hypotheses, while Z3 still returns candidates for 7 of
them.

## Files behind these numbers

- `real_arch_campaign.csv`, this campaign
- `kernels/aes/`, the bare-metal AES-128 binary and its sources
- `patches/simx_fault_instrument.patch`, the injection point and its command-line options
