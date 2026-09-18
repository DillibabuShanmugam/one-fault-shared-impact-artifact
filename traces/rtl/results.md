# RTL commit-stage fault, measured 2026-07-13

One fault injected at the write-back stage of the Vortex core corrupted all four active
lanes of the warp, on the write-back bus and in the memory written by the dependent store.
This is the RTL counterpart of the SIMT amplification we obtain in the SimX model.

## Platform

| Item | Value |
|---|---|
| Simulator | Vortex rtlsim (Verilator 5.037), cycle-accurate RTL of the core |
| Configuration | 1 core, 4 warps, 4 threads per warp, SIMD_WIDTH=4, ISSUE_WIDTH=1, XLEN=32 |
| Write-back bus | `writeback_t.data` = `logic [SIMD_WIDTH-1:0][XLEN-1:0]`, gated by `tmask` |
| Injection site | `hw/rtl/core/VX_commit.sv`, the per-lane write-back data assignment |
| Kernel | `amp_kernel.S`: a four-lane warp, each lane writes `0xA5A50000 | tid` |

Build times on this host with Verilator 5.037 and `-j16`: about 43 s for a full Verilation
of the core, about 13 s to rebuild after a harness change, about 5 s with a warm ccache.

## Injection primitive

The hook sits in `VX_commit.sv` and is off by default. With `fi_enable=0` the write-back path
is a bit-identical pass-through. When armed it fires once and XORs `FI_MASK` into the committed
register data of every active lane of the targeted write-back, before the register file is written.
A latch enforces the single fire. Control comes from simulator plusargs, which mirror the SimX
options one for one.

| Plusarg | Meaning | SimX option |
|---|---|---|
| `+fi_enable=1` | arm the hook | enable flag |
| `+fi_warp=W` | target warp | `-W` |
| `+fi_instr=N` | target the N-th retiring write-back of that warp | `-i` |
| `+fi_mask=0xHH` | XOR mask applied to every active lane | `-x` |

## Target instruction

A golden enumeration with `fi_mask=0` never injects and lists every warp-0 write-back:

```
[FI] pass  wid=0 instr=0 rd=11 tmask=0001 data= [0]=0x0000000f              (li a1,15, pre-tmc, one lane)
[FI] pass  wid=0 instr=1 rd=10 tmask=1111 data= [0]=0x0 [1]=0x1 [2]=0x2 [3]=0x3   (csrr a0,tid)
[FI] pass  wid=0 instr=2 rd=15 tmask=1111 data= [0..3]=0xa5a50000           (lui a5)
[FI] pass  wid=0 instr=3 rd=15 tmask=1111 data= [0]=0xa5a50000 [1]=0xa5a50001 [2]=0xa5a50002 [3]=0xa5a50003
```

Write-back index 3 is `or a5,a5,a0` with `rd=x15` and `tmask=1111`. It produces the per-lane
value `0xA5A50000 | tid`, so it is the instruction we target.

## Result

```
rtlsim amp_kernel.bin +fi_enable=1 +fi_warp=0 +fi_instr=3 +fi_mask=0x000000FF

[FI] INJECT wid=0 instr=3 rd=15 tmask=1111 mask=0x000000ff
[FI]   lane 0 ACTIVE  0xa5a50000 -> 0xa5a500ff
[FI]   lane 1 ACTIVE  0xa5a50001 -> 0xa5a500fe
[FI]   lane 2 ACTIVE  0xa5a50002 -> 0xa5a500fd
[FI]   lane 3 ACTIVE  0xa5a50003 -> 0xa5a500fc
[RESULT] lane0=0xa5a500ff lane1=0xa5a500fe lane2=0xa5a500fd lane3=0xa5a500fc
```

| | lane 0 | lane 1 | lane 2 | lane 3 | corrupted |
|---|---|---|---|---|---|
| tmask | 1 | 1 | 1 | 1 | 4 active |
| golden write-back | a5a50000 | a5a50001 | a5a50002 | a5a50003 | |
| faulty write-back | a5a500ff | a5a500fe | a5a500fd | a5a500fc | 4 of 4 |
| golden memory | a5a50000 | a5a50001 | a5a50002 | a5a50003 | |
| faulty memory | a5a500ff | a5a500fe | a5a500fd | a5a500fc | 4 of 4 |

One fault event was injected and the latch then blocked any further fire. Four lanes were
active and all four were corrupted, each by exactly the mask. Vortex has no operand bypass,
so the store read the faulted register and the corruption reached memory. The effect is
therefore architecturally visible and not confined to the commit stage.

Scope: this is an RTL simulation of a four-lane test kernel. It is not a silicon measurement,
and the kernel is not the AES binary.

## Reproduce

```
VORTEX=/path/to/patched/vortex campaigns/rtl_run_experiment.sh
```

The script builds the kernel, runs the golden enumeration, then runs the faulty injection.
Raw output from the original run is in `golden_enum_raw.txt` and `faulty_run_raw.txt`.
The RTL change itself is one per-lane XOR in `VX_commit.sv` that is a no-op unless armed;
the harness change only forwards the plusargs and dumps the result buffer.

Absolute paths in the archived build log are redacted to `<workspace>`.
