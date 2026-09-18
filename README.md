# One Fault, Shared Impact: artifact

Fault propagation in AES and Ascon on the open-source Vortex RISC-V GPGPU.

Every result is a simulation on Vortex SimX or the Verilator RTL. There is no silicon measurement. The RTL check ran a four-lane test kernel, not the AES binary. The Ascon 128- and 192-fault figures are a modeled analysis.

## Check the paper's numbers

```
python3 verify_tables.py
```

Recomputes every Table II value from `traces/` and prints PASS or FAIL per row.

## Layout

| Path | One line |
|---|---|
| `patches/VORTEX_COMMIT.txt` | Vortex commit the patches apply to |
| `patches/simx_fault_instrument.patch` | Fault-injection instrument for SimX (`-i` instruction, `-x` mask, `-W` warp, `-T` thread, `-R` register) |
| `patches/rtl_commit_fault.patch` | Same instrument at the RTL commit stage (`+fi_enable +fi_warp +fi_instr +fi_mask`) |
| `kernels/aes/` | Single-lane AES-128 source and binary |
| `kernels/aes_simt/` | Four-lane batched AES-128 source and binary |
| `kernels/ascon/` | Ascon-128 finalization kernel, reference model, trace analysis |
| `kernels/rtl_amp/` | Four-lane RTL test kernel |
| `campaigns/` | Scripts that produced every trace set |
| `solver/` | AES DFA solver and 20-seed driver |
| `solver/ascon/` | Ascon DFA recovery and its result files |
| `traces/` | Trace sets behind Table II, one folder per experiment |
| `figures/` | Figure generators and plotted figures |

## Rebuild the simulator

```
git clone https://github.com/vortexgpgpu/vortex && cd vortex
git checkout $(cat ../patches/VORTEX_COMMIT.txt)
git apply ../patches/simx_fault_instrument.patch
make -C build/sim/simx
```

For the RTL check, also `git apply ../patches/rtl_commit_fault.patch` and build `rtlsim` (Verilator 5.037).

## Rebuild a kernel

```
make -C kernels/aes
```

Needs `riscv32-unknown-elf-gcc` 12.2. Shipped `.bin` files work without rebuilding.

## Inject one fault

```
simx -i 3800 -x 0x55 -W 0 -T 0 -R 15 kernels/aes/aes.bin
```

`-i` retired-instruction index, `-x` XOR mask, `-W`/`-T` warp and thread (`-1` = every lane), `-R` destination register. The round-9 window of the single-lane build spans instructions 3700 to 4010.

## Rerun a campaign

```
python3 campaigns/collect_real_traces.py        # AES recovery pairs
python3 campaigns/collect_arch_campaign.py      # round selectivity, 1054 sites
python3 campaigns/collect_singlebit_campaign.py # single-bit sweep, 593 faults
python3 campaigns/collect_simt_campaign.py      # four-lane kernel, 200 injections
python3 campaigns/collect_ascon_campaign.py     # Ascon finalization sweep, 1066 injections
VORTEX=/path/to/vortex campaigns/rtl_run_experiment.sh   # RTL commit-stage check
```

Each script writes its CSV next to it. The RTL script writes to `traces/rtl/rerun/`.

## Recover a key

```
python3 solver/multiseed_recovery.py                          # AES, 20 seeds, Table II rows 1-3
python3 solver/ascon/ascon_key_recovery.py --only minfaults   # Ascon 128 / 192 faults
python3 solver/ascon/ascon_key_recovery.py --only multikey    # Ascon 20 random keys
```

## Regenerate figures

```
python3 figures/generate_simt_amplification_figure.py
python3 figures/generate_ascon_figure.py
```

## Table II map

| Row | Value | File |
|---|---|---|
| AES 1 pair/column, 20 seeds | 0/20 | `traces/aes_recovery/multiseed_recovery.csv` |
| AES 2 pairs/column, 20 seeds | 20/20 | same |
| AES 8 pairs, solve time | 43.0 +/- 6.9 ms | same |
| AES 20 random keys | 19/20 | `traces/aes_recovery/real_simx_multikey.csv` |
| AES single-bit diagonals | 531 of 593 | `traces/singlebit/real_singlebit_campaign.csv` |
| Round selectivity | 4 / 1 bytes, 1054 sites | `traces/round_selectivity/real_arch_campaign.csv` |
| SIMT all-lane fires | 46 of 200 | `traces/simt/real_simt_campaign.csv` |
| SIMT injections for unique key | 4 | same (all 46 fires sit in one DFA column) |
| RTL lanes corrupted | 4/4 | `traces/rtl/faulty_run_raw.txt` |
| Ascon effective / usable | 778 / 403 | `traces/ascon/real_ascon_campaign.csv` |
| Ascon K1, modeled | 128 faults | `solver/ascon/ascon_minfaults.csv` |
| Ascon full key, modeled | 192 faults | `solver/ascon/ascon_recovery_results.csv` |

Trace sets for single-bit, SIMT and Ascon begin with one golden row; the paper's counts exclude it. The Ascon recovery runs on a modeled fault oracle because the SimX trace records instruction and mask but not the struck lane and column. The workstation path in `traces/rtl/results.md` and `rtlsim_build_clean.log` is redacted to `<workspace>`.
