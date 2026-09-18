# Build the bare-metal AES-128 kernel (aes.bin) for Vortex SimX with the RISC-V GCC toolchain
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute
RISCV     ?= $(HOME)/tools/riscv32-gnu-toolchain
CC        := $(RISCV)/bin/riscv32-unknown-elf-gcc
OBJCOPY   := $(RISCV)/bin/riscv32-unknown-elf-objcopy
OBJDUMP   := $(RISCV)/bin/riscv32-unknown-elf-objdump

CFLAGS    := -march=rv32imaf -mabi=ilp32f -O2 -nostdlib -nostartfiles \
             -ffreestanding -fno-builtin -fdata-sections -ffunction-sections \
             -mcmodel=medany -Wall
LDFLAGS   := -T link.ld -nostdlib -Wl,--gc-sections

VORTEX_ROOT ?= $(abspath ../vortex)
SIMX        ?= $(VORTEX_ROOT)/build/sim/simx/simx

all: aes.bin aes.dump

aes.elf: start.S aes.c link.ld
	$(CC) $(CFLAGS) start.S aes.c -o $@ $(LDFLAGS)

aes.bin: aes.elf
	$(OBJCOPY) -O binary $< $@

aes.dump: aes.elf
	$(OBJDUMP) -d $< > $@

run: aes.bin
	$(SIMX) -c 1 -w 1 -t 1 aes.bin

run-warps: aes.bin
	$(SIMX) -c 1 -w 4 -t 4 aes.bin

clean:
	rm -f aes.elf aes.bin aes.dump
