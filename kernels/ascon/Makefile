# Build the bare-metal Ascon-128 kernel (ascon.bin) for Vortex SimX with the RISC-V GCC toolchain
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

all: ascon.bin ascon.dump

ascon.elf: start.S ascon.c link.ld
	$(CC) $(CFLAGS) start.S ascon.c -o $@ $(LDFLAGS)

ascon.bin: ascon.elf
	$(OBJCOPY) -O binary $< $@

ascon.dump: ascon.elf
	$(OBJDUMP) -d $< > $@

run: ascon.bin
	$(SIMX) ascon.bin

clean:
	rm -f ascon.elf ascon.bin ascon.dump
