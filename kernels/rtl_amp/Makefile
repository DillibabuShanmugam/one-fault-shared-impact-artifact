# Build the SIMT amplification test kernel (amp_kernel.bin) for Vortex rtlsim
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute
RVCC    := $(HOME)/tools/riscv32-gnu-toolchain/bin/riscv32-unknown-elf-gcc
OBJCOPY := $(HOME)/tools/riscv32-gnu-toolchain/bin/riscv32-unknown-elf-objcopy
OBJDUMP := $(HOME)/tools/riscv32-gnu-toolchain/bin/riscv32-unknown-elf-objdump

CFLAGS  := -march=rv32imaf -mabi=ilp32f -O1 -ffreestanding -nostdlib -nostartfiles -fno-inline

all: amp_kernel.bin

# Hand-written assembly kernel (fast, deterministic) -- primary target.
amp_kernel.elf: amp_kernel.S link.ld
	$(RVCC) $(CFLAGS) -T link.ld amp_kernel.S -o $@

amp_kernel.bin: amp_kernel.elf
	$(OBJCOPY) -O binary $< $@
	$(OBJDUMP) -d $< > amp_kernel.dis

# C reference kernel (kept for documentation).
amp_kernel_c.elf: start.S amp_kernel.c link.ld
	$(RVCC) $(CFLAGS) -T link.ld start.S amp_kernel.c -o $@

clean:
	rm -f amp_kernel.elf amp_kernel.bin amp_kernel.dis amp_kernel_c.elf
