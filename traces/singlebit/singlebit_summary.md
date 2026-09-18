# Single-Bit Fault Campaign Summary

Restricted to single-bit XOR masks (powers of two only) as a more conservative physical fault model than the arbitrary 8-bit masks of the main campaign.

## Numbers
- Total runs: 593
- Round-9 4-byte diagonal hits: 531
- Diff distribution: {4: 531, 16: 44, 0: 14, 12: 1, 15: 2, 8: 1}
- Column distribution: {0: 141, 2: 148, 1: 140, 3: 102}
- Wall time: 483.9s

## Comparison vs multi-bit campaign

- Multi-bit (5 masks: 0xff,0x80,0x55,0x2a,0x01): 669 round-9 hits across instr 3700..4010
- Single-bit (8 masks: 0x01..0x80): 531 round-9 hits
- The single-bit primitive is strictly more constrained and corresponds to the standard CPU DFA bit-flip model (Biham-Shamir 1997, Piret 2003).
