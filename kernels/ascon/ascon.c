// Ascon-128 bare-metal reference (non-bitsliced, no libc) for Vortex SimX: tag of an empty plaintext with empty AD
// Authors: Dillibabu Shanmugam and Patrick Schaumont
// Affiliation: Worcester Polytechnic Institute

#include <stdint.h>

#define RATE      8                          // bytes
#define PA_ROUNDS 12
#define PB_ROUNDS 6
#define IV ((uint64_t)0x80400c0600000000ULL) // Ascon-128 IV: k=128, r=64, a=12, b=6

// Endianness helpers (Vortex is little-endian RV32IMAF)
static inline uint64_t U64BIG(uint64_t x) {
    // Big-endian load: Ascon spec uses MSB-first byte order.
    return ((x & 0xFF00000000000000ULL) >> 56) |
           ((x & 0x00FF000000000000ULL) >> 40) |
           ((x & 0x0000FF0000000000ULL) >> 24) |
           ((x & 0x000000FF00000000ULL) >>  8) |
           ((x & 0x00000000FF000000ULL) <<  8) |
           ((x & 0x0000000000FF0000ULL) << 24) |
           ((x & 0x000000000000FF00ULL) << 40) |
           ((x & 0x00000000000000FFULL) << 56);
}

static inline uint64_t ROR64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

// Round constants (12 rounds)
static const uint64_t round_constants[12] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
    0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

// One Ascon permutation round on a 5-word state s[0..4].
static inline void ascon_round(uint64_t s[5], uint64_t C) {
    uint64_t x0 = s[0], x1 = s[1], x2 = s[2], x3 = s[3], x4 = s[4];
    uint64_t t0, t1, t2, t3, t4;

    // Add round constant to x2
    x2 ^= C;

    // Substitution layer (Ascon S-box, 5-bit, applied bitslice across 64 bits)
    x0 ^= x4; x4 ^= x3; x2 ^= x1;
    t0 = x0; t1 = x1; t2 = x2; t3 = x3; t4 = x4;
    t0 = ~t0; t1 = ~t1; t2 = ~t2; t3 = ~t3; t4 = ~t4;
    t0 &= x1; t1 &= x2; t2 &= x3; t3 &= x4; t4 &= x0;
    x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
    x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = ~x2;

    // Linear diffusion layer
    s[0] = x0 ^ ROR64(x0, 19) ^ ROR64(x0, 28);
    s[1] = x1 ^ ROR64(x1, 61) ^ ROR64(x1, 39);
    s[2] = x2 ^ ROR64(x2,  1) ^ ROR64(x2,  6);
    s[3] = x3 ^ ROR64(x3, 10) ^ ROR64(x3, 17);
    s[4] = x4 ^ ROR64(x4,  7) ^ ROR64(x4, 41);
}

// Permutation P_a (12 rounds)
static void P12(uint64_t s[5]) {
    for (int i = 0; i < PA_ROUNDS; i++)
        ascon_round(s, round_constants[i]);
}

// Permutation P_b (6 rounds)
static void P6(uint64_t s[5]) {
    for (int i = PA_ROUNDS - PB_ROUNDS; i < PA_ROUNDS; i++)
        ascon_round(s, round_constants[i]);
}

// Ascon-128 tag for empty associated data and empty plaintext: key[16], nonce[16] -> tag[16]
static void ascon128_tag_empty(const uint8_t key[16], const uint8_t nonce[16],
                                uint8_t tag[16]) {
    uint64_t s[5];
    uint64_t K0, K1, N0, N1;

    // Load big-endian
    K0 = U64BIG(((const uint64_t*)key)[0]);
    K1 = U64BIG(((const uint64_t*)key)[1]);
    N0 = U64BIG(((const uint64_t*)nonce)[0]);
    N1 = U64BIG(((const uint64_t*)nonce)[1]);

    // Initialization
    s[0] = IV;
    s[1] = K0;
    s[2] = K1;
    s[3] = N0;
    s[4] = N1;
    P12(s);
    s[3] ^= K0;
    s[4] ^= K1;

    // Empty AD: still domain-separation step (one bit padded into rate)
    s[4] ^= 0x0000000000000001ULL;

    // Empty plaintext: nothing to absorb/squeeze, only the padding bit
    s[0] ^= 0x8000000000000000ULL; // 1-bit pad on empty block

    // Finalization
    s[1] ^= K0;
    s[2] ^= K1;
    P12(s);
    s[3] ^= K0;
    s[4] ^= K1;

    // Tag
    ((uint64_t*)tag)[0] = U64BIG(s[3]);
    ((uint64_t*)tag)[1] = U64BIG(s[4]);
}

// result_buf layout (read by SimX host, must match the -A flag): [0..15] key, [16..31] nonce, [32..47] tag, [48] done flag
volatile uint8_t result_buf[64] __attribute__((section(".result_buf"))) = {0};

// Memory-mapped fault control (legacy, retained for cross-validation)
volatile uint32_t fault_ctrl[8] __attribute__((section(".fault_ctrl"))) = {0};

static const uint8_t default_key[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t default_nonce[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};

int main(void) {
    uint8_t key[16], nonce[16], tag[16];

    // If host left result_buf empty, use NIST KAT inputs
    int empty_key = 1;
    for (int i = 0; i < 16; i++) if (result_buf[i] != 0) { empty_key = 0; break; }
    if (empty_key) {
        for (int i = 0; i < 16; i++) result_buf[i] = default_key[i];
    }
    int empty_nonce = 1;
    for (int i = 0; i < 16; i++) if (result_buf[16+i] != 0) { empty_nonce = 0; break; }
    if (empty_nonce) {
        for (int i = 0; i < 16; i++) result_buf[16+i] = default_nonce[i];
    }

    for (int i = 0; i < 16; i++) key[i]   = result_buf[i];
    for (int i = 0; i < 16; i++) nonce[i] = result_buf[16+i];

    ascon128_tag_empty(key, nonce, tag);

    for (int i = 0; i < 16; i++) result_buf[32+i] = tag[i];
    result_buf[48] = 1;
    return 0;
}
