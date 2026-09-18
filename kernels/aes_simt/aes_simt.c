// AES-128 batched across the SIMT lanes of warp 0 on Vortex: each lane encrypts a different plaintext under one key
// Authors: Dillibabu Shanmugam and Patrick Schaumont
// Affiliation: Worcester Polytechnic Institute

#include <stdint.h>

// Vortex kernel runtime headers for per-thread bring-up (custom-0 = 0x0B)
#include "vx_intrinsics.h"
#include "vx_spawn.h"

// AES-128 (same algorithm as aes.c, no fault_ctrl path)
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t rcon[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static inline uint8_t xtime(uint8_t a) {
    return (a << 1) ^ ((a >> 7) * 0x1b);
}

static void key_expansion(const uint8_t *key, uint8_t *rk) {
    for (int i = 0; i < 16; i++) rk[i] = key[i];
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        t[0]=rk[(i-1)*4+0]; t[1]=rk[(i-1)*4+1];
        t[2]=rk[(i-1)*4+2]; t[3]=rk[(i-1)*4+3];
        if (i % 4 == 0) {
            uint8_t tmp = t[0];
            t[0] = sbox[t[1]] ^ rcon[i/4 - 1];
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[tmp];
        }
        for (int j = 0; j < 4; j++) rk[i*4+j] = rk[(i-4)*4+j] ^ t[j];
    }
}

static void aes128_encrypt(const uint8_t *pt, const uint8_t *key, uint8_t *ct) {
    uint8_t rk[176];
    uint8_t s[16];
    key_expansion(key, rk);
    for (int i = 0; i < 16; i++) s[i] = pt[i] ^ rk[i];
    for (int round = 1; round < 10; round++) {
        for (int i = 0; i < 16; i++) s[i] = sbox[s[i]];
        uint8_t t;
        t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
        t=s[2]; s[2]=s[10]; s[10]=t;
        t=s[6]; s[6]=s[14]; s[14]=t;
        t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
        for (int c = 0; c < 4; c++) {
            uint8_t s0=s[c*4+0], s1=s[c*4+1], s2=s[c*4+2], s3=s[c*4+3];
            uint8_t tt = s0^s1^s2^s3;
            s[c*4+0] ^= tt ^ xtime(s0^s1);
            s[c*4+1] ^= tt ^ xtime(s1^s2);
            s[c*4+2] ^= tt ^ xtime(s2^s3);
            s[c*4+3] ^= tt ^ xtime(s3^s0);
        }
        for (int i = 0; i < 16; i++) s[i] ^= rk[round*16+i];
    }
    for (int i = 0; i < 16; i++) s[i] = sbox[s[i]];
    uint8_t t;
    t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    t=s[2]; s[2]=s[10]; s[10]=t;
    t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
    for (int i = 0; i < 16; i++) ct[i] = s[i] ^ rk[160+i];
}

// SIMT batched layout
#define NUM_LANES 4

// result_buf at a fixed address via the .result_buf section (reserved in link_simt.ld)
volatile uint8_t result_buf[256] __attribute__((section(".result_buf"),aligned(16))) = {0};
// result_buf layout: [0..63] 4 x 16-byte plaintexts, [64..79] key, [80..143] 4 x 16-byte ciphertexts, [144] done flag, [145] lanes executed

static const uint8_t default_key[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};
static const uint8_t default_pts[4][16] = {
    {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34},
    {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
    {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00},
    {0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}
};

volatile uint8_t lane_done[NUM_LANES] __attribute__((section(".lane_done"))) = {0};

// Per-lane scratch: SIMT lanes share SP here, so stack locals would collide
static volatile uint8_t per_lane_scratch[NUM_LANES][240]
    __attribute__((aligned(16)));
// per_lane_scratch[tid] layout: [0..15] pt, [16..31] key, [32..47] ct, [48..223] round keys (176 bytes)

static void lane_encrypt_inplace(volatile uint8_t *pt, volatile uint8_t *key,
                                  volatile uint8_t *ct, volatile uint8_t *rk) {
    // Inline key expansion + encryption on caller-supplied buffers (no stack arrays)
    for (int i = 0; i < 16; i++) rk[i] = key[i];
    for (int i = 4; i < 44; i++) {
        uint8_t t0=rk[(i-1)*4+0], t1=rk[(i-1)*4+1], t2=rk[(i-1)*4+2], t3=rk[(i-1)*4+3];
        if (i % 4 == 0) {
            uint8_t tmp = t0;
            t0 = sbox[t1] ^ rcon[i/4 - 1];
            t1 = sbox[t2];
            t2 = sbox[t3];
            t3 = sbox[tmp];
        }
        rk[i*4+0] = rk[(i-4)*4+0] ^ t0;
        rk[i*4+1] = rk[(i-4)*4+1] ^ t1;
        rk[i*4+2] = rk[(i-4)*4+2] ^ t2;
        rk[i*4+3] = rk[(i-4)*4+3] ^ t3;
    }
    // state in ct buffer
    for (int i = 0; i < 16; i++) ct[i] = pt[i] ^ rk[i];
    for (int round = 1; round < 10; round++) {
        for (int i = 0; i < 16; i++) ct[i] = sbox[ct[i]];
        uint8_t t;
        t=ct[1]; ct[1]=ct[5]; ct[5]=ct[9]; ct[9]=ct[13]; ct[13]=t;
        t=ct[2]; ct[2]=ct[10]; ct[10]=t;
        t=ct[6]; ct[6]=ct[14]; ct[14]=t;
        t=ct[15]; ct[15]=ct[11]; ct[11]=ct[7]; ct[7]=ct[3]; ct[3]=t;
        for (int c = 0; c < 4; c++) {
            uint8_t s0=ct[c*4+0], s1=ct[c*4+1], s2=ct[c*4+2], s3=ct[c*4+3];
            uint8_t tt = s0^s1^s2^s3;
            ct[c*4+0] ^= tt ^ xtime(s0^s1);
            ct[c*4+1] ^= tt ^ xtime(s1^s2);
            ct[c*4+2] ^= tt ^ xtime(s2^s3);
            ct[c*4+3] ^= tt ^ xtime(s3^s0);
        }
        for (int i = 0; i < 16; i++) ct[i] ^= rk[round*16+i];
    }
    for (int i = 0; i < 16; i++) ct[i] = sbox[ct[i]];
    uint8_t t;
    t=ct[1]; ct[1]=ct[5]; ct[5]=ct[9]; ct[9]=ct[13]; ct[13]=t;
    t=ct[2]; ct[2]=ct[10]; ct[10]=t;
    t=ct[6]; ct[6]=ct[14]; ct[14]=t;
    t=ct[15]; ct[15]=ct[11]; ct[11]=ct[7]; ct[7]=ct[3]; ct[3]=t;
    for (int i = 0; i < 16; i++) ct[i] ^= rk[160+i];
}

// Kernel callback invoked by vx_spawn_threads on every lane in lockstep after per-thread bring-up
static void lane_encrypt(void *arg) {
    (void)arg;
    int tid = vx_thread_id();
    volatile uint8_t *scratch = per_lane_scratch[tid];
    volatile uint8_t *pt  = scratch +   0;
    volatile uint8_t *key = scratch +  16;
    volatile uint8_t *ct  = scratch +  32;
    volatile uint8_t *rk  = scratch +  48;

    for (int i = 0; i < 16; i++) pt[i]  = result_buf[tid*16 + i];
    for (int i = 0; i < 16; i++) key[i] = result_buf[64 + i];

    lane_encrypt_inplace(pt, key, ct, rk);

    // Sentinel: each lane writes 0xA0+tid at a unique slot in result_buf[200..]
    result_buf[200 + tid] = 0xA0 + (uint8_t)tid;
    for (int i = 0; i < 16; i++) result_buf[80 + tid*16 + i] = ct[i];
    // Sentinel: confirm the CT loop completed
    result_buf[210 + tid] = 0xB0 + (uint8_t)tid;
    lane_done[tid] = 1;
}

int main(void) {
    // Defaults if host did not override.
    int empty_pt = 1;
    for (int i = 0; i < 64; i++)
        if (result_buf[i] != 0) { empty_pt = 0; break; }
    if (empty_pt) {
        for (int lane = 0; lane < NUM_LANES; lane++)
            for (int i = 0; i < 16; i++)
                result_buf[lane*16 + i] = default_pts[lane][i];
    }
    int empty_key = 1;
    for (int i = 0; i < 16; i++)
        if (result_buf[64+i] != 0) { empty_key = 0; break; }
    if (empty_key) {
        for (int i = 0; i < 16; i++) result_buf[64 + i] = default_key[i];
    }

    // Vortex runtime: 1 block of NUM_LANES threads (grid_dim = {1}, block_dim = {NUM_LANES})
    uint32_t grid[1]  = { 1 };
    uint32_t block[1] = { NUM_LANES };
    vx_spawn_threads(1, grid, block, lane_encrypt, NULL);

    int n = 0;
    for (int i = 0; i < NUM_LANES; i++) if (lane_done[i]) n++;
    result_buf[145] = (uint8_t)n;
    result_buf[144] = 1;
    return 0;
}
