/*
 * SPH Blake512 exact port to CUDA - Complete implementation
 * Matches sph/blake.c COMPRESS64 non-compact: 16 rounds + 2 extra (rounds 0,1 repeated) = 18 rounds total
 */

#ifndef SPH_BLAKE512_CUDA_CUH
#define SPH_BLAKE512_CUDA_CUH

#include <stdint.h>
#include "cuda_helper.h"

// =========================================================================
// Constants in constant memory (device)
// =========================================================================

__device__ __constant__ uint64_t c_IV512[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

__device__ __constant__ uint64_t c_CB[8] = {
    0x243f6a8885a308d3ULL, 0x13198a2e03707344ULL,
    0xa4093822299f31d0ULL, 0x082efa98ec4e6c89ULL,
    0x452821e638d01377ULL, 0xbe5466cf34e90c6cULL,
    0xc0ac29b7c97c50ddULL, 0x3f84d5b5b5470917ULL
};

__device__ __constant__ unsigned char c_sigma[16][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 }
};

// Host constants
static const uint64_t IV512_HOST[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

static const uint64_t CB_HOST[8] = {
    0x243f6a8885a308d3ULL, 0x13198a2e03707344ULL,
    0xa4093822299f31d0ULL, 0x082efa98ec4e6c89ULL,
    0x452821e638d01377ULL, 0xbe5466cf34e90c6cULL,
    0xc0ac29b7c97c50ddULL, 0x3f84d5b5b5470917ULL
};

static const unsigned char sigma_HOST[16][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 }
};

// =========================================================================
// Blake512 G function - EXACTLY from sph/blake.c lines 427-436
// =========================================================================
__device__ __forceinline__ void blake512_G(uint64_t m0, uint64_t m1, uint64_t c0, uint64_t c1,
                                           uint64_t &a, uint64_t &b, uint64_t &c, uint64_t &d) {
    a += b + (m0 ^ c1);
    d = ROTR64(d ^ a, 32);
    c += d;
    b = ROTR64(b ^ c, 25);
    a += b + (m1 ^ c0);
    d = ROTR64(d ^ a, 16);
    c += d;
    b = ROTR64(b ^ c, 11);
}

// =========================================================================
// Device Blake512 Compress - EXACT port of SPH COMPRESS64 non-compact
// 16 rounds + 2 extra (rounds 0,1 repeated) = 18 rounds total
// =========================================================================
__device__ void sph_blake512_compress_exact(uint64_t h[8], const uint64_t block[16],
                                             uint64_t S0, uint64_t S1, uint64_t S2, uint64_t S3,
                                             uint64_t T0, uint64_t T1) {
    // Initialize V from h
    uint64_t V[16];
    V[0] = h[0]; V[1] = h[1]; V[2] = h[2]; V[3] = h[3];
    V[4] = h[4]; V[5] = h[5]; V[6] = h[6]; V[7] = h[7];
    
    // V8-VF from state + CB
    V[8]  = S0 ^ c_CB[0]; V[9]  = S1 ^ c_CB[1];
    V[10] = S2 ^ c_CB[2]; V[11] = S3 ^ c_CB[3];
    V[12] = T0 ^ c_CB[4]; V[13] = T0 ^ c_CB[5];
    V[14] = T1 ^ c_CB[6]; V[15] = T1 ^ c_CB[7];
    
    // Decode block from big-endian to M[16]
    uint64_t M[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        uint64_t val = block[i];
        M[i] = ((val & 0xFF00000000000000ULL) >> 56) |
               ((val & 0x00FF000000000000ULL) >> 40) |
               ((val & 0x0000FF0000000000ULL) >> 24) |
               ((val & 0x000000FF00000000ULL) >> 8) |
               ((val & 0x00000000FF000000ULL) << 8) |
               ((val & 0x0000000000FF0000ULL) << 24) |
               ((val & 0x000000000000FF00ULL) << 40) |
               ((val & 0x00000000000000FFULL) << 56);
    }
    
    // 16 rounds + 2 extra = 18 rounds total
    for (int r = 0; r < 16; r++) {
        // V0, V4, V8, VC
        {
            uint64_t a = V[0], b = V[4], c = V[8], d = V[12];
            uint64_t m0 = M[c_sigma[r][0]], m1 = M[c_sigma[r][1]];
            uint64_t c0 = c_CB[c_sigma[r][0]], c1 = c_CB[c_sigma[r][1]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[0] = a; V[4] = b; V[8] = c; V[12] = d;
        }
        // V1, V5, V9, VD
        {
            uint64_t a = V[1], b = V[5], c = V[9], d = V[13];
            uint64_t m0 = M[c_sigma[r][2]], m1 = M[c_sigma[r][3]];
            uint64_t c0 = c_CB[c_sigma[r][2]], c1 = c_CB[c_sigma[r][3]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[1] = a; V[5] = b; V[9] = c; V[13] = d;
        }
        // V2, V6, VA, VE
        {
            uint64_t a = V[2], b = V[6], c = V[10], d = V[14];
            uint64_t m0 = M[c_sigma[r][4]], m1 = M[c_sigma[r][5]];
            uint64_t c0 = c_CB[c_sigma[r][4]], c1 = c_CB[c_sigma[r][5]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[2] = a; V[6] = b; V[10] = c; V[14] = d;
        }
        // V3, V7, VB, VF
        {
            uint64_t a = V[3], b = V[7], c = V[11], d = V[15];
            uint64_t m0 = M[c_sigma[r][6]], m1 = M[c_sigma[r][7]];
            uint64_t c0 = c_CB[c_sigma[r][6]], c1 = c_CB[c_sigma[r][7]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[3] = a; V[7] = b; V[11] = c; V[15] = d;
        }
        // V0, V5, VA, VF
        {
            uint64_t a = V[0], b = V[5], c = V[10], d = V[15];
            uint64_t m0 = M[c_sigma[r][8]], m1 = M[c_sigma[r][9]];
            uint64_t c0 = c_CB[c_sigma[r][8]], c1 = c_CB[c_sigma[r][9]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[0] = a; V[5] = b; V[10] = c; V[15] = d;
        }
        // V1, V6, VB, VC
        {
            uint64_t a = V[1], b = V[6], c = V[11], d = V[12];
            uint64_t m0 = M[c_sigma[r][10]], m1 = M[c_sigma[r][11]];
            uint64_t c0 = c_CB[c_sigma[r][10]], c1 = c_CB[c_sigma[r][11]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[1] = a; V[6] = b; V[11] = c; V[12] = d;
        }
        // V2, V7, V8, VD
        {
            uint64_t a = V[2], b = V[7], c = V[8], d = V[13];
            uint64_t m0 = M[c_sigma[r][12]], m1 = M[c_sigma[r][13]];
            uint64_t c0 = c_CB[c_sigma[r][12]], c1 = c_CB[c_sigma[r][13]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[2] = a; V[7] = b; V[8] = c; V[13] = d;
        }
        // V3, V4, V9, VE
        {
            uint64_t a = V[3], b = V[4], c = V[9], d = V[14];
            uint64_t m0 = M[c_sigma[r][14]], m1 = M[c_sigma[r][15]];
            uint64_t c0 = c_CB[c_sigma[r][14]], c1 = c_CB[c_sigma[r][15]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[3] = a; V[4] = b; V[9] = c; V[14] = d;
        }
    }
    
    // 2 extra rounds (rounds 0 and 1 repeated)
    for (int r = 0; r < 2; r++) {
        // V0, V4, V8, VC
        {
            uint64_t a = V[0], b = V[4], c = V[8], d = V[12];
            uint64_t m0 = M[c_sigma[r][0]], m1 = M[c_sigma[r][1]];
            uint64_t c0 = c_CB[c_sigma[r][0]], c1 = c_CB[c_sigma[r][1]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[0] = a; V[4] = b; V[8] = c; V[12] = d;
        }
        // V1, V5, V9, VD
        {
            uint64_t a = V[1], b = V[5], c = V[9], d = V[13];
            uint64_t m0 = M[c_sigma[r][2]], m1 = M[c_sigma[r][3]];
            uint64_t c0 = c_CB[c_sigma[r][2]], c1 = c_CB[c_sigma[r][3]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[1] = a; V[5] = b; V[9] = c; V[13] = d;
        }
        // V2, V6, VA, VE
        {
            uint64_t a = V[2], b = V[6], c = V[10], d = V[14];
            uint64_t m0 = M[c_sigma[r][4]], m1 = M[c_sigma[r][5]];
            uint64_t c0 = c_CB[c_sigma[r][4]], c1 = c_CB[c_sigma[r][5]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[2] = a; V[6] = b; V[10] = c; V[14] = d;
        }
        // V3, V7, VB, VF
        {
            uint64_t a = V[3], b = V[7], c = V[11], d = V[15];
            uint64_t m0 = M[c_sigma[r][6]], m1 = M[c_sigma[r][7]];
            uint64_t c0 = c_CB[c_sigma[r][6]], c1 = c_CB[c_sigma[r][7]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[3] = a; V[7] = b; V[11] = c; V[15] = d;
        }
        // V0, V5, VA, VF
        {
            uint64_t a = V[0], b = V[5], c = V[10], d = V[15];
            uint64_t m0 = M[c_sigma[r][8]], m1 = M[c_sigma[r][9]];
            uint64_t c0 = c_CB[c_sigma[r][8]], c1 = c_CB[c_sigma[r][9]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[0] = a; V[5] = b; V[10] = c; V[15] = d;
        }
        // V1, V6, VB, VC
        {
            uint64_t a = V[1], b = V[6], c = V[11], d = V[12];
            uint64_t m0 = M[c_sigma[r][10]], m1 = M[c_sigma[r][11]];
            uint64_t c0 = c_CB[c_sigma[r][10]], c1 = c_CB[c_sigma[r][11]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[1] = a; V[6] = b; V[11] = c; V[12] = d;
        }
        // V2, V7, V8, VD
        {
            uint64_t a = V[2], b = V[7], c = V[8], d = V[13];
            uint64_t m0 = M[c_sigma[r][12]], m1 = M[c_sigma[r][13]];
            uint64_t c0 = c_CB[c_sigma[r][12]], c1 = c_CB[c_sigma[r][13]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[2] = a; V[7] = b; V[8] = c; V[13] = d;
        }
        // V3, V4, V9, VE
        {
            uint64_t a = V[3], b = V[4], c = V[9], d = V[14];
            uint64_t m0 = M[c_sigma[r][14]], m1 = M[c_sigma[r][15]];
            uint64_t c0 = c_CB[c_sigma[r][14]], c1 = c_CB[c_sigma[r][15]];
            blake512_G(m0, m1, c0, c1, a, b, c, d);
            V[3] = a; V[4] = b; V[9] = c; V[14] = d;
        }
    }
    
    // Final: h[i] ^= V[i] ^ V[i+8]
    h[0] ^= V[0] ^ V[8];
    h[1] ^= V[1] ^ V[9];
    h[2] ^= V[2] ^ V[10];
    h[3] ^= V[3] ^ V[11];
    h[4] ^= V[4] ^ V[12];
    h[5] ^= V[5] ^ V[13];
    h[6] ^= V[6] ^ V[14];
    h[7] ^= V[7] ^ V[15];
}

// =========================================================================
// Host Blake512 init - EXACTLY matching SPH sph_blake512_init
// =========================================================================
__host__ static inline void sph_blake512_init_host(uint64_t H[8], uint64_t S[4], uint64_t *T0, uint64_t *T1) {
    static const uint64_t IV512_HOST[8] = {
        0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
        0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
        0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
        0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
    };
    for (int i = 0; i < 8; i++) H[i] = IV512_HOST[i];
    for (int i = 0; i < 4; i++) S[i] = 0;
    *T0 = 0;
    *T1 = 0;
}

#endif // SPH_BLAKE512_CUDA_CUH