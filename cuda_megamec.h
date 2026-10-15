#ifndef CUDA_MEGAMEC_H
#define CUDA_MEGAMEC_H

#include "cuda_helper.h"

// MEGAMEC uses 17 algorithms, 23 rounds (8/8/7 distribution)
// Algorithm indices:
#define MEGAMEC_BLAKE        0
#define MEGAMEC_BMW          1
#define MEGAMEC_GROESTL      2
#define MEGAMEC_JH           3
#define MEGAMEC_KECCAK       4
#define MEGAMEC_SKEIN        5
#define MEGAMEC_LUFFA        6
#define MEGAMEC_CUBEHASH     7
#define MEGAMEC_SHAVITE      8
#define MEGAMEC_SIMD         9
#define MEGAMEC_ECHO         10
#define MEGAMEC_HAMSI        11
#define MEGAMEC_FUGUE        12
#define MEGAMEC_SHABAL       13
#define MEGAMEC_WHIRLPOOL    14
#define MEGAMEC_SHA512       15
#define MEGAMEC_HAVAL        16

#define MEGAMEC_HASH_COUNT   (MEGAMEC_HAVAL + 1)
#define MEGAMEC_ROUNDS       23

// 23 rounds: 8 + 8 + 7
#define MEGAMEC_ROUND_1_COUNT 8
#define MEGAMEC_ROUND_2_COUNT 8
#define MEGAMEC_ROUND_3_COUNT 7

static const char *megamec_hash_names[MEGAMEC_HASH_COUNT] =
{
    "blake",
    "bmw",
    "groestl",
    "jh",
    "keccak",
    "skein",
    "luffa",
    "cubehash",
    "shavite",
    "simd",
    "echo",
    "hamsi",
    "fugue",
    "shabal",
    "whirlpool",
    "sha512",
    "haval",
};

// Get permutation from timestamp (input[68..71])
inline int get_megamec_selection(const uint8_t *timestamp, int round)
{
    // timestamp is 4 bytes at input[68..71]
    // Use round to select which nibble
    uint8_t nibble = timestamp[3 - (round / 2)];
    if (round % 2 == 0)
    {
        return (nibble >> 4) % MEGAMEC_HASH_COUNT;
    }
    else
    {
        return (nibble & 0x0f) % MEGAMEC_HASH_COUNT;
    }
}

// CPU hash function for validation
extern "C" void megamechash(void *output, const void *input);

// CUDA kernel declarations
extern void megamec_blake512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_blake512_cpu_setBlock_80(int thr_id, uint32_t *endiandata);
extern void megamec_blake512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);
extern void megamec_blake512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);

extern void megamec_bmw512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_bmw512_cpu_setBlock_80(uint32_t *endiandata);
extern void megamec_bmw512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash, int order);
extern void megamec_bmw512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);

extern void megamec_groestl512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_groestl512_setBlock_80(int thr_id, uint32_t *endiandata);
extern void megamec_groestl512_cuda_hash_80(const int thr_id, const uint32_t threads, const uint32_t startNounce, uint32_t *d_hash);
extern void megamec_groestl512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);

extern void megamec_jh512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_jh512_setBlock_80(int thr_id, uint32_t *endiandata);
extern void megamec_jh512_cuda_hash_80(const int thr_id, const uint32_t threads, const uint32_t startNounce, uint32_t *d_hash);
extern void megamec_jh512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);

extern void megamec_keccak512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_keccak512_setBlock_80(int thr_id, uint32_t *endiandata);
extern void megamec_keccak512_cuda_hash_80(const int thr_id, const uint32_t threads, const uint32_t startNounce, uint32_t *d_hash);
extern void megamec_keccak512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);

extern void megamec_skein512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_skein512_cpu_setBlock_80(uint32_t *endiandata);
extern void megamec_skein512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash, int swap);
extern void megamec_skein512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);

extern void megamec_luffa512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_luffa512_cpu_setBlock_80(uint32_t *endiandata);
extern void megamec_luffa512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash, int order);
extern void megamec_luffa512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);

extern void megamec_cubehash512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_cubehash512_setBlock_80(int thr_id, uint32_t *endiandata);
extern void megamec_cubehash512_cuda_hash_80(const int thr_id, const uint32_t threads, const uint32_t startNounce, uint32_t *d_hash);
extern void megamec_cubehash512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);

extern void megamec_shavite512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_shavite512_setBlock_80(void *pdata);
extern void megamec_shavite512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_outputHash, int order);
extern void megamec_shavite512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);

extern void megamec_simd512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_simd512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash, int order);
extern void megamec_simd512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);

extern void megamec_echo512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_echo512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash, int order);
extern void megamec_echo512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);

extern void megamec_hamsi512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_hamsi512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order);

extern void megamec_fugue512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_fugue512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order);

extern void megamec_shabal512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_shabal512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order);

extern void megamec_whirlpool512_cpu_init(int thr_id, uint32_t threads, int flag);
extern void megamec_whirlpool512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order);

extern void megamec_sha512_cpu_init(int thr_id, uint32_t threads);
extern void megamec_sha512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash, int order);

extern void megamec_haval256_cpu_init(int thr_id, uint32_t threads);
extern void megamec_haval256_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_outputHash);
extern void megamec_haval256_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);

// Scanhash function
extern "C" int scanhash_megamec(int thr_id, struct work *work, uint32_t max_nonce, unsigned long *hashes_done);

// Cleanup function
extern "C" void free_megamec(int thr_id);

#endif // CUDA_MEGAMEC_H