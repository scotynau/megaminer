#ifndef CUDA_MEGAMEC_H
#define CUDA_MEGAMEC_H

#include <stdint.h>
#include "miner.h"

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
static inline int get_megamec_selection(const uint8_t *timestamp, int round)
{
    uint8_t nibble = timestamp[3 - (round / 2)];
    if (round % 2 == 0)
        return (nibble >> 4) % MEGAMEC_HASH_COUNT;
    else
        return (nibble & 0x0f) % MEGAMEC_HASH_COUNT;
}

// CPU hash function for validation (23 full rounds)
extern "C" void megamechash(void *output, const void *input);

// Scanhash and free
extern "C" int scanhash_megamec(int thr_id, struct work *work, uint32_t max_nonce, unsigned long *hashes_done);
extern "C" void free_megamec(int thr_id);

#endif // CUDA_MEGAMEC_H
