#ifndef CUDA_MEGAMEC_H
#define CUDA_MEGAMEC_H

#include <stdint.h>
#include "miner.h"

// MEGAMEC: 18 hash functions, 23 rounds
// Permutation via std::next_permutation seeded by block timestamp
// Each round applies a pair of hash functions (except groestl=3, hamsi=12)
// Based on Megacoin src/crypto/mega-mec.h

extern "C" void megamechash(void *output, const void *input);
extern "C" int scanhash_megamec(int thr_id, struct work *work, uint32_t max_nonce, unsigned long *hashes_done);
extern "C" void free_megamec(int thr_id);

#endif // CUDA_MEGAMEC_H
