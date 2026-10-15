// Megacoin MEGAMEC CPU/CUDA Implementation
// Based on /home/soptech/Megacoin/src/crypto/mega-mec.h
//
// 18 hash functions, 23 rounds (1 blake512 + 7 + 8 + 7)
// Permutation generated via std::next_permutation seeded by timestamp
// Each round applies a PAIR of hash functions (except groestl=3, hamsi=12)

extern "C"
{
#include "sph/sph_blake.h"
#include "sph/sph_bmw.h"
#include "sph/sph_groestl.h"
#include "sph/sph_jh.h"
#include "sph/sph_keccak.h"
#include "sph/sph_skein.h"
#include "sph/sph_luffa.h"
#include "sph/sph_cubehash.h"
#include "sph/sph_shavite.h"
#include "sph/sph_simd.h"
#include "sph/sph_echo.h"
#include "sph/sph_hamsi.h"
#include "sph/sph_fugue.h"
#include "sph/sph_shabal.h"
#include "sph/sph_whirlpool.h"
#include "sph/sph_sha2.h"
#include "sph/sph_haval.h"
#include "sph/sph_streebog.h"
}

#include <algorithm>  // std::next_permutation — MUST be before miner.h which defines min/max macros

#include "miner.h"
#include "cuda_helper.h"
#include "cuda_megamec.h"

#include <stdio.h>
#include <unistd.h>
#include <memory.h>

// ---------- GPU kernel declarations ----------

// init
extern void quark_blake512_cpu_init(int thr_id, uint32_t threads);
extern void quark_bmw512_cpu_init(int thr_id, uint32_t threads);
extern void quark_groestl512_cpu_init(int thr_id, uint32_t threads);
extern void quark_jh512_cpu_init(int thr_id, uint32_t threads);
extern void quark_keccak512_cpu_init(int thr_id, uint32_t threads);
extern void quark_skein512_cpu_init(int thr_id, uint32_t threads);
extern void qubit_luffa512_cpu_init(int thr_id, uint32_t threads);
extern void x11_luffa512_cpu_init(int thr_id, uint32_t threads);
extern void x11_cubehash512_cpu_init(int thr_id, uint32_t threads);
extern void x11_shavite512_cpu_init(int thr_id, uint32_t threads);
extern void x11_simd512_cpu_init(int thr_id, uint32_t threads);
extern void x11_echo512_cpu_init(int thr_id, uint32_t threads);
extern void x13_hamsi512_cpu_init(int thr_id, uint32_t threads);
extern void x13_fugue512_cpu_init(int thr_id, uint32_t threads);
extern void x14_shabal512_cpu_init(int thr_id, uint32_t threads);
extern void x15_whirlpool_cpu_init(int thr_id, uint32_t threads, int flag);
extern void x17_sha512_cpu_init(int thr_id, uint32_t threads);
extern void x17_haval256_cpu_init(int thr_id, uint32_t threads);

// setBlock_80 (round 0 only, always blake512)
extern void quark_blake512_cpu_setBlock_80(int thr_id, uint32_t *endiandata);

// hash_80 (round 0)
extern void quark_blake512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);

// hash_64 (rounds 1-22) — all operate in-place on d_hash
extern void quark_blake512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void quark_bmw512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void quark_groestl512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void quark_jh512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void quark_keccak512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void quark_skein512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void x11_luffa512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void x11_cubehash512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void x11_shavite512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void x11_simd512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void x11_echo512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void x13_hamsi512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void x13_fugue512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void x14_shabal512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void x15_whirlpool_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *prev_hash, uint32_t *d_hash, int order);
extern void x17_sha512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);
extern void x17_haval256_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash, const int outlen);
extern void streebog_cpu_hash_64(int thr_id, uint32_t threads, uint32_t *d_hash);

// free
extern void quark_blake512_cpu_free(int thr_id);
extern void quark_groestl512_cpu_free(int thr_id);
extern void x11_simd512_cpu_free(int thr_id);
extern void x13_fugue512_cpu_free(int thr_id);
extern void x15_whirlpool_cpu_free(int thr_id);

// ---------- Constants from mega-mec.h ----------

#define HASH_FUNC_BASE_TIMESTAMP_1 1370079299  // Megacoin Block 1
#define HASH_FUNC_COUNT_1 8
#define HASH_FUNC_COUNT_2 8
#define HASH_FUNC_COUNT_3 7
#define HASH_FUNC_VAR_1 2100
#define HASH_FUNC_VAR_2 2100
#define HASH_FUNC_COUNT_PERMUTATIONS_7 5040   // 7!
#define HASH_FUNC_COUNT_PERMUTATIONS 40320    // 8!

static const char *megamec_hash_names[18] =
{
    "blake", "echo", "simd", "bmw", "groestl", "whirlpool", "jh",
    "gost", "keccak", "fugue", "skein", "shavite", "luffa",
    "cubehash", "shabal", "hamsi", "sha512", "haval"
};

// Extract nTime (host order) from a big-endian word-swapped header array.
// endiandata[i] = be32enc(pdata[i]) => bytes 68..71 hold nTime big-endian,
// so a little-endian read yields swab32(nTime); swab32() restores nTime.
static inline uint32_t megamec_timestamp(const void *endiandata)
{
    const uint8_t *b = (const uint8_t *)endiandata;
    uint32_t le = (uint32_t)b[68] | ((uint32_t)b[69] << 8) |
                  ((uint32_t)b[70] << 16) | ((uint32_t)b[71] << 24);
    return swab32(le);
}

// ---------- CPU hash (exact port of mega-mec.h) ----------

extern "C" void megamechash(void *output, const void *input)
{
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;
    sph_luffa512_context     ctx_luffa;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    sph_hamsi512_context     ctx_hamsi;
    sph_fugue512_context     ctx_fugue;
    sph_shabal512_context    ctx_shabal;
    sph_whirlpool_context    ctx_whirlpool;
    sph_sha512_context       ctx_sha512;
    sph_gost512_context      ctx_gost;
    sph_haval256_5_context   ctx_haval;

    // Extract timestamp from block header (nTime field)
    uint32_t timestamp = megamec_timestamp(input);

    uint32_t hash[23][16];  // 23 rounds × 64 bytes (16 × uint32_t)
    uint32_t permutation_1[HASH_FUNC_COUNT_1];
    uint32_t permutation_2[HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1];
    uint32_t permutation_3[HASH_FUNC_COUNT_3 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1];

    // Init permutations (matching mega-mec.h exactly)
    // permutation_1[0] is left uninitialized in the original (stack garbage)
    // but we zero it for determinism — the loop starts at i=1
    memset(permutation_1, 0, sizeof(permutation_1));
    for (uint32_t i = 1; i < HASH_FUNC_COUNT_1; i++)
        permutation_1[i] = i;

    for (uint32_t i = HASH_FUNC_COUNT_1; i < HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1; i++)
        permutation_2[i] = i;

    for (uint32_t i = HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2; i < HASH_FUNC_COUNT_3 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1; i++)
        permutation_3[i] = i;

    // Generate permutations from timestamp
    uint32_t steps_1 = (timestamp - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS_7;
    for (uint32_t i = 0; i < steps_1; i++)
        std::next_permutation(permutation_1, permutation_1 + HASH_FUNC_COUNT_1);

    uint32_t steps_2 = (timestamp + HASH_FUNC_VAR_1 - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS;
    for (uint32_t i = 0; i < steps_2; i++)
        std::next_permutation(permutation_2 + HASH_FUNC_COUNT_1, permutation_2 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2);

    uint32_t steps_3 = (timestamp + HASH_FUNC_VAR_2 - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS_7;
    for (uint32_t i = 0; i < steps_3; i++)
        std::next_permutation(permutation_3 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2,
                              permutation_3 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_3);

    int lenToHash = 64;
    int lenToHashinit = 80;  // full block header
    const void *toHash;
    const void *toHashinit = input;

    // Round 0: always blake512 on full 80-byte header
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, toHashinit, lenToHashinit);
    sph_blake512_close(&ctx_blake, hash[0]);

    // Group 1: rounds 1-7 (permutation_1 values 1-7)
    for (int i = 1; i < HASH_FUNC_COUNT_1; i++) {
        toHash = hash[i - 1];
        switch (permutation_1[i]) {
        case 1: // echo → blake
            sph_echo512_init(&ctx_echo);
            sph_echo512(&ctx_echo, toHash, lenToHash);
            sph_echo512_close(&ctx_echo, hash[i]);
            sph_blake512_init(&ctx_blake);
            sph_blake512(&ctx_blake, hash[i], 64);
            sph_blake512_close(&ctx_blake, hash[i]);
            break;
        case 2: // simd → bmw
            sph_simd512_init(&ctx_simd);
            sph_simd512(&ctx_simd, toHash, lenToHash);
            sph_simd512_close(&ctx_simd, hash[i]);
            sph_bmw512_init(&ctx_bmw);
            sph_bmw512(&ctx_bmw, hash[i], 64);
            sph_bmw512_close(&ctx_bmw, hash[i]);
            break;
        case 3: // groestl
            sph_groestl512_init(&ctx_groestl);
            sph_groestl512(&ctx_groestl, toHash, lenToHash);
            sph_groestl512_close(&ctx_groestl, hash[i]);
            break;
        case 4: // whirlpool → jh
            sph_whirlpool_init(&ctx_whirlpool);
            sph_whirlpool(&ctx_whirlpool, toHash, lenToHash);
            sph_whirlpool_close(&ctx_whirlpool, hash[i]);
            sph_jh512_init(&ctx_jh);
            sph_jh512(&ctx_jh, hash[i], 64);
            sph_jh512_close(&ctx_jh, hash[i]);
            break;
        case 5: // gost → keccak
            sph_gost512_init(&ctx_gost);
            sph_gost512(&ctx_gost, toHash, lenToHash);
            sph_gost512_close(&ctx_gost, hash[i]);
            sph_keccak512_init(&ctx_keccak);
            sph_keccak512(&ctx_keccak, hash[i], 64);
            sph_keccak512_close(&ctx_keccak, hash[i]);
            break;
        case 6: // fugue → skein
            sph_fugue512_init(&ctx_fugue);
            sph_fugue512(&ctx_fugue, toHash, lenToHash);
            sph_fugue512_close(&ctx_fugue, hash[i]);
            sph_skein512_init(&ctx_skein);
            sph_skein512(&ctx_skein, hash[i], 64);
            sph_skein512_close(&ctx_skein, hash[i]);
            break;
        case 7: // shavite → luffa
            sph_shavite512_init(&ctx_shavite);
            sph_shavite512(&ctx_shavite, toHash, lenToHash);
            sph_shavite512_close(&ctx_shavite, hash[i]);
            sph_luffa512_init(&ctx_luffa);
            sph_luffa512(&ctx_luffa, hash[i], 64);
            sph_luffa512_close(&ctx_luffa, hash[i]);
            break;
        }
    }

    // Group 2: rounds 8-15 (permutation_2 values 8-15)
    for (int i = HASH_FUNC_COUNT_1; i < HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2; i++) {
        toHash = hash[i - 1];
        switch (permutation_2[i]) {
        case 8: // whirlpool → cubehash
            sph_whirlpool_init(&ctx_whirlpool);
            sph_whirlpool(&ctx_whirlpool, toHash, lenToHash);
            sph_whirlpool_close(&ctx_whirlpool, hash[i]);
            sph_cubehash512_init(&ctx_cubehash);
            sph_cubehash512(&ctx_cubehash, hash[i], 64);
            sph_cubehash512_close(&ctx_cubehash, hash[i]);
            break;
        case 9: // jh → shavite
            sph_jh512_init(&ctx_jh);
            sph_jh512(&ctx_jh, toHash, lenToHash);
            sph_jh512_close(&ctx_jh, hash[i]);
            sph_shavite512_init(&ctx_shavite);
            sph_shavite512(&ctx_shavite, hash[i], 64);
            sph_shavite512_close(&ctx_shavite, hash[i]);
            break;
        case 10: // blake → simd
            sph_blake512_init(&ctx_blake);
            sph_blake512(&ctx_blake, toHash, lenToHash);
            sph_blake512_close(&ctx_blake, hash[i]);
            sph_simd512_init(&ctx_simd);
            sph_simd512(&ctx_simd, hash[i], 64);
            sph_simd512_close(&ctx_simd, hash[i]);
            break;
        case 11: // shabal → echo
            sph_shabal512_init(&ctx_shabal);
            sph_shabal512(&ctx_shabal, toHash, lenToHash);
            sph_shabal512_close(&ctx_shabal, hash[i]);
            sph_echo512_init(&ctx_echo);
            sph_echo512(&ctx_echo, hash[i], 64);
            sph_echo512_close(&ctx_echo, hash[i]);
            break;
        case 12: // hamsi
            sph_hamsi512_init(&ctx_hamsi);
            sph_hamsi512(&ctx_hamsi, toHash, lenToHash);
            sph_hamsi512_close(&ctx_hamsi, hash[i]);
            break;
        case 13: // bmw → fugue
            sph_bmw512_init(&ctx_bmw);
            sph_bmw512(&ctx_bmw, toHash, lenToHash);
            sph_bmw512_close(&ctx_bmw, hash[i]);
            sph_fugue512_init(&ctx_fugue);
            sph_fugue512(&ctx_fugue, hash[i], 64);
            sph_fugue512_close(&ctx_fugue, hash[i]);
            break;
        case 14: // keccak → shabal
            sph_keccak512_init(&ctx_keccak);
            sph_keccak512(&ctx_keccak, toHash, lenToHash);
            sph_keccak512_close(&ctx_keccak, hash[i]);
            sph_shabal512_init(&ctx_shabal);
            sph_shabal512(&ctx_shabal, hash[i], 64);
            sph_shabal512_close(&ctx_shabal, hash[i]);
            break;
        case 15: // luffa → whirlpool
            sph_luffa512_init(&ctx_luffa);
            sph_luffa512(&ctx_luffa, toHash, lenToHash);
            sph_luffa512_close(&ctx_luffa, hash[i]);
            sph_whirlpool_init(&ctx_whirlpool);
            sph_whirlpool(&ctx_whirlpool, hash[i], 64);
            sph_whirlpool_close(&ctx_whirlpool, hash[i]);
            break;
        }
    }

    // Group 3: rounds 16-22 (permutation_3 values 16-22)
    for (int i = HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2;
         i < HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_3; i++) {
        toHash = hash[i - 1];
        switch (permutation_3[i]) {
        case 16: // sha512 → haval
            sph_sha512_init(&ctx_sha512);
            sph_sha512(&ctx_sha512, toHash, lenToHash);
            sph_sha512_close(&ctx_sha512, hash[i]);
            sph_haval256_5_init(&ctx_haval);
            sph_haval256_5(&ctx_haval, hash[i], 64);
            sph_haval256_5_close(&ctx_haval, hash[i]);
            break;
        case 17: // skein → groestl
            sph_skein512_init(&ctx_skein);
            sph_skein512(&ctx_skein, toHash, lenToHash);
            sph_skein512_close(&ctx_skein, hash[i]);
            sph_groestl512_init(&ctx_groestl);
            sph_groestl512(&ctx_groestl, hash[i], 64);
            sph_groestl512_close(&ctx_groestl, hash[i]);
            break;
        case 18: // simd → hamsi
            sph_simd512_init(&ctx_simd);
            sph_simd512(&ctx_simd, toHash, lenToHash);
            sph_simd512_close(&ctx_simd, hash[i]);
            sph_hamsi512_init(&ctx_hamsi);
            sph_hamsi512(&ctx_hamsi, hash[i], 64);
            sph_hamsi512_close(&ctx_hamsi, hash[i]);
            break;
        case 19: // gost → haval
            sph_gost512_init(&ctx_gost);
            sph_gost512(&ctx_gost, toHash, lenToHash);
            sph_gost512_close(&ctx_gost, hash[i]);
            sph_haval256_5_init(&ctx_haval);
            sph_haval256_5(&ctx_haval, hash[i], 64);
            sph_haval256_5_close(&ctx_haval, hash[i]);
            break;
        case 20: // cubehash → sha512
            sph_cubehash512_init(&ctx_cubehash);
            sph_cubehash512(&ctx_cubehash, toHash, lenToHash);
            sph_cubehash512_close(&ctx_cubehash, hash[i]);
            sph_sha512_init(&ctx_sha512);
            sph_sha512(&ctx_sha512, hash[i], 64);
            sph_sha512_close(&ctx_sha512, hash[i]);
            break;
        case 21: // echo → shavite
            sph_echo512_init(&ctx_echo);
            sph_echo512(&ctx_echo, toHash, lenToHash);
            sph_echo512_close(&ctx_echo, hash[i]);
            sph_shavite512_init(&ctx_shavite);
            sph_shavite512(&ctx_shavite, hash[i], 64);
            sph_shavite512_close(&ctx_shavite, hash[i]);
            break;
        case 22: // luffa → shabal
            sph_luffa512_init(&ctx_luffa);
            sph_luffa512(&ctx_luffa, toHash, lenToHash);
            sph_luffa512_close(&ctx_luffa, hash[i]);
            sph_shabal512_init(&ctx_shabal);
            sph_shabal512(&ctx_shabal, hash[i], 64);
            sph_shabal512_close(&ctx_shabal, hash[i]);
            break;
        }
    }

    // Output: lower 256 bits of hash[22]
    memcpy(output, hash[22], 32);
}

// ---------- GPU hash dispatch for rounds 1-22 ----------
// Each permutation value maps to one or two GPU kernel calls on d_hash

static void megamec_gpu_hash_pair(int thr_id, uint32_t throughput, uint32_t startNounce,
                                   uint32_t *d_hash, int perm_value, int *order)
{
    switch (perm_value) {
    case 1: // echo → blake
        x11_echo512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        quark_blake512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 2: // simd → bmw
        x11_simd512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        quark_bmw512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 3: // groestl
        quark_groestl512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 4: // whirlpool → jh
        x15_whirlpool_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        quark_jh512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 5: // gost → keccak
        streebog_cpu_hash_64(thr_id, throughput, d_hash);
        quark_keccak512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 6: // fugue → skein
        x13_fugue512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        quark_skein512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 7: // shavite → luffa
        x11_shavite512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        x11_luffa512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 8: // whirlpool → cubehash
        x15_whirlpool_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        x11_cubehash512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 9: // jh → shavite
        quark_jh512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        x11_shavite512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 10: // blake → simd
        quark_blake512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        x11_simd512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 11: // shabal → echo
        x14_shabal512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        x11_echo512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 12: // hamsi
        x13_hamsi512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 13: // bmw → fugue
        quark_bmw512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        x13_fugue512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 14: // keccak → shabal
        quark_keccak512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        x14_shabal512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 15: // luffa → whirlpool
        x11_luffa512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        x15_whirlpool_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 16: // sha512 → haval
        x17_sha512_cpu_hash_64(thr_id, throughput, startNounce, d_hash);
        x17_haval256_cpu_hash_64(thr_id, throughput, startNounce, d_hash, 256);
        break;
    case 17: // skein → groestl
        quark_skein512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        quark_groestl512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 18: // simd → hamsi
        x11_simd512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        x13_hamsi512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 19: // gost → haval
        streebog_cpu_hash_64(thr_id, throughput, d_hash);
        x17_haval256_cpu_hash_64(thr_id, throughput, startNounce, d_hash, 256);
        break;
    case 20: // cubehash → sha512
        x11_cubehash512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        x17_sha512_cpu_hash_64(thr_id, throughput, startNounce, d_hash);
        break;
    case 21: // echo → shavite
        x11_echo512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        x11_shavite512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    case 22: // luffa → shabal
        x11_luffa512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        x14_shabal512_cpu_hash_64(thr_id, throughput, startNounce, NULL, d_hash, (*order)++);
        break;
    default:
        gpulog(LOG_ERR, thr_id, "MEGAMEC: unknown permutation value %d", perm_value);
        break;
    }
}

// ---------- Init state ----------

static uint32_t *d_hash[MAX_GPUS];
static bool init[MAX_GPUS] = { 0 };

// ---------- Scanhash ----------

extern "C" int scanhash_megamec(int thr_id, struct work* work, uint32_t max_nonce, unsigned long *hashes_done)
{
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t first_nonce = pdata[19];
    int intensity = (device_sm[device_map[thr_id]] >= 500 && !is_windows()) ? 19 : 18;
    uint32_t throughput = cuda_default_throughput(thr_id, 1U << intensity);

    if (opt_benchmark)
        ptarget[7] = 0x5;

    if (!init[thr_id])
    {
        cudaSetDevice(device_map[thr_id]);
        if (opt_cudaschedule == -1 && gpu_threads == 1)
        {
            cudaDeviceReset();
            cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
            CUDA_LOG_ERROR();
        }
        gpulog(LOG_INFO, thr_id, "MEGAMEC intensity set to %g, %u cuda threads",
            throughput2intensity(throughput), throughput);

        quark_blake512_cpu_init(thr_id, throughput);
        quark_bmw512_cpu_init(thr_id, throughput);
        quark_groestl512_cpu_init(thr_id, throughput);
        quark_jh512_cpu_init(thr_id, throughput);
        quark_keccak512_cpu_init(thr_id, throughput);
        quark_skein512_cpu_init(thr_id, throughput);
        qubit_luffa512_cpu_init(thr_id, throughput);
        x11_luffa512_cpu_init(thr_id, throughput);
        x11_cubehash512_cpu_init(thr_id, throughput);
        x11_shavite512_cpu_init(thr_id, throughput);
        x11_simd512_cpu_init(thr_id, throughput);
        x11_echo512_cpu_init(thr_id, throughput);
        x13_hamsi512_cpu_init(thr_id, throughput);
        x13_fugue512_cpu_init(thr_id, throughput);
        x14_shabal512_cpu_init(thr_id, throughput);
        x15_whirlpool_cpu_init(thr_id, throughput, 0);
        x17_sha512_cpu_init(thr_id, throughput);
        x17_haval256_cpu_init(thr_id, throughput);

        CUDA_CALL_OR_RET_X(cudaMalloc(&d_hash[thr_id], (size_t)64 * throughput), 0);

        cuda_check_cpu_init(thr_id, throughput);

        init[thr_id] = true;
    }

    // Convert header to big-endian for GPU kernels
    uint32_t endiandata[20];
    for (int i = 0; i < 20; i++)
        be32enc(&endiandata[i], pdata[i]);

    // Extract timestamp from the header — MUST use the same source as megamechash
    uint32_t timestamp = megamec_timestamp(endiandata);

    // Compute permutations from timestamp
    uint32_t permutation_1[HASH_FUNC_COUNT_1];
    uint32_t permutation_2[HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1];
    uint32_t permutation_3[HASH_FUNC_COUNT_3 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1];

    memset(permutation_1, 0, sizeof(permutation_1));
    for (uint32_t i = 1; i < HASH_FUNC_COUNT_1; i++)
        permutation_1[i] = i;
    for (uint32_t i = HASH_FUNC_COUNT_1; i < HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1; i++)
        permutation_2[i] = i;
    for (uint32_t i = HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2; i < HASH_FUNC_COUNT_3 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1; i++)
        permutation_3[i] = i;

    uint32_t steps_1 = (timestamp - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS_7;
    for (uint32_t i = 0; i < steps_1; i++)
        std::next_permutation(permutation_1, permutation_1 + HASH_FUNC_COUNT_1);

    uint32_t steps_2 = (timestamp + HASH_FUNC_VAR_1 - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS;
    for (uint32_t i = 0; i < steps_2; i++)
        std::next_permutation(permutation_2 + HASH_FUNC_COUNT_1, permutation_2 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2);

    uint32_t steps_3 = (timestamp + HASH_FUNC_VAR_2 - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS_7;
    for (uint32_t i = 0; i < steps_3; i++)
        std::next_permutation(permutation_3 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2,
                              permutation_3 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_3);

    if (opt_debug)
    {
        gpulog(LOG_DEBUG, thr_id, "MEGAMEC timestamp=%u steps=%u/%u/%u",
            timestamp, steps_1, steps_2, steps_3);
        gpulog(LOG_DEBUG, thr_id, "MEGAMEC perm1: %u-%u-%u-%u-%u-%u-%u-%u",
            permutation_1[0], permutation_1[1], permutation_1[2], permutation_1[3],
            permutation_1[4], permutation_1[5], permutation_1[6], permutation_1[7]);
    }

    // Round 0: always blake512 on 80-byte header
    quark_blake512_cpu_setBlock_80(thr_id, endiandata);
    cuda_check_cpu_setTarget(ptarget);

    if (opt_debug)
        gpulog(LOG_DEBUG, thr_id, "MEGAMEC scan enter thr=%d ts=%u throughput=%u max_nonce=%08x",
            thr_id, timestamp, throughput, max_nonce);

    static int dbgcnt[MAX_GPUS] = { 0 };
    int dbg = (opt_debug && dbgcnt[thr_id] < 3);

    do
    {
        int order = 0;

        // Round 0: blake512 hash_80
        quark_blake512_cpu_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id]);
        order++;

        // Rounds 1-7: permutation_1 values
        for (int i = 1; i < HASH_FUNC_COUNT_1; i++)
            megamec_gpu_hash_pair(thr_id, throughput, pdata[19], d_hash[thr_id], permutation_1[i], &order);

        // Rounds 8-15: permutation_2 values
        for (int i = HASH_FUNC_COUNT_1; i < HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2; i++)
            megamec_gpu_hash_pair(thr_id, throughput, pdata[19], d_hash[thr_id], permutation_2[i], &order);

        // Rounds 16-22: permutation_3 values
        for (int i = HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2;
             i < HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_3; i++)
            megamec_gpu_hash_pair(thr_id, throughput, pdata[19], d_hash[thr_id], permutation_3[i], &order);

        // One-shot GPU-vs-CPU hash comparison for the first nonce of this batch
        if (dbg) {
            uint32_t gh[16];
            uint32_t vh[8];
            uint32_t ed[20];
            cudaMemcpy(gh, d_hash[thr_id], 64, cudaMemcpyDeviceToHost);
            memcpy(ed, endiandata, sizeof(ed));
            be32enc(&ed[19], pdata[19]);
            megamechash(vh, ed);
            gpulog(LOG_DEBUG, thr_id, "MEGAMEC GPU hash: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x",
                gh[0], gh[1], gh[2], gh[3], gh[4], gh[5], gh[6], gh[7],
                gh[8], gh[9], gh[10], gh[11], gh[12], gh[13], gh[14], gh[15]);
            gpulog(LOG_DEBUG, thr_id, "MEGAMEC CPU hash: %08x %08x %08x %08x %08x %08x %08x %08x",
                vh[0], vh[1], vh[2], vh[3], vh[4], vh[5], vh[6], vh[7]);
            gpulog(LOG_DEBUG, thr_id, "MEGAMEC target[7]=%08x nonce=%08x", ptarget[7], pdata[19]);
            dbgcnt[thr_id]++;
        }

        *hashes_done = pdata[19] - first_nonce + throughput;

        work->nonces[0] = cuda_check_hash(thr_id, throughput, pdata[19], d_hash[thr_id]);
        if (work->nonces[0] != UINT32_MAX)
        {
            const uint32_t Htarg = ptarget[7];
            uint32_t _ALIGN(64) vhash[8];
            be32enc(&endiandata[19], work->nonces[0]);
            megamechash(vhash, endiandata);
            if (vhash[7] <= Htarg && fulltest(vhash, ptarget))
            {
                work->valid_nonces = 1;
                work_set_target_ratio(work, vhash);
                work->nonces[1] = cuda_check_hash_suppl(thr_id, throughput, pdata[19], d_hash[thr_id], 1);
                if (work->nonces[1] != 0)
                {
                    be32enc(&endiandata[19], work->nonces[1]);
                    megamechash(vhash, endiandata);
                    bn_set_target_ratio(work, vhash, 1);
                    work->valid_nonces++;
                    pdata[19] = max(work->nonces[0], work->nonces[1]) + 1;
                }
                else
                {
                    pdata[19] = work->nonces[0] + 1;
                }
                return work->valid_nonces;
            }
            else
            {
                gpu_increment_reject(thr_id);
                if (!opt_quiet)
                    gpulog(LOG_WARNING, thr_id, "MEGAMEC result for %08x does not validate on CPU!", work->nonces[0]);
                pdata[19] = work->nonces[0] + 1;
                continue;
            }
        }

        if ((uint64_t) throughput + pdata[19] >= max_nonce)
        {
            pdata[19] = max_nonce;
            break;
        }
        pdata[19] += throughput;
    }
    while (!work_restart[thr_id].restart);

    *hashes_done = pdata[19] - first_nonce;
    return 0;
}

// ---------- Cleanup ----------

extern "C" void free_megamec(int thr_id)
{
    if (!init[thr_id])
        return;

    cudaThreadSynchronize();

    cudaFree(d_hash[thr_id]);

    quark_blake512_cpu_free(thr_id);
    quark_groestl512_cpu_free(thr_id);
    x11_simd512_cpu_free(thr_id);
    x13_fugue512_cpu_free(thr_id);
    x15_whirlpool_cpu_free(thr_id);

    cuda_check_cpu_free(thr_id);
    init[thr_id] = false;
    cudaDeviceSynchronize();
}
