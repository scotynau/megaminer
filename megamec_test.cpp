// Standalone Mega_Mec test — validates the CPU algorithm against a known
// Megacoin block (height 2153900).
// Build: g++ + sph C sources. No CUDA required.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <algorithm>

extern "C" {
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

#define HASH_FUNC_BASE_TIMESTAMP_1 1370079299
#define HASH_FUNC_COUNT_1 8
#define HASH_FUNC_COUNT_2 8
#define HASH_FUNC_COUNT_3 7
#define HASH_FUNC_VAR_1 2100
#define HASH_FUNC_VAR_2 2100
#define HASH_FUNC_COUNT_PERMUTATIONS_7 5040
#define HASH_FUNC_COUNT_PERMUTATIONS 40320

static void mega_mec(void *output, const void *input, uint32_t timestamp)
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

    uint32_t hash[23][16];
    uint32_t permutation_1[HASH_FUNC_COUNT_1];
    uint32_t permutation_2[HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1];
    uint32_t permutation_3[HASH_FUNC_COUNT_3 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1];

    memset(permutation_1, 0, sizeof(permutation_1));
    for (uint32_t i = 1; i < HASH_FUNC_COUNT_1; i++) permutation_1[i] = i;
    for (uint32_t i = HASH_FUNC_COUNT_1; i < HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1; i++) permutation_2[i] = i;
    for (uint32_t i = HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2; i < HASH_FUNC_COUNT_3 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1; i++) permutation_3[i] = i;

    uint32_t steps_1 = (timestamp - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS_7;
    for (uint32_t i = 0; i < steps_1; i++) std::next_permutation(permutation_1, permutation_1 + HASH_FUNC_COUNT_1);
    uint32_t steps_2 = (timestamp + HASH_FUNC_VAR_1 - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS;
    for (uint32_t i = 0; i < steps_2; i++) std::next_permutation(permutation_2 + HASH_FUNC_COUNT_1, permutation_2 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2);
    uint32_t steps_3 = (timestamp + HASH_FUNC_VAR_2 - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS_7;
    for (uint32_t i = 0; i < steps_3; i++) std::next_permutation(permutation_3 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2,
                              permutation_3 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_3);

    int lenToHash = 64;
    const void *toHash;
    const void *toHashinit = input;

    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, toHashinit, 80);
    sph_blake512_close(&ctx_blake, hash[0]);

    for (int i = 1; i < HASH_FUNC_COUNT_1; i++) {
        toHash = hash[i - 1];
        switch (permutation_1[i]) {
        case 1: sph_echo512_init(&ctx_echo); sph_echo512(&ctx_echo, toHash, lenToHash); sph_echo512_close(&ctx_echo, hash[i]);
                sph_blake512_init(&ctx_blake); sph_blake512(&ctx_blake, hash[i], 64); sph_blake512_close(&ctx_blake, hash[i]); break;
        case 2: sph_simd512_init(&ctx_simd); sph_simd512(&ctx_simd, toHash, lenToHash); sph_simd512_close(&ctx_simd, hash[i]);
                sph_bmw512_init(&ctx_bmw); sph_bmw512(&ctx_bmw, hash[i], 64); sph_bmw512_close(&ctx_bmw, hash[i]); break;
        case 3: sph_groestl512_init(&ctx_groestl); sph_groestl512(&ctx_groestl, toHash, lenToHash); sph_groestl512_close(&ctx_groestl, hash[i]); break;
        case 4: sph_whirlpool_init(&ctx_whirlpool); sph_whirlpool(&ctx_whirlpool, toHash, lenToHash); sph_whirlpool_close(&ctx_whirlpool, hash[i]);
                sph_jh512_init(&ctx_jh); sph_jh512(&ctx_jh, hash[i], 64); sph_jh512_close(&ctx_jh, hash[i]); break;
        case 5: sph_gost512_init(&ctx_gost); sph_gost512(&ctx_gost, toHash, lenToHash); sph_gost512_close(&ctx_gost, hash[i]);
                sph_keccak512_init(&ctx_keccak); sph_keccak512(&ctx_keccak, hash[i], 64); sph_keccak512_close(&ctx_keccak, hash[i]); break;
        case 6: sph_fugue512_init(&ctx_fugue); sph_fugue512(&ctx_fugue, toHash, lenToHash); sph_fugue512_close(&ctx_fugue, hash[i]);
                sph_skein512_init(&ctx_skein); sph_skein512(&ctx_skein, hash[i], 64); sph_skein512_close(&ctx_skein, hash[i]); break;
        case 7: sph_shavite512_init(&ctx_shavite); sph_shavite512(&ctx_shavite, toHash, lenToHash); sph_shavite512_close(&ctx_shavite, hash[i]);
                sph_luffa512_init(&ctx_luffa); sph_luffa512(&ctx_luffa, hash[i], 64); sph_luffa512_close(&ctx_luffa, hash[i]); break;
        }
    }
    for (int i = HASH_FUNC_COUNT_1; i < HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2; i++) {
        toHash = hash[i - 1];
        switch (permutation_2[i]) {
        case 8: sph_whirlpool_init(&ctx_whirlpool); sph_whirlpool(&ctx_whirlpool, toHash, lenToHash); sph_whirlpool_close(&ctx_whirlpool, hash[i]);
                sph_cubehash512_init(&ctx_cubehash); sph_cubehash512(&ctx_cubehash, hash[i], 64); sph_cubehash512_close(&ctx_cubehash, hash[i]); break;
        case 9: sph_jh512_init(&ctx_jh); sph_jh512(&ctx_jh, toHash, lenToHash); sph_jh512_close(&ctx_jh, hash[i]);
                sph_shavite512_init(&ctx_shavite); sph_shavite512(&ctx_shavite, hash[i], 64); sph_shavite512_close(&ctx_shavite, hash[i]); break;
        case 10: sph_blake512_init(&ctx_blake); sph_blake512(&ctx_blake, toHash, lenToHash); sph_blake512_close(&ctx_blake, hash[i]);
                 sph_simd512_init(&ctx_simd); sph_simd512(&ctx_simd, hash[i], 64); sph_simd512_close(&ctx_simd, hash[i]); break;
        case 11: sph_shabal512_init(&ctx_shabal); sph_shabal512(&ctx_shabal, toHash, lenToHash); sph_shabal512_close(&ctx_shabal, hash[i]);
                 sph_echo512_init(&ctx_echo); sph_echo512(&ctx_echo, hash[i], 64); sph_echo512_close(&ctx_echo, hash[i]); break;
        case 12: sph_hamsi512_init(&ctx_hamsi); sph_hamsi512(&ctx_hamsi, toHash, lenToHash); sph_hamsi512_close(&ctx_hamsi, hash[i]); break;
        case 13: sph_bmw512_init(&ctx_bmw); sph_bmw512(&ctx_bmw, toHash, lenToHash); sph_bmw512_close(&ctx_bmw, hash[i]);
                 sph_fugue512_init(&ctx_fugue); sph_fugue512(&ctx_fugue, hash[i], 64); sph_fugue512_close(&ctx_fugue, hash[i]); break;
        case 14: sph_keccak512_init(&ctx_keccak); sph_keccak512(&ctx_keccak, toHash, lenToHash); sph_keccak512_close(&ctx_keccak, hash[i]);
                 sph_shabal512_init(&ctx_shabal); sph_shabal512(&ctx_shabal, hash[i], 64); sph_shabal512_close(&ctx_shabal, hash[i]); break;
        case 15: sph_luffa512_init(&ctx_luffa); sph_luffa512(&ctx_luffa, toHash, lenToHash); sph_luffa512_close(&ctx_luffa, hash[i]);
                 sph_whirlpool_init(&ctx_whirlpool); sph_whirlpool(&ctx_whirlpool, hash[i], 64); sph_whirlpool_close(&ctx_whirlpool, hash[i]); break;
        }
    }
    for (int i = HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2; i < HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_3; i++) {
        toHash = hash[i - 1];
        switch (permutation_3[i]) {
        case 16: sph_sha512_init(&ctx_sha512); sph_sha512(&ctx_sha512, toHash, lenToHash); sph_sha512_close(&ctx_sha512, hash[i]);
                 sph_haval256_5_init(&ctx_haval); sph_haval256_5(&ctx_haval, hash[i], 64); sph_haval256_5_close(&ctx_haval, hash[i]); break;
        case 17: sph_skein512_init(&ctx_skein); sph_skein512(&ctx_skein, toHash, lenToHash); sph_skein512_close(&ctx_skein, hash[i]);
                 sph_groestl512_init(&ctx_groestl); sph_groestl512(&ctx_groestl, hash[i], 64); sph_groestl512_close(&ctx_groestl, hash[i]); break;
        case 18: sph_simd512_init(&ctx_simd); sph_simd512(&ctx_simd, toHash, lenToHash); sph_simd512_close(&ctx_simd, hash[i]);
                 sph_hamsi512_init(&ctx_hamsi); sph_hamsi512(&ctx_hamsi, hash[i], 64); sph_hamsi512_close(&ctx_hamsi, hash[i]); break;
        case 19: sph_gost512_init(&ctx_gost); sph_gost512(&ctx_gost, toHash, lenToHash); sph_gost512_close(&ctx_gost, hash[i]);
                 sph_haval256_5_init(&ctx_haval); sph_haval256_5(&ctx_haval, hash[i], 64); sph_haval256_5_close(&ctx_haval, hash[i]); break;
        case 20: sph_cubehash512_init(&ctx_cubehash); sph_cubehash512(&ctx_cubehash, toHash, lenToHash); sph_cubehash512_close(&ctx_cubehash, hash[i]);
                 sph_sha512_init(&ctx_sha512); sph_sha512(&ctx_sha512, hash[i], 64); sph_sha512_close(&ctx_sha512, hash[i]); break;
        case 21: sph_echo512_init(&ctx_echo); sph_echo512(&ctx_echo, toHash, lenToHash); sph_echo512_close(&ctx_echo, hash[i]);
                 sph_shavite512_init(&ctx_shavite); sph_shavite512(&ctx_shavite, hash[i], 64); sph_shavite512_close(&ctx_shavite, hash[i]); break;
        case 22: sph_luffa512_init(&ctx_luffa); sph_luffa512(&ctx_luffa, toHash, lenToHash); sph_luffa512_close(&ctx_luffa, hash[i]);
                 sph_shabal512_init(&ctx_shabal); sph_shabal512(&ctx_shabal, hash[i], 64); sph_shabal512_close(&ctx_shabal, hash[i]); break;
        }
    }
    memcpy(output, hash[22], 32);
}

int main(void)
{
    // Block 2153900 header fields
    const uint32_t version = 536870912u;      // 0x20000000
    const char *prev = "e05532fa319a88a5d6e804ba0470f6511de873766337b876d72d6837654aab1d";
    const char *merkle = "75ff1c552a46988bd18a152cb145db575d13dcc1d8cb67d1e51efc0d9563029a";
    const uint32_t tm = 1792089217u;
    const uint32_t bits = 0x1d00ccdeu;
    const uint32_t nonce = 2254377731u;

    unsigned char hdr[80];
    memset(hdr, 0, sizeof(hdr));
    memcpy(hdr + 0, &version, 4);
    for (int i = 0; i < 32; i++) { unsigned b; sscanf(prev + 2 * (31 - i), "%2x", &b); hdr[4 + i] = (unsigned char)b; }
    for (int i = 0; i < 32; i++) { unsigned b; sscanf(merkle + 2 * (31 - i), "%2x", &b); hdr[36 + i] = (unsigned char)b; }
    memcpy(hdr + 68, &tm, 4);
    memcpy(hdr + 72, &bits, 4);
    memcpy(hdr + 76, &nonce, 4);

    unsigned char out[32];
    mega_mec(out, hdr, tm);

    printf("header hex: ");
    for (int i = 0; i < 80; i++) printf("%02x", hdr[i]);
    printf("\n");
    printf("computed raw: ");
    for (int i = 0; i < 32; i++) printf("%02x", out[i]);
    printf("\n");
    printf("computed rev: ");
    for (int i = 31; i >= 0; i--) printf("%02x", out[i]);
    printf("\n");
    printf("expected:     73306c18b690e2c2d9c90946c1bd84cf34750746919c3cd614910130e5b13823\n");
    return 0;
}
