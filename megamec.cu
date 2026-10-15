// Megacoin MEGAMEC hybrid CPU/CUDA Implementation
// 17 algorithms, 23 rounds, permutation derived from block timestamp (input[68..71])

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
}

#include "miner.h"
#include "cuda_helper.h"
#include "cuda_megamec.h"

#include <stdio.h>
#include <unistd.h>
#include <memory.h>
#include <pthread.h>

// ---------- Existing GPU kernel declarations (same ones used by x16r) ----------

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
extern void whirlpool512_init_sm3(int thr_id, uint32_t threads, int mode);
extern void x15_whirlpool_cpu_init(int thr_id, uint32_t threads, int flag);
extern void x17_sha512_cpu_init(int thr_id, uint32_t threads);
extern void x17_haval256_cpu_init(int thr_id, uint32_t threads);

// setBlock_80
extern void quark_blake512_cpu_setBlock_80(int thr_id, uint32_t *endiandata);
extern void quark_bmw512_cpu_setBlock_80(void *pdata);
extern void groestl512_setBlock_80(int thr_id, uint32_t *endiandata);
extern void jh512_setBlock_80(int thr_id, uint32_t *endiandata);
extern void keccak512_setBlock_80(int thr_id, uint32_t *endiandata);
extern void skein512_cpu_setBlock_80(void *pdata);
extern void qubit_luffa512_cpu_setBlock_80(void *pdata);
extern void cubehash512_setBlock_80(int thr_id, uint32_t *endiandata);
extern void x11_shavite512_setBlock_80(void *pdata);
extern void whirlpool512_setBlock_80_sm3(void *pdata, const void *ptarget);

// hash_80 (first round, nonce in block header)
extern void quark_blake512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);
extern void quark_bmw512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash, int order);
extern void groestl512_cuda_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);
extern void jh512_cuda_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);
extern void keccak512_cuda_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);
extern void skein512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash, int swap);
extern void qubit_luffa512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash, int order);
extern void cubehash512_cuda_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);
extern void x11_shavite512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash, int order);
extern void whirlpool512_hash_80_sm3(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);

// hash_64 (rounds 1..22)
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

// free (only some have real free functions)
extern void quark_blake512_cpu_free(int thr_id);
extern void quark_groestl512_cpu_free(int thr_id);
extern void x11_simd512_cpu_free(int thr_id);
extern void x13_fugue512_cpu_free(int thr_id);
extern void whirlpool512_free_sm3(int thr_id);
extern void x15_whirlpool_cpu_free(int thr_id);

// ---------- CPU fallback sub-threads for unimplemented hash_80 ----------

typedef struct
{
    int                     id;
    pthread_t               thread;
    pthread_cond_t          cond;
    pthread_mutex_t         mutex;
    int                     thr_id;
    uint32_t                joboffset;
    uint32_t                jobcount;
    uint32_t                nonce_begin;
    uint32_t                endiandata[20];
    int                     hash_selection;
    bool                    exit_thread;

    sph_simd512_context     ctx_simd;
    sph_echo512_context     ctx_echo;
    sph_hamsi512_context    ctx_hamsi;
    sph_fugue512_context    ctx_fugue;
    sph_shabal512_context   ctx_shabal;
    sph_sha512_context      ctx_sha512;
    sph_haval256_5_context  ctx_haval;
} subthread_t;

static uint32_t *d_hash[MAX_GPUS];
static uint32_t *h_hash[MAX_GPUS];
static subthread_t *sub_threads[MAX_GPUS];

// ---------- CPU hash for validation ----------

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
    sph_haval256_5_context   ctx_haval;

    uchar _ALIGN(64) hash[64];
    uint32_t *phash = (uint32_t *) hash;
    uint8_t *timestamp = (uint8_t *) input + 68;

    for (int i = 0; i < MEGAMEC_ROUNDS; i++)
    {
        int length = (i == 0) ? 80 : 64;
        const void *data = (i == 0) ? input : phash;

        switch (get_megamec_selection(timestamp, i))
        {
            case MEGAMEC_BLAKE:
                sph_blake512_init(&ctx_blake);
                sph_blake512(&ctx_blake, data, length);
                sph_blake512_close(&ctx_blake, phash);
                break;
            case MEGAMEC_BMW:
                sph_bmw512_init(&ctx_bmw);
                sph_bmw512(&ctx_bmw, data, length);
                sph_bmw512_close(&ctx_bmw, phash);
                break;
            case MEGAMEC_GROESTL:
                sph_groestl512_init(&ctx_groestl);
                sph_groestl512(&ctx_groestl, data, length);
                sph_groestl512_close(&ctx_groestl, phash);
                break;
            case MEGAMEC_JH:
                sph_jh512_init(&ctx_jh);
                sph_jh512(&ctx_jh, data, length);
                sph_jh512_close(&ctx_jh, phash);
                break;
            case MEGAMEC_KECCAK:
                sph_keccak512_init(&ctx_keccak);
                sph_keccak512(&ctx_keccak, data, length);
                sph_keccak512_close(&ctx_keccak, phash);
                break;
            case MEGAMEC_SKEIN:
                sph_skein512_init(&ctx_skein);
                sph_skein512(&ctx_skein, data, length);
                sph_skein512_close(&ctx_skein, phash);
                break;
            case MEGAMEC_LUFFA:
                sph_luffa512_init(&ctx_luffa);
                sph_luffa512(&ctx_luffa, data, length);
                sph_luffa512_close(&ctx_luffa, phash);
                break;
            case MEGAMEC_CUBEHASH:
                sph_cubehash512_init(&ctx_cubehash);
                sph_cubehash512(&ctx_cubehash, data, length);
                sph_cubehash512_close(&ctx_cubehash, phash);
                break;
            case MEGAMEC_SHAVITE:
                sph_shavite512_init(&ctx_shavite);
                sph_shavite512(&ctx_shavite, data, length);
                sph_shavite512_close(&ctx_shavite, phash);
                break;
            case MEGAMEC_SIMD:
                sph_simd512_init(&ctx_simd);
                sph_simd512(&ctx_simd, data, length);
                sph_simd512_close(&ctx_simd, phash);
                break;
            case MEGAMEC_ECHO:
                sph_echo512_init(&ctx_echo);
                sph_echo512(&ctx_echo, data, length);
                sph_echo512_close(&ctx_echo, phash);
                break;
            case MEGAMEC_HAMSI:
                sph_hamsi512_init(&ctx_hamsi);
                sph_hamsi512(&ctx_hamsi, data, length);
                sph_hamsi512_close(&ctx_hamsi, phash);
                break;
            case MEGAMEC_FUGUE:
                sph_fugue512_init(&ctx_fugue);
                sph_fugue512(&ctx_fugue, data, length);
                sph_fugue512_close(&ctx_fugue, phash);
                break;
            case MEGAMEC_SHABAL:
                sph_shabal512_init(&ctx_shabal);
                sph_shabal512(&ctx_shabal, data, length);
                sph_shabal512_close(&ctx_shabal, phash);
                break;
            case MEGAMEC_WHIRLPOOL:
                sph_whirlpool_init(&ctx_whirlpool);
                sph_whirlpool(&ctx_whirlpool, data, length);
                sph_whirlpool_close(&ctx_whirlpool, phash);
                break;
            case MEGAMEC_SHA512:
                sph_sha512_init(&ctx_sha512);
                sph_sha512(&ctx_sha512, data, length);
                sph_sha512_close(&ctx_sha512, phash);
                break;
            case MEGAMEC_HAVAL:
                sph_haval256_5_init(&ctx_haval);
                sph_haval256_5(&ctx_haval, data, length);
                sph_haval256_5_close(&ctx_haval, phash);
                break;
            default:
                gpulog(LOG_ERR, -1, "MEGAMEC: unknown hash selection %d", get_megamec_selection(timestamp, i));
                break;
        }
    }
    memcpy(output, phash, 32);
}

// ---------- CPU fallback thread ----------

static void *scanhash_cpufallback_thread(void *userdata)
{
    subthread_t& subthread = *((subthread_t*)userdata);

    pthread_mutex_lock(&subthread.mutex);

    while (1)
    {
        while (!subthread.jobcount)
        {
            pthread_cond_wait(&subthread.cond, &subthread.mutex);
            if (subthread.exit_thread)
                break;
        }

        if (subthread.exit_thread)
        {
            pthread_mutex_unlock(&subthread.mutex);
            break;
        }

        for (uint32_t i = subthread.joboffset; i < subthread.joboffset + subthread.jobcount; i++)
        {
            uint32_t* target_hash = &h_hash[subthread.thr_id][16 * i];
            be32enc(&subthread.endiandata[19], subthread.nonce_begin + i);

            switch (subthread.hash_selection)
            {
                case MEGAMEC_SIMD:
                    sph_simd512_init(&subthread.ctx_simd);
                    sph_simd512(&subthread.ctx_simd, subthread.endiandata, 80);
                    sph_simd512_close(&subthread.ctx_simd, target_hash);
                    break;
                case MEGAMEC_ECHO:
                    sph_echo512_init(&subthread.ctx_echo);
                    sph_echo512(&subthread.ctx_echo, subthread.endiandata, 80);
                    sph_echo512_close(&subthread.ctx_echo, target_hash);
                    break;
                case MEGAMEC_HAMSI:
                    sph_hamsi512_init(&subthread.ctx_hamsi);
                    sph_hamsi512(&subthread.ctx_hamsi, subthread.endiandata, 80);
                    sph_hamsi512_close(&subthread.ctx_hamsi, target_hash);
                    break;
                case MEGAMEC_FUGUE:
                    sph_fugue512_init(&subthread.ctx_fugue);
                    sph_fugue512(&subthread.ctx_fugue, subthread.endiandata, 80);
                    sph_fugue512_close(&subthread.ctx_fugue, target_hash);
                    break;
                case MEGAMEC_SHABAL:
                    sph_shabal512_init(&subthread.ctx_shabal);
                    sph_shabal512(&subthread.ctx_shabal, subthread.endiandata, 80);
                    sph_shabal512_close(&subthread.ctx_shabal, target_hash);
                    break;
                case MEGAMEC_SHA512:
                    sph_sha512_init(&subthread.ctx_sha512);
                    sph_sha512(&subthread.ctx_sha512, subthread.endiandata, 80);
                    sph_sha512_close(&subthread.ctx_sha512, target_hash);
                    break;
                case MEGAMEC_HAVAL:
                    sph_haval256_5_init(&subthread.ctx_haval);
                    sph_haval256_5(&subthread.ctx_haval, subthread.endiandata, 80);
                    sph_haval256_5_close(&subthread.ctx_haval, target_hash);
                    break;
                default:
                    gpulog(LOG_ERR, subthread.thr_id, "MEGAMEC CPU fallback: invalid selection %d", subthread.hash_selection);
                    break;
            }
        }

        cudaMemcpy(d_hash[subthread.thr_id] + (subthread.joboffset * 16),
                   h_hash[subthread.thr_id] + (subthread.joboffset * 16),
                   (subthread.jobcount * 16) * sizeof(uint32_t), cudaMemcpyHostToDevice);

        subthread.jobcount = 0;
        pthread_cond_signal(&subthread.cond);
    }

    pthread_mutex_unlock(&subthread.mutex);
    return NULL;
}

// ---------- Init ----------

static bool init[MAX_GPUS] = { 0 };

// ---------- Scanhash ----------

extern "C" int scanhash_megamec(int thr_id, struct work* work, uint32_t max_nonce, unsigned long *hashes_done)
{
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t first_nonce = pdata[19];
    int intensity = (device_sm[device_map[thr_id]] >= 500 && !is_windows()) ? 20 : 19;
    uint32_t throughput = cuda_default_throughput(thr_id, 1U << intensity);

    if (opt_benchmark)
        ptarget[7] = 0x5;

    int num_sub_threads = opt_n_cpu_fallback_threads;

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
        whirlpool512_init_sm3(thr_id, throughput, 0);
        x15_whirlpool_cpu_init(thr_id, throughput, 0);
        x17_sha512_cpu_init(thr_id, throughput);
        x17_haval256_cpu_init(thr_id, throughput);

        CUDA_CALL_OR_RET_X(cudaMalloc(&d_hash[thr_id], (size_t)64 * throughput), 0);
        h_hash[thr_id] = (uint32_t*)malloc((size_t)64 * throughput);

        cuda_check_cpu_init(thr_id, throughput);

        sub_threads[thr_id] = (subthread_t*)calloc(num_sub_threads, sizeof(subthread_t));
        for (int i = 0; i < num_sub_threads; ++i)
        {
            subthread_t& sub_thr = sub_threads[thr_id][i];
            sub_thr.jobcount = 0;
            sub_thr.id = i;
            sub_thr.thr_id = thr_id;
            sub_thr.exit_thread = false;
            pthread_mutex_init(&sub_thr.mutex, NULL);
            pthread_cond_init(&sub_thr.cond, NULL);
            pthread_create(&sub_thr.thread, NULL, scanhash_cpufallback_thread, &sub_thr);
        }

        init[thr_id] = true;
    }

    uint32_t endiandata[20];
    for (int i = 0; i < 20; i++)
        be32enc(&endiandata[i], pdata[i]);

    uint8_t *timestamp = (uint8_t *) endiandata + 68;
    int hash_selection[MEGAMEC_ROUNDS];
    for (int i = 0; i < MEGAMEC_ROUNDS; i++)
        hash_selection[i] = get_megamec_selection(timestamp, i);

    if (opt_debug)
    {
        char sel_str[512] = { 0 };
        for (int i = 0; i < MEGAMEC_ROUNDS; i++) {
            strcat(sel_str, megamec_hash_names[hash_selection[i]]);
            if (i < MEGAMEC_ROUNDS - 1) strcat(sel_str, "-");
        }
        gpulog(LOG_DEBUG, thr_id, "MEGAMEC selection: %s", sel_str);
    }

    // Determine if first round needs CPU fallback
    bool cpuFallback = false;
    switch (hash_selection[0])
    {
        case MEGAMEC_BLAKE:
            quark_blake512_cpu_setBlock_80(thr_id, endiandata);
            break;
        case MEGAMEC_BMW:
            quark_bmw512_cpu_setBlock_80(endiandata);
            break;
        case MEGAMEC_GROESTL:
            groestl512_setBlock_80(thr_id, endiandata);
            break;
        case MEGAMEC_JH:
            jh512_setBlock_80(thr_id, endiandata);
            break;
        case MEGAMEC_KECCAK:
            keccak512_setBlock_80(thr_id, endiandata);
            break;
        case MEGAMEC_SKEIN:
            skein512_cpu_setBlock_80(endiandata);
            break;
        case MEGAMEC_LUFFA:
            qubit_luffa512_cpu_setBlock_80(endiandata);
            break;
        case MEGAMEC_CUBEHASH:
            cubehash512_setBlock_80(thr_id, endiandata);
            break;
        case MEGAMEC_SHAVITE:
            x11_shavite512_setBlock_80(endiandata);
            break;
        case MEGAMEC_WHIRLPOOL:
            whirlpool512_setBlock_80_sm3((void*)endiandata, ptarget);
            break;
        default:
            // SIMD, ECHO, HAMSI, FUGUE, SHABAL, SHA512, HAVAL: no GPU hash_80 kernel
            cpuFallback = true;
            if (opt_debug)
                gpulog(LOG_DEBUG, thr_id, "MEGAMEC first round is CPU fallback: %s", megamec_hash_names[hash_selection[0]]);
            break;
    }

    cuda_check_cpu_setTarget(ptarget);

    if (cpuFallback)
        gpulog(LOG_INFO, thr_id, "Partial GPU job - first round on CPU (%d threads).", num_sub_threads);
    else
        gpulog(LOG_INFO, thr_id, "100%% GPU job.");

    do
    {
        int order = 0;
        memset(h_hash[thr_id], 0, (size_t)64 * throughput);

        // First round (80 bytes)
        switch (hash_selection[0])
        {
            case MEGAMEC_BLAKE:
                quark_blake512_cpu_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id]); order++;
                break;
            case MEGAMEC_BMW:
                quark_bmw512_cpu_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id], order++);
                break;
            case MEGAMEC_GROESTL:
                groestl512_cuda_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id]); order++;
                break;
            case MEGAMEC_JH:
                jh512_cuda_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id]); order++;
                break;
            case MEGAMEC_KECCAK:
                keccak512_cuda_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id]); order++;
                break;
            case MEGAMEC_SKEIN:
                skein512_cpu_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id], 1); order++;
                break;
            case MEGAMEC_LUFFA:
                qubit_luffa512_cpu_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id], order++);
                break;
            case MEGAMEC_CUBEHASH:
                cubehash512_cuda_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id]); order++;
                break;
            case MEGAMEC_SHAVITE:
                x11_shavite512_cpu_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id], order++);
                break;
            case MEGAMEC_WHIRLPOOL:
                whirlpool512_hash_80_sm3(thr_id, throughput, pdata[19], d_hash[thr_id]); order++;
                break;
            default:
                break; // handled by CPU fallback below
        }

        // Dispatch CPU fallback work for first round if needed
        if (cpuFallback)
        {
            int num = (int)(throughput / num_sub_threads);
            int extra = throughput - (num * num_sub_threads);
            int start = 0;

            for (int i = 0; i < num_sub_threads; ++i)
            {
                subthread_t& sub_thr = sub_threads[thr_id][i];
                pthread_mutex_lock(&sub_thr.mutex);
                sub_thr.hash_selection = hash_selection[0];
                memcpy(sub_thr.endiandata, endiandata, sizeof(endiandata));
                sub_thr.nonce_begin = pdata[19];
                sub_thr.joboffset = start;
                sub_thr.jobcount = num;
                if (i < extra) sub_thr.jobcount++;
                start += sub_thr.jobcount;
                pthread_cond_signal(&sub_thr.cond);
                pthread_mutex_unlock(&sub_thr.mutex);
            }

            for (int i = 0; i < num_sub_threads; ++i)
            {
                subthread_t& sub_thr = sub_threads[thr_id][i];
                pthread_mutex_lock(&sub_thr.mutex);
                while (sub_thr.jobcount > 0 && !sub_thr.exit_thread)
                    pthread_cond_wait(&sub_thr.cond, &sub_thr.mutex);
                pthread_mutex_unlock(&sub_thr.mutex);
            }
        }

        // Rounds 1..22 (64 bytes)
        for (int i = 1; i < MEGAMEC_ROUNDS; i++)
        {
            switch (hash_selection[i])
            {
                case MEGAMEC_BLAKE:
                    quark_blake512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_BMW:
                    quark_bmw512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_GROESTL:
                    quark_groestl512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_JH:
                    quark_jh512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_KECCAK:
                    quark_keccak512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_SKEIN:
                    quark_skein512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_LUFFA:
                    x11_luffa512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_CUBEHASH:
                    x11_cubehash512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_SHAVITE:
                    x11_shavite512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_SIMD:
                    x11_simd512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_ECHO:
                    x11_echo512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_HAMSI:
                    x13_hamsi512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_FUGUE:
                    x13_fugue512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_SHABAL:
                    x14_shabal512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_WHIRLPOOL:
                    x15_whirlpool_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_SHA512:
                    x17_sha512_cpu_hash_64(thr_id, throughput, pdata[19], d_hash[thr_id]); order++;
                    break;
                case MEGAMEC_HAVAL:
                    x17_haval256_cpu_hash_64(thr_id, throughput, pdata[19], d_hash[thr_id], 256); order++;
                    break;
                default:
                    gpulog(LOG_ERR, thr_id, "MEGAMEC round %d: unknown selection %d", i, hash_selection[i]);
                    break;
            }
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

    int num_sub_threads = opt_n_cpu_fallback_threads;
    for (int i = 0; i < num_sub_threads; ++i)
    {
        subthread_t& sub_thr = sub_threads[thr_id][i];
        sub_thr.exit_thread = true;
        pthread_mutex_lock(&sub_thr.mutex);
        pthread_cond_signal(&sub_thr.cond);
        pthread_mutex_unlock(&sub_thr.mutex);
        void* ret;
        pthread_join(sub_thr.thread, &ret);
        pthread_mutex_destroy(&sub_thr.mutex);
        pthread_cond_destroy(&sub_thr.cond);
    }

    cudaFree(d_hash[thr_id]);
    free(h_hash[thr_id]);
    free(sub_threads[thr_id]);

    quark_blake512_cpu_free(thr_id);
    quark_groestl512_cpu_free(thr_id);
    x11_simd512_cpu_free(thr_id);
    x13_fugue512_cpu_free(thr_id);
    whirlpool512_free_sm3(thr_id);
    x15_whirlpool_cpu_free(thr_id);

    cuda_check_cpu_free(thr_id);
    init[thr_id] = false;
    cudaDeviceSynchronize();
}
