// Megacoin MEGAMEC hybrid CPU/CUDA Implementation
// 17 algorithms, 23 rounds (8/8/7) with timestamp-based permutation

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
#include "quark/cuda_quark.h"
#include "x11/cuda_x11.h"
#include "x16r/cuda_x16r.h"

#include <stdio.h>
#include <unistd.h>
#include <memory.h>
#include <pthread.h>

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

    sph_simd512_context     ctx_simd;       // 9
    sph_echo512_context     ctx_echo;       // 10
    sph_hamsi512_context    ctx_hamsi;      // 11
    sph_fugue512_context    ctx_fugue;      // 12
    sph_shabal512_context   ctx_shabal;     // 13
    sph_whirlpool_context   ctx_whirlpool;  // 14
    sph_sha512_context      ctx_sha512;     // 15
    sph_haval256_5_context  ctx_haval;      // 16

} subthread_t;

static uint32_t *d_hash[MAX_GPUS];
static uint32_t *h_hash[MAX_GPUS];
static subthread_t *sub_threads[MAX_GPUS];

// CPU HASH - full 23 rounds
extern "C" void megamechash(void *output, const void *input)
{
    sph_blake512_context     ctx_blake;      // 0
    sph_bmw512_context       ctx_bmw;        // 1
    sph_groestl512_context   ctx_groestl;    // 2
    sph_jh512_context        ctx_jh;         // 3
    sph_keccak512_context    ctx_keccak;     // 4
    sph_skein512_context     ctx_skein;      // 5
    sph_luffa512_context     ctx_luffa;      // 6
    sph_cubehash512_context  ctx_cubehash;   // 7
    sph_shavite512_context   ctx_shavite;    // 8
    sph_simd512_context      ctx_simd;       // 9
    sph_echo512_context      ctx_echo;       // 10
    sph_hamsi512_context     ctx_hamsi;      // 11
    sph_fugue512_context     ctx_fugue;      // 12
    sph_shabal512_context    ctx_shabal;     // 13
    sph_whirlpool_context    ctx_whirlpool;  // 14
    sph_sha512_context       ctx_sha512;     // 15
    sph_haval256_5_context   ctx_haval;      // 16

    uchar _ALIGN(64) hash[64];
    uint32_t *phash = (uint32_t *) hash;
    uint8_t *timestamp = (uint8_t *) input + 68;  // timestamp at input[68..71]

    for (int i = 0; i < MEGAMEC_ROUNDS; i++)
    {
        int length;
        if (i == 0)
        {
            length = 80;
        }
        else
        {
            input = phash;
            length = 64;
        }

        int hash_selection = get_megamec_selection(timestamp, i);
        switch (hash_selection)
        {
            case MEGAMEC_BLAKE:
                sph_blake512_init(&ctx_blake);
                sph_blake512(&ctx_blake, input, length);
                sph_blake512_close(&ctx_blake, phash);
                break;
            case MEGAMEC_BMW:
                sph_bmw512_init(&ctx_bmw);
                sph_bmw512(&ctx_bmw, input, length);
                sph_bmw512_close(&ctx_bmw, phash);
                break;
            case MEGAMEC_GROESTL:
                sph_groestl512_init(&ctx_groestl);
                sph_groestl512(&ctx_groestl, input, length);
                sph_groestl512_close(&ctx_groestl, phash);
                break;
            case MEGAMEC_JH:
                sph_jh512_init(&ctx_jh);
                sph_jh512(&ctx_jh, input, length);
                sph_jh512_close(&ctx_jh, phash);
                break;
            case MEGAMEC_KECCAK:
                sph_keccak512_init(&ctx_keccak);
                sph_keccak512(&ctx_keccak, input, length);
                sph_keccak512_close(&ctx_keccak, phash);
                break;
            case MEGAMEC_SKEIN:
                sph_skein512_init(&ctx_skein);
                sph_skein512(&ctx_skein, input, length);
                sph_skein512_close(&ctx_skein, phash);
                break;
            case MEGAMEC_LUFFA:
                sph_luffa512_init(&ctx_luffa);
                sph_luffa512(&ctx_luffa, input, length);
                sph_luffa512_close(&ctx_luffa, phash);
                break;
            case MEGAMEC_CUBEHASH:
                sph_cubehash512_init(&ctx_cubehash);
                sph_cubehash512(&ctx_cubehash, input, length);
                sph_cubehash512_close(&ctx_cubehash, phash);
                break;
            case MEGAMEC_SHAVITE:
                sph_shavite512_init(&ctx_shavite);
                sph_shavite512(&ctx_shavite, input, length);
                sph_shavite512_close(&ctx_shavite, phash);
                break;
            case MEGAMEC_SIMD:
                sph_simd512_init(&ctx_simd);
                sph_simd512(&ctx_simd, input, length);
                sph_simd512_close(&ctx_simd, phash);
                break;
            case MEGAMEC_ECHO:
                sph_echo512_init(&ctx_echo);
                sph_echo512(&ctx_echo, input, length);
                sph_echo512_close(&ctx_echo, phash);
                break;
            case MEGAMEC_HAMSI:
                sph_hamsi512_init(&ctx_hamsi);
                sph_hamsi512(&ctx_hamsi, input, length);
                sph_hamsi512_close(&ctx_hamsi, phash);
                break;
            case MEGAMEC_FUGUE:
                sph_fugue512_init(&ctx_fugue);
                sph_fugue512(&ctx_fugue, input, length);
                sph_fugue512_close(&ctx_fugue, phash);
                break;
            case MEGAMEC_SHABAL:
                sph_shabal512_init(&ctx_shabal);
                sph_shabal512(&ctx_shabal, input, length);
                sph_shabal512_close(&ctx_shabal, phash);
                break;
            case MEGAMEC_WHIRLPOOL:
                sph_whirlpool_init(&ctx_whirlpool);
                sph_whirlpool(&ctx_whirlpool, input, length);
                sph_whirlpool_close(&ctx_whirlpool, phash);
                break;
            case MEGAMEC_SHA512:
                sph_sha512_init(&ctx_sha512);
                sph_sha512(&ctx_sha512, input, length);
                sph_sha512_close(&ctx_sha512, phash);
                break;
            case MEGAMEC_HAVAL:
                sph_haval256_5_init(&ctx_haval);
                sph_haval256_5(&ctx_haval, input, length);
                sph_haval256_5_close(&ctx_haval, phash);
                break;
            default:
                gpulog(LOG_ERR, -1, "Unknown MEGAMEC hash selection: %d (this should never happen!)", hash_selection);
                break;
        }
    }
    memcpy(output, phash, 32);
}

//#define _DEBUG
#define _DEBUG_PREFIX "megamec"
#include "cuda_debug.cuh"

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
            {
                break;
            }
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
                case MEGAMEC_WHIRLPOOL:
                    sph_whirlpool_init(&subthread.ctx_whirlpool);
                    sph_whirlpool(&subthread.ctx_whirlpool, subthread.endiandata, 80);
                    sph_whirlpool_close(&subthread.ctx_whirlpool, target_hash);
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
                    gpulog(LOG_ERR, subthread.thr_id, "hash selection not valid for cpu multithreading: %d (this should never happen!)", subthread.hash_selection);
                    break;
            }   
        }

        cudaMemcpy(d_hash[subthread.thr_id] + (subthread.joboffset * 16), h_hash[subthread.thr_id] + (subthread.joboffset * 16), (subthread.jobcount * 16) *sizeof(uint32_t), cudaMemcpyHostToDevice);

        subthread.jobcount = 0;

        pthread_cond_signal(&subthread.cond);
    }

    pthread_mutex_unlock(&subthread.mutex);

    return NULL;
}

static bool init[MAX_GPUS] = { 0 };

extern "C" int scanhash_megamec(int thr_id, struct work* work, uint32_t max_nonce, unsigned long *hashes_done)
{
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t first_nonce = pdata[19];
    int intensity = (device_sm[device_map[thr_id]] >= 500 && !is_windows()) ? 20 : 19;
    uint32_t throughput = cuda_default_throughput(thr_id, 1U << intensity);

    if (opt_benchmark)
    {
        ptarget[7] = 0x5;
    }

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
        gpulog(LOG_INFO, thr_id, "MEGAMEC Intensity set to %g, %u cuda threads", throughput2intensity(throughput), throughput);

        // Initialize all 17 algorithms
        megamec_blake512_cpu_init(thr_id, throughput);
        megamec_bmw512_cpu_init(thr_id, throughput);
        megamec_groestl512_cpu_init(thr_id, throughput);
        megamec_jh512_cpu_init(thr_id, throughput);
        megamec_keccak512_cpu_init(thr_id, throughput);
        megamec_skein512_cpu_init(thr_id, throughput);
        megamec_luffa512_cpu_init(thr_id, throughput);
        megamec_cubehash512_cpu_init(thr_id, throughput);
        megamec_shavite512_cpu_init(thr_id, throughput);
        megamec_simd512_cpu_init(thr_id, throughput);
        megamec_echo512_cpu_init(thr_id, throughput);
        megamec_hamsi512_cpu_init(thr_id, throughput);
        megamec_fugue512_cpu_init(thr_id, throughput);
        megamec_shabal512_cpu_init(thr_id, throughput);
        megamec_whirlpool512_cpu_init(thr_id, throughput, 0);
        megamec_sha512_cpu_init(thr_id, throughput);
        megamec_haval256_cpu_init(thr_id, throughput);

        CUDA_CALL_OR_RET_X(cudaMalloc(&d_hash[thr_id], (size_t) 64 * throughput), 0);

        h_hash[thr_id] = (uint32_t*)malloc((size_t)64 * throughput);
        
        if (opt_debug)
        {
            gpulog(LOG_DEBUG, thr_id, "Num CPU-Fallback subthreads  = %d", num_sub_threads);
        }

        cuda_check_cpu_init(thr_id, throughput);

        sub_threads[thr_id] = (subthread_t*)calloc(num_sub_threads, sizeof(subthread_t));

        for (int i = 0; i < num_sub_threads; ++i)
        {
            subthread_t& sub_thr = sub_threads[thr_id][i];

            sub_thr.jobcount = 0;
            sub_thr.id = i;
            sub_thr.thr_id = thr_id;
            sub_thr.exit_thread = false;

            int ret = pthread_mutex_init(&sub_thr.mutex, NULL);

            if (ret != 0)
            {
                gpulog(LOG_ERR, thr_id, "pthread_mutex_init : failed %d", ret);
            }

            ret = pthread_cond_init(&sub_thr.cond, NULL);

            if (ret != 0)
            {
                gpulog(LOG_ERR, thr_id, "pthread_cond_init : failed %d", ret);
            }

            ret = pthread_create(&sub_thr.thread, NULL, scanhash_cpufallback_thread, &sub_thr);

            if (ret != 0)
            {
                gpulog(LOG_ERR, thr_id, "pthread_create : failed %d", ret);
            }
        }

        init[thr_id] = true;
    }

    uint32_t endiandata[20];
    
    for (int i = 0; i < 20; i++)
    {
        be32enc(&endiandata[i], pdata[i]);
    }

    uint8_t *timestamp = (uint8_t *) endiandata + 68;
    int hash_selection[MEGAMEC_ROUNDS];
    for (int i = 0; i < MEGAMEC_ROUNDS; i++)
    {
        hash_selection[i] = get_megamec_selection(timestamp, i);
    }

    if (opt_debug)
    {
        applog_hex((void *) endiandata, 80);
        applog_hex((void *) ptarget, 32);
        gpulog(LOG_DEBUG, thr_id, "MEGAMEC hash selection: %s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s",
            megamec_hash_names[hash_selection[0]],
            megamec_hash_names[hash_selection[1]],
            megamec_hash_names[hash_selection[2]],
            megamec_hash_names[hash_selection[3]],
            megamec_hash_names[hash_selection[4]],
            megamec_hash_names[hash_selection[5]],
            megamec_hash_names[hash_selection[6]],
            megamec_hash_names[hash_selection[7]],
            megamec_hash_names[hash_selection[8]],
            megamec_hash_names[hash_selection[9]],
            megamec_hash_names[hash_selection[10]],
            megamec_hash_names[hash_selection[11]],
            megamec_hash_names[hash_selection[12]],
            megamec_hash_names[hash_selection[13]],
            megamec_hash_names[hash_selection[14]],
            megamec_hash_names[hash_selection[15]],
            megamec_hash_names[hash_selection[16]],
            megamec_hash_names[hash_selection[17]],
            megamec_hash_names[hash_selection[18]],
            megamec_hash_names[hash_selection[19]],
            megamec_hash_names[hash_selection[20]],
            megamec_hash_names[hash_selection[21]],
            megamec_hash_names[hash_selection[22]]
        );
    }

    bool cpuFallback = false;
    
    switch (hash_selection[0])
    {
        case MEGAMEC_BLAKE:
            megamec_blake512_cpu_setBlock_80(thr_id, endiandata);
            break;
        case MEGAMEC_BMW:
            megamec_bmw512_cpu_setBlock_80(endiandata);
            break;
        case MEGAMEC_GROESTL:
            megamec_groestl512_setBlock_80(thr_id, endiandata);
            break;
        case MEGAMEC_JH:
            megamec_jh512_setBlock_80(thr_id, endiandata);
            break;
        case MEGAMEC_KECCAK:
            megamec_keccak512_setBlock_80(thr_id, endiandata);
            break;
        case MEGAMEC_SKEIN:
            megamec_skein512_cpu_setBlock_80(endiandata);
            break;
        case MEGAMEC_LUFFA:
            megamec_luffa512_cpu_setBlock_80(endiandata);
            break;
        case MEGAMEC_CUBEHASH:
            megamec_cubehash512_setBlock_80(thr_id, endiandata);
            break;
        case MEGAMEC_SHAVITE:
            megamec_shavite512_setBlock_80(endiandata);
            break;
        case MEGAMEC_SIMD:
            cpuFallback = true;
            if (opt_debug)
            {
                gpulog(LOG_DEBUG, thr_id, "Not yet implemented: simd512/80 (falling back on CPU for first round)");
            }
            break;
        case MEGAMEC_ECHO:
            cpuFallback = true;
            if (opt_debug)
            {
                gpulog(LOG_DEBUG, thr_id, "Not yet implemented: echo512/80 (falling back on CPU for first round)");
            }
            break;
        case MEGAMEC_HAMSI:
            cpuFallback = true;
            if (opt_debug)
            {
                gpulog(LOG_DEBUG, thr_id, "Not yet implemented: hamsi512/80 (falling back on CPU for first round)");
            }
            break;
        case MEGAMEC_FUGUE:
            cpuFallback = true;
            if (opt_debug)
            {
                gpulog(LOG_DEBUG, thr_id, "Not yet implemented: fugue512/80 (falling back on CPU for first round)");
            }
            break;
        case MEGAMEC_SHABAL:
            cpuFallback = true;
            if (opt_debug)
            {
                gpulog(LOG_DEBUG, thr_id, "Not yet implemented: shabal512/80 (falling back on CPU for first round)");
            }
            break;
        case MEGAMEC_WHIRLPOOL:
            cpuFallback = true;
            if (opt_debug)
            {
                gpulog(LOG_DEBUG, thr_id, "Not yet implemented: whirlpool512/80 (falling back on CPU for first round)");
            }
            break;
        case MEGAMEC_SHA512:
            cpuFallback = true;
            if (opt_debug)
            {
                gpulog(LOG_DEBUG, thr_id, "Not yet implemented: sha512/80 (falling back on CPU for first round)");
            }
            break;
        case MEGAMEC_HAVAL:
            cpuFallback = true;
            if (opt_debug)
            {
                gpulog(LOG_DEBUG, thr_id, "Not yet implemented: haval256/80 (falling back on CPU for first round)");
            }
            break;
        default:
            gpulog(LOG_ERR, thr_id, "Unknown MEGAMEC hash selection: %d (this should never happen!)", hash_selection[0]);
            break;
    }

    cuda_check_cpu_setTarget(ptarget);

    if (cpuFallback)
    {
        gpulog(LOG_INFO, thr_id, "Partial GPU job - first round is CPU (%d threads).", num_sub_threads);
    }
    else
    {
        gpulog(LOG_INFO, thr_id, "100%% GPU job.");
    }

    do
    {
        int order = 0;

        memset(h_hash[thr_id], 0, (size_t)64 * throughput);

        switch (hash_selection[0])
        {
            case MEGAMEC_BLAKE:
                megamec_blake512_cpu_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id]); order++;
                break;
            case MEGAMEC_BMW:
                megamec_bmw512_cpu_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id], order++);
                break;
            case MEGAMEC_GROESTL:
                megamec_groestl512_cuda_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id]); order++;
                break;
            case MEGAMEC_JH:
                megamec_jh512_cuda_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id]); order++;
                break;
            case MEGAMEC_KECCAK:
                megamec_keccak512_cuda_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id]); order++;
                break;
            case MEGAMEC_SKEIN:
                megamec_skein512_cpu_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id], 1); order++;
                break;
            case MEGAMEC_LUFFA:
                megamec_luffa512_cpu_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id], order++);
                break;
            case MEGAMEC_CUBEHASH:
                megamec_cubehash512_cuda_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id]); order++;
                break;
            case MEGAMEC_SHAVITE:
                megamec_shavite512_cpu_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id], order++);
                break;
            case MEGAMEC_SIMD:
            case MEGAMEC_ECHO:
            case MEGAMEC_HAMSI:
            case MEGAMEC_FUGUE:
            case MEGAMEC_SHABAL:
            case MEGAMEC_WHIRLPOOL:
            case MEGAMEC_SHA512:
            case MEGAMEC_HAVAL:
                // Now handled on separate threads.
                break;

            default:
                gpulog(LOG_ERR, thr_id, "Round 0 unknown MEGAMEC hash selection: %d (this should never happen!)", hash_selection[0]);
                break;
        }

        // FIXME: CPU fallback for unimplemented first round algorithms
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

                if (i < extra)
                {
                    sub_thr.jobcount++;
                }

                start += sub_thr.jobcount;

                pthread_cond_signal(&sub_thr.cond);
                pthread_mutex_unlock(&sub_thr.mutex);
            }

            // Wait for all sub-threads to complete :

            for (int i = 0; i < num_sub_threads; ++i)
            {
                subthread_t& sub_thr = sub_threads[thr_id][i];

                pthread_mutex_lock(&sub_thr.mutex);

                while (sub_thr.jobcount > 0 && !sub_thr.exit_thread)
                {
                    pthread_cond_wait(&sub_thr.cond, &sub_thr.mutex);
                }
    
                pthread_mutex_unlock(&sub_thr.mutex);
            }
        }

        // Rounds 1-22 (64-byte input)
        for (int i = 1; i < MEGAMEC_ROUNDS; i++)
        {
            switch (hash_selection[i])
            {
                case MEGAMEC_BLAKE:
                    megamec_blake512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_BMW:
                    megamec_bmw512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_GROESTL:
                    megamec_groestl512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_JH:
                    megamec_jh512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_KECCAK:
                    megamec_keccak512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_SKEIN:
                    megamec_skein512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_LUFFA:
                    megamec_luffa512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_CUBEHASH:
                    megamec_cubehash512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_SHAVITE:
                    megamec_shavite512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_SIMD:
                    megamec_simd512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_ECHO:
                    megamec_echo512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_HAMSI:
                    megamec_hamsi512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_FUGUE:
                    megamec_fugue512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_SHABAL:
                    megamec_shabal512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_WHIRLPOOL:
                    megamec_whirlpool512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                case MEGAMEC_SHA512:
                    megamec_sha512_cpu_hash_64(thr_id, throughput, pdata[19], d_hash[thr_id], order++);
                    break;
                case MEGAMEC_HAVAL:
                    megamec_haval256_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
                    break;
                default:
                    gpulog(LOG_ERR, thr_id, "Round %d unknown MEGAMEC hash selection: %d (this should never happen!)", i, hash_selection[i]);
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
                {
                    gpulog(LOG_WARNING, thr_id, "MEGAMEC result for %08x does not validate on CPU!", work->nonces[0]);
                }
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

// cleanup
extern "C" void free_megamec(int thr_id)
{
    if (!init[thr_id])
    {
        return;
    }

    cudaThreadSynchronize();

    int num_sub_threads = opt_n_cpu_fallback_threads;

    if (opt_debug)
    {
        gpulog(LOG_DEBUG, thr_id, "Ending MEGAMEC CPU-Fallback subthreads...");
    }

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


    if (opt_debug)
    {
        gpulog(LOG_DEBUG, thr_id, "Finished MEGAMEC CPU-Fallback subthreads.");
    }

    cudaFree(d_hash[thr_id]);
    free(h_hash[thr_id]);
    free(sub_threads[thr_id]);

    // Only call free for algorithms that actually have free functions
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