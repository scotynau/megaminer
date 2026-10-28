#include <stdio.h>
#include <memory.h>
#include <sys/types.h> // off_t

#include "miner.h"
#include "cuda_helper.h"
#include "sph_blake512_cuda.cuh"

#define ROTR(x,n) ROTR64(x,n)

// use sp kernel on SM 5+
#define SP_KERNEL

#define USE_SHUFFLE 0

__constant__
static uint64_t c_PaddedMessage80[16]; // padded message (80 bytes + padding)

// ---------------------------- BEGIN CUDA quark_blake512 functions ------------------------------------

// Device Blake512 compress using exact SPH implementation
__device__ __forceinline__
void quark_blake512_compress(uint64_t *h, const uint64_t *block, const uint8_t ((*sigma)[16]), const uint64_t *u512, const int T0)
{
    // Use exact SPH Blake512 compress
    uint64_t S[4] = {0, 0, 0, 0};
    uint64_t T0_val = T0, T1_val = 0;
    sph_blake512_compress_exact(h, block, S[0], S[1], S[2], S[3], T0_val, T1_val);
}

__global__ __launch_bounds__(256, 4)
void quark_blake512_gpu_hash_64(uint32_t threads, uint32_t startNounce, uint32_t *g_nonceVector, uint64_t *g_hash)
{
#if !defined(SP_KERNEL) || __CUDA_ARCH__ < 500
    uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);

#if USE_SHUFFLE
    const uint32_t warpBlockID = (thread + 15)>>4; // aufrunden auf volle Warp-Blöcke

    if (warpBlockID < ( (threads+15)>>4 ))
#else
    if (thread < threads)
#endif
    {
        uint32_t nounce = (g_nonceVector != NULL) ? g_nonceVector[thread] : (startNounce + thread);

        off_t hashPosition = nounce - startNounce;
        uint64_t *inpHash = &g_hash[hashPosition<<3]; // hashPosition * 8

        // 128 Bytes
        uint64_t buf[16];

        // State
        uint64_t h[8] = {
            0x6a09e667f3bcc908ULL,
            0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL,
            0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL,
            0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL,
            0x5be0cd19137e2179ULL
        };

        // Message for first round
        #pragma unroll 8
        for (int i=0; i < 8; ++i)
            buf[i] = inpHash[i];

        // Hash Pad
        buf[8]  = 0x0000000000000080ull;
        buf[9]  = 0;
        buf[10] = 0;
        buf[11] = 0;
        buf[12] = 0;
        buf[13] = 0;
        buf[14] = 0;
        buf[15] = 0x280ull;

        // Use exact SPH Blake512 compress
        quark_blake512_compress(h, buf, NULL, NULL, 512);

#if __CUDA_ARCH__ <= 350
        uint32_t *outHash = (uint32_t*)g_hash + (thread * 16U);
        #pragma unroll 8
        for (uint32_t i=0; i < 8; i++) {
            outHash[2*i]   = cuda_swab32( _HIDWORD(h[i]) );
            outHash[2*i+1] = cuda_swab32( _LODWORD(h[i]) );
        }
#else
        uint64_t *outHash = (uint64_t*)g_hash + (thread * 8U);
        for (uint32_t i=0; i < 8; i++) {
            outHash[i] = cuda_swab64( h[i] );
        }
#endif
    }
#endif
}

// Blake512 80-byte hash for stratum (uses exact SPH implementation)
__global__ __launch_bounds__(256,4)
void quark_blake512_gpu_hash_80(uint32_t threads, uint32_t startNounce, void *outputHash)
{
#if !defined(SP_KERNEL) || __CUDA_ARCH__ < 500
    uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
    if (thread < threads)
    {
        uint64_t buf[16];

        // State
        uint64_t h[8] = {
            0x6a09e667f3bcc908ULL,
            0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL,
            0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL,
            0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL,
            0x5be0cd19137e2179ULL
        };

        // The test Nonce
        const uint32_t nounce = startNounce + thread;

        // Load padded message from constant memory
        #pragma unroll
        for (int i=0; i < 16; ++i)
            buf[i] = c_PaddedMessage80[i];

        // The test Nonce - already declared above
        ((uint32_t*)buf)[19] = cuda_swab32(nounce);

        // Use exact SPH Blake512 compress
        uint64_t S[4] = {0, 0, 0, 0};
        uint64_t T0 = 512, T1 = 0;
        sph_blake512_compress_exact(h, buf, S[0], S[1], S[2], S[3], T0, T1);

#if __CUDA_ARCH__ <= 350
        uint32_t *outHash = (uint32_t*)outputHash + (thread * 16U);
        #pragma unroll 8
        for (uint32_t i=0; i < 8; i++) {
            outHash[2*i]   = cuda_swab32( _HIDWORD(h[i]) );
            outHash[2*i+1] = cuda_swab32( _LODWORD(h[i]) );
        }
#else
        uint64_t *outHash = (uint64_t*)outputHash + (thread * 8U);
        for (uint32_t i=0; i < 8; i++) {
            outHash[i] = cuda_swab64( h[i] );
        }
#endif
    }
#endif
}

#ifdef SP_KERNEL
#include "cuda_quark_blake512_sp.cuh"
#endif

__host__
void quark_blake512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_outputHash, int order)
{
#ifdef SP_KERNEL
    int dev_id = device_map[thr_id];
    if (device_sm[dev_id] >= 500 && cuda_arch[dev_id] >= 500)
        quark_blake512_cpu_hash_64_sp(threads, startNounce, d_nonceVector, d_outputHash);
    else
#endif
    {
        const uint32_t threadsperblock = 256;
        dim3 grid((threads + threadsperblock-1)/threadsperblock);
        dim3 block(threadsperblock);
        quark_blake512_gpu_hash_64<<<grid, block>>>(threads, startNounce, d_nonceVector, (uint64_t*)d_outputHash);
    }
    MyStreamSynchronize(NULL, order, thr_id);
}

__host__
void quark_blake512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_outputHash)
{
#ifdef SP_KERNEL
    int dev_id = device_map[thr_id];
    if (device_sm[dev_id] >= 500 && cuda_arch[dev_id] >= 500)
        quark_blake512_cpu_hash_80_sp(threads, startNounce, d_outputHash);
    else
#endif
    {
        const uint32_t threadsperblock = 256;
        dim3 grid((threads + threadsperblock-1)/threadsperblock);
        dim3 block(threadsperblock);

        quark_blake512_gpu_hash_80<<<grid, block>>>(threads, startNounce, d_outputHash);
    }
}

// ---------------------------- END CUDA quark_blake512 functions ------------------------------------

__host__
void quark_blake512_cpu_init(int thr_id, uint32_t threads)
{
    cuda_get_arch(thr_id);
}

__host__
void quark_blake512_cpu_free(int thr_id)
{
}

// ----------------------------- Host midstate for 80-bytes input ------------------------------------

#undef SPH_C32
#undef SPH_T32
#undef SPH_C64
#undef SPH_T64

extern "C" {
#include "sph/sph_blake.h"
}

__host__
void quark_blake512_cpu_setBlock_80(int thr_id, uint32_t *endiandata)
{
#ifdef SP_KERNEL
    int dev_id = device_map[thr_id];
    if (device_sm[dev_id] >= 50)
        quark_blake512_cpu_setBlock_80_sp(thr_id, (uint64_t*) endiandata);
    else
#endif
    {
        uint64_t message[16];
        uint64_t *pdata = (uint64_t*) endiandata;

        // Match SP kernel padding exactly: cuda_swab64 + SP padding values
        for (int i = 0; i < 10; i++)
            message[i] = cuda_swab64(pdata[i]);
        message[10] = 0x8000000000000000ull;
        message[11] = 0;
        message[12] = 0;
        message[13] = 1;
        message[14] = 0;
        message[15] = 0x280ull; // 640 bits = 80 bytes

        cudaMemcpyToSymbol(c_PaddedMessage80, message, sizeof(message), 0, cudaMemcpyHostToDevice);
    }
    CUDA_LOG_ERROR();
}