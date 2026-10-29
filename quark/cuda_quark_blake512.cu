#include <stdio.h>
#include <memory.h>
#include <sys/types.h> // off_t

#include "miner.h"
#include "cuda_helper.h"
#include "sph_blake512_cuda.cuh"

#define ROTR(x,n) ROTR64(x,n)

// use sp kernel on SM 5+
// #define SP_KERNEL  // Disabled: SP kernel uses custom Blake512, use non-SP with exact SPH

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
        uint32_t *pdata = endiandata;

        // Copy 80-byte header (10 x uint64_t) with byte-swap for endianness
        for (int i = 0; i < 10; i++)
            message[i] = cuda_swab64(((uint64_t*)endiandata)[i]);

        // Blake512 padding: 1 bit '1', zeros, 128-bit big-endian length (640 bits = 0x280)
        // message[10] = 0x8000000000000000 (1 bit at MSB of first padding byte)
        // message[11-14] = 0
        // message[15] = 640 as 128-bit big-endian = 0x0000000000000280 (split across 2 uint64_t)
        // Since we only have message[10-15] = 6 slots = 48 bytes, but need 16 bytes for 128-bit length...
        // Actually Blake512 uses 128-byte blocks. 80 bytes data + 1 bit + zeros + 16 bytes length = 128 bytes
        // So we need 48 bytes of padding + 16 bytes length = 64 bytes = 4 uint64_t
        // message[10] = 0x8000000000000000 (first padding byte = 0x80)
        // message[11] = message[12] = message[13] = 0 (24 bytes zeros)
        // message[14] = 0 (high 64 bits of 128-bit length = 0)
        // message[15] = 640 as big-endian 64-bit = 0x0000000000000280 (but byte-swapped for network order)
        
        // Actually, the SPH Blake512 expects the 128-bit length as TWO uint64_t in BIG-ENDIAN:
        // High 64 bits (bits 127-64) = 0, Low 64 bits (bits 63-0) = 640 (0x280)
        // But stored in memory as big-endian bytes, so when loaded as uint64_t array:
        // message[14] = 0 (high 64 bits of 128-bit length)
        // message[15] = 640 << 56? No...
        
        // Let's think: 128-bit length = 640 = 0x00000000000000000000000000000280
        // As big-endian bytes: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 80
        // As uint64_t[2] in memory (big-endian): [0x0000000000000000, 0x0000000000000280]
        // But cudaMemcpyToSymbol copies raw bytes, so we need to arrange the uint64_t correctly
        
        // The padding bytes (after 80 bytes data):
        // byte 80: 0x80
        // bytes 81-111: zeros (31 bytes)
        // bytes 112-127: 128-bit length = 640 big-endian
        
        // In uint64_t array (8 bytes each):
        // message[10] = bytes 80-87:  0x80 00 00 00 00 00 00 00  (big-endian = 0x8000000000000000)
        // message[11] = bytes 88-95:  00 00 00 00 00 00 00 00
        // message[12] = bytes 96-103: 00 00 00 00 00 00 00 00
        // message[13] = bytes 104-111:00 00 00 00 00 00 00 00
        // message[14] = bytes 112-119:00 00 00 00 00 00 00 00 (high 64 of length)
        // message[15] = bytes 120-127:00 00 00 00 00 00 02 80 (low 64 of length = 640 big-endian)
        
        message[10] = 0x8000000000000000ULL;  // padding start: 1 bit
        message[11] = 0;
        message[12] = 0;
        message[13] = 0;
        message[14] = 0;                       // high 64 bits of 128-bit length = 0
        message[15] = 0x0000000000000280ULL;  // low 64 bits = 640 in BIG-ENDIAN byte order
        // Note: 0x0000000000000280 as uint64_t in host memory (little-endian machine)
        // represents the bytes 80 02 00 00 00 00 00 00 in memory
        // But the GPU expects big-endian byte order for the length field!
        
        // Wait - the GPU will load these as uint64_t from constant memory.
        // The SPH compress function does byte-swap on each uint64_t.
        // So we need the bytes in memory to match what SPH expects after byte-swap.
        
        // SPH's COMPRESS64 does: M[i] = be64_to_cpu(block[i])
        // So block[i] should be in BIG-ENDIAN byte order in memory.
        // Our message[] array will be copied to device as raw bytes.
        // The GPU will read as uint64_t and then byte-swap (cuda_swab64).
        // So we need message[] in HOST byte order (little-endian) such that
        // after cuda_swab64 on GPU, it matches SPH's expected big-endian values.
        
        // For the length field: SPH expects M[14]=0, M[15]=0x280 (after be64_to_cpu)
        // cuda_swab64 on GPU will reverse bytes, so we need to store PRE-SWAPPED values:
        // M[14] after swap = 0 => store 0
        // M[15] after swap = 0x280 => store 0x280 << 56? No, cuda_swab64 reverses bytes.
        // 0x0000000000000280 byte-swapped = 0x8002000000000000
        // So store 0x8002000000000000 for M[15] to get 0x280 after swap.
        
        // Actually wait - the host copies message[] directly to device symbol.
        // The GPU kernel reads block[i] and does cuda_swab64(block[i]) to get M[i].
        // So we need: cuda_swab64(message[i]) == expected_M[i] (SPH's big-endian M)
        
        // For padding: SPH expects M[10] = 0x8000000000000000 (0x80 + zeros)
        // So message[10] = cuda_swab64(0x8000000000000000) = 0x0000000000000080
        // For length: SPH expects M[14]=0, M[15]=0x0000000000000280
        // message[14] = cuda_swab64(0) = 0
        // message[15] = cuda_swab64(0x0000000000000280) = 0x8002000000000000
        
        // But wait - the host already does cuda_swab64 on pdata[i] for the header!
        // So for consistency, we should pre-swap the padding too.
        
        // Simpler approach: construct the 128-byte block in correct big-endian format,
        // then byte-swap each uint64_t before copying to device.
        
        uint8_t padded_block[128];
        memcpy(padded_block, endiandata, 80);  // 80-byte header (already big-endian from network)
        padded_block[80] = 0x80;  // 1 bit
        memset(padded_block + 81, 0, 31);  // 31 bytes zeros (81-111)
        // 128-bit length = 640 at bytes 112-127 (big-endian)
        padded_block[126] = 0x02;
        padded_block[127] = 0x80;
        // bytes 112-125 are 0 (already zero from memset)
        
        // Now byte-swap each uint64_t and copy to message
        uint64_t *padded64 = (uint64_t*)padded_block;
        for (int i = 0; i < 16; i++) {
            message[i] = cuda_swab64(padded64[i]);
        }

        cudaMemcpyToSymbol(c_PaddedMessage80, message, sizeof(message), 0, cudaMemcpyHostToDevice);
    }
    CUDA_LOG_ERROR();
}