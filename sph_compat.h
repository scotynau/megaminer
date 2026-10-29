// Minimal SPH compatibility header - replaces miner.h for standalone SPH compilation

#ifndef SPH_COMPAT_H
#define SPH_COMPAT_H

#include <stdint.h>
#include <string.h>

// Endian conversion functions (from miner.h)
static inline uint32_t be32dec(const void *pp)
{
    const uint8_t *p = (const uint8_t *)pp;
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint32_t le32dec(const void *pp)
{
    const uint8_t *p = (const uint8_t *)pp;
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

static inline void be32enc(void *pp, uint32_t x)
{
    uint8_t *p = (uint8_t *)pp;
    p[0] = (x >> 24) & 0xff;
    p[1] = (x >> 16) & 0xff;
    p[2] = (x >> 8) & 0xff;
    p[3] = x & 0xff;
}

static inline void le32enc(void *pp, uint32_t x)
{
    uint8_t *p = (uint8_t *)pp;
    p[0] = x & 0xff;
    p[2] = (x >> 8) & 0xff;
    p[3] = (x >> 16) & 0xff;
    p[1] = (x >> 24) & 0xff;
}

static inline uint32_t swab32(uint32_t x)
{
    return ((x & 0x000000FF) << 24) | ((x & 0x0000FF00) << 8) |
           ((x & 0x00FF0000) >> 8) | ((x & 0xFF000000) >> 24);
}

#endif // SPH_COMPAT_H