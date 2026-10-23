#ifndef CCMINER_COMPAT_ENDIAN_H
#define CCMINER_COMPAT_ENDIAN_H

/*
 * Portable little/big-endian conversion macros.
 *
 * Linux/BSD/macOS get these from the platform <endian.h> family. Windows has
 * no such header, and <winsock2.h> only provides htonl/ntohl, so the full
 * htole/htobe/letoh/betoh set is emulated here. Every current Windows
 * architecture (x86, x64, ARM64) is little-endian.
 *
 * Serialization code (serialize.hpp) is templated, so these must be macros or
 * inline functions visible at parse time, not implicit declarations.
 */

#ifdef _WIN32

#include <stdlib.h>

#ifndef htole16
#define htole16(x) ((uint16_t)(x))
#endif
#ifndef htole32
#define htole32(x) ((uint32_t)(x))
#endif
#ifndef htole64
#define htole64(x) ((uint64_t)(x))
#endif

#ifndef le16toh
#define le16toh(x) ((uint16_t)(x))
#endif
#ifndef le32toh
#define le32toh(x) ((uint32_t)(x))
#endif
#ifndef le64toh
#define le64toh(x) ((uint64_t)(x))
#endif

#ifndef htobe16
#define htobe16(x) _byteswap_ushort((uint16_t)(x))
#endif
#ifndef htobe32
#define htobe32(x) _byteswap_ulong((uint32_t)(x))
#endif
#ifndef htobe64
#define htobe64(x) _byteswap_uint64((uint64_t)(x))
#endif

#ifndef be16toh
#define be16toh(x) _byteswap_ushort((uint16_t)(x))
#endif
#ifndef be32toh
#define be32toh(x) _byteswap_ulong((uint32_t)(x))
#endif
#ifndef be64toh
#define be64toh(x) _byteswap_uint64((uint64_t)(x))
#endif

#else /* !_WIN32 */

#if defined(__has_include)
#if __has_include(<endian.h>)
#include <endian.h>
#endif
#endif

#endif /* _WIN32 */

#endif /* CCMINER_COMPAT_ENDIAN_H */
