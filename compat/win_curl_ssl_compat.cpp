#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifndef CURL_STATICLIB
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

/* =========================================================================
 * 1. OpenSSL SHA-256 Compatibility Layer (SHA256_Init/Update/Final/Transform)
 * ========================================================================= */

static const uint32_t k_sha256[64] = {
	0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
	0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
	0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
	0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
	0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
	0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
	0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
	0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
	0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
	0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
	0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
	0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
	0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
	0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
	0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
	0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static inline uint32_t sha_rotr32(uint32_t x, unsigned int n)
{
	return (x >> n) | (x << (32U - n));
}

static inline uint32_t sha_be32_load(const unsigned char *p)
{
	return ((uint32_t)p[0] << 24) |
	       ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8)  |
	       ((uint32_t)p[3]);
}

static inline void sha_be32_store(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)(v);
}

extern "C" void SHA256_Transform(SHA256_CTX *c, const unsigned char *data)
{
	uint32_t w[64];
	for (int i = 0; i < 16; ++i)
		w[i] = sha_be32_load(data + (i * 4));
	for (int i = 16; i < 64; ++i) {
		uint32_t s0 = sha_rotr32(w[i - 15], 7) ^ sha_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = sha_rotr32(w[i - 2], 17) ^ sha_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	uint32_t a = c->h[0];
	uint32_t b = c->h[1];
	uint32_t d_c = c->h[2];
	uint32_t d = c->h[3];
	uint32_t e = c->h[4];
	uint32_t f = c->h[5];
	uint32_t g = c->h[6];
	uint32_t h = c->h[7];

	for (int i = 0; i < 64; ++i) {
		uint32_t S1 = sha_rotr32(e, 6) ^ sha_rotr32(e, 11) ^ sha_rotr32(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t temp1 = h + S1 + ch + k_sha256[i] + w[i];
		uint32_t S0 = sha_rotr32(a, 2) ^ sha_rotr32(a, 13) ^ sha_rotr32(a, 22);
		uint32_t maj = (a & b) ^ (a & d_c) ^ (b & d_c);
		uint32_t temp2 = S0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = d_c;
		d_c = b;
		b = a;
		a = temp1 + temp2;
	}

	c->h[0] += a;
	c->h[1] += b;
	c->h[2] += d_c;
	c->h[3] += d;
	c->h[4] += e;
	c->h[5] += f;
	c->h[6] += g;
	c->h[7] += h;
}

extern "C" int SHA256_Init(SHA256_CTX *c)
{
	memset(c, 0, sizeof(*c));
	c->h[0] = 0x6a09e667UL;
	c->h[1] = 0xbb67ae85UL;
	c->h[2] = 0x3c6ef372UL;
	c->h[3] = 0xa54ff53aUL;
	c->h[4] = 0x510e527fUL;
	c->h[5] = 0x9b05688cUL;
	c->h[6] = 0x1f83d9abUL;
	c->h[7] = 0x5be0cd19UL;
	c->md_len = SHA256_DIGEST_LENGTH;
	return 1;
}

extern "C" int SHA256_Update(SHA256_CTX *c, const void *data_, size_t len)
{
	if (len == 0)
		return 1;

	const unsigned char *data = (const unsigned char *)data_;
	SHA_LONG l = c->Nl + (((SHA_LONG)len) << 3);
	if (l < c->Nl)
		c->Nh++;
	c->Nh += (SHA_LONG)(len >> 29);
	c->Nl = l;

	unsigned char *p = (unsigned char *)c->data;
	size_t n = c->num;
	if (n != 0) {
		size_t todo = SHA256_CBLOCK - n;
		if (len < todo) {
			memcpy(p + n, data, len);
			c->num += (unsigned int)len;
			return 1;
		}
		memcpy(p + n, data, todo);
		SHA256_Transform(c, p);
		c->num = 0;
		memset(p, 0, SHA256_CBLOCK);
		data += todo;
		len -= todo;
	}

	while (len >= SHA256_CBLOCK) {
		SHA256_Transform(c, data);
		data += SHA256_CBLOCK;
		len -= SHA256_CBLOCK;
	}

	if (len > 0) {
		memcpy(p, data, len);
		c->num = (unsigned int)len;
	}
	return 1;
}

extern "C" int SHA256_Final(unsigned char *md, SHA256_CTX *c)
{
	unsigned char *p = (unsigned char *)c->data;
	size_t n = c->num;

	p[n++] = 0x80;
	if (n > (SHA256_CBLOCK - 8)) {
		memset(p + n, 0, SHA256_CBLOCK - n);
		SHA256_Transform(c, p);
		n = 0;
	}
	memset(p + n, 0, (SHA256_CBLOCK - 8) - n);
	sha_be32_store(p + SHA256_CBLOCK - 8, c->Nh);
	sha_be32_store(p + SHA256_CBLOCK - 4, c->Nl);
	SHA256_Transform(c, p);

	for (int i = 0; i < 8; ++i)
		sha_be32_store(md + (i * 4), c->h[i]);

	memset(c, 0, sizeof(*c));
	return 1;
}

/* =========================================================================
 * 2. OpenSSL BIGNUM Compatibility Layer (for bignum.cpp / bignum_ssl10.hpp)
 * ========================================================================= */

struct bignum_ctx {
	int dummy;
};

static void bn_normalize_top(BIGNUM *a)
{
	while (a->top > 0 && a->d[a->top - 1] == 0)
		a->top--;
	if (a->top == 0)
		a->neg = 0;
}

static int bn_reserve(BIGNUM *a, int words)
{
	if (words <= a->dmax)
		return 1;
	int new_max = (words < 16) ? 16 : (words * 2);
	BN_ULONG *nd = (BN_ULONG *)calloc((size_t)new_max, sizeof(BN_ULONG));
	if (!nd)
		return 0;
	if (a->d) {
		if (a->top > 0)
			memcpy(nd, a->d, (size_t)a->top * sizeof(BN_ULONG));
		free(a->d);
	}
	a->d = nd;
	a->dmax = new_max;
	return 1;
}

extern "C" BN_CTX *BN_CTX_new(void)
{
	return (BN_CTX *)calloc(1, sizeof(struct bignum_ctx));
}

extern "C" void BN_CTX_free(BN_CTX *c)
{
	free(c);
}

extern "C" void BN_init(BIGNUM *a)
{
	memset(a, 0, sizeof(*a));
}

extern "C" BIGNUM *BN_new(void)
{
	BIGNUM *a = (BIGNUM *)calloc(1, sizeof(BIGNUM));
	if (a)
		a->flags = BN_FLG_MALLOCED;
	return a;
}

extern "C" void BN_clear_free(BIGNUM *a)
{
	if (!a)
		return;
	if (a->d) {
		memset(a->d, 0, (size_t)a->dmax * sizeof(BN_ULONG));
		free(a->d);
		a->d = NULL;
	}
	int flags = a->flags;
	memset(a, 0, sizeof(*a));
	if (flags & BN_FLG_MALLOCED)
		free(a);
}

extern "C" void BN_free(BIGNUM *a)
{
	BN_clear_free(a);
}

extern "C" BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)
{
	if (a == b)
		return a;
	if (!bn_reserve(a, b->top))
		return NULL;
	if (b->top > 0)
		memcpy(a->d, b->d, (size_t)b->top * sizeof(BN_ULONG));
	a->top = b->top;
	a->neg = b->neg;
	return a;
}

extern "C" int BN_set_word(BIGNUM *a, BN_ULONG w)
{
	if (w == 0) {
		a->top = 0;
		a->neg = 0;
		return 1;
	}
	if (!bn_reserve(a, 1))
		return 0;
	a->d[0] = w;
	a->top = 1;
	a->neg = 0;
	return 1;
}

extern "C" BN_ULONG BN_get_word(const BIGNUM *a)
{
	if (a->top > 1)
		return BN_MASK2;
	if (a->top == 1)
		return a->d[0];
	return 0;
}

extern "C" void BN_set_negative(BIGNUM *b, int n)
{
	if (b->top == 0)
		b->neg = 0;
	else
		b->neg = (n != 0) ? 1 : 0;
}

extern "C" const BIGNUM *BN_value_one(void)
{
	static BN_ULONG one_word = 1;
	static const BIGNUM k_one = { &one_word, 1, 1, 0, BN_FLG_STATIC_DATA };
	return &k_one;
}

extern "C" int BN_num_bits(const BIGNUM *a)
{
	if (a->top <= 0)
		return 0;
	int idx = a->top - 1;
	BN_ULONG w = a->d[idx];
	int bits = idx * 32;
	while (w != 0) {
		bits++;
		w >>= 1;
	}
	return bits;
}

static int bn_ucmp(const BIGNUM *a, const BIGNUM *b)
{
	if (a->top != b->top)
		return (a->top > b->top) ? 1 : -1;
	for (int i = a->top - 1; i >= 0; --i) {
		if (a->d[i] != b->d[i])
			return (a->d[i] > b->d[i]) ? 1 : -1;
	}
	return 0;
}

extern "C" int BN_cmp(const BIGNUM *a, const BIGNUM *b)
{
	if (!a || !b) {
		if (a) return -1;
		if (b) return 1;
		return 0;
	}
	if (a->neg != b->neg)
		return a->neg ? -1 : 1;
	int r = bn_ucmp(a, b);
	return a->neg ? -r : r;
}

static int bn_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
	int max_top = (a->top > b->top) ? a->top : b->top;
	BIGNUM tmp;
	BN_init(&tmp);
	if (!bn_reserve(&tmp, max_top + 1))
		return 0;

	uint64_t carry = 0;
	for (int i = 0; i < max_top; ++i) {
		uint64_t av = (i < a->top) ? a->d[i] : 0;
		uint64_t bv = (i < b->top) ? b->d[i] : 0;
		uint64_t sum = av + bv + carry;
		tmp.d[i] = (BN_ULONG)(sum & 0xffffffffULL);
		carry = sum >> 32;
	}
	tmp.top = max_top;
	if (carry)
		tmp.d[tmp.top++] = (BN_ULONG)carry;
	bn_normalize_top(&tmp);
	BN_copy(r, &tmp);
	BN_clear_free(&tmp);
	return 1;
}

/* Prerequisite: |a| >= |b| */
static int bn_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
	BIGNUM tmp;
	BN_init(&tmp);
	if (!bn_reserve(&tmp, a->top))
		return 0;

	int64_t borrow = 0;
	for (int i = 0; i < a->top; ++i) {
		int64_t av = (int64_t)a->d[i];
		int64_t bv = (i < b->top) ? (int64_t)b->d[i] : 0;
		int64_t diff = av - bv - borrow;
		if (diff < 0) {
			diff += ((int64_t)1 << 32);
			borrow = 1;
		} else {
			borrow = 0;
		}
		tmp.d[i] = (BN_ULONG)diff;
	}
	tmp.top = a->top;
	bn_normalize_top(&tmp);
	BN_copy(r, &tmp);
	BN_clear_free(&tmp);
	return 1;
}

extern "C" int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
	int a_neg = a->neg;
	int b_neg = b->neg;
	if (a_neg == b_neg) {
		if (!bn_uadd(r, a, b))
			return 0;
		r->neg = (r->top > 0) ? a_neg : 0;
		return 1;
	}
	int cmp = bn_ucmp(a, b);
	if (cmp == 0) {
		BN_set_word(r, 0);
		return 1;
	}
	if (cmp > 0) {
		if (!bn_usub(r, a, b))
			return 0;
		r->neg = (r->top > 0) ? a_neg : 0;
	} else {
		if (!bn_usub(r, b, a))
			return 0;
		r->neg = (r->top > 0) ? b_neg : 0;
	}
	return 1;
}

extern "C" int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
	BIGNUM b_negated = *b;
	b_negated.neg = (b->top > 0) ? (!b->neg) : 0;
	return BN_add(r, a, &b_negated);
}

extern "C" int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
	(void)ctx;
	if (a->top == 0 || b->top == 0) {
		BN_set_word(r, 0);
		return 1;
	}
	BIGNUM tmp;
	BN_init(&tmp);
	int rtop = a->top + b->top;
	if (!bn_reserve(&tmp, rtop))
		return 0;
	memset(tmp.d, 0, (size_t)rtop * sizeof(BN_ULONG));

	for (int i = 0; i < a->top; ++i) {
		uint64_t carry = 0;
		uint64_t av = a->d[i];
		for (int j = 0; j < b->top; ++j) {
			uint64_t prod = av * (uint64_t)b->d[j] + (uint64_t)tmp.d[i + j] + carry;
			tmp.d[i + j] = (BN_ULONG)(prod & 0xffffffffULL);
			carry = prod >> 32;
		}
		tmp.d[i + b->top] = (BN_ULONG)carry;
	}
	tmp.top = rtop;
	tmp.neg = (a->neg != b->neg) ? 1 : 0;
	bn_normalize_top(&tmp);
	BN_copy(r, &tmp);
	BN_clear_free(&tmp);
	return 1;
}

extern "C" int BN_lshift(BIGNUM *r, const BIGNUM *a, int n)
{
	if (n < 0)
		return 0;
	if (a->top == 0 || n == 0)
		return BN_copy(r, a) != NULL;

	int word_shift = n / 32;
	int bit_shift = n % 32;
	int new_top = a->top + word_shift + 1;

	BIGNUM tmp;
	BN_init(&tmp);
	if (!bn_reserve(&tmp, new_top))
		return 0;
	memset(tmp.d, 0, (size_t)new_top * sizeof(BN_ULONG));

	if (bit_shift == 0) {
		for (int i = 0; i < a->top; ++i)
			tmp.d[i + word_shift] = a->d[i];
	} else {
		BN_ULONG carry = 0;
		for (int i = 0; i < a->top; ++i) {
			BN_ULONG w = a->d[i];
			tmp.d[i + word_shift] = (w << bit_shift) | carry;
			carry = w >> (32 - bit_shift);
		}
		tmp.d[a->top + word_shift] = carry;
	}
	tmp.top = new_top;
	tmp.neg = a->neg;
	bn_normalize_top(&tmp);
	BN_copy(r, &tmp);
	BN_clear_free(&tmp);
	return 1;
}

extern "C" int BN_rshift(BIGNUM *r, const BIGNUM *a, int n)
{
	if (n < 0)
		return 0;
	if (a->top == 0 || n == 0)
		return BN_copy(r, a) != NULL;

	int word_shift = n / 32;
	int bit_shift = n % 32;
	if (word_shift >= a->top) {
		BN_set_word(r, 0);
		return 1;
	}

	int new_top = a->top - word_shift;
	BIGNUM tmp;
	BN_init(&tmp);
	if (!bn_reserve(&tmp, new_top))
		return 0;

	if (bit_shift == 0) {
		for (int i = 0; i < new_top; ++i)
			tmp.d[i] = a->d[i + word_shift];
	} else {
		for (int i = 0; i < new_top; ++i) {
			BN_ULONG lo = a->d[i + word_shift] >> bit_shift;
			BN_ULONG hi = (i + word_shift + 1 < a->top)
				? (a->d[i + word_shift + 1] << (32 - bit_shift))
				: 0;
			tmp.d[i] = lo | hi;
		}
	}
	tmp.top = new_top;
	tmp.neg = a->neg;
	bn_normalize_top(&tmp);
	BN_copy(r, &tmp);
	BN_clear_free(&tmp);
	return 1;
}

static int bn_is_bit_set(const BIGNUM *a, int n)
{
	if (n < 0)
		return 0;
	int w = n / 32;
	int b = n % 32;
	if (w >= a->top)
		return 0;
	return (a->d[w] >> b) & 1;
}

static int bn_set_bit(BIGNUM *a, int n)
{
	if (n < 0)
		return 0;
	int w = n / 32;
	int b = n % 32;
	if (!bn_reserve(a, w + 1))
		return 0;
	while (a->top <= w)
		a->d[a->top++] = 0;
	a->d[w] |= ((BN_ULONG)1U << b);
	return 1;
}

extern "C" int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
{
	(void)ctx;
	if (d->top == 0)
		return 0;

	BIGNUM q, r, abs_d;
	BN_init(&q);
	BN_init(&r);
	BN_init(&abs_d);
	BN_copy(&abs_d, d);
	abs_d.neg = 0;

	int nbits = BN_num_bits(m);
	for (int i = nbits - 1; i >= 0; --i) {
		BN_lshift(&r, &r, 1);
		if (bn_is_bit_set(m, i)) {
			if (r.top == 0)
				BN_set_word(&r, 1);
			else
				r.d[0] |= 1U;
		}
		if (bn_ucmp(&r, &abs_d) >= 0) {
			bn_usub(&r, &r, &abs_d);
			bn_set_bit(&q, i);
		}
	}
	q.neg = (q.top > 0 && (m->neg != d->neg)) ? 1 : 0;
	r.neg = (r.top > 0 && m->neg) ? 1 : 0;
	bn_normalize_top(&q);
	bn_normalize_top(&r);

	if (dv)
		BN_copy(dv, &q);
	if (rem)
		BN_copy(rem, &r);

	BN_clear_free(&q);
	BN_clear_free(&r);
	BN_clear_free(&abs_d);
	return 1;
}

extern "C" BIGNUM *BN_mpi2bn(const unsigned char *s, int len, BIGNUM *ret)
{
	if (len < 4)
		return NULL;
	uint32_t mlen = sha_be32_load(s);
	if ((uint64_t)mlen + 4ULL != (uint64_t)len)
		return NULL;

	BIGNUM *a = ret ? ret : BN_new();
	if (!a)
		return NULL;
	BN_set_word(a, 0);
	if (mlen == 0)
		return a;

	const unsigned char *p = s + 4;
	int neg = (p[0] & 0x80) != 0;

	int nwords = (int)((mlen + 3) / 4);
	if (!bn_reserve(a, nwords)) {
		if (!ret)
			BN_clear_free(a);
		return NULL;
	}
	memset(a->d, 0, (size_t)nwords * sizeof(BN_ULONG));

	for (uint32_t i = 0; i < mlen; ++i) {
		unsigned char b = p[mlen - 1 - i];
		if (i == mlen - 1 && neg)
			b &= 0x7f;
		a->d[i / 4] |= ((BN_ULONG)b) << ((i % 4) * 8);
	}
	a->top = nwords;
	a->neg = neg;
	bn_normalize_top(a);
	return a;
}

extern "C" int BN_bn2mpi(const BIGNUM *a, unsigned char *d)
{
	int bits = BN_num_bits(a);
	int bytes = (bits + 7) / 8;
	int ext = (bits > 0 && ((bits & 7) == 0)) ? 1 : 0;
	int payload = bytes + ext;

	if (!d)
		return payload + 4;

	sha_be32_store(d, (uint32_t)payload);
	if (payload == 0)
		return 4;

	unsigned char *p = d + 4;
	if (ext)
		p[0] = a->neg ? 0x80 : 0x00;

	for (int i = 0; i < bytes; ++i) {
		int byte_idx = bytes - 1 - i;
		BN_ULONG w = a->d[byte_idx / 4];
		unsigned char b = (unsigned char)((w >> ((byte_idx % 4) * 8)) & 0xff);
		p[ext + i] = b;
	}
	if (!ext && a->neg)
		p[0] |= 0x80;

	return payload + 4;
}

/* =========================================================================
 * 3. libcurl Compatibility Layer (Winsock2 Stratum + WinHTTP RPC)
 * ========================================================================= */

/* MSVC implements va_arg as a macro, so a function-pointer type with commas
   must be named through a typedef. */
typedef size_t (*cc_write_cb)(void *, size_t, size_t, void *);
typedef curl_socket_t (*cc_opensocket_cb)(void *, curlsocktype, struct curl_sockaddr *);
typedef int (*cc_sockopt_cb)(void *, curl_socket_t, curlsocktype);
typedef int (*cc_debug_cb)(CURL *, curl_infotype, char *, size_t, void *);

struct CurlEasyHandle {
	char url[2048];
	char proxy[1024];
	char userpwd[512];
	char useragent[256];
	char encoding[128];
	char *errorbuffer;
	const char *postfields;
	long postfieldsize;
	long proxytype;
	long connect_only;
	long connecttimeout;
	long timeout;
	long tcp_keepalive;
	long tcp_keepidle;
	long tcp_keepintvl;
	long netrc;
	long httpauth;
	long followlocation;
	long ssl_verifypeer;
	long verbose;
	long failonerror;
	long nosignal;
	long upload;
	long infilesize;

	cc_write_cb writefunction;
	void *writedata;
	cc_write_cb readfunction;
	void *readdata;
	cc_opensocket_cb opensocketfunction;
	void *opensocketdata;
	cc_sockopt_cb sockoptfunction;
	void *sockoptdata;
	cc_debug_cb debugfunction;
	void *debugdata;

	struct curl_slist *httpheader;
	curl_socket_t sock;
};

static void set_curl_err(CurlEasyHandle *h, const char *fmt, ...)
{
	if (!h || !h->errorbuffer)
		return;
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(h->errorbuffer, CURL_ERROR_SIZE, fmt, ap);
	va_end(ap);
	h->errorbuffer[CURL_ERROR_SIZE - 1] = '\0';
}

extern "C" CURLcode curl_global_init(long flags)
{
	(void)flags;
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		return CURLE_FAILED_INIT;
	return CURLE_OK;
}

extern "C" void curl_global_cleanup(void)
{
	WSACleanup();
}

extern "C" char *curl_version(void)
{
	static char ver[] = "libcurl/8.10.1-win-native WinHTTP/Winsock2";
	return ver;
}

extern "C" void curl_free(void *p)
{
	free(p);
}

extern "C" struct curl_slist *curl_slist_append(struct curl_slist *list, const char *data)
{
	struct curl_slist *node = (struct curl_slist *)calloc(1, sizeof(struct curl_slist));
	if (!node)
		return NULL;
	node->data = _strdup(data ? data : "");
	if (!node->data) {
		free(node);
		return NULL;
	}
	if (!list)
		return node;
	struct curl_slist *cur = list;
	while (cur->next)
		cur = cur->next;
	cur->next = node;
	return list;
}

extern "C" void curl_slist_free_all(struct curl_slist *list)
{
	while (list) {
		struct curl_slist *next = list->next;
		free(list->data);
		free(list);
		list = next;
	}
}

extern "C" CURL *curl_easy_init(void)
{
	CurlEasyHandle *h = (CurlEasyHandle *)calloc(1, sizeof(CurlEasyHandle));
	if (!h)
		return NULL;
	h->sock = CURL_SOCKET_BAD;
	h->ssl_verifypeer = 1;
	h->postfieldsize = -1;
	return (CURL *)h;
}

extern "C" void curl_easy_reset(CURL *curl)
{
	if (!curl)
		return;
	CurlEasyHandle *h = (CurlEasyHandle *)curl;
	curl_socket_t saved_sock = h->sock;
	memset(h, 0, sizeof(*h));
	h->sock = saved_sock;
	h->ssl_verifypeer = 1;
	h->postfieldsize = -1;
}

extern "C" void curl_easy_cleanup(CURL *curl)
{
	if (!curl)
		return;
	CurlEasyHandle *h = (CurlEasyHandle *)curl;
	if (h->sock != CURL_SOCKET_BAD) {
		closesocket(h->sock);
		h->sock = CURL_SOCKET_BAD;
	}
	free(h);
}

extern "C" CURLcode curl_easy_setopt(CURL *curl, CURLoption option, ...)
{
	if (!curl)
		return CURLE_BAD_FUNCTION_ARGUMENT;
	CurlEasyHandle *h = (CurlEasyHandle *)curl;

	va_list ap;
	va_start(ap, option);

	switch (option) {
	case CURLOPT_URL: {
		const char *s = va_arg(ap, const char *);
		snprintf(h->url, sizeof(h->url), "%s", s ? s : "");
		break;
	}
	case CURLOPT_PROXY: {
		const char *s = va_arg(ap, const char *);
		snprintf(h->proxy, sizeof(h->proxy), "%s", s ? s : "");
		break;
	}
	case CURLOPT_USERPWD: {
		const char *s = va_arg(ap, const char *);
		snprintf(h->userpwd, sizeof(h->userpwd), "%s", s ? s : "");
		break;
	}
	case CURLOPT_USERAGENT: {
		const char *s = va_arg(ap, const char *);
		snprintf(h->useragent, sizeof(h->useragent), "%s", s ? s : "");
		break;
	}
	case CURLOPT_ENCODING: {
		const char *s = va_arg(ap, const char *);
		snprintf(h->encoding, sizeof(h->encoding), "%s", s ? s : "");
		break;
	}
	case CURLOPT_ERRORBUFFER:
		h->errorbuffer = va_arg(ap, char *);
		break;
	case CURLOPT_POSTFIELDS:
		h->postfields = va_arg(ap, const char *);
		break;
	case CURLOPT_POSTFIELDSIZE:
		h->postfieldsize = va_arg(ap, long);
		break;
	case CURLOPT_PROXYTYPE:
		h->proxytype = va_arg(ap, long);
		break;
	case CURLOPT_CONNECT_ONLY:
		h->connect_only = va_arg(ap, long);
		break;
	case CURLOPT_CONNECTTIMEOUT:
		h->connecttimeout = va_arg(ap, long);
		break;
	case CURLOPT_TIMEOUT:
		h->timeout = va_arg(ap, long);
		break;
	case CURLOPT_TCP_KEEPALIVE:
		h->tcp_keepalive = va_arg(ap, long);
		break;
	case CURLOPT_TCP_KEEPIDLE:
		h->tcp_keepidle = va_arg(ap, long);
		break;
	case CURLOPT_TCP_KEEPINTVL:
		h->tcp_keepintvl = va_arg(ap, long);
		break;
	case CURLOPT_NETRC:
		h->netrc = va_arg(ap, long);
		break;
	case CURLOPT_HTTPAUTH:
		h->httpauth = va_arg(ap, long);
		break;
	case CURLOPT_FOLLOWLOCATION:
		h->followlocation = va_arg(ap, long);
		break;
	case CURLOPT_SSL_VERIFYPEER:
		h->ssl_verifypeer = va_arg(ap, long);
		break;
	case CURLOPT_VERBOSE:
		h->verbose = va_arg(ap, long);
		break;
	case CURLOPT_FAILONERROR:
		h->failonerror = va_arg(ap, long);
		break;
	case CURLOPT_NOSIGNAL:
		h->nosignal = va_arg(ap, long);
		break;
	case CURLOPT_UPLOAD:
		h->upload = va_arg(ap, long);
		break;
	case CURLOPT_INFILESIZE:
		h->infilesize = va_arg(ap, long);
		break;
	case CURLOPT_WRITEFUNCTION:
		h->writefunction = va_arg(ap, cc_write_cb);
		break;
	case CURLOPT_WRITEDATA:
		h->writedata = va_arg(ap, void *);
		break;
	case CURLOPT_READFUNCTION:
		h->readfunction = va_arg(ap, cc_write_cb);
		break;
	case CURLOPT_READDATA:
		h->readdata = va_arg(ap, void *);
		break;
	case CURLOPT_OPENSOCKETFUNCTION:
		h->opensocketfunction = va_arg(ap, cc_opensocket_cb);
		break;
	case CURLOPT_OPENSOCKETDATA:
		h->opensocketdata = va_arg(ap, void *);
		break;
	case CURLOPT_SOCKOPTFUNCTION:
		h->sockoptfunction = va_arg(ap, cc_sockopt_cb);
		break;
	case CURLOPT_SOCKOPTDATA:
		h->sockoptdata = va_arg(ap, void *);
		break;
	case CURLOPT_DEBUGFUNCTION:
		h->debugfunction = va_arg(ap, cc_debug_cb);
		break;
	case CURLOPT_DEBUGDATA:
		h->debugdata = va_arg(ap, void *);
		break;
	case CURLOPT_HTTPHEADER:
		h->httpheader = va_arg(ap, struct curl_slist *);
		break;
	default:
		break;
	}

	va_end(ap);
	return CURLE_OK;
}

extern "C" CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...)
{
	if (!curl)
		return CURLE_BAD_FUNCTION_ARGUMENT;
	CurlEasyHandle *h = (CurlEasyHandle *)curl;

	va_list ap;
	va_start(ap, info);

	CURLcode rc = CURLE_OK;
	switch (info) {
	case CURLINFO_LASTSOCKET: {
		long *out = va_arg(ap, long *);
		if (out)
			*out = (h->sock == CURL_SOCKET_BAD) ? -1L : (long)h->sock;
		break;
	}
#ifdef CURLINFO_ACTIVESOCKET
	case CURLINFO_ACTIVESOCKET: {
		curl_socket_t *out = va_arg(ap, curl_socket_t *);
		if (out)
			*out = h->sock;
		break;
	}
#endif
	default:
		rc = CURLE_UNKNOWN_OPTION;
		break;
	}

	va_end(ap);
	return rc;
}

struct ParsedUrl {
	bool is_https;
	char host[512];
	int port;
	char path[1024];
};

static bool parse_url_parts(const char *raw_url, ParsedUrl *out)
{
	memset(out, 0, sizeof(*out));
	out->port = 80;
	strcpy(out->path, "/");

	const char *p = raw_url;
	if (_strnicmp(p, "https://", 8) == 0) {
		out->is_https = true;
		out->port = 443;
		p += 8;
	} else if (_strnicmp(p, "http://", 7) == 0) {
		out->is_https = false;
		out->port = 80;
		p += 7;
	} else {
		const char *scheme = strstr(p, "://");
		if (scheme)
			p = scheme + 3;
	}

	const char *slash = strchr(p, '/');
	size_t host_port_len = slash ? (size_t)(slash - p) : strlen(p);
	char host_port[512];
	if (host_port_len >= sizeof(host_port))
		host_port_len = sizeof(host_port) - 1;
	memcpy(host_port, p, host_port_len);
	host_port[host_port_len] = '\0';

	if (slash)
		snprintf(out->path, sizeof(out->path), "%s", slash);

	/* Strip optional user:pass@ prefix in URL */
	const char *at = strrchr(host_port, '@');
	const char *hp = at ? (at + 1) : host_port;

	const char *colon = strrchr(hp, ':');
	if (colon && strchr(colon, ']') == NULL) {
		size_t hlen = (size_t)(colon - hp);
		if (hlen >= sizeof(out->host))
			hlen = sizeof(out->host) - 1;
		memcpy(out->host, hp, hlen);
		out->host[hlen] = '\0';
		out->port = atoi(colon + 1);
	} else {
		snprintf(out->host, sizeof(out->host), "%s", hp);
	}

	return out->host[0] != '\0' && out->port > 0;
}

static CURLcode perform_connect_only(CurlEasyHandle *h, const ParsedUrl *u)
{
	if (h->sock != CURL_SOCKET_BAD) {
		closesocket(h->sock);
		h->sock = CURL_SOCKET_BAD;
	}

	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%d", u->port);

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo *res = NULL;
	int gai = getaddrinfo(u->host, port_str, &hints, &res);
	if (gai != 0 || !res) {
		set_curl_err(h, "Could not resolve host: %s (WSA error %d)", u->host, WSAGetLastError());
		return CURLE_COULDNT_RESOLVE_HOST;
	}

	curl_socket_t s = CURL_SOCKET_BAD;
	for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
		if (h->opensocketfunction) {
			struct curl_sockaddr csa;
			memset(&csa, 0, sizeof(csa));
			csa.family = ai->ai_family;
			csa.socktype = ai->ai_socktype;
			csa.protocol = ai->ai_protocol;
			csa.addrlen = (unsigned int)ai->ai_addrlen;
			memcpy(&csa.addr, ai->ai_addr, ai->ai_addrlen < sizeof(csa.addr) ? ai->ai_addrlen : sizeof(csa.addr));
			s = h->opensocketfunction(h->opensocketdata, CURLSOCKTYPE_IPCXN, &csa);
		} else {
			s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		}

		if (s == CURL_SOCKET_BAD)
			continue;

		if (h->sockoptfunction) {
			int sopt = h->sockoptfunction(h->sockoptdata, s, CURLSOCKTYPE_IPCXN);
			if (sopt != 0) {
				closesocket(s);
				s = CURL_SOCKET_BAD;
				continue;
			}
		}

		/* Connect with timeout if requested */
		if (h->connecttimeout > 0) {
			u_long nonblock = 1;
			ioctlsocket(s, FIONBIO, &nonblock);
			int rc = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
			if (rc == SOCKET_ERROR) {
				int err = WSAGetLastError();
				if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
					fd_set wfds, efds;
					FD_ZERO(&wfds);
					FD_ZERO(&efds);
					FD_SET(s, &wfds);
					FD_SET(s, &efds);
					struct timeval tv;
					tv.tv_sec = h->connecttimeout;
					tv.tv_usec = 0;
					int sel = select(0, NULL, &wfds, &efds, &tv);
					if (sel > 0 && FD_ISSET(s, &wfds) && !FD_ISSET(s, &efds)) {
						int so_err = 0;
						int so_len = sizeof(so_err);
						getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&so_err, &so_len);
						if (so_err == 0)
							rc = 0;
					}
				}
			}
			nonblock = 0;
			ioctlsocket(s, FIONBIO, &nonblock);
			if (rc == 0)
				break;
		} else {
			if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0)
				break;
		}

		closesocket(s);
		s = CURL_SOCKET_BAD;
	}

	freeaddrinfo(res);

	if (s == CURL_SOCKET_BAD) {
		set_curl_err(h, "Failed to connect to %s port %d", u->host, u->port);
		return CURLE_COULDNT_CONNECT;
	}

	h->sock = s;
	return CURLE_OK;
}

static LPWSTR utf8_to_wide(const char *s)
{
	if (!s)
		return NULL;
	int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
	if (n <= 0)
		return NULL;
	LPWSTR w = (LPWSTR)calloc((size_t)n, sizeof(WCHAR));
	if (!w)
		return NULL;
	MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
	return w;
}

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode_str(const char *in, char *out, size_t out_sz)
{
	size_t len = strlen(in);
	size_t j = 0;
	for (size_t i = 0; i < len && j + 4 < out_sz; i += 3) {
		uint32_t v = ((uint32_t)(unsigned char)in[i]) << 16;
		if (i + 1 < len) v |= ((uint32_t)(unsigned char)in[i + 1]) << 8;
		if (i + 2 < len) v |= ((uint32_t)(unsigned char)in[i + 2]);

		out[j++] = b64_table[(v >> 18) & 0x3f];
		out[j++] = b64_table[(v >> 12) & 0x3f];
		out[j++] = (i + 1 < len) ? b64_table[(v >> 6) & 0x3f] : '=';
		out[j++] = (i + 2 < len) ? b64_table[v & 0x3f] : '=';
	}
	out[j] = '\0';
}

static CURLcode perform_http_request(CurlEasyHandle *h, const ParsedUrl *u)
{
	LPWSTR w_ua = utf8_to_wide(h->useragent[0] ? h->useragent : "megaminer/1.0");
	HINTERNET hSession = WinHttpOpen(
		w_ua ? w_ua : L"megaminer/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		0);
	free(w_ua);

	if (!hSession) {
		set_curl_err(h, "WinHttpOpen failed (%lu)", GetLastError());
		return CURLE_FAILED_INIT;
	}

	if (h->connecttimeout > 0 || h->timeout > 0) {
		int c_ms = (h->connecttimeout > 0) ? (int)(h->connecttimeout * 1000) : 30000;
		int t_ms = (h->timeout > 0) ? (int)(h->timeout * 1000) : 30000;
		WinHttpSetTimeouts(hSession, c_ms, c_ms, t_ms, t_ms);
	}

	LPWSTR w_host = utf8_to_wide(u->host);
	HINTERNET hConnect = WinHttpConnect(hSession, w_host ? w_host : L"localhost", (INTERNET_PORT)u->port, 0);
	free(w_host);

	if (!hConnect) {
		set_curl_err(h, "Failed to connect to host %s:%d (%lu)", u->host, u->port, GetLastError());
		WinHttpCloseHandle(hSession);
		return CURLE_COULDNT_CONNECT;
	}

	/* Prepare request body (from postfields or readfunction callback) */
	char *body_buf = NULL;
	DWORD body_len = 0;
	bool is_post = false;

	if (h->postfields) {
		is_post = true;
		long sz = (h->postfieldsize >= 0) ? h->postfieldsize : (long)strlen(h->postfields);
		body_len = (DWORD)sz;
		body_buf = (char *)malloc(body_len + 1);
		if (body_buf)
			memcpy(body_buf, h->postfields, body_len);
	} else if (h->readfunction) {
		is_post = true;
		size_t cap = (h->infilesize > 0) ? (size_t)h->infilesize : 4096;
		body_buf = (char *)malloc(cap);
		while (body_buf) {
			size_t space = cap - body_len;
			if (space == 0) {
				cap *= 2;
				char *nb = (char *)realloc(body_buf, cap);
				if (!nb) break;
				body_buf = nb;
				space = cap - body_len;
			}
			size_t nread = h->readfunction(body_buf + body_len, 1, space, h->readdata);
			if (nread == 0)
				break;
			body_len += (DWORD)nread;
		}
	}

	LPWSTR w_path = utf8_to_wide(u->path);
	DWORD req_flags = u->is_https ? WINHTTP_FLAG_SECURE : 0;
	HINTERNET hRequest = WinHttpOpenRequest(
		hConnect,
		is_post ? L"POST" : L"GET",
		w_path ? w_path : L"/",
		NULL,
		WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		req_flags);
	free(w_path);

	if (!hRequest) {
		set_curl_err(h, "WinHttpOpenRequest failed (%lu)", GetLastError());
		free(body_buf);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return CURLE_COULDNT_CONNECT;
	}

	if (u->is_https && !h->ssl_verifypeer) {
		DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
		                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
		                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
		                  SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
		WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(sec_flags));
	}

	if (h->userpwd[0]) {
		char b64[1024];
		base64_encode_str(h->userpwd, b64, sizeof(b64));
		char auth_hdr[1200];
		snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Basic %s\r\n", b64);
		LPWSTR w_auth = utf8_to_wide(auth_hdr);
		if (w_auth) {
			WinHttpAddRequestHeaders(hRequest, w_auth, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
			free(w_auth);
		}
	}

	for (struct curl_slist *hdr = h->httpheader; hdr != NULL; hdr = hdr->next) {
		if (hdr->data && hdr->data[0]) {
			char line[1024];
			snprintf(line, sizeof(line), "%s\r\n", hdr->data);
			LPWSTR w_hdr = utf8_to_wide(line);
			if (w_hdr) {
				WinHttpAddRequestHeaders(hRequest, w_hdr, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
				free(w_hdr);
			}
		}
	}

	BOOL ok = WinHttpSendRequest(
		hRequest,
		WINHTTP_NO_ADDITIONAL_HEADERS,
		0,
		body_buf ? (LPVOID)body_buf : WINHTTP_NO_REQUEST_DATA,
		body_len,
		body_len,
		0);

	if (ok)
		ok = WinHttpReceiveResponse(hRequest, NULL);

	free(body_buf);

	if (!ok) {
		set_curl_err(h, "HTTP request to %s:%d failed (%lu)", u->host, u->port, GetLastError());
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return CURLE_COULDNT_CONNECT;
	}

	if (h->failonerror) {
		DWORD status_code = 0;
		DWORD status_sz = sizeof(status_code);
		if (WinHttpQueryHeaders(
			hRequest,
			WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
			WINHTTP_HEADER_NAME_BY_INDEX,
			&status_code,
			&status_sz,
			WINHTTP_NO_HEADER_INDEX)) {
			if (status_code >= 400) {
				set_curl_err(h, "The requested URL returned error: %lu", (unsigned long)status_code);
				WinHttpCloseHandle(hRequest);
				WinHttpCloseHandle(hConnect);
				WinHttpCloseHandle(hSession);
				return CURLE_HTTP_RETURNED_ERROR;
			}
		}
	}

	for (;;) {
		DWORD avail = 0;
		if (!WinHttpQueryDataAvailable(hRequest, &avail) || avail == 0)
			break;
		char *chunk = (char *)malloc(avail);
		if (!chunk)
			break;
		DWORD nread = 0;
		if (WinHttpReadData(hRequest, chunk, avail, &nread) && nread > 0) {
			if (h->writefunction)
				h->writefunction(chunk, 1, (size_t)nread, h->writedata);
		}
		free(chunk);
	}

	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);
	return CURLE_OK;
}

extern "C" CURLcode curl_easy_perform(CURL *curl)
{
	if (!curl)
		return CURLE_BAD_FUNCTION_ARGUMENT;
	CurlEasyHandle *h = (CurlEasyHandle *)curl;
	if (h->errorbuffer)
		h->errorbuffer[0] = '\0';

	ParsedUrl u;
	if (!parse_url_parts(h->url, &u)) {
		set_curl_err(h, "URL using bad/illegal format or missing URL: %s", h->url);
		return CURLE_URL_MALFORMAT;
	}

	if (h->connect_only)
		return perform_connect_only(h, &u);

	return perform_http_request(h, &u);
}

#endif /* _WIN32 */
