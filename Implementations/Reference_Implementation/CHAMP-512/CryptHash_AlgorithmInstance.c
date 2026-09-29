/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

/*
* CHAMP-512 (NGCC ICCS submission)
*
* Hash function based on walks in the Cayley graph of GL(2, F_p) where
*     p = 2^128 - 15449  (a 128-bit safe prime; p-1 = 2q, q prime)
* and generators
*     A = [[-2, 1], [4, -3]]
*     B = [[-5, 2], [-6, 2]]  (entries reduced mod p)
*
* Each input BIT is mapped to a matrix (0 -> A, 1 -> B), MSB-first within 
* a byte. The product of these matrices is accumulated modulo p, and the 
* final result is obtained by inverting and concatenating its entries.
*/

#include <stdint.h>
#include <string.h>
#include "CryptHash_AlgorithmInstance.h"

/* 128-bit integer type: stored as 2 little-endian 64-bit limbs.   */
typedef struct { uint64_t w[2]; } u128;

/* p = 2^128 - 15449.  15449 = 0x3C59, so low limb = 2^64 - 15449. */
static const u128 P = {{ 0xFFFFFFFFFFFFC3A7ULL, 0xFFFFFFFFFFFFFFFFULL }};

/* Generators (mod p) stored column-major: (m00, m10, m01, m11)    */
static const u128 GEN_A[4] = {
    {{0xFFFFFFFFFFFFC3A5ULL, 0xFFFFFFFFFFFFFFFFULL}}, {{4,0}}, {{1,0}}, {{0xFFFFFFFFFFFFC3A4ULL, 0xFFFFFFFFFFFFFFFFULL}}
};
/* B = [[-5, 2], [-6, 2]] mod p.  col-major (-5, -6, 2, 2).
 * p-5 = 0xFFFFFFFFFFFFFFFF_FFFFFFFFFFFFC3A2
 * p-6 = 0xFFFFFFFFFFFFFFFF_FFFFFFFFFFFFC3A1 */
static const u128 GEN_B[4] = {
    {{0xFFFFFFFFFFFFC3A2ULL, 0xFFFFFFFFFFFFFFFFULL}},
    {{0xFFFFFFFFFFFFC3A1ULL, 0xFFFFFFFFFFFFFFFFULL}},
    {{2, 0}},
    {{2, 0}}
};

/* Identity matrix col-major (1, 0, 0, 1) */
static const u128 MAT_IDENTITY[4] = {
    {{1,0}}, {{0,0}}, {{0,0}}, {{1,0}}
};

/* Returns the upper 64 bits of the 128-bit unsigned product a*b. */
static uint64_t u64_mulhi(uint64_t a, uint64_t b)
{
    uint32_t a0 = (uint32_t)a,        a1 = (uint32_t)(a >> 32);
    uint32_t b0 = (uint32_t)b,        b1 = (uint32_t)(b >> 32);
    uint64_t p00 = (uint64_t)a0 * b0;
    uint64_t p01 = (uint64_t)a0 * b1;
    uint64_t p10 = (uint64_t)a1 * b0;
    uint64_t p11 = (uint64_t)a1 * b1;
    uint64_t mid  = (p00 >> 32) + (uint32_t)p01 + (uint32_t)p10;
    return p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}

/* -------------------------------------------------------------------------
 * 128-bit arithmetic helpers
 * ------------------------------------------------------------------------- */

/* Returns 1 if a >= b (unsigned). */
static int u128_gte(const u128 *a, const u128 *b)
{
    if (a->w[1] != b->w[1]) return a->w[1] > b->w[1];
    return a->w[0] >= b->w[0];
}

/* Returns 1 if a == 0. */
static int u128_is_zero(const u128 *a)
{
    return (a->w[0] | a->w[1]) == 0;
}

/* r = a + b.  Returns carry out (0 or 1). */
static uint64_t u128_add(u128 *r, const u128 *a, const u128 *b)
{
    uint64_t s0 = a->w[0] + b->w[0];
    uint64_t c0 = (s0 < a->w[0]) ? 1 : 0;
    r->w[0] = s0;
    uint64_t s1 = a->w[1] + b->w[1];
    uint64_t c1 = (s1 < a->w[1]) ? 1 : 0;
    s1 += c0;
    uint64_t c2 = (s1 < c0) ? 1 : 0;
    r->w[1] = s1;
    return c1 + c2;
}

/* r = a - b (assumes a >= b). */
static void u128_sub(u128 *r, const u128 *a, const u128 *b)
{
    uint64_t a0 = a->w[0];
    uint64_t a1 = a->w[1];
    uint64_t w0 = a0 - b->w[0];
    uint64_t borrow = (a0 < b->w[0]) ? 1 : 0;
    r->w[0] = w0;
    r->w[1] = a1 - b->w[1] - borrow;
}

/* r = a mod p  (a has 256 bits: a[0..3] are 4 little-endian 64-bit limbs) */
static void reduce256(u128 *r, const uint64_t a[4])
{
    static const uint64_t c = 15449ULL;

    /* Step 1: hi_c = a_hi * c  where a_hi = {a[2], a[3]} */
    uint64_t hi_c[3]; /* 3 limbs: hi_c[2] < 2^14 */
    {
        uint64_t carry = 0;
        int i;
        for (i = 0; i < 2; i++) {
            uint64_t lo = a[2 + i] * c;
            uint64_t hi = u64_mulhi(a[2 + i], c);
            uint64_t s  = lo + carry;
            uint64_t c0 = (s < lo) ? 1 : 0;
            hi_c[i] = s;
            carry   = hi + c0;
        }
        hi_c[2] = carry; /* <= u64_mulhi(2^64-1, c) < c < 2^14 */
    }

    /* Step 2: t = a_lo + hi_c  where a_lo = {a[0], a[1]} */
    uint64_t t[3]; /* t[2] < c + 1 */
    {
        uint64_t carry = 0;
        int i;
        for (i = 0; i < 2; i++) {
            uint64_t s  = a[i] + hi_c[i];
            uint64_t c0 = (s < a[i]) ? 1 : 0;
            s  += carry;
            uint64_t c1 = (s < carry) ? 1 : 0;
            t[i]  = s;
            carry = c0 + c1;
        }
        t[2] = hi_c[2] + carry; /* tiny: at most c */
    }

    /* Step 3: t[2] * 2^128 = t[2] * c (mod p).  t[2]*c < c^2 < 2^28. */
    {
        uint64_t extra = t[2] * c; /* fits in 28 bits */
        uint64_t carry;
        r->w[0] = t[0] + extra;
        carry   = (r->w[0] < t[0]) ? 1 : 0;
        r->w[1] = t[1] + carry;
        carry   = (r->w[1] < t[1]) ? 1 : 0;
        if (carry) {
            r->w[0] += c;
            r->w[1] += (r->w[0] < c) ? 1 : 0;
        }
    }

    /* Step 4: conditional subtract to bring into [0, p) */
    if (u128_gte(r, &P)) {
        u128_sub(r, r, &P);
    }
}

/* r = (a + b) mod p */
static void addmod(u128 *r, const u128 *a, const u128 *b)
{
    uint64_t carry = u128_add(r, a, b);
    if (carry || u128_gte(r, &P)) {
        u128_sub(r, r, &P);
    }
}

/* r = (a * b) mod p */
static void mulmod(u128 *r, const u128 *a, const u128 *b)
{
    /* Schoolbook 2x2 limb multiply -> 4 limbs (256 bits) */
    uint64_t prod[4] = {0};
    int i;
    for (i = 0; i < 2; i++) {
        uint64_t carry = 0;
        int j;
        for (j = 0; j < 2; j++) {
            uint64_t lo = a->w[i] * b->w[j];
            uint64_t hi = u64_mulhi(a->w[i], b->w[j]);
            uint64_t s  = prod[i + j] + carry;
            uint64_t c0 = (s < prod[i + j]) ? 1 : 0;
            uint64_t s2 = s + lo;
            uint64_t c1 = (s2 < s) ? 1 : 0;
            prod[i + j] = s2;
            carry = hi + c0 + c1;
        }
        prod[i + 2] += carry;
    }
    reduce256(r, prod);
}

/* 2x2 matrix multiplication over F_p  */
static void mat2x2_mul(u128 r[4], const u128 x[4], const u128 y[4])
{
    u128 t0, t1;
    mulmod(&t0, &x[0], &y[0]); mulmod(&t1, &x[2], &y[1]); addmod(&r[0], &t0, &t1);
    mulmod(&t0, &x[1], &y[0]); mulmod(&t1, &x[3], &y[1]); addmod(&r[1], &t0, &t1);
    mulmod(&t0, &x[0], &y[2]); mulmod(&t1, &x[2], &y[3]); addmod(&r[2], &t0, &t1);
    mulmod(&t0, &x[1], &y[2]); mulmod(&t1, &x[3], &y[3]); addmod(&r[3], &t0, &t1);
}

/* Modular inverse: r = a^(p-2) mod p  (Fermat's little theorem, p prime). */
static void invmod(u128 *r, const u128 *a)
{
    /*  p-2  */
    u128 exp = {{ 0xFFFFFFFFFFFFC3A5ULL, 0xFFFFFFFFFFFFFFFFULL }};
    u128 base   = *a;
    u128 result = {{ 1, 0 }};
    int limb;
    for (limb = 0; limb < 2; limb++) {
        uint64_t bits = exp.w[limb];
        int bit;
        for (bit = 0; bit < 64; bit++) {
            if (bits & 1ULL) mulmod(&result, &result, &base);
            mulmod(&base, &base, &base);
            bits >>= 1;
        }
    }
    *r = result;
}

/* -------------------------------------------------------------------------
 * Byte-table: precomputed 2x2 matrix product for each byte value 0..255.
 * ------------------------------------------------------------------------- */
typedef struct { u128 m[4]; } Mat2x2;

static Mat2x2 byte_table[256];
static int     byte_table_ready = 0;

static void build_byte_table(void)
{
    int i;
    if (byte_table_ready) return;
    for (i = 0; i < 256; i++) {
        Mat2x2 acc;
        int b;
        memcpy(acc.m, MAT_IDENTITY, sizeof(acc.m));
        for (b = 7; b >= 0; b--) {
            int bit = (i >> b) & 1;
            Mat2x2 tmp;
            mat2x2_mul(tmp.m, acc.m, bit ? GEN_B : GEN_A);
            acc = tmp;
        }
        byte_table[i] = acc;
    }
    byte_table_ready = 1;
}

/* -------------------------------------------------------------------------
 * public API
 * ------------------------------------------------------------------------- */
int CryptHash(int digest_len_bits, const unsigned char *msg,
              unsigned long long msg_len_bits, unsigned char *digest)
{
    unsigned long long full_bytes, i;
    unsigned int remaining_bits;
    u128 state[4];
    u128 u1, u2, u3, u4;
    const u128 *out[4];
    int ci, limb;

    (void)digest_len_bits; /* fixed at 512 bits for this instance */

    build_byte_table();

    memcpy(state, MAT_IDENTITY, sizeof(state));

    full_bytes = msg_len_bits >> 3;
    for (i = 0; i < full_bytes; i++) {
        Mat2x2 tmp;
        mat2x2_mul(tmp.m, state, byte_table[(unsigned char)msg[i]].m);
        memcpy(state, tmp.m, sizeof(state));
    }

    /* Handle remaining partial byte bits, MSB first */
    remaining_bits = (unsigned int)(msg_len_bits & 7u);
    if (remaining_bits > 0) {
        unsigned char byte = msg[full_bytes];
        int b;
        for (b = 7; b >= (int)(8 - remaining_bits); b--) {
            int bit = (byte >> b) & 1;
            Mat2x2 tmp;
            mat2x2_mul(tmp.m, state, bit ? GEN_B : GEN_A);
            memcpy(state, tmp.m, sizeof(state));
        }
    }

    /*
     * Digest construction (512 bits = 4 x 128 bits, little-endian):
     */
    if (u128_is_zero(&state[0])) memset(&u1, 0, sizeof(u1)); else invmod(&u1, &state[0]);
    if (u128_is_zero(&state[1])) memset(&u2, 0, sizeof(u2)); else invmod(&u2, &state[1]);
    if (u128_is_zero(&state[2])) memset(&u3, 0, sizeof(u3)); else invmod(&u3, &state[2]);
    if (u128_is_zero(&state[3])) memset(&u4, 0, sizeof(u4)); else invmod(&u4, &state[3]);

    out[0] = &u1;
    out[1] = &u2;
    out[2] = &u3;
    out[3] = &u4;

    for (ci = 0; ci < 4; ci++) {
        for (limb = 0; limb < 2; limb++) {
            uint64_t val = out[ci]->w[limb];
            digest[ci * 16 + limb * 8 + 0] = (unsigned char)(val);
            digest[ci * 16 + limb * 8 + 1] = (unsigned char)(val >>  8);
            digest[ci * 16 + limb * 8 + 2] = (unsigned char)(val >> 16);
            digest[ci * 16 + limb * 8 + 3] = (unsigned char)(val >> 24);
            digest[ci * 16 + limb * 8 + 4] = (unsigned char)(val >> 32);
            digest[ci * 16 + limb * 8 + 5] = (unsigned char)(val >> 40);
            digest[ci * 16 + limb * 8 + 6] = (unsigned char)(val >> 48);
            digest[ci * 16 + limb * 8 + 7] = (unsigned char)(val >> 56);
        }
    }

    return 0;
}
