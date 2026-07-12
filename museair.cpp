/*
 * MuseAir v1a
 * By K--Aethiax
 *
 * Released into the public domain under the CC0 1.0 license. To view a copy
 * of this license, visit: https://creativecommons.org/publicdomain/zero/1.0/
 *
 * Note that this file is used with SMHasher3, not a standalone implementation;
 * there isn't a C one because I don't want to deal with boilerplates in C yet.
 */

#include "Platform.h"
#include "Hashlib.h"
#include "Mathmult.h"

#define u64x(N) (N * 8)

// `AiryAi(0)` fractional part calculated by Y-Cruncher.
static const uint64_t CONSTANT[13] = {
    UINT64_C(0x5ae31e589c56e17a), UINT64_C(0x96d7bb04e64f6da9), UINT64_C(0x7ab1006b26f9eb64),
    UINT64_C(0x21233394220b8457), UINT64_C(0x047cb9557c9f3b43), UINT64_C(0xd24f2590c0bcee28),
    UINT64_C(0x33ea8f71bb6016d8), UINT64_C(0xb5d2697595d0a01f), UINT64_C(0x9bb30a32f00e2b4f),
    UINT64_C(0x4acea09317a429d1), UINT64_C(0xc2b2435dfdd545c6), UINT64_C(0xfda811a785572a42),
    UINT64_C(0xe5f50676bf67137b),
};

static const uint64_t MASK_A = UINT64_C(0xAAAAAAAAAAAAAAAA);
static const uint64_t MASK_B = UINT64_C(0x5555555555555555);
static const uint64_t MASK_I = UINT64_C(01555555555555555555555);
static const uint64_t MASK_J = UINT64_C(01333333333333333333333);
static const uint64_t MASK_K = UINT64_C(00666666666666666666666);

template <bool bswap>
static FORCE_INLINE void museair_read_short(const uint8_t* bytes, const size_t len, uint64_t* i, uint64_t* j) {
    if (len >= 8) {
        *i = GET_U64<bswap>(bytes, 0);
        *j = GET_U64<bswap>(bytes + len - 8, 0);
    } else if (len >= 4) {
        *i = GET_U32<bswap>(bytes, 0);
        *j = GET_U32<bswap>(bytes + len - 4, 0);
    } else if (len > 0) {
        *i = (uint64_t)bytes[0] << 48 | bytes[len - 1];
        *j = (uint64_t)bytes[len >> 1];
    } else {
        *i = 0;
        *j = 0;
    }
}

template <bool bswap, bool bfast, bool b128>
static FORCE_INLINE void museair_hash_short(const uint8_t* bytes,
                                            const size_t len,
                                            const seed_t seed_a,
                                            const seed_t seed_b,
                                            uint64_t* out_lo,
                                            uint64_t* out_hi) {
    uint64_t lo0, lo1, lo2;
    uint64_t hi0, hi1, hi2;
    uint64_t i, j;
    museair_read_short<bswap>(bytes, len <= 16 ? len : 16, &i, &j);

    if (b128) {
        MathMult::mult64_128(lo0, hi0, (CONSTANT[0] + seed_a) ^ len, CONSTANT[1] ^ len);
        MathMult::mult64_128(lo1, hi1, (CONSTANT[2] - seed_b) ^ len, CONSTANT[3] ^ len);
        i ^= lo0 ^ hi1;
        j ^= lo1 ^ hi0;
    } else {
        MathMult::mult64_128(lo2, hi2, (CONSTANT[2] ^ seed_a) ^ len, CONSTANT[3] ^ len);
        i ^= lo2;
        j ^= hi2;
    }

    if (unlikely(len > u64x(2))) {
        uint64_t u, v;
        museair_read_short<bswap>(bytes + u64x(2), len - u64x(2), &u, &v);
        if (b128) {
            MathMult::mult64_128(lo0, hi0, (CONSTANT[4] + seed_a) ^ u, CONSTANT[5]);
            MathMult::mult64_128(lo1, hi1, (CONSTANT[6] - seed_b) ^ v, CONSTANT[7]);
        } else {
            MathMult::mult64_128(lo0, hi0, (CONSTANT[4] ^ seed_a) ^ u, CONSTANT[5]);
            MathMult::mult64_128(lo1, hi1, (CONSTANT[6] ^ seed_a) ^ v, CONSTANT[7]);
        }
        i ^= lo0 ^ hi1;
        j ^= lo1 ^ hi0;
    }

    if (b128) {
        if (!bfast) {
            MathMult::mult64_128(lo0, hi0, i ^ CONSTANT[8], j ^ CONSTANT[9]);
            MathMult::mult64_128(lo1, hi1, i ^ CONSTANT[11], j ^ CONSTANT[10]);
            MathMult::mult64_128(lo0, hi0, lo0 ^ CONSTANT[10], hi0 ^ CONSTANT[11]);
            MathMult::mult64_128(lo1, hi1, lo1 ^ CONSTANT[9], hi1 ^ CONSTANT[8]);
        } else {
            MathMult::mult64_128(lo0, hi0, i ^ CONSTANT[8], j ^ CONSTANT[9]);
            MathMult::mult64_128(lo1, hi1, i, j);
            MathMult::mult64_128(lo0, hi0, lo0 ^ CONSTANT[10], hi0 ^ CONSTANT[11]);
            MathMult::mult64_128(lo1, hi1, lo1, hi1);
        }
        *out_lo = lo0 ^ hi1;
        *out_hi = lo1 ^ hi0;
    } else {
        if (!bfast) {
            MathMult::mult64_128(lo2, hi2, i ^ CONSTANT[8], j ^ CONSTANT[9]);
            i -= lo2;
            j -= hi2;
            MathMult::mult64_128(lo2, hi2, i ^ CONSTANT[10], j ^ CONSTANT[11]);
            i -= lo2;
            j -= hi2;
        } else {
            MathMult::mult64_128(i, j, i ^ CONSTANT[8], j ^ CONSTANT[9]);
            MathMult::mult64_128(i, j, i ^ CONSTANT[10], j ^ CONSTANT[11]);
        }
        *out_lo = i ^ j;
    }
}

template <bool bswap, bool bfast, bool b128>
static NEVER_INLINE void museair_hash_loong(const uint8_t* bytes,
                                            const size_t len,
                                            const seed_t seed_a,
                                            const seed_t seed_b,
                                            uint64_t* out_lo,
                                            uint64_t* out_hi) {
    const uint8_t* p = bytes;
    size_t q = len;

    uint64_t i, j, k;
    uint64_t lo0, lo1, lo2, lo3, lo4, lo5 = CONSTANT[6];
    uint64_t hi0, hi1, hi2, hi3, hi4, hi5 = CONSTANT[6];
    uint64_t state[6] = {CONSTANT[0], CONSTANT[1], CONSTANT[2], CONSTANT[3], CONSTANT[4], CONSTANT[5]};

    if (b128) {
        state[0] ^= seed_a & MASK_I;
        state[1] ^= seed_b & MASK_J;
        state[2] ^= seed_a & MASK_K;
        state[3] ^= seed_b & MASK_I;
        state[4] ^= seed_a & MASK_J;
        state[5] ^= seed_b & MASK_K;
    } else {
        state[0] ^= seed_a & MASK_A;
        state[1] ^= seed_a & MASK_B;
        state[2] ^= seed_a & MASK_A;
        state[3] ^= seed_a & MASK_B;
        state[4] ^= seed_a & MASK_A;
        state[5] ^= seed_a & MASK_B;
    }

    if (unlikely(q > u64x(12))) {
        do {
            if (!bfast) {
                state[0] ^= GET_U64<bswap>(p, u64x(0));
                state[1] ^= GET_U64<bswap>(p, u64x(1));
                MathMult::mult64_128(lo0, hi0, state[0], state[1]);
                state[0] -= lo0 ^ hi5;

                state[1] ^= GET_U64<bswap>(p, u64x(2));
                state[2] ^= GET_U64<bswap>(p, u64x(3));
                MathMult::mult64_128(lo1, hi1, state[1], state[2]);
                state[1] -= lo1 ^ hi0;

                state[2] ^= GET_U64<bswap>(p, u64x(4));
                state[3] ^= GET_U64<bswap>(p, u64x(5));
                MathMult::mult64_128(lo2, hi2, state[2], state[3]);
                state[2] -= lo2 ^ hi1;

                state[3] ^= GET_U64<bswap>(p, u64x(6));
                state[4] ^= GET_U64<bswap>(p, u64x(7));
                MathMult::mult64_128(lo3, hi3, state[3], state[4]);
                state[3] -= lo3 ^ hi2;

                state[4] ^= GET_U64<bswap>(p, u64x(8));
                state[5] ^= GET_U64<bswap>(p, u64x(9));
                MathMult::mult64_128(lo4, hi4, state[4], state[5]);
                state[4] -= lo4 ^ hi3;

                state[5] ^= GET_U64<bswap>(p, u64x(10));
                state[0] ^= GET_U64<bswap>(p, u64x(11));
                MathMult::mult64_128(lo5, hi5, state[5], state[0]);
                state[5] -= lo5 ^ hi4;
            } else {
                state[0] ^= GET_U64<bswap>(p, u64x(0));
                state[1] ^= GET_U64<bswap>(p, u64x(1));
                MathMult::mult64_128(lo0, hi0, state[0], state[1]);
                state[0] = lo5 ^ hi0;

                state[1] ^= GET_U64<bswap>(p, u64x(2));
                state[2] ^= GET_U64<bswap>(p, u64x(3));
                MathMult::mult64_128(lo1, hi1, state[1], state[2]);
                state[1] = lo0 ^ hi1;

                state[2] ^= GET_U64<bswap>(p, u64x(4));
                state[3] ^= GET_U64<bswap>(p, u64x(5));
                MathMult::mult64_128(lo2, hi2, state[2], state[3]);
                state[2] = lo1 ^ hi2;

                state[3] ^= GET_U64<bswap>(p, u64x(6));
                state[4] ^= GET_U64<bswap>(p, u64x(7));
                MathMult::mult64_128(lo3, hi3, state[3], state[4]);
                state[3] = lo2 ^ hi3;

                state[4] ^= GET_U64<bswap>(p, u64x(8));
                state[5] ^= GET_U64<bswap>(p, u64x(9));
                MathMult::mult64_128(lo4, hi4, state[4], state[5]);
                state[4] = lo3 ^ hi4;

                state[5] ^= GET_U64<bswap>(p, u64x(10));
                state[0] ^= GET_U64<bswap>(p, u64x(11));
                MathMult::mult64_128(lo5, hi5, state[5], state[0]);
                state[5] = lo4 ^ hi5;
            }

            p += u64x(12);
            q -= u64x(12);

        } while (likely(q > u64x(12)));

        if (!bfast) {
            state[0] ^= hi5;
        } else { /* Don't forget these! */
            state[0] ^= lo5;
        }
    }

    lo0 = 0, lo1 = 0, lo2 = 0, lo3 = 0;
    hi0 = state[1];
    hi1 = state[2];
    hi2 = state[3];
    hi3 = state[4];

    if (q > u64x(4)) {
        state[0] ^= GET_U64<bswap>(p, u64x(0));
        state[1] ^= GET_U64<bswap>(p, u64x(1));
        MathMult::mult64_128(lo0, hi0, state[0], state[1]);

        if (q > u64x(6)) {
            state[1] ^= GET_U64<bswap>(p, u64x(2));
            state[2] ^= GET_U64<bswap>(p, u64x(3));
            MathMult::mult64_128(lo1, hi1, state[1], state[2]);

            if (q > u64x(8)) {
                state[2] ^= GET_U64<bswap>(p, u64x(4));
                state[3] ^= GET_U64<bswap>(p, u64x(5));
                MathMult::mult64_128(lo2, hi2, state[2], state[3]);

                if (q > u64x(10)) {
                    state[3] ^= GET_U64<bswap>(p, u64x(6));
                    state[4] ^= GET_U64<bswap>(p, u64x(7));
                    MathMult::mult64_128(lo3, hi3, state[3], state[4]);
                }
            }
        }
    }

    state[4] ^= GET_U64<bswap>(p + q - u64x(4), 0);
    state[5] ^= GET_U64<bswap>(p + q - u64x(3), 0);
    MathMult::mult64_128(lo4, hi4, state[4], state[5]);

    state[5] ^= GET_U64<bswap>(p + q - u64x(2), 0);
    state[0] ^= GET_U64<bswap>(p + q - u64x(1), 0);
    MathMult::mult64_128(lo5, hi5, state[5], state[0]);

    i = (state[0] - state[1]) ^ CONSTANT[7];
    j = (state[2] - state[3]) ^ CONSTANT[8];
    k = (state[4] - state[5]) ^ CONSTANT[9];

    int rot = len & 63;
    i = ROTL64(i, rot);
    j = ROTR64(j, rot);
    k = k - len;

    i = i - (lo3 ^ hi3) - (lo4 ^ hi4);
    j = j - (lo5 ^ hi5) - (lo0 ^ hi0);
    k = k - (lo1 ^ hi1) - (lo2 ^ hi2);

    MathMult::mult64_128(lo0, hi0, i, j);
    MathMult::mult64_128(lo1, hi1, j, k);
    MathMult::mult64_128(lo2, hi2, k, i);

    if (!bfast) {
        i -= lo0 ^ hi2;
        j -= lo1 ^ hi0;
        k -= lo2 ^ hi1;
    } else {
        i = lo2 ^ hi0;
        j = lo0 ^ hi1;
        k = lo1 ^ hi2;
    }

    if (b128) {
        MathMult::mult64_128(lo3, hi3, i, CONSTANT[10]);
        MathMult::mult64_128(lo4, hi4, j, CONSTANT[11]);
        MathMult::mult64_128(lo5, hi5, k, CONSTANT[12]);

        *out_lo = lo3 ^ hi4 ^ lo5;
        *out_hi = hi3 ^ lo4 ^ hi5;
    } else {
        *out_lo = i + j + k;
    }
}

template <bool bswap, bool bfast, bool b128>
static inline void MuseAirHash(const void* bytes, const size_t len, const seed_t seed, void* out) {
    uint64_t out_lo, out_hi;

    if (likely(len <= u64x(4))) {
        museair_hash_short<bswap, bfast, b128>((const uint8_t*)bytes, len, seed, seed, &out_lo, &out_hi);
    } else {
        museair_hash_loong<bswap, bfast, b128>((const uint8_t*)bytes, len, seed, seed, &out_lo, &out_hi);
    }

    PUT_U64<false>(COND_BSWAP(out_lo, isBE()), (uint8_t*)out, 0);
    if (b128)
        PUT_U64<false>(COND_BSWAP(out_hi, isBE()), (uint8_t*)out, 8);
}

template <bool bswap, bool bfast>
static inline void MuseAirHashFolded(const void* bytes, const size_t len, const seed_t seed, void* out) {
    uint64_t out_lo, out_hi;

    if (likely(len <= u64x(4))) {
        museair_hash_short<bswap, bfast, false>((const uint8_t*)bytes, len, seed, seed, &out_lo, &out_hi);
    } else {
        museair_hash_loong<bswap, bfast, false>((const uint8_t*)bytes, len, seed, seed, &out_lo, &out_hi);
    }

    PUT_U32<false>(COND_BSWAP((uint32_t)out_lo ^ (out_lo >> 32), isBE()), (uint8_t*)out, 0);
}

template <bool bswap, bool bfast>
static inline void MuseAirHash128Folded(const void* bytes, const size_t len, const seed_t seed, void* out) {
    uint64_t out_lo, out_hi;

    if (likely(len <= u64x(4))) {
        museair_hash_short<bswap, bfast, true>((const uint8_t*)bytes, len, seed, seed, &out_lo, &out_hi);
    } else {
        museair_hash_loong<bswap, bfast, true>((const uint8_t*)bytes, len, seed, seed, &out_lo, &out_hi);
    }

    PUT_U64<false>(COND_BSWAP(out_lo + out_hi, isBE()), (uint8_t*)out, 0);
}

//------------------------------------------------------------------------------
// clang-format off
REGISTER_FAMILY(MuseAir,
    $.src_url    = "https://github.com/eternal-io/museair",
    $.src_status = HashFamilyInfo::SRC_STABLEISH
);

REGISTER_HASH(MuseAir,
    $.desc       = "MuseAir v1a, 64-bit version",
    $.impl       = "portable",
    $.hash_flags = FLAG_HASH_ENDIAN_INDEPENDENT,
    $.impl_flags = FLAG_IMPL_CANONICAL_LE
                 | FLAG_IMPL_MULTIPLY_64_128
                 | FLAG_IMPL_ROTATE_VARIABLE
                 | FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
    $.bits = 64,
    $.verification_LE = 0x7140CABC,
    $.hashfn_native   = MuseAirHash<false, false, false>,
    $.hashfn_bswap    = MuseAirHash<true, false, false>
);
REGISTER_HASH(MuseAir__folded,
    $.desc       = "MuseAir v1a, 64-bit version, XOR-folded down to 32-bit",
    $.impl       = "portable",
    $.hash_flags = FLAG_HASH_ENDIAN_INDEPENDENT,
    $.impl_flags = FLAG_IMPL_CANONICAL_LE
                 | FLAG_IMPL_MULTIPLY_64_128
                 | FLAG_IMPL_ROTATE_VARIABLE
                 | FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
    $.bits = 32,
    $.verification_LE = 0x0B8F0243,
    $.hashfn_native   = MuseAirHashFolded<false, false>,
    $.hashfn_bswap    = MuseAirHashFolded<true, false>
);
REGISTER_HASH(MuseAir_128,
    $.desc       = "MuseAir v1a, 128-bit version",
    $.impl       = "portable",
    $.hash_flags = FLAG_HASH_ENDIAN_INDEPENDENT,
    $.impl_flags = FLAG_IMPL_CANONICAL_LE
                 | FLAG_IMPL_MULTIPLY_64_128
                 | FLAG_IMPL_ROTATE_VARIABLE
                 | FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
    $.bits = 128,
    $.verification_LE = 0x38028C88,
    $.hashfn_native   = MuseAirHash<false, false, true>,
    $.hashfn_bswap    = MuseAirHash<true, false, true>
);
REGISTER_HASH(MuseAir_128__folded,
    $.desc       = "MuseAir v1a, 128-bit version, ADD-folded down to 64-bit",
    $.impl       = "portable",
    $.hash_flags = FLAG_HASH_ENDIAN_INDEPENDENT,
    $.impl_flags = FLAG_IMPL_CANONICAL_LE
                 | FLAG_IMPL_MULTIPLY_64_128
                 | FLAG_IMPL_ROTATE_VARIABLE
                 | FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
    $.bits = 64,
    $.verification_LE = 0xB9CD57B7,
    $.hashfn_native   = MuseAirHash128Folded<false, false>,
    $.hashfn_bswap    = MuseAirHash128Folded<true, false>
);

REGISTER_HASH(MuseAir_BFast,
    $.desc       = "MuseAir v1a, BFast variant, 64-bit version",
    $.impl       = "portable",
    $.hash_flags = FLAG_HASH_ENDIAN_INDEPENDENT,
    $.impl_flags = FLAG_IMPL_CANONICAL_LE
                 | FLAG_IMPL_MULTIPLY_64_128
                 | FLAG_IMPL_ROTATE_VARIABLE
                 | FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
    $.bits = 64,
    $.verification_LE = 0xA4BFD093,
    $.hashfn_native   = MuseAirHash<false, true, false>,
    $.hashfn_bswap    = MuseAirHash<true, true, false>
);
REGISTER_HASH(MuseAir_BFast__folded,
    $.desc       = "MuseAir v1a, BFast variant, 64-bit version, XOR-folded down to 32-bit",
    $.impl       = "portable",
    $.hash_flags = FLAG_HASH_ENDIAN_INDEPENDENT,
    $.impl_flags = FLAG_IMPL_CANONICAL_LE
                 | FLAG_IMPL_MULTIPLY_64_128
                 | FLAG_IMPL_ROTATE_VARIABLE
                 | FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
    $.bits = 32,
    $.verification_LE = 0xDCCDD53A,
    $.hashfn_native   = MuseAirHashFolded<false, true>,
    $.hashfn_bswap    = MuseAirHashFolded<true, true>
);
REGISTER_HASH(MuseAir_BFast_128,
    $.desc       = "MuseAir v1a, BFast variant, 128-bit version",
    $.impl       = "portable",
    $.hash_flags = FLAG_HASH_ENDIAN_INDEPENDENT,
    $.impl_flags = FLAG_IMPL_CANONICAL_LE
                 | FLAG_IMPL_MULTIPLY_64_128
                 | FLAG_IMPL_ROTATE_VARIABLE
                 | FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
    $.bits = 128,
    $.verification_LE = 0x81863E77,
    $.hashfn_native   = MuseAirHash<false, true, true>,
    $.hashfn_bswap    = MuseAirHash<true, true, true>
);
REGISTER_HASH(MuseAir_BFast_128__folded,
    $.desc       = "MuseAir v1a, BFast variant, 128-bit version, ADD-folded down to 64-bit",
    $.impl       = "portable",
    $.hash_flags = FLAG_HASH_ENDIAN_INDEPENDENT,
    $.impl_flags = FLAG_IMPL_CANONICAL_LE
                 | FLAG_IMPL_MULTIPLY_64_128
                 | FLAG_IMPL_ROTATE_VARIABLE
                 | FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
    $.bits = 64,
    $.verification_LE = 0x9BAAAF63,
    $.hashfn_native   = MuseAirHash128Folded<false, true>,
    $.hashfn_bswap    = MuseAirHash128Folded<true, true>
);
