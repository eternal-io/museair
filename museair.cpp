/*
 * Copyright (c) 2024 K--Aethiax
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Alternatively, the contents of this file may be used under the terms of
 * the MIT license as described below.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "Platform.h"
#include "Hashlib.h"

#include "Mathmult.h"

#define HASH_ALGORITHM_VERSION "0.3-rc5"

#define u64x(N) N * 8

// `AiryAi(0)` mantissa calculated by Y-Cruncher.
static const uint64_t CONSTANT[7] = {
    UINT64_C(0x5ae31e589c56e17a), UINT64_C(0x96d7bb04e64f6da9), UINT64_C(0x7ab1006b26f9eb64),
    UINT64_C(0x21233394220b8457), UINT64_C(0x047cb9557c9f3b43), UINT64_C(0xd24f2590c0bcee28),
    UINT64_C(0x33ea8f71bb6016d8),
};

//------------------------------------------------------------------------------

template <bool bswap>
static FORCE_INLINE uint64_t read_u64(const uint8_t* p) {
    return GET_U64<bswap>(p, 0);
}
template <bool bswap>
static FORCE_INLINE uint64_t read_u32(const uint8_t* p) {
    return (uint64_t)GET_U32<bswap>(p, 0);
}
template <bool bswap>
static FORCE_INLINE void read_short(const uint8_t* bytes, const size_t len, uint64_t* i, uint64_t* j) {
    if (len >= 4) {
        int off = (len & 24) >> (len >> 3);  // len >= 8 ? 4 : 0
        *i = (read_u32<bswap>(bytes) << 32) | read_u32<bswap>(bytes + len - 4);
        *j = (read_u32<bswap>(bytes + off) << 32) | read_u32<bswap>(bytes + len - 4 - off);
    } else if (len > 0) {
        // MSB <-> LSB
        // [0] [0] [0] for len == 1 (0b01)
        // [0] [1] [1] for len == 2 (0b10)
        // [0] [1] [2] for len == 3 (0b11)
        *i = ((uint64_t)bytes[0] << 48) | ((uint64_t)bytes[len >> 1] << 24) | (uint64_t)bytes[len - 1];
        *j = 0;
    } else {
        *i = 0;
        *j = 0;
    }
}

static FORCE_INLINE void _mumix(uint64_t* state_p, uint64_t* state_q, uint64_t input_p, uint64_t input_q) {
    uint64_t lo, hi;
    *state_p ^= input_p;
    *state_q ^= input_q;
    MathMult::mult64_128(lo, hi, *state_p, *state_q);
    *state_p ^= lo;
    *state_q ^= hi;
}

//------------------------------------------------------------------------------

template <bool bswap, bool b128>
static FORCE_INLINE void hash_short(const uint8_t* bytes, const size_t len, const seed_t seed, uint64_t*, uint64_t*);

template <bool bswap, bool bfast, bool b128>
static NEVER_INLINE void hash_loong(const uint8_t* bytes, const size_t len, const seed_t seed, uint64_t*, uint64_t*);

template <bool bswap, bool bfast, bool b128>
static inline void hash(const void* bytes, const size_t len, const seed_t seed, void* out) {
    uint64_t out_lo, out_hi;

    if (likely(len <= u64x(4))) {
        hash_short<bswap, b128>((const uint8_t*)bytes, len, seed, &out_lo, &out_hi);
    } else {
        hash_loong<bswap, bfast, b128>((const uint8_t*)bytes, len, seed, &out_lo, &out_hi);
    }

    if (b128) {
        if (isLE()) {
            PUT_U64<false>(out_lo, (uint8_t*)out, 0);
            PUT_U64<false>(out_hi, (uint8_t*)out, 8);
        } else {
            PUT_U64<true>(out_lo, (uint8_t*)out, 0);
            PUT_U64<true>(out_hi, (uint8_t*)out, 8);
        }
    } else {
        if (isLE()) {
            PUT_U64<false>(out_lo, (uint8_t*)out, 0);
        } else {
            PUT_U64<true>(out_lo, (uint8_t*)out, 0);
        }
    }
}

template <bool bswap, bool b128>
static FORCE_INLINE void hash_short(const uint8_t* bytes,
                                    const size_t len,
                                    const seed_t seed,
                                    uint64_t* out_lo,
                                    uint64_t* out_hi) {
    uint64_t lo0, lo1, lo2;
    uint64_t hi0, hi1, hi2;

    uint64_t i, j;

    MathMult::mult64_128(lo2, hi2, seed ^ CONSTANT[0], len ^ CONSTANT[1]);

    // Seems compilers are smart enough to make `min(len, 16)` branchless.
    read_short<bswap>(bytes, len <= 16 ? len : 16, &i, &j);
    i ^= len ^ lo2;
    j ^= seed ^ hi2;

    if (unlikely(len >= u64x(2))) {
        uint64_t u, v;
        read_short<bswap>(bytes + u64x(2), len - u64x(2), &u, &v);
        MathMult::mult64_128(lo0, hi0, CONSTANT[2], CONSTANT[3] ^ u);
        MathMult::mult64_128(lo1, hi1, CONSTANT[4], CONSTANT[5] ^ v);
        i ^= lo0 ^ hi1;
        j ^= lo1 ^ hi0;
    }

    if (b128) {
        MathMult::mult64_128(lo0, hi0, i, j);
        MathMult::mult64_128(lo1, hi1, i ^ CONSTANT[2], j ^ CONSTANT[3]);
        i = lo0 ^ hi1;
        j = lo1 ^ hi0;
        MathMult::mult64_128(lo0, hi0, i, j);
        MathMult::mult64_128(lo1, hi1, i ^ CONSTANT[4], j ^ CONSTANT[5]);

        *out_lo = lo0 ^ hi1;
        *out_hi = lo1 ^ hi0;
    } else {
        i ^= CONSTANT[2];
        j ^= CONSTANT[3];
        MathMult::mult64_128(lo0, hi0, i, j);
        i ^= lo0 ^ CONSTANT[4];
        j ^= hi0 ^ CONSTANT[5];
        MathMult::mult64_128(lo0, hi0, i, j);

        *out_lo = i ^ j ^ lo0 ^ hi0;
    }
}

template <bool bswap, bool bfast, bool b128>
static NEVER_INLINE void hash_loong(const uint8_t* bytes,
                                    const size_t len,
                                    const seed_t seed,
                                    uint64_t* out_lo,
                                    uint64_t* out_hi) {
    const uint8_t* p = bytes;
    size_t q = len;

    uint64_t i, j, k;

    uint64_t lo0, lo1, lo2, lo3, lo4, lo5 = CONSTANT[6];
    uint64_t hi0, hi1, hi2, hi3, hi4, hi5;

    uint64_t state[6] = {CONSTANT[0] + seed, CONSTANT[1] - seed, CONSTANT[2] ^ seed,
                         CONSTANT[3] + seed, CONSTANT[4] - seed, CONSTANT[5] ^ seed};

    if (unlikely(q >= u64x(12))) {
        do {
            if (!bfast) {
                state[0] ^= read_u64<bswap>(p + u64x(0));
                state[1] ^= read_u64<bswap>(p + u64x(1));
                MathMult::mult64_128(lo0, hi0, state[0], state[1]);
                state[0] += lo5 ^ hi0;

                state[1] ^= read_u64<bswap>(p + u64x(2));
                state[2] ^= read_u64<bswap>(p + u64x(3));
                MathMult::mult64_128(lo1, hi1, state[1], state[2]);
                state[1] += lo0 ^ hi1;

                state[2] ^= read_u64<bswap>(p + u64x(4));
                state[3] ^= read_u64<bswap>(p + u64x(5));
                MathMult::mult64_128(lo2, hi2, state[2], state[3]);
                state[2] += lo1 ^ hi2;

                state[3] ^= read_u64<bswap>(p + u64x(6));
                state[4] ^= read_u64<bswap>(p + u64x(7));
                MathMult::mult64_128(lo3, hi3, state[3], state[4]);
                state[3] += lo2 ^ hi3;

                state[4] ^= read_u64<bswap>(p + u64x(8));
                state[5] ^= read_u64<bswap>(p + u64x(9));
                MathMult::mult64_128(lo4, hi4, state[4], state[5]);
                state[4] += lo3 ^ hi4;

                state[5] ^= read_u64<bswap>(p + u64x(10));
                state[0] ^= read_u64<bswap>(p + u64x(11));
                MathMult::mult64_128(lo5, hi5, state[5], state[0]);
                state[5] += lo4 ^ hi5;
            } else {
                state[0] ^= read_u64<bswap>(p + u64x(0));
                state[1] ^= read_u64<bswap>(p + u64x(1));
                MathMult::mult64_128(lo0, hi0, state[0], state[1]);
                state[0] = lo5 ^ hi0;

                state[1] ^= read_u64<bswap>(p + u64x(2));
                state[2] ^= read_u64<bswap>(p + u64x(3));
                MathMult::mult64_128(lo1, hi1, state[1], state[2]);
                state[1] = lo0 ^ hi1;

                state[2] ^= read_u64<bswap>(p + u64x(4));
                state[3] ^= read_u64<bswap>(p + u64x(5));
                MathMult::mult64_128(lo2, hi2, state[2], state[3]);
                state[2] = lo1 ^ hi2;

                state[3] ^= read_u64<bswap>(p + u64x(6));
                state[4] ^= read_u64<bswap>(p + u64x(7));
                MathMult::mult64_128(lo3, hi3, state[3], state[4]);
                state[3] = lo2 ^ hi3;

                state[4] ^= read_u64<bswap>(p + u64x(8));
                state[5] ^= read_u64<bswap>(p + u64x(9));
                MathMult::mult64_128(lo4, hi4, state[4], state[5]);
                state[4] = lo3 ^ hi4;

                state[5] ^= read_u64<bswap>(p + u64x(10));
                state[0] ^= read_u64<bswap>(p + u64x(11));
                MathMult::mult64_128(lo5, hi5, state[5], state[0]);
                state[5] = lo4 ^ hi5;
            }

            p += u64x(12);
            q -= u64x(12);

        } while (likely(q >= u64x(12)));

        state[0] ^= lo5;
    }

    /* 交换下方`state[]`的使用顺序会明显影响性能表现，现在这样似乎是最好的组合。
       还没有检查过它们生成的汇编，有可能是编译器“太过聪明”以至于产生了一些负优化。就像之前的`state[N] += lo[N-1] ^ hi[N]`那样，加法不能用异或替代。 */

    if (unlikely(q >= u64x(6))) {
        _mumix(&state[0], &state[1], read_u64<bswap>(p + u64x(0)), read_u64<bswap>(p + u64x(1)));
        _mumix(&state[2], &state[3], read_u64<bswap>(p + u64x(2)), read_u64<bswap>(p + u64x(3)));
        _mumix(&state[4], &state[5], read_u64<bswap>(p + u64x(4)), read_u64<bswap>(p + u64x(5)));

        p += u64x(6);
        q -= u64x(6);
    }

    if (likely(q >= u64x(2))) {
        _mumix(&state[0], &state[3], read_u64<bswap>(p + u64x(0)), read_u64<bswap>(p + u64x(1)));
        if (likely(q >= u64x(4))) {
            _mumix(&state[1], &state[4], read_u64<bswap>(p + u64x(2)), read_u64<bswap>(p + u64x(3)));
        }
    }

    _mumix(&state[2], &state[5], read_u64<bswap>(p + q - u64x(2)), read_u64<bswap>(p + q - u64x(1)));

    /*-------- epilogue --------*/

    i = state[0] + state[1];
    j = state[2] + state[3];
    k = state[4] + state[5];

    int rot = len & 63;
    i = ROTL64(i, rot);
    j = ROTR64(j, rot);
    k ^= len;

    MathMult::mult64_128(lo0, hi0, i, j);
    MathMult::mult64_128(lo1, hi1, j, k);
    MathMult::mult64_128(lo2, hi2, k, i);
    i = lo0 ^ hi2;
    j = lo1 ^ hi0;
    k = lo2 ^ hi1;

    if (b128) {
        MathMult::mult64_128(lo0, hi0, i, j);
        MathMult::mult64_128(lo1, hi1, j, k);
        MathMult::mult64_128(lo2, hi2, k, i);
        *out_lo = lo0 ^ lo1 ^ hi2;
        *out_hi = hi0 ^ hi1 ^ lo2;
    } else {
        MathMult::mult64_128(lo0, hi0, i, j);
        MathMult::mult64_128(lo1, hi1, j, k);
        MathMult::mult64_128(lo2, hi2, k, i);

        /* Observed that this branch cannot be simplified,
            otherwise `-BFast` will be strangely slower than `-BFast-128` 😑 */
        /* This may related to template specialization? Haven't check its assembly yet.
            If there is no such problem in Rust, I will remove this branch. */
        if (!bfast) {
            *out_lo = (k ^ hi0 ^ lo1) + (i ^ hi1 ^ lo2) + (j ^ hi2 ^ lo0);
        } else {
            *out_lo = (lo0 ^ hi2) + (lo1 ^ hi0) + (lo2 ^ hi1);
        }
    }
}

//------------------------------------------------------------------------------
// clang-format off
REGISTER_FAMILY(MuseAir,
    $.src_url    = "https://github.com/eternal-io/museair",
    $.src_status = HashFamilyInfo::SRC_ACTIVE
);

REGISTER_HASH(
    MuseAir,
    $.desc       = "MuseAir hash v" HASH_ALGORITHM_VERSION " @ 64-bit output",
    $.hash_flags = 0,
    $.impl_flags = FLAG_IMPL_MULTIPLY_64_128
                 | FLAG_IMPL_ROTATE_VARIABLE
                 | FLAG_IMPL_LICENSE_MIT
                 | FLAG_IMPL_LICENSE_APACHE2,
    $.bits = 64,
    $.verification_LE = 0xF154752B,
    $.hashfn_native   = hash<false, false, false>,
    $.hashfn_bswap    = hash<true, false, false>
);
REGISTER_HASH(
    MuseAir_128,
    $.desc       = "MuseAir hash v" HASH_ALGORITHM_VERSION " @ 128-bit output",
    $.hash_flags = 0,
    $.impl_flags = FLAG_IMPL_MULTIPLY_64_128
                 | FLAG_IMPL_ROTATE_VARIABLE
                 | FLAG_IMPL_LICENSE_MIT
                 | FLAG_IMPL_LICENSE_APACHE2,
    $.bits = 128,
    $.verification_LE = 0x158D5E9B,
    $.hashfn_native   = hash<false, false, true>,
    $.hashfn_bswap    = hash<true, false, true>
);

REGISTER_HASH(
    MuseAir_BFast,
    $.desc       = "MuseAir hash BFast variant v" HASH_ALGORITHM_VERSION " @ 64-bit output",
    $.hash_flags = 0,
    $.impl_flags = FLAG_IMPL_MULTIPLY_64_128
                 | FLAG_IMPL_ROTATE_VARIABLE
                 | FLAG_IMPL_LICENSE_MIT
                 | FLAG_IMPL_LICENSE_APACHE2,
    $.bits = 64,
    $.verification_LE = 0x23E98FFC,
    $.hashfn_native   = hash<false, true, false>,
    $.hashfn_bswap    = hash<true, true, false>
);
REGISTER_HASH(
    MuseAir_BFast_128,
    $.desc       = "MuseAir hash BFast variant v" HASH_ALGORITHM_VERSION " @ 128-bit output",
    $.hash_flags = 0,
    $.impl_flags = FLAG_IMPL_MULTIPLY_64_128
                 | FLAG_IMPL_ROTATE_VARIABLE
                 | FLAG_IMPL_LICENSE_MIT
                 | FLAG_IMPL_LICENSE_APACHE2,
    $.bits = 128,
    $.verification_LE = 0x3032E8B3,
    $.hashfn_native   = hash<false, true, true>,
    $.hashfn_bswap    = hash<true, true, true>
);

// Maintaining verification value annoys me. Leave it until v0.3 is ready.
