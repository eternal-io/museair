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

#define HASH_ALGORITHM_VERSION "0.2"
#define HASH_ALGORITHM_BFAST_VERSION "0.2"

static const uint64_t DEFAULT_SECRET[6] = {
    UINT64_C(0x5ae31e589c56e17a), UINT64_C(0x96d7bb04e64f6da9), UINT64_C(0x7ab1006b26f9eb64),
    UINT64_C(0x21233394220b8457), UINT64_C(0x047cb9557c9f3b43), UINT64_C(0xd24f2590c0bcee28),
};
static const uint64_t INIT_RING_PREV = UINT64_C(0x33ea8f71bb6016d8);

#define seg(N) N * 8

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
    // For short inputs, refer to rapidhash, MuseAir has no much different from that.
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

template <bool blindfast>
static FORCE_INLINE void _frac_6(uint64_t* state_p, uint64_t* state_q, const uint64_t input_p, const uint64_t input_q) {
    uint64_t lo, hi;
    if (!blindfast) {
        *state_p ^= input_p;
        *state_q ^= input_q;
        MathMult::mult64_128(lo, hi, *state_p, *state_q);
        *state_p ^= lo;
        *state_q ^= hi;
    } else {
        MathMult::mult64_128(lo, hi, *state_p ^ input_p, *state_q ^ input_q);
        *state_p = lo;
        *state_q = hi;
    }
}
template <bool blindfast>
static FORCE_INLINE void _frac_3(uint64_t* state_p, uint64_t* state_q, const uint64_t input) {
    uint64_t lo, hi;
    if (!blindfast) {
        *state_q ^= input;
        MathMult::mult64_128(lo, hi, *state_p, *state_q);
        *state_p ^= lo;
        *state_q ^= hi;
    } else {
        MathMult::mult64_128(lo, hi, *state_p, *state_q ^ input);
        *state_p = lo;
        *state_q = hi;
    }
}
static FORCE_INLINE void _chixx(uint64_t* t, uint64_t* u, uint64_t* v) {
    uint64_t x = ~*u & *v;
    uint64_t y = ~*v & *t;
    uint64_t z = ~*t & *u;
    *t ^= x;
    *u ^= y;
    *v ^= z;
}

template <bool bswap, bool blindfast>
static FORCE_INLINE void _tower_layer_12(uint64_t* state, const uint8_t* p, uint64_t* ring_prev) {
    uint64_t lo0, lo1, lo2, lo3, lo4, lo5;
    uint64_t hi0, hi1, hi2, hi3, hi4, hi5;
    if (!blindfast) {
        state[0] ^= read_u64<bswap>(p + seg(0));
        state[1] ^= read_u64<bswap>(p + seg(1));
        MathMult::mult64_128(lo0, hi0, state[0], state[1]);
        state[0] += *ring_prev ^ hi0;

        state[1] ^= read_u64<bswap>(p + seg(2));
        state[2] ^= read_u64<bswap>(p + seg(3));
        MathMult::mult64_128(lo1, hi1, state[1], state[2]);
        state[1] += lo0 ^ hi1;

        state[2] ^= read_u64<bswap>(p + seg(4));
        state[3] ^= read_u64<bswap>(p + seg(5));
        MathMult::mult64_128(lo2, hi2, state[2], state[3]);
        state[2] += lo1 ^ hi2;

        state[3] ^= read_u64<bswap>(p + seg(6));
        state[4] ^= read_u64<bswap>(p + seg(7));
        MathMult::mult64_128(lo3, hi3, state[3], state[4]);
        state[3] += lo2 ^ hi3;

        state[4] ^= read_u64<bswap>(p + seg(8));
        state[5] ^= read_u64<bswap>(p + seg(9));
        MathMult::mult64_128(lo4, hi4, state[4], state[5]);
        state[4] += lo3 ^ hi4;

        state[5] ^= read_u64<bswap>(p + seg(10));
        state[0] ^= read_u64<bswap>(p + seg(11));
        MathMult::mult64_128(lo5, hi5, state[5], state[0]);
        state[5] += lo4 ^ hi5;
    } else {
        state[0] ^= read_u64<bswap>(p + seg(0));
        state[1] ^= read_u64<bswap>(p + seg(1));
        MathMult::mult64_128(lo0, hi0, state[0], state[1]);
        state[0] = *ring_prev ^ hi0;

        state[1] ^= read_u64<bswap>(p + seg(2));
        state[2] ^= read_u64<bswap>(p + seg(3));
        MathMult::mult64_128(lo1, hi1, state[1], state[2]);
        state[1] = lo0 ^ hi1;

        state[2] ^= read_u64<bswap>(p + seg(4));
        state[3] ^= read_u64<bswap>(p + seg(5));
        MathMult::mult64_128(lo2, hi2, state[2], state[3]);
        state[2] = lo1 ^ hi2;

        state[3] ^= read_u64<bswap>(p + seg(6));
        state[4] ^= read_u64<bswap>(p + seg(7));
        MathMult::mult64_128(lo3, hi3, state[3], state[4]);
        state[3] = lo2 ^ hi3;

        state[4] ^= read_u64<bswap>(p + seg(8));
        state[5] ^= read_u64<bswap>(p + seg(9));
        MathMult::mult64_128(lo4, hi4, state[4], state[5]);
        state[4] = lo3 ^ hi4;

        state[5] ^= read_u64<bswap>(p + seg(10));
        state[0] ^= read_u64<bswap>(p + seg(11));
        MathMult::mult64_128(lo5, hi5, state[5], state[0]);
        state[5] = lo4 ^ hi5;
    }
    *ring_prev = lo5;
}
template <bool bswap, bool blindfast>
static FORCE_INLINE void _tower_layer_6(uint64_t* state, const uint8_t* p) {
    _frac_6<blindfast>(&state[0], &state[1], read_u64<bswap>(p + seg(0)), read_u64<bswap>(p + seg(1)));
    _frac_6<blindfast>(&state[2], &state[3], read_u64<bswap>(p + seg(2)), read_u64<bswap>(p + seg(3)));
    _frac_6<blindfast>(&state[4], &state[5], read_u64<bswap>(p + seg(4)), read_u64<bswap>(p + seg(5)));
}
template <bool bswap, bool blindfast>
static FORCE_INLINE void _tower_layer_3(uint64_t* state, const uint8_t* p) {
    _frac_3<blindfast>(&state[0], &state[3], read_u64<bswap>(p + seg(0)));
    _frac_3<blindfast>(&state[1], &state[4], read_u64<bswap>(p + seg(1)));
    _frac_3<blindfast>(&state[2], &state[5], read_u64<bswap>(p + seg(2)));
}
template <bool bswap>
static FORCE_INLINE void
_tower_layer_0(uint64_t* state, const uint8_t* p, size_t q, size_t len, uint64_t* i, uint64_t* j, uint64_t* k) {
    if (q <= seg(2)) {
        uint64_t i_, j_;
        read_short<bswap>(p, q, &i_, &j_);
        *i = i_;
        *j = j_;
        *k = 0;
    } else {
        *i = read_u64<bswap>(p);
        *j = read_u64<bswap>(p + seg(1));
        *k = read_u64<bswap>(p + q - seg(1));
    }

    if (len >= seg(3)) {
        _chixx(&state[0], &state[2], &state[4]);
        _chixx(&state[1], &state[3], &state[5]);
        *i ^= state[0] + state[1];
        *j ^= state[2] + state[3];
        *k ^= state[4] + state[5];
    } else {
        *i ^= state[0];
        *j ^= state[1];
        *k ^= state[2];
    }
}
template <bool blindfast>
static FORCE_INLINE void _tower_layer_x(const size_t tot_len, uint64_t* i, uint64_t* j, uint64_t* k) {
    // 首先，`tower_loong`不得内联，否则对于所有大小的输入都会变慢。
    // 这个函数如果放在`tower_loong`里，那么对于 bulk 而言总是能够提速 ~1 GiB/s。
    // 这个函数如果放在`epi_loong_*`里，那么对小于 16-bytes 的 key 而言会慢 ~2 cyc，对大于 16-bytes 的 key 而言会快 ~3 cyc。
    // 目前 MuseAir 最大的亮点是对 bulk 的处理速度，所以这个函数应该放在`tower_loong`里。
    // 这些特性可能是机器特定的，或与缓存性能相关。但我想，不论如何，想办法让`tower_short`能够处理更长的 key 才是最好的解决方案。
    int rot = tot_len & 63;
    uint64_t lo0, lo1, lo2;
    uint64_t hi0, hi1, hi2;
    _chixx(i, j, k);
    *i = ROTL64(*i, rot);
    *j = ROTR64(*j, rot);
    *k ^= tot_len;
    if (!blindfast) {
        MathMult::mult64_128(lo0, hi0, *i ^ DEFAULT_SECRET[3], *j);
        MathMult::mult64_128(lo1, hi1, *j ^ DEFAULT_SECRET[4], *k);
        MathMult::mult64_128(lo2, hi2, *k ^ DEFAULT_SECRET[5], *i);
        *i ^= lo0 ^ hi2;
        *j ^= lo1 ^ hi0;
        *k ^= lo2 ^ hi1;
    } else {
        MathMult::mult64_128(lo0, hi0, *i, *j);
        MathMult::mult64_128(lo1, hi1, *j, *k);
        MathMult::mult64_128(lo2, hi2, *k, *i);
        *i = lo0 ^ hi2;
        *j = lo1 ^ hi0;
        *k = lo2 ^ hi1;
    }
}

template <bool bswap, bool blindfast>
static NEVER_INLINE void tower_loong(const uint8_t* bytes,
                                     const size_t len,
                                     const seed_t seed,
                                     uint64_t* i,
                                     uint64_t* j,
                                     uint64_t* k) {
    const uint8_t* p = bytes;
    size_t q = len;

    uint64_t state[6] = {DEFAULT_SECRET[0] + seed, DEFAULT_SECRET[1] - seed, DEFAULT_SECRET[2] ^ seed,
                         DEFAULT_SECRET[3],        DEFAULT_SECRET[4],        DEFAULT_SECRET[5]};

    if (q >= seg(12)) {
        state[3] += seed;
        state[4] -= seed;
        state[5] ^= seed;
        uint64_t ring_prev = INIT_RING_PREV;
        do {
            _tower_layer_12<bswap, blindfast>(&state[0], p, &ring_prev);
            p += seg(12);
            q -= seg(12);
        } while (likely(q >= seg(12)));
        state[0] ^= ring_prev;
    }

    if (q >= seg(6)) {
        _tower_layer_6<bswap, blindfast>(&state[0], p);
        p += seg(6);
        q -= seg(6);
    }

    if (q >= seg(3)) {
        _tower_layer_3<bswap, blindfast>(&state[0], p);
        p += seg(3);
        q -= seg(3);
    }

    _tower_layer_0<bswap>(&state[0], p, q, len, i, j, k);
    _tower_layer_x<blindfast>(len, i, j, k);
}

template <bool bswap>
static FORCE_INLINE void tower_short(const uint8_t* bytes,
                                     const size_t len,
                                     const seed_t seed,
                                     uint64_t* i,
                                     uint64_t* j) {
    uint64_t lo, hi;
    read_short<bswap>(bytes, len, i, j);
    MathMult::mult64_128(lo, hi, seed ^ DEFAULT_SECRET[0], len ^ DEFAULT_SECRET[1]);
    *i ^= lo ^ len;
    *j ^= hi ^ seed;
}

static FORCE_INLINE void epi_short(uint64_t* i, uint64_t* j) {
    uint64_t lo, hi;
    *i ^= DEFAULT_SECRET[2];
    *j ^= DEFAULT_SECRET[3];
    MathMult::mult64_128(lo, hi, *i, *j);
    *i ^= lo ^ DEFAULT_SECRET[4];
    *j ^= hi ^ DEFAULT_SECRET[5];
    MathMult::mult64_128(lo, hi, *i, *j);
    *i ^= *j ^ lo ^ hi;
}
template <bool blindfast>
static FORCE_INLINE void epi_short_128(uint64_t* i, uint64_t* j) {
    uint64_t lo0, lo1;
    uint64_t hi0, hi1;
    if (!blindfast) {
        MathMult::mult64_128(lo0, hi0, *i ^ DEFAULT_SECRET[2], *j);
        MathMult::mult64_128(lo1, hi1, *i, *j ^ DEFAULT_SECRET[3]);
        *i ^= lo0 ^ hi1;
        *j ^= lo1 ^ hi0;
        MathMult::mult64_128(lo0, hi0, *i ^ DEFAULT_SECRET[4], *j);
        MathMult::mult64_128(lo1, hi1, *i, *j ^ DEFAULT_SECRET[5]);
        *i ^= lo0 ^ hi1;
        *j ^= lo1 ^ hi0;
    } else {
        MathMult::mult64_128(lo0, hi0, *i, *j);
        MathMult::mult64_128(lo1, hi1, *i ^ DEFAULT_SECRET[2], *j ^ DEFAULT_SECRET[3]);
        *i = lo0 ^ hi1;
        *j = lo1 ^ hi0;
        MathMult::mult64_128(lo0, hi0, *i, *j);
        MathMult::mult64_128(lo1, hi1, *i ^ DEFAULT_SECRET[4], *j ^ DEFAULT_SECRET[5]);
        *i = lo0 ^ hi1;
        *j = lo1 ^ hi0;
    }
}

template <bool blindfast>
static FORCE_INLINE void epi_loong(uint64_t* i, uint64_t* j, uint64_t* k) {
    uint64_t lo0, lo1, lo2;
    uint64_t hi0, hi1, hi2;
    if (!blindfast) {
        MathMult::mult64_128(lo0, hi0, *i ^ DEFAULT_SECRET[0], *j);
        MathMult::mult64_128(lo1, hi1, *j ^ DEFAULT_SECRET[1], *k);
        MathMult::mult64_128(lo2, hi2, *k ^ DEFAULT_SECRET[2], *i);
        *i ^= lo0 ^ hi2;
        *j ^= lo1 ^ hi0;
        *k ^= lo2 ^ hi1;
    } else {
        MathMult::mult64_128(lo0, hi0, *i, *j);
        MathMult::mult64_128(lo1, hi1, *j, *k);
        MathMult::mult64_128(lo2, hi2, *k, *i);
        *i = lo0 ^ hi2;
        *j = lo1 ^ hi0;
        *k = lo2 ^ hi1;
    }
    *i += *j + *k;
}
template <bool blindfast>
static FORCE_INLINE void epi_loong_128(uint64_t* i, uint64_t* j, uint64_t* k) {
    uint64_t lo0, lo1, lo2;
    uint64_t hi0, hi1, hi2;
    if (!blindfast) {
        MathMult::mult64_128(lo0, hi0, *i ^ DEFAULT_SECRET[0], *j);
        MathMult::mult64_128(lo1, hi1, *j ^ DEFAULT_SECRET[1], *k);
        MathMult::mult64_128(lo2, hi2, *k ^ DEFAULT_SECRET[2], *i);
        *i ^= lo0 ^ lo1 ^ hi2;  // `k` already mixed in via `_chixx`.
        *j ^= hi0 ^ hi1 ^ lo2;
    } else {
        MathMult::mult64_128(lo0, hi0, *i, *j);
        MathMult::mult64_128(lo1, hi1, *j, *k);
        MathMult::mult64_128(lo2, hi2, *k, *i);
        *i = lo0 ^ lo1 ^ hi2;
        *j = hi0 ^ hi1 ^ lo2;
    }
}

template <bool bswap, bool blindfast>
static inline void hash(const void* bytes, const size_t len, const seed_t seed, void* out) {
    uint64_t i, j, k;
    if (likely(len <= 16)) {
        tower_short<bswap>((const uint8_t*)bytes, len, seed, &i, &j);
        epi_short(&i, &j);
    } else {
        tower_loong<bswap, blindfast>((const uint8_t*)bytes, len, seed, &i, &j, &k);
        epi_loong<blindfast>(&i, &j, &k);
    }
    if (isLE()) {
        PUT_U64<false>(i, (uint8_t*)out, 0);
    } else {
        PUT_U64<true>(i, (uint8_t*)out, 0);
    }
}
template <bool bswap, bool blindfast>
static inline void hash_128(const void* bytes, const size_t len, const seed_t seed, void* out) {
    uint64_t i, j, k;
    if (likely(len <= 16)) {
        tower_short<bswap>((const uint8_t*)bytes, len, seed, &i, &j);
        epi_short_128<blindfast>(&i, &j);
    } else {
        tower_loong<bswap, blindfast>((const uint8_t*)bytes, len, seed, &i, &j, &k);
        epi_loong_128<blindfast>(&i, &j, &k);
    }
    if (isLE()) {
        PUT_U64<false>(i, (uint8_t*)out, 0);
        PUT_U64<false>(j, (uint8_t*)out, 8);
    } else {
        PUT_U64<true>(i, (uint8_t*)out, 0);
        PUT_U64<true>(j, (uint8_t*)out, 8);
    }
}

// --------------------------------------------------------------------------------
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
    $.verification_LE = 0x46B2D34D,
    $.verification_BE = 0xE2A5BB5A,
    $.hashfn_native   = hash<false, false>,
    $.hashfn_bswap    = hash<true, false>
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
    $.verification_LE = 0xCABAA4CD,
    $.verification_BE = 0x0C85AD17,
    $.hashfn_native   = hash_128<false, false>,
    $.hashfn_bswap    = hash_128<true, false>
);

REGISTER_HASH(
    MuseAir_BFast,
    $.desc       = "MuseAir hash BFast variant v" HASH_ALGORITHM_BFAST_VERSION " @ 64-bit output",
    $.hash_flags = 0,
    $.impl_flags = FLAG_IMPL_MULTIPLY_64_128
                 | FLAG_IMPL_ROTATE_VARIABLE
                 | FLAG_IMPL_LICENSE_MIT
                 | FLAG_IMPL_LICENSE_APACHE2,
    $.bits = 64,
    $.verification_LE = 0x98CDFE3E,
    $.verification_BE = 0x06E465A0,
    $.hashfn_native   = hash<false, true>,
    $.hashfn_bswap    = hash<true, true>
);
REGISTER_HASH(
    MuseAir_BFast_128,
    $.desc       = "MuseAir hash BFast variant v" HASH_ALGORITHM_BFAST_VERSION " @ 128-bit output",
    $.hash_flags = 0,
    $.impl_flags = FLAG_IMPL_MULTIPLY_64_128
                 | FLAG_IMPL_ROTATE_VARIABLE
                 | FLAG_IMPL_LICENSE_MIT
                 | FLAG_IMPL_LICENSE_APACHE2,
    $.bits = 128,
    $.verification_LE = 0x81D30B6E,
    $.verification_BE = 0xF659322A,
    $.hashfn_native   = hash_128<false, true>,
    $.hashfn_bswap    = hash_128<true, true>
);
