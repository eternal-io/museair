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

static bool base_selftest(void (*hash_function)(const void*, const size_t, seed_t, void*),
                          const uint64_t* expected,
                          const size_t len,
                          const size_t stripe) {
    uint8_t* bytes = new uint8_t[len];
    memset(&bytes[0], 0xAB, len);
    uint8_t digest[16];
    for (size_t i = 0; i < len / stripe; i += stripe) {
        hash_function(&bytes[0], i, 0, &digest[0]);
        for (size_t j = 0; j < stripe; j++) {
            uint64_t seg;
            if (isLE()) {
                seg = GET_U64<false>(&digest[j * 8], 0);
            } else {
                seg = GET_U64<true>(&digest[j * 8], 0);
            }
            if (seg != expected[i * stripe + j]) {
                delete[] bytes;
                printf("Unexpected hash result for bytes array `[0xAB; %zu]`!!\n", i);
                return false;
            }
        }
    }
    delete[] bytes;
    return true;
}
static bool hash_selftest() {
    // clang-format off
    const int stripe = 1;
    uint64_t expected[] = {
        UINT64_C(0x0b6d39af88433ee6), UINT64_C(0x9cc00eea41bd3bc9), UINT64_C(0x32b27bb7bb9f736a), UINT64_C(0x4feb8452bd56e235), UINT64_C(0xa5114a825618597c), UINT64_C(0x0bdef0a3ea34a1a6), UINT64_C(0x956881a26db0cf30), UINT64_C(0x2990f2b2e70c7d05), UINT64_C(0x07d1c1d80535f006), UINT64_C(0xe86d73ddb3754d7c),
        UINT64_C(0x31fa0d6e44a0f27e), UINT64_C(0x5013736ed17cbc5e), UINT64_C(0x69cc4eb7af802701), UINT64_C(0x4b1091c1d43ab72c), UINT64_C(0x216c965fc9ab9751), UINT64_C(0xc18056db002f3bbc), UINT64_C(0xa8aa59e62173ed5d), UINT64_C(0x4373103b94387939), UINT64_C(0xde99771e9bbd8d4c), UINT64_C(0xc7c381341387c5fe),
        UINT64_C(0x90b57f4f1c69c5a7), UINT64_C(0xecf7fa79cb53429b), UINT64_C(0xcff4bfdab0f71f1e), UINT64_C(0xe140d89a0ff60541), UINT64_C(0x8a19c7f2f6b7bd61), UINT64_C(0x474598eb56bd2aeb), UINT64_C(0x79f275aa8bf11687), UINT64_C(0xd5cf4b1e78f89c0e), UINT64_C(0xac3a38a616c8915c), UINT64_C(0x797bb417a3babafe),
        UINT64_C(0xc0ad6a59cafbc53b), UINT64_C(0x4422fdc8d2a69cda), UINT64_C(0x16fd16590ff35926), UINT64_C(0xd71e0ba325bae5c4), UINT64_C(0xe2b7be25a0aae8da), UINT64_C(0x046d5d46126d073d), UINT64_C(0x810f5b449ede45fe), UINT64_C(0x887b27b975632388), UINT64_C(0xc49aac01b4356752), UINT64_C(0x5600c945ea8879c5),
        UINT64_C(0x44769c263bc51c7f), UINT64_C(0xce5c5f515d74bf6c), UINT64_C(0x71618f721452e5b1), UINT64_C(0xa8c8b07b7adef460), UINT64_C(0xd836ea88450d9baf), UINT64_C(0xb4f219fec42c4191), UINT64_C(0x9c3cef0e3b8e98f4), UINT64_C(0x91082be3b45729b2), UINT64_C(0x93ed7bd9a8d36eea), UINT64_C(0x35b244af83f67a31),
        UINT64_C(0x106e71fb71e4b5ea), UINT64_C(0x8d1af305ffde3421), UINT64_C(0xbe531e4932b96f36), UINT64_C(0x9df6da515dfcd450), UINT64_C(0x1daab0778e5d984a), UINT64_C(0x67d4120e933cb3b5), UINT64_C(0xdad7a58655531478), UINT64_C(0xc2ff34ad10282834), UINT64_C(0xa0011cef8b776acb), UINT64_C(0x5229868a14c856ef),
        UINT64_C(0x0570225833d90c84), UINT64_C(0xf5e06cc158c5a432), UINT64_C(0x95569d58b1de557f), UINT64_C(0xde7aa3a4c3e70c5d), UINT64_C(0x25cc5b90a027e55c), UINT64_C(0x2e04d82214d8ee43), UINT64_C(0xd02a2ede714419b8), UINT64_C(0x148443abe1bc757d), UINT64_C(0xe029ba152ddc730f), UINT64_C(0x6f5a394519dc5e54),
        UINT64_C(0xd54b2fd27e6be0b2), UINT64_C(0xf5b84e22530f6688), UINT64_C(0x57963c7346ea2353), UINT64_C(0x5715fc0c0917d7b6), UINT64_C(0x5f017ca00fac2f89), UINT64_C(0x3344fb798b726bcd), UINT64_C(0x3a9ff40746656206), UINT64_C(0x881e2c878a94b333), UINT64_C(0xd02cf90c6eb96976), UINT64_C(0x5d0e5d28a6324c4f),
        UINT64_C(0x28fa1744fd995e3e), UINT64_C(0x1e0a4ae1444fa083), UINT64_C(0x60a55c6d5bbc2e7a), UINT64_C(0xac10edea386252cb), UINT64_C(0x79cb84af3a9d545a), UINT64_C(0x006e2d57351e6640), UINT64_C(0xeec9fd7a41925a70), UINT64_C(0x0b052945cce0f715), UINT64_C(0x729dd450d1a009e7), UINT64_C(0x15ad5c4f271b1498),
        UINT64_C(0xe8b7cc8ccf647f81), UINT64_C(0x76fb1916a3d8f1bc), UINT64_C(0x5b9490c401bb1aa9), UINT64_C(0xa9d5018ac77afb14), UINT64_C(0xe401b269b091a67b), UINT64_C(0xd29a938f15e10c69), UINT64_C(0x883817996fb97020), UINT64_C(0x6d25ba0149938550), UINT64_C(0x3b251625aaa5dae1), UINT64_C(0xe13e1433d0d37e76),
        UINT64_C(0x9061b9682d20bf25), UINT64_C(0xfd52b41cca311b3f), UINT64_C(0xaf27913c70e55474), UINT64_C(0x3c2cba85c85d918c), UINT64_C(0xbf31a47e6ee1e8d2), UINT64_C(0x65985a82a3e412a7), UINT64_C(0x0cdca9cda47c7d74), UINT64_C(0xaa047b5dd0feac60), UINT64_C(0x4c63b05d1b17e834), UINT64_C(0x37ff6ed87810d587),
        UINT64_C(0xd05c5b008a3da500), UINT64_C(0x0bb5d32d6b80e6f6), UINT64_C(0x6a353fbef065631e), UINT64_C(0x70418e1878a519c5), UINT64_C(0xa23b42432f4a0e7c), UINT64_C(0x55908aee6ec2471a), UINT64_C(0x6e29ad311d0c039c), UINT64_C(0x979bfc2ae961b9b7), UINT64_C(0xd08a19e9658d56fc), UINT64_C(0x0319c861c157ee31),
        UINT64_C(0xe68f99dd83fee865), UINT64_C(0xedd922733236650a), UINT64_C(0x62fd38e95fc39ca1), UINT64_C(0xcc022a4cdc495f7c), UINT64_C(0x3f93691daef7d612), UINT64_C(0xcadea7461ea5198d), UINT64_C(0xc5cba273c3005193), UINT64_C(0x87a7499b259360c4), UINT64_C(0x20770edff90ccf64), UINT64_C(0x36ebc4b5e494d671),
        UINT64_C(0xf35f2e1f4101e943), UINT64_C(0xf1b19c5c6d0d1783), UINT64_C(0xe0d5835d7fda9c29), UINT64_C(0x8600e0b26e87ca59), UINT64_C(0x6bb5e20ad197b591), UINT64_C(0x1b3f795851f6e760), UINT64_C(0xa56749a88ae64a3d), UINT64_C(0xb3000dcef0e4693d), UINT64_C(0x3c25270d129d952c), UINT64_C(0x5fe27b6f5dbb2a2a),
        UINT64_C(0x03af431fcba272ae), UINT64_C(0xb9afd6946dd9bc6d), UINT64_C(0xc7da40e06ca6f656), UINT64_C(0xec64fca3ae5e3704), UINT64_C(0x656cf372d990caf7), UINT64_C(0x03e58a2afd46198b), UINT64_C(0xe70ff8e867eee089), UINT64_C(0x05bb6ac84e1e7d08), UINT64_C(0xff3d3c2dff5ef23a), UINT64_C(0x4c4cf6465f5c1643),
        UINT64_C(0x168a500bf56ffa05), UINT64_C(0x41c2b5a2d3574bb5), UINT64_C(0xa1b868f2663a0a0f), UINT64_C(0xef122f010e71d4b3), UINT64_C(0x70d0072ae39e5222), UINT64_C(0xbae7466760eddd47), UINT64_C(0xed52313d88559aab), UINT64_C(0x200edc42416cde9c), UINT64_C(0x8d28ac3005e50a57), UINT64_C(0xcf830a27ce8f03a5),
        UINT64_C(0xb7124e7e8cd7914b), UINT64_C(0x54dd44e32ee41af9), UINT64_C(0xd5608193f75353b9), UINT64_C(0xf0dcda47d16a4cf9), UINT64_C(0xc19f2971120466ac), UINT64_C(0xcd385d1a237580ac), UINT64_C(0x6cc6bc17eccd2487), UINT64_C(0x01fd83e8a58b6c0f), UINT64_C(0xecd9d0ca24a03780), UINT64_C(0xe84dec6f27d762b1),
        UINT64_C(0x36a54eac0d6db1ce), UINT64_C(0x61261987c6f96a6f), UINT64_C(0xa623f7b12ee1db55), UINT64_C(0x64164064b4d06f53), UINT64_C(0xffec3687ddbbbb38), UINT64_C(0xfa342281291ae94b), UINT64_C(0x50b6fc812193c0b1), UINT64_C(0xe20ca499aead2dd1), UINT64_C(0x3de464e3a6ad761f), UINT64_C(0x0a2a66ee137b6a53),
        UINT64_C(0x1285acdee14adf20), UINT64_C(0xd3b61f73e8dbf7ce), UINT64_C(0xcf4f3e4ad56dd560), UINT64_C(0x0e6d9f0ca6e5b87a), UINT64_C(0x9845cc3bee70b0b1), UINT64_C(0xe0dc0633035d3c20), UINT64_C(0x7609981f49ffdbc0), UINT64_C(0xe7be2ec3c4704cb0), UINT64_C(0xd3bcecdf0370c5b0), UINT64_C(0xf23e37e9bae6f609),
        UINT64_C(0xad582d409cba1c16), UINT64_C(0x381a4dbb0b675792), UINT64_C(0x71e379de8107157a), UINT64_C(0x8a1f6e28058c5f3c), UINT64_C(0xed7c2ba7e7a751a6), UINT64_C(0x0d665751df9f4275), UINT64_C(0xe7f83a916d3369c8), UINT64_C(0x402650585a8ec912), UINT64_C(0x0e4cb5cb030f8675), UINT64_C(0x457716ad2e5ca034),
    };
    // clang-format on
    if (isLE()) {
        return base_selftest(hash<false, false>, &expected[0], sizeof(expected) / sizeof(expected[0]), stripe);
    } else {
        return base_selftest(hash<true, false>, &expected[0], sizeof(expected) / sizeof(expected[0]), stripe);
    }
}
static bool hash_128_selftest() {
    // clang-format off
    const int stripe = 2;
    uint64_t expected[] = {
        UINT64_C(0x881dd5945be152c9), UINT64_C(0xebf383f81508a6f4), UINT64_C(0xc067c23663b6b5c3), UINT64_C(0xb726c94cba19391d), UINT64_C(0x59a219f6f2b97dbd), UINT64_C(0x325d07ccad00839f), UINT64_C(0x50030dff83d55547), UINT64_C(0xd2127ff17a7d6f87), UINT64_C(0x5751e4a9843313c1), UINT64_C(0x96b9ce52a2f325c4), UINT64_C(0x3b905b0868c84294), UINT64_C(0x21c0fbf55c21fd7e), UINT64_C(0x11d521d2b4224dcc), UINT64_C(0xc707e581d691e371), UINT64_C(0x29c5e75f31b83ab6), UINT64_C(0xa69b7a290ab73189), UINT64_C(0x4985e1755f9e3808), UINT64_C(0xcf3d172cee861a28), UINT64_C(0x1d3483b785305ec2), UINT64_C(0x8bf378fee653b327),
        UINT64_C(0xb2d0ff7179fccf45), UINT64_C(0x5fc15615e9eb7ca8), UINT64_C(0x5955038b824b4d3d), UINT64_C(0xbb9f187ab4698698), UINT64_C(0xfe07ca36b022eecd), UINT64_C(0x9414fbfccdf5328b), UINT64_C(0x0aee9bf705be28fd), UINT64_C(0xba9c5035e3de21aa), UINT64_C(0x3be4df79d5753c68), UINT64_C(0xb4e8e0b3cc4b0ea9), UINT64_C(0x455b6ffe2eda72de), UINT64_C(0x2ff3de7a9a5af187), UINT64_C(0x3084e7740c21ac43), UINT64_C(0xbdfc8ef937c4a0fd), UINT64_C(0x8476510e1279e2a5), UINT64_C(0x0f8d7255ca5310e4), UINT64_C(0xbf38996719368bc4), UINT64_C(0x559f911c0cdd011d), UINT64_C(0xe245ed39a23bc141), UINT64_C(0x4ca0bbd60fcc782d),
        UINT64_C(0x5386c3f220d04b6e), UINT64_C(0x389eccc620e04abb), UINT64_C(0x2deaef611d1b03b7), UINT64_C(0x532560a76d15fca4), UINT64_C(0x51866728ebf1e02e), UINT64_C(0x0af2c1f319a1624e), UINT64_C(0x3c77c229a49d1029), UINT64_C(0x91a12536d6d55dbb), UINT64_C(0xb3cf422093b515a7), UINT64_C(0x39a78ce99784d5cf), UINT64_C(0xe8068bdfd379f50e), UINT64_C(0x9d935a362b7e3ccb), UINT64_C(0x5e24697e491e371a), UINT64_C(0x58218afbfdef01ab), UINT64_C(0x2692794bfa7612e9), UINT64_C(0xbef1e2d8cd0eaa5a), UINT64_C(0x25322c158774a9a4), UINT64_C(0x929be0ddeb3fa8fa), UINT64_C(0x481e7f514d64242b), UINT64_C(0xf93a7068c3fc7409),
        UINT64_C(0x90c9aee8ccbd578b), UINT64_C(0xa15498b10744829d), UINT64_C(0x44aae4095c384254), UINT64_C(0x73a6eb425da7bed0), UINT64_C(0xee1a745df8b34331), UINT64_C(0x365bb35c22599091), UINT64_C(0xa7b9746722459c1b), UINT64_C(0x9089e0b39f2f4f36), UINT64_C(0xc66e8b1444bb9002), UINT64_C(0x9907dc9c75423a85), UINT64_C(0x7881ebb1da5d6d28), UINT64_C(0x79f8b31d1afe58d1), UINT64_C(0x00f358f0e71afdd3), UINT64_C(0x337a15be55ba16ba), UINT64_C(0xb54820a63a4db854), UINT64_C(0x17ef3060061a4185), UINT64_C(0x7bfd802937cc8045), UINT64_C(0xa3db5a00f03eec33), UINT64_C(0x336074ca00c78f91), UINT64_C(0xd3ea97153d73751a),
        UINT64_C(0xc7c7309dbed0e3a6), UINT64_C(0x165a893fd97c5cab), UINT64_C(0x10f680d01bb06b31), UINT64_C(0x42fee43b319e114a), UINT64_C(0x5b97969540230156), UINT64_C(0xa5779d8268fa2b3f), UINT64_C(0x6a1cb8db984c9dcb), UINT64_C(0x3adf42c18bf1b5ef), UINT64_C(0x11bd65c126531290), UINT64_C(0xb2f96fc99093174d), UINT64_C(0xb091db751c950e4e), UINT64_C(0x2ffc2f769921faca), UINT64_C(0x8ea387f847a3b889), UINT64_C(0x31a435e1d44a2ecb), UINT64_C(0x83ad6e3103345b9b), UINT64_C(0x90f676d26601568a), UINT64_C(0x0c8cf0e3536749e3), UINT64_C(0x5ad4fe108f18ca1b), UINT64_C(0xeeaeb1037c4ba6ec), UINT64_C(0xd64b5a7b8af2394b),
        UINT64_C(0xe3ba47e1009e2a47), UINT64_C(0xac3ad91689b32012), UINT64_C(0x22f950488b72d44c), UINT64_C(0xee78f128fee18a18), UINT64_C(0xda4f88d700145ad8), UINT64_C(0x8d7b101fdea07fe3), UINT64_C(0x46745735b69fbae0), UINT64_C(0x80850b1705a91df0), UINT64_C(0xc9d020dcd4c0cdf1), UINT64_C(0xc2d9efc0f2b93b96), UINT64_C(0xec27ba5133ca47d0), UINT64_C(0x048482f701562aa2), UINT64_C(0x11b93f2172b619f8), UINT64_C(0x8df004cfd2b6f9ee), UINT64_C(0x719d4a51e8e41a25), UINT64_C(0x0a71177f74e2b966), UINT64_C(0xeaac9a5b4bd4b983), UINT64_C(0x79efa1844abe4659), UINT64_C(0xb01311ce9f620ecd), UINT64_C(0xc1e2db5d27d192ad),
        UINT64_C(0x38105b2958ce4589), UINT64_C(0xa41686d99c3aaed1), UINT64_C(0x400cc896da95a3ee), UINT64_C(0xa46e7a718d3d4381), UINT64_C(0x7df0706b763a0416), UINT64_C(0x4758ea4507a909ce), UINT64_C(0x33fcd18b6deddd6e), UINT64_C(0xcd2f3d45dda37e0b), UINT64_C(0x9117cf1a7d3b9fe1), UINT64_C(0x6c33d8748ad4644e), UINT64_C(0x1a0ddf646f3afbdf), UINT64_C(0x3cc73045ff7a7112), UINT64_C(0x94def6e5da54b1fc), UINT64_C(0x08624b610e4aabf6), UINT64_C(0x579660e049826893), UINT64_C(0xaa16f645bf7c167e), UINT64_C(0xf4aa00b79aa2457b), UINT64_C(0x74640162c6009400), UINT64_C(0x0fb48e486552181c), UINT64_C(0xa110420d99436b8b),
        UINT64_C(0x6a71d8782396c2fe), UINT64_C(0x3f5484516d8fe546), UINT64_C(0x90463a58ecca708f), UINT64_C(0xafa53696408c7fce), UINT64_C(0x128f529463122a58), UINT64_C(0x75b4867608b2715c), UINT64_C(0x7204b0340569320e), UINT64_C(0x484bb29c0d254d76), UINT64_C(0xf6f1d48809d5b341), UINT64_C(0xfbb9b2a396e6b174), UINT64_C(0x2396b8f522aa57a4), UINT64_C(0x706ecbca8cd3b1cb), UINT64_C(0xe208d0f1ac4624f0), UINT64_C(0x4200421bccd0eeef), UINT64_C(0xd4a8b31a2d46a498), UINT64_C(0x037ac8cce8af1bb7), UINT64_C(0xc3edd3467f5a857e), UINT64_C(0x0ca19ac0111e8ad4), UINT64_C(0x5964c03cc6e0a5bb), UINT64_C(0xb854f7c6508c82f7),
        UINT64_C(0x41bc1fcf700cfa45), UINT64_C(0xfae5613026b9e706), UINT64_C(0xc689b40f7e80406a), UINT64_C(0xb68de4343bcd6dba), UINT64_C(0x5021fc5bda3d2597), UINT64_C(0xdfd8fe7b3085de86), UINT64_C(0xa803e8e1ba362314), UINT64_C(0xcd0f05f68bc39fa9), UINT64_C(0xc23c8b97fa0a2cfc), UINT64_C(0x84ac002bf90b076d), UINT64_C(0x314ea22f4104393a), UINT64_C(0x8f3d427a030105a4), UINT64_C(0xa21673f29ec60f8b), UINT64_C(0xe6fbd10d920a2468), UINT64_C(0x45bcae9bd7904874), UINT64_C(0xdb10cf3b185c4904), UINT64_C(0xb311d378c28ac53d), UINT64_C(0x1c6a22abe09dff05), UINT64_C(0x8dc625302a4076fd), UINT64_C(0x4265eb76ae1fc689),
        UINT64_C(0x23b9e1c76ef72ca6), UINT64_C(0xebe0a1e750dff5f6), UINT64_C(0x401844a64f56fb95), UINT64_C(0x6a24ef2bec678569), UINT64_C(0xa350aaec249fd8b7), UINT64_C(0xc8f0693be63c1d17), UINT64_C(0x81c342778b026c6e), UINT64_C(0x2e469f0eca046a38), UINT64_C(0x124a8a9a0aae46b3), UINT64_C(0xc2fe3ca0083488a3), UINT64_C(0x177f88c2343bd9f4), UINT64_C(0xc6f436d7e36dd65a), UINT64_C(0x31808223a73a4b36), UINT64_C(0x4cafa069328deebd), UINT64_C(0xd99cbf464e1abaf0), UINT64_C(0xed618c6ab10c11be), UINT64_C(0x5d483268971025a7), UINT64_C(0xe59de80990c805b7), UINT64_C(0x9169ee83a7ed1a64), UINT64_C(0xccd97a98a4356a91),
        UINT64_C(0x12f1efbd08a89682), UINT64_C(0xa4f70d78a7ad1472), UINT64_C(0xf7d4549a8babf55e), UINT64_C(0xbdd96a0863da93b0), UINT64_C(0x00503e41da508be7), UINT64_C(0x1dcafce6478437ec), UINT64_C(0xd8afe201efb29282), UINT64_C(0x0a250c0142ba56e0), UINT64_C(0x404e58b01f5b2b34), UINT64_C(0xd432ccfd946c664d), UINT64_C(0xd18a1a1f0525dbd8), UINT64_C(0xf72ed37b445e5306), UINT64_C(0x670f92661c7f19d5), UINT64_C(0x561508d9b1121a02), UINT64_C(0xee2d2390b041089e), UINT64_C(0x6583d6519e2cb22a), UINT64_C(0x45e0136043669e07), UINT64_C(0x93db8c8eaf628cc4), UINT64_C(0xbde1e45509b61afd), UINT64_C(0xabb4482e80ca20ea),
        UINT64_C(0x9f3c3dced1a4c363), UINT64_C(0x4cba9ba69bdcbce8), UINT64_C(0xe982764ac2ae683b), UINT64_C(0xd87bdf7d82710f76), UINT64_C(0x3891790b3565c613), UINT64_C(0x6e1a0330ca4f4cfe), UINT64_C(0x9ba6ff371fda5d27), UINT64_C(0xaae364aa152973b8), UINT64_C(0xe6cdd5e83bfa43c2), UINT64_C(0x9918e9d15600d62c), UINT64_C(0x367982f6972e80ce), UINT64_C(0x7eb818749b24d476), UINT64_C(0x2be94d25aed2d173), UINT64_C(0x28251c78b3c8e38a), UINT64_C(0x49426d350cc7204d), UINT64_C(0x68d97f645e2d6765), UINT64_C(0x416a23a66b583a05), UINT64_C(0xf8cbb331c838dc7d), UINT64_C(0x8c7d51261e2bacf7), UINT64_C(0x4d344d51004fa05d),
        UINT64_C(0xace65832bb4d1d85), UINT64_C(0xa6f077c3de5d81c2), UINT64_C(0x669e562e321ba45a), UINT64_C(0xfce7cfd2d73cb073), UINT64_C(0x97e842c0c509ad25), UINT64_C(0xcf0515355ff3a04c), UINT64_C(0x65f27c6bafa90d97), UINT64_C(0xfb3e0448cd0b24e4), UINT64_C(0x65a8b539387238ea), UINT64_C(0x2061c2eefc707fba), UINT64_C(0x096a17cef40ef322), UINT64_C(0xc0b22106f04b7af0), UINT64_C(0x4f0ba33d5c6eaa9a), UINT64_C(0x71e6b50c4dc05360), UINT64_C(0x3261bff8a969105c), UINT64_C(0x7d7b45adbce32ba9), UINT64_C(0x598529f77d9e7df3), UINT64_C(0xe0c1095bdb625c8b), UINT64_C(0xad55b130f9473d14), UINT64_C(0x13c9b495ffe0adc2),
        UINT64_C(0x8e4a24eed984ad73), UINT64_C(0xaa145c6b70452711), UINT64_C(0x4e05fb2eb05e11e0), UINT64_C(0x544e3b2bc7d94016), UINT64_C(0x089c313be686c229), UINT64_C(0x6acf567a6dff4612), UINT64_C(0xb9e0f828d3a8456d), UINT64_C(0x5aa59d231b08e830), UINT64_C(0x0c07f260e1c70cc2), UINT64_C(0x3a5956a4fb14b2af), UINT64_C(0xd569b098752c7e27), UINT64_C(0x973bbc3426ac866e), UINT64_C(0x03cb051bff33ab94), UINT64_C(0x33558dadac5c84ee), UINT64_C(0x74ff542d4c8376fb), UINT64_C(0x287c293e779fe8ce), UINT64_C(0xaf1f23e8d77c2dad), UINT64_C(0x75f4103daf403c3a), UINT64_C(0x054af00bbaa130bc), UINT64_C(0x60e9b36426a619b8),
        UINT64_C(0x87be3850566e1575), UINT64_C(0x98b14a48cb194557), UINT64_C(0xff6e3626718ebf81), UINT64_C(0x5df715b7d3232fa7), UINT64_C(0x6bc3a4be9da219dd), UINT64_C(0x8b8ed1098bb91ebe), UINT64_C(0x08901ddbc1ce46e9), UINT64_C(0xea919de6172611ee), UINT64_C(0x6973d832c41a097f), UINT64_C(0x0a04599e222b2a0c), UINT64_C(0x556647f85b95082c), UINT64_C(0x10035351f7a865e2), UINT64_C(0x00dbe17534677079), UINT64_C(0x8c71e0027ceae004), UINT64_C(0xeacf368440173393), UINT64_C(0x700f9c67df40cde2), UINT64_C(0x9a311855608d2ba1), UINT64_C(0xbdeb791e0768a5ae), UINT64_C(0xb1c24cfba937519d), UINT64_C(0x0c010430de07eb34),
        UINT64_C(0x952e7fe9f77eafb0), UINT64_C(0xce79484a2d3d3350), UINT64_C(0x9cc91198b074c9fa), UINT64_C(0x9356cf950c8e0fc2), UINT64_C(0x6552718ee66a76ef), UINT64_C(0x752308bf679e00c2), UINT64_C(0x8f8fedd52658043f), UINT64_C(0x2e9608ed0547aa43), UINT64_C(0x3cd591b22d0546fd), UINT64_C(0x779434465f44a5ac), UINT64_C(0xb34874e99ff97a09), UINT64_C(0x73798aa6daa998d0), UINT64_C(0x326f983ac426ef0e), UINT64_C(0x8f04d94dd1227a2a), UINT64_C(0x93039b028293a051), UINT64_C(0xd2091a44ee88f4ca), UINT64_C(0xd10aeb3169cb79e5), UINT64_C(0x5148c3435029ade7), UINT64_C(0xbc94c182aacfe72d), UINT64_C(0x0a6af4f59d09ee79),
        UINT64_C(0x214fad70b2e2180e), UINT64_C(0xb5f6f3befac3c341), UINT64_C(0x0e858e5c3ccb4ba4), UINT64_C(0x84ec55cb27aea709), UINT64_C(0x7ef26e946f8722fe), UINT64_C(0xbb4cd2daaa03f610), UINT64_C(0xf169d32f185f413c), UINT64_C(0xafde9666c7f98278), UINT64_C(0x9d75cc2ab212c1af), UINT64_C(0x699afa7156a260d0), UINT64_C(0xe12377b4f255709b), UINT64_C(0xf0ff8e0d1ec79aff), UINT64_C(0xc8cea75c1cb43813), UINT64_C(0x0d03eae0d097234d), UINT64_C(0x87ffe852ab56f458), UINT64_C(0x6ef62a40d8e93931), UINT64_C(0x151561abdf9f4666), UINT64_C(0x6b96fe09f378d4b1), UINT64_C(0x45f092dae764df74), UINT64_C(0x287e1a3d0f2e7324),
        UINT64_C(0x3bb3d727a12b6d67), UINT64_C(0xea9d77061f89952b), UINT64_C(0xadf7ef23d098a08f), UINT64_C(0xbb4edd248babec42), UINT64_C(0x6b00142ebf081c54), UINT64_C(0xa0568ccb8466e06a), UINT64_C(0xce88c5fafda97b8a), UINT64_C(0xbaa1c6586d6f616a), UINT64_C(0xa49e005d0c4834d6), UINT64_C(0x219a0584f0eeffdc), UINT64_C(0x173d9b75525f2707), UINT64_C(0x72d45893fcb725e1), UINT64_C(0x59d93dd86b3c8847), UINT64_C(0x96ab5f5175496bd0), UINT64_C(0x337111d981c26273), UINT64_C(0xb8cc57241f1b489b), UINT64_C(0x73ee5d6e27b917af), UINT64_C(0x6a281f0c014a3ac9), UINT64_C(0x488e4985211e14b7), UINT64_C(0xa0b9a46501eff346),
        UINT64_C(0xe3a8ee4b10c73515), UINT64_C(0x409d0a4368cae56b), UINT64_C(0x7f24c08eb8d6c23d), UINT64_C(0x2c41ce665bb70962), UINT64_C(0x4d6c451f1aa75a34), UINT64_C(0xe50774d55a878086), UINT64_C(0x90d98c93637fc84f), UINT64_C(0x415f66b510ee9437), UINT64_C(0x794378c909642882), UINT64_C(0xf7d5c7957f03355f), UINT64_C(0xf74eca5ebcb2d437), UINT64_C(0xdc7f5afdae4be2fd), UINT64_C(0x6de15dc78b360df5), UINT64_C(0x8eeccc59d7e0707c), UINT64_C(0x85acda330641b8db), UINT64_C(0xf557f84297f0ccb6), UINT64_C(0x4775b38083dd809f), UINT64_C(0x8f8ad32127b7ea7c), UINT64_C(0x7ab933aeec45047b), UINT64_C(0x3ef21fa2b2645082),
        UINT64_C(0xee20d2f15c9f0088), UINT64_C(0x0239077f60195d69), UINT64_C(0xf35d7c2496bff68f), UINT64_C(0x3436b893b8a15fbb), UINT64_C(0xd3dc712e69f94ae4), UINT64_C(0xe4c0306aaf8397a7), UINT64_C(0xe1d17c307ec52edc), UINT64_C(0xe961d6d87bd5678c), UINT64_C(0x07c3e79281955adb), UINT64_C(0x33c51e10ff9c530d), UINT64_C(0xfcccb8abd7bb2818), UINT64_C(0x61efbbd142385cb5), UINT64_C(0x277f31ea0c0f4590), UINT64_C(0x2131693c6bad1ec5), UINT64_C(0x053cfa5cec4922a8), UINT64_C(0xe53805f3ba937eb6), UINT64_C(0x16c1cc7889b5858b), UINT64_C(0x67a6bd55ff22345b), UINT64_C(0xf223a3701772d284), UINT64_C(0x58b66b21e91ea418),
    };
    // clang-format on
    if (isLE()) {
        return base_selftest(hash_128<false, false>, &expected[0], sizeof(expected) / sizeof(expected[0]), stripe);
    } else {
        return base_selftest(hash_128<true, false>, &expected[0], sizeof(expected) / sizeof(expected[0]), stripe);
    }
}
static bool hash_bfast_selftest() {
    // clang-format off
    const int stripe = 1;
    uint64_t expected[] = {
        UINT64_C(0x0b6d39af88433ee6), UINT64_C(0x9cc00eea41bd3bc9), UINT64_C(0x32b27bb7bb9f736a), UINT64_C(0x4feb8452bd56e235), UINT64_C(0xa5114a825618597c), UINT64_C(0x0bdef0a3ea34a1a6), UINT64_C(0x956881a26db0cf30), UINT64_C(0x2990f2b2e70c7d05), UINT64_C(0x07d1c1d80535f006), UINT64_C(0xe86d73ddb3754d7c),
        UINT64_C(0x31fa0d6e44a0f27e), UINT64_C(0x5013736ed17cbc5e), UINT64_C(0x69cc4eb7af802701), UINT64_C(0x4b1091c1d43ab72c), UINT64_C(0x216c965fc9ab9751), UINT64_C(0xc18056db002f3bbc), UINT64_C(0xa8aa59e62173ed5d), UINT64_C(0xd1f945707666cb0b), UINT64_C(0x4f843f2ed84831d0), UINT64_C(0xb4f204617908520f),
        UINT64_C(0x761b1ce504ecbc7a), UINT64_C(0x2c9ae95cf08e51e5), UINT64_C(0x9311b23672c4f9a7), UINT64_C(0x3fa807d332331578), UINT64_C(0x7ed8195a6e8d81dd), UINT64_C(0x859c4514fb1ac098), UINT64_C(0x2171ad42e5d9d2b5), UINT64_C(0x4c83c4438d1eda0f), UINT64_C(0x239a7c0e6eed5701), UINT64_C(0xac647c08274c5306),
        UINT64_C(0x58d9d6387c2aa8a0), UINT64_C(0xdcec6dd90d44c2fc), UINT64_C(0x6e2e7d5f32889f94), UINT64_C(0xdedd61d7192e0e70), UINT64_C(0x4b5f3b63c12eb9ef), UINT64_C(0x26beb607f763c8a5), UINT64_C(0x745ac7b800d604d6), UINT64_C(0x3d2597a8e27d7c2e), UINT64_C(0xef1196bc0e6d5355), UINT64_C(0x640e72b5451a2ed8),
        UINT64_C(0xa52a4108ba6b4e2d), UINT64_C(0xdfa37eca2b03429b), UINT64_C(0xb9c4d979a043ec23), UINT64_C(0xbde7fbed95a70441), UINT64_C(0x3e5616e4eb9be2a7), UINT64_C(0xc86f229e341e09c9), UINT64_C(0x70a166b7d1afc716), UINT64_C(0x80fcdacffd877084), UINT64_C(0xd2cc99d98b1f4fcd), UINT64_C(0x6a51d0a703f0583a),
        UINT64_C(0xc2a73cc2d09309a0), UINT64_C(0x67ada5ce28bb9b02), UINT64_C(0xb8328f9ceeb7de63), UINT64_C(0x8e261a84f601b132), UINT64_C(0xcf67b3e1e877e509), UINT64_C(0x6fc0279cec76d661), UINT64_C(0xe2ea6d27cce7e887), UINT64_C(0x78134a0cbc885755), UINT64_C(0x1742c70a5bc96d6a), UINT64_C(0x2cf63eb1cc348edf),
        UINT64_C(0xfd75faf2bae7d5e3), UINT64_C(0x5e7db2744df1c09a), UINT64_C(0xa88a626b873daf1d), UINT64_C(0x6f93f30310e4443b), UINT64_C(0x0e42cb6837d89165), UINT64_C(0x135bdc8f37e58ae2), UINT64_C(0xb3de57613abe2300), UINT64_C(0x72e2d5a9dfaed673), UINT64_C(0x6282c537fa811eaa), UINT64_C(0x4d2ace8f07c4d2d5),
        UINT64_C(0x07acb2b78bdfecdc), UINT64_C(0x77b807a49dc030e5), UINT64_C(0x3f8b71af6644ca93), UINT64_C(0xa2ff3fe38e187cd8), UINT64_C(0xcec88d459a76e40b), UINT64_C(0x1a470bb4a7b439a0), UINT64_C(0x3ce3c336bfce7f57), UINT64_C(0x321731db6f0d50b1), UINT64_C(0x481b7a6de257e27a), UINT64_C(0x6bd556eae247bc63),
        UINT64_C(0x7c0e45b45a195fdf), UINT64_C(0xad5a2aa2a520c67d), UINT64_C(0x98d3c2186e0ded1f), UINT64_C(0x1821468cbed31af4), UINT64_C(0x7ac70eac95252b4f), UINT64_C(0x632bf674dd4614e2), UINT64_C(0xc1d03a7b1f26f010), UINT64_C(0x04101ee555439ba1), UINT64_C(0xb1afa00affd77250), UINT64_C(0xd71a67f780c09741),
        UINT64_C(0xbea4cd33ecb0cf09), UINT64_C(0x21e5be1d99cb9528), UINT64_C(0xe2c4ac753de88b26), UINT64_C(0xb29328cc62133faa), UINT64_C(0xaabb5e4edf2357c6), UINT64_C(0xc58023ec1aae3ead), UINT64_C(0xbf266223e9c3ed98), UINT64_C(0x183175de5285088b), UINT64_C(0x347e3812e53a6bb2), UINT64_C(0x94fa935cde0e0a5f),
        UINT64_C(0x1a9288250f3d1d46), UINT64_C(0xbdb5115865d4a2eb), UINT64_C(0x7ed89138ede7c49b), UINT64_C(0x419977ef68cef709), UINT64_C(0xbb8fb25714c72f3f), UINT64_C(0x7907686750d9812c), UINT64_C(0x2ddaf1ae03fd2325), UINT64_C(0x3eebf3ae4dd11a4a), UINT64_C(0xac6a1e12cd45b432), UINT64_C(0xada55af3f260ded5),
        UINT64_C(0x10d115d1362656d1), UINT64_C(0x16eed6afa9615702), UINT64_C(0x5ea9bcf51a47bf49), UINT64_C(0x7d2dc77a54ddf5a1), UINT64_C(0x54fd5c9419a3c05c), UINT64_C(0xdb011e0d0ff3af88), UINT64_C(0xfda2af2b0516833e), UINT64_C(0x2f5a42242b68b46b), UINT64_C(0x94de6c766cb555da), UINT64_C(0x460dbc8afa11e753),
        UINT64_C(0xffe46c8d859d0919), UINT64_C(0xbc1936f8fd9278a2), UINT64_C(0xe0e61b4524580d92), UINT64_C(0x666a10c08a43d3ce), UINT64_C(0x63627c61e0f91386), UINT64_C(0xc7d64346e39e0b60), UINT64_C(0x3d094923731c93e3), UINT64_C(0xb29ff264552e3ec3), UINT64_C(0xa90e2712f57a122b), UINT64_C(0x00f4afa95cb5aca4),
        UINT64_C(0xc8fd230bbdacec1c), UINT64_C(0xcee72d73ec69fb15), UINT64_C(0xab2245fd5661fd72), UINT64_C(0x350130316b180fe1), UINT64_C(0x2640ac7ff164db12), UINT64_C(0x6b709b18d2f84738), UINT64_C(0xead969f045fb937a), UINT64_C(0x30842bff221720cd), UINT64_C(0x8572cb2f642b4e57), UINT64_C(0x8cdd96bd217bed40),
        UINT64_C(0x67ae42369674dc8f), UINT64_C(0x6ed95f9bb0a033a3), UINT64_C(0x59bcbf0cd480aa14), UINT64_C(0x32c7cba603fa61e3), UINT64_C(0x2989b7889ae7fe66), UINT64_C(0xf9c5884cc32e5ea1), UINT64_C(0x7dfe9b4ff8ed61b6), UINT64_C(0x6fc10ba1b90380fb), UINT64_C(0xc3ac30b84a3bcae8), UINT64_C(0xe58b27f0c62c1ee5),
        UINT64_C(0x6a7b39aa3e4cda42), UINT64_C(0x8906cf98e50d7da0), UINT64_C(0x1109ebf49e23c814), UINT64_C(0x42d719da0b9d5d3e), UINT64_C(0x4b57152509030bb4), UINT64_C(0x2d83414907afead8), UINT64_C(0x79a66a5ca0bbe06e), UINT64_C(0x7e776a15ba0d65b6), UINT64_C(0x1a1f79c0e9bf11a7), UINT64_C(0x21a62beb08ed2c28),
        UINT64_C(0x017460b48dc5db50), UINT64_C(0x6d011b92dc943a17), UINT64_C(0xee3379c4b3da7216), UINT64_C(0x858baa5ff3751d77), UINT64_C(0x6f1fb6b5fed96f73), UINT64_C(0x4ff5e541b1759bb1), UINT64_C(0xab7b567c650e34da), UINT64_C(0xd536b0a7c9df9535), UINT64_C(0xbb201cb00e17378e), UINT64_C(0xddb56bd6b87dc3e5),
        UINT64_C(0xa26b116480a111b1), UINT64_C(0x984530ef64bb5df9), UINT64_C(0x0cec20a896f16746), UINT64_C(0x0f2571182458e638), UINT64_C(0xde08aa2fa5a327a6), UINT64_C(0xcc4a05eee36a146b), UINT64_C(0x21a11983ce4ea106), UINT64_C(0xee8b5159af20b730), UINT64_C(0xf4d5a4d1981c38c2), UINT64_C(0xfd3bd9ea409f9eb0),
        UINT64_C(0x5e11df5cf8dff375), UINT64_C(0xdfb1f643cd89ead1), UINT64_C(0x3e065a9d1f4ca3b4), UINT64_C(0x1ef82cfad86694f5), UINT64_C(0xc9d028e62d8aee13), UINT64_C(0xdb623599e848c52d), UINT64_C(0xc1ca0076c92fa191), UINT64_C(0x505f27ab31432341), UINT64_C(0x4918908aaaf0d67f), UINT64_C(0x4ab4ee227d02b2c1),
        UINT64_C(0x12482868a02186e2), UINT64_C(0xa792704240e7edc1), UINT64_C(0x2218234b3166c138), UINT64_C(0x5cb7dff1dc749d63), UINT64_C(0x2a8d99702027ec3c), UINT64_C(0x8af28b59e5c7409a), UINT64_C(0x846f2cad2cd17a3c), UINT64_C(0x09a28151f4da8dad), UINT64_C(0xf58a860eef09b449), UINT64_C(0x2e00a42bc197ca2e),
    };
    // clang-format on
    if (isLE()) {
        return base_selftest(hash<false, true>, &expected[0], sizeof(expected) / sizeof(expected[0]), stripe);
    } else {
        return base_selftest(hash<true, true>, &expected[0], sizeof(expected) / sizeof(expected[0]), stripe);
    }
}
static bool hash_bfast_128_selftest() {
    // clang-format off
    const int stripe = 2;
    uint64_t expected[] = {
        UINT64_C(0xc23b5ed54b4832bb), UINT64_C(0x702894363ff40815), UINT64_C(0x400d0527c8be4293), UINT64_C(0x00bceb6a4a1f300e), UINT64_C(0xf43c1e8f942ccc26), UINT64_C(0x11d82a1b09d2dad6), UINT64_C(0x70f0f9e742eeb5a5), UINT64_C(0x5fcdb5e02b6cf190), UINT64_C(0xca00b56f87489f8d), UINT64_C(0xce84231a4afbf113), UINT64_C(0x5f4fedf85fb20af8), UINT64_C(0x4e9201106c75af60), UINT64_C(0xd7d042b162e6a071), UINT64_C(0xd3ba1a83edcdfbb8), UINT64_C(0x1d07be95963c9cb9), UINT64_C(0x4bb04d8a9a15f053), UINT64_C(0x055524dcb16b0aae), UINT64_C(0x5e4e3c31478967d6), UINT64_C(0x17934a2a8ef65260), UINT64_C(0xbe6a2284f6bc638d),
        UINT64_C(0x8c80f416b9df2363), UINT64_C(0x4f1671824200de09), UINT64_C(0xdc1a9a488af58602), UINT64_C(0xbe163dbea4d3a29a), UINT64_C(0x6d992f402e34d4d8), UINT64_C(0x215fb5577fb7ae5f), UINT64_C(0x8d6e386f8aa20258), UINT64_C(0x522eeefc60e0a35c), UINT64_C(0xd7bae3d1bacff555), UINT64_C(0x8e7337bc4dac8aef), UINT64_C(0xdaf256d8345318f2), UINT64_C(0x6d7f2f39e711f688), UINT64_C(0x27ba957901102a00), UINT64_C(0x972cc14c28d4c68b), UINT64_C(0xec2e02f637af2918), UINT64_C(0xc017b8597efe7dcf), UINT64_C(0x8804cca8dab4c9eb), UINT64_C(0x04bf1279fe037fe5), UINT64_C(0x5ee30e336ce8c28b), UINT64_C(0x1478f2acc9c86f72),
        UINT64_C(0x3138959242ffe48b), UINT64_C(0x2bac57a939e9a107), UINT64_C(0xd15dfb081dbe4d62), UINT64_C(0x1a7f22e8d1fd9abb), UINT64_C(0x32f74754384f013a), UINT64_C(0xc60914a5ac0023e1), UINT64_C(0x346a74741ffd5992), UINT64_C(0xca1a8458898efd84), UINT64_C(0x0dd1325e65071ada), UINT64_C(0xb6f6f527057167db), UINT64_C(0xc761f6bd05ed0c49), UINT64_C(0x930152c7c039d10f), UINT64_C(0xb6d46f1fad1f8865), UINT64_C(0x7888259a87baad4e), UINT64_C(0x63650b147c2a7df4), UINT64_C(0xd01a56e76eeabb1b), UINT64_C(0x42105feff1a00ebd), UINT64_C(0x6e519fde4e96b1f6), UINT64_C(0x476a641967bd5090), UINT64_C(0x6ccd267eca36ede6),
        UINT64_C(0x0b6fcab20659f62e), UINT64_C(0x0e787135c004e170), UINT64_C(0x25a51b7264b6f1cf), UINT64_C(0xd64f4555784c3ecd), UINT64_C(0x2d84b5d194665cb9), UINT64_C(0xbe54c04d46f1b9f7), UINT64_C(0xd63e22dff896c978), UINT64_C(0x0f077b749d67c876), UINT64_C(0x6c8ea193cc541fd9), UINT64_C(0xd8100337efc515c4), UINT64_C(0xc950ceb73ac7ce4d), UINT64_C(0x1831875fb844f916), UINT64_C(0xd5f8aa1611131e08), UINT64_C(0x5e7efed18f3ae630), UINT64_C(0xd389e53a1d344e07), UINT64_C(0x6f918b50b8b7ac4f), UINT64_C(0xcc375e46a1690815), UINT64_C(0x1cba576ad0ffb4bc), UINT64_C(0x95ef052c25b2c4b6), UINT64_C(0x0a461873de9b0abc),
        UINT64_C(0xbd35067c90ebf93a), UINT64_C(0x60f1b59bd119dc73), UINT64_C(0xf2b1c1a1614e1f7b), UINT64_C(0xef6d011685b6c01c), UINT64_C(0x2e384b7347921a28), UINT64_C(0x6e076b1aea2ef1f5), UINT64_C(0x0735a3deda68005f), UINT64_C(0x3d4ddbec75387ba2), UINT64_C(0x6de3b71d3864ec24), UINT64_C(0xef427e0409453105), UINT64_C(0x977f16fb7bf495b1), UINT64_C(0xefeffba0f5855184), UINT64_C(0x3d7fc1b6c81c660c), UINT64_C(0xe2015939fa1cd024), UINT64_C(0x470dee81b3452fff), UINT64_C(0x00a2cbad81317f05), UINT64_C(0xb00abf69861adbcb), UINT64_C(0xd8a9d97f0d7a93fa), UINT64_C(0xa30c49f4973cd99a), UINT64_C(0x3eda38ec5cef7e5c),
        UINT64_C(0x9df43e8bc6501fef), UINT64_C(0x81ac6dc6a7acea9d), UINT64_C(0xe0c35035e1681752), UINT64_C(0x70b12a5336287756), UINT64_C(0x3cbef12c15e0f9b0), UINT64_C(0x0b91094f968464f3), UINT64_C(0x1c12127a9c16353c), UINT64_C(0xf7cbc7019de00990), UINT64_C(0x9c3b03a6083adafb), UINT64_C(0x3221cc6027b6c04e), UINT64_C(0xe51dd5dd4b68254d), UINT64_C(0x7d228b861c311ce2), UINT64_C(0x744cfdfa5f3ab01c), UINT64_C(0x4845eea8783eae63), UINT64_C(0x992605fea41f7841), UINT64_C(0x14cc330ddf9096a8), UINT64_C(0xaabff879f6c63ad5), UINT64_C(0x6a06a18c6df06081), UINT64_C(0x2f51965b256c9964), UINT64_C(0x7f182b8696a36815),
        UINT64_C(0xa6dd7fe129ea6d48), UINT64_C(0x5d547b33ab69ff15), UINT64_C(0x30d0fbb1d34a0ff7), UINT64_C(0xd3acdadda15f775b), UINT64_C(0xc35efaaf86496c56), UINT64_C(0x43a8597d200b4087), UINT64_C(0xdc0354d445c74616), UINT64_C(0xd47c9c2b81fb8eed), UINT64_C(0x63fff927dbce35a1), UINT64_C(0x8236dfbc59cadbb8), UINT64_C(0x0edd2257aa3a62df), UINT64_C(0x924ce6c5a990d6e3), UINT64_C(0xf086fd16b1ec7c17), UINT64_C(0xbaa5990a755be369), UINT64_C(0x0a2176abf6dd0cdb), UINT64_C(0x66208cd1feec0186), UINT64_C(0x40235de01e2a7e83), UINT64_C(0xddae16201bd55397), UINT64_C(0x8ad56c122141c22a), UINT64_C(0x08001a622b7b1f03),
        UINT64_C(0xfddd66c62cc5bf53), UINT64_C(0xe58c6c8268e5ad39), UINT64_C(0x05bf270ab83d16c3), UINT64_C(0x65f0d1a55a42d416), UINT64_C(0x067a8cc6e9e1a310), UINT64_C(0x42121a86503f1edb), UINT64_C(0x9356d2b1c5f537ee), UINT64_C(0xca5532bd55bc54f8), UINT64_C(0xc74cc1e751fbab4d), UINT64_C(0x907b52a8f4e4b770), UINT64_C(0x8ffb270f018a0e50), UINT64_C(0x5b43d02b1286ca8e), UINT64_C(0x81bd419f61e4e3c1), UINT64_C(0x3329f9ba41f4c368), UINT64_C(0xa1549ae8dd56a435), UINT64_C(0x369057438d4fab68), UINT64_C(0x08b500c6abc13d03), UINT64_C(0xa850e156d92e04a7), UINT64_C(0xec224a87640055fd), UINT64_C(0x7b9aeb83c3b41966),
        UINT64_C(0xfc721e04f0bff9c5), UINT64_C(0x9ffbc48bc96861d4), UINT64_C(0x939b328c986c34af), UINT64_C(0xb17ee3d8c1f3ed4e), UINT64_C(0xdbf9254b08019940), UINT64_C(0xd2f308837aa80a0f), UINT64_C(0x7c7f4121b8b818f5), UINT64_C(0x8b03b8069894faf7), UINT64_C(0x8e8f1bf7694c1a5c), UINT64_C(0x8bd66aaccdd14ef3), UINT64_C(0x1be6c995beb205bc), UINT64_C(0x4112c0d6580bf8a0), UINT64_C(0x141897bb7ee199af), UINT64_C(0x2a36123b5c737651), UINT64_C(0x9d2d2dbb096fcfcc), UINT64_C(0x67ce7095e3d22d31), UINT64_C(0xe6504461ff761848), UINT64_C(0x94182474f0e384a6), UINT64_C(0xbbbb672b47f7c9a2), UINT64_C(0x83ffd0dd2149418f),
        UINT64_C(0x8383145bf9c5ff03), UINT64_C(0x41d5279066eace16), UINT64_C(0x191dbbe45c24c658), UINT64_C(0xd08536260c704984), UINT64_C(0xe2ae257dd80166df), UINT64_C(0xfe2556150a1a0603), UINT64_C(0xa373124254298907), UINT64_C(0x5619e66005c53b65), UINT64_C(0xbd005abfe79dd220), UINT64_C(0xe144f70ee6790a58), UINT64_C(0xed9f0da5f5a2db67), UINT64_C(0xa31cd42192d31214), UINT64_C(0xc621c3b8c3d88c56), UINT64_C(0x02f45d6ed9a5fa58), UINT64_C(0x226c7ceca38f747c), UINT64_C(0xe5cefeee0d6ffccb), UINT64_C(0xc6895f28a7caf961), UINT64_C(0x05289804b98f6d3d), UINT64_C(0xe65965c7b179762f), UINT64_C(0xb52c8922a09f17b0),
        UINT64_C(0xf7b256e3be4c73cf), UINT64_C(0xd2ce22ab4ebe93f9), UINT64_C(0x58e5928c53b8bbd1), UINT64_C(0x5eef9d65c593f46e), UINT64_C(0x61a3e2da3cdc35fb), UINT64_C(0xf8b75a58f6f58e9c), UINT64_C(0x296efdea1927d6be), UINT64_C(0x6e0f9a2aad06d25b), UINT64_C(0x7fa9460b9bea3557), UINT64_C(0x4fc50bad70ed908e), UINT64_C(0x55bf3d54c619cebf), UINT64_C(0xdca7aad065b54a7d), UINT64_C(0x9fc1fda52f45b27f), UINT64_C(0x1da1b6d75556ee96), UINT64_C(0xc76b960e94033692), UINT64_C(0x041d9d792431eeb8), UINT64_C(0xaaf35bfa3c6c561c), UINT64_C(0xd969b2070ed44242), UINT64_C(0x70e256659eb97a23), UINT64_C(0x27baf7b02d5c1a22),
        UINT64_C(0x373f4c8f4abb331a), UINT64_C(0x9f912f7882e89b35), UINT64_C(0x031c4e189d5ea2ee), UINT64_C(0x1a1b65584a810400), UINT64_C(0x6f29aa9c70cb0edd), UINT64_C(0xecbed39690ef368a), UINT64_C(0x516de7d651ffa337), UINT64_C(0xe4307c5bccfeb272), UINT64_C(0x8f08e6e7cdd32ca3), UINT64_C(0x20ca7cc42a486c27), UINT64_C(0xe2afd9a390aec404), UINT64_C(0x83a33b93e4b62762), UINT64_C(0x8327198d7e02d2a9), UINT64_C(0x81ca481d06fbaa51), UINT64_C(0x92e224a36cf8bdf8), UINT64_C(0xc3b5e144b860766b), UINT64_C(0x386d0db73c38a54f), UINT64_C(0x530e9fa2af324d6b), UINT64_C(0x7953b8ddc960a9d2), UINT64_C(0xf33f5b50b8ac9d79),
        UINT64_C(0xb9ee8a1566d01cc4), UINT64_C(0xa157b6895ab76a61), UINT64_C(0xb90bdbc1c41c635b), UINT64_C(0x00e52d46c663e807), UINT64_C(0x7f86fb1282a56527), UINT64_C(0x80979fa6de0f12bb), UINT64_C(0x9dbc293b997017b9), UINT64_C(0x25cdec63264c3b89), UINT64_C(0x0bf2d1e4696795ab), UINT64_C(0x49f74dff88657d13), UINT64_C(0xd874da732a8135ed), UINT64_C(0x8251078a5adaf77b), UINT64_C(0xfb9a5499009feb33), UINT64_C(0x4c6df205cc4888ae), UINT64_C(0x3bad0ab9751c4295), UINT64_C(0xafca6c27fecf83ac), UINT64_C(0x1bb4d3520b54d22d), UINT64_C(0x6d5e0baeeed13ffe), UINT64_C(0xbe0e112242232fcc), UINT64_C(0x408ade7701097a98),
        UINT64_C(0x3e92588bea96f56e), UINT64_C(0x3f978abf88d5be8e), UINT64_C(0xb389cdc237a1b3c9), UINT64_C(0x04b13b8e241b9722), UINT64_C(0x2ce96eee6363b76c), UINT64_C(0xf235547c9a5db5e4), UINT64_C(0xf000a75879c254d7), UINT64_C(0xb107d72e7d0228d2), UINT64_C(0xb9b444d81134c860), UINT64_C(0xd14d59981c2f898a), UINT64_C(0xefc6e45f76619321), UINT64_C(0x448983b9dbf623e5), UINT64_C(0x1cb87b0fc47d2f36), UINT64_C(0x35d4ecc066ab8350), UINT64_C(0x909fe75f6ef9e7dc), UINT64_C(0x481434ab816d06ed), UINT64_C(0x1bc76534247c8423), UINT64_C(0x406e1598dffa2d84), UINT64_C(0xf2f325247bcd3820), UINT64_C(0x6ffb4d07bf394b26),
        UINT64_C(0x5b034a3efc0b3953), UINT64_C(0xa44137cd43885a3a), UINT64_C(0x626bdd6d79fc68b2), UINT64_C(0x8f0d018937a7bd5f), UINT64_C(0x44db3be2ad03c974), UINT64_C(0x4169a729827c175e), UINT64_C(0x915ef6b3980a97d3), UINT64_C(0x3b66c2ad83850bc8), UINT64_C(0xf69e827b96d60352), UINT64_C(0x28d9c7dcddc634ca), UINT64_C(0xf1e23afb26d1e982), UINT64_C(0x3b18475069a1f4cf), UINT64_C(0x36c67ef416faf0e4), UINT64_C(0x253d9a5a10e82e2c), UINT64_C(0xd31537069c5f6fa4), UINT64_C(0x9cab4410cb651729), UINT64_C(0xe260f229e79a10ec), UINT64_C(0x91330b626c74210a), UINT64_C(0xf818fdc158785d94), UINT64_C(0xe2ac61b27da5214d),
        UINT64_C(0x1f334de2906db4c0), UINT64_C(0x0a47f9b72128d238), UINT64_C(0x1733c36e17d84657), UINT64_C(0x4c0ab3040d3e030b), UINT64_C(0x594352e6bdcb23bd), UINT64_C(0xd675228c1bf5746f), UINT64_C(0xbaff4fa147710b94), UINT64_C(0x7dc7990f8f8f8352), UINT64_C(0x7977c48912453891), UINT64_C(0xb5cefee7f2bcdcbb), UINT64_C(0xb6d694097c6e6a62), UINT64_C(0x6a6b70af8c21e706), UINT64_C(0x4c5cf03dcb360988), UINT64_C(0xc6a5651a94743606), UINT64_C(0xba6fc0dc3a123dd9), UINT64_C(0xd10374b71420a73f), UINT64_C(0x2e0df936c8e38b0a), UINT64_C(0xb7cc7bf93100a50d), UINT64_C(0x9fc2fdbdcbb3fef6), UINT64_C(0xc98789812cb3346e),
        UINT64_C(0x5579baf3b595de98), UINT64_C(0x6b77fdb8c83ce236), UINT64_C(0xa1a5758fdc69455b), UINT64_C(0xc20b91f370d4813a), UINT64_C(0x86de92baf469f99a), UINT64_C(0x952728c15c8894d2), UINT64_C(0xe8526684d2f9d682), UINT64_C(0x9a22381f5e6734c5), UINT64_C(0x9e5b0a05bc02280b), UINT64_C(0xd7082a4e6b04a080), UINT64_C(0x83bce609207d6566), UINT64_C(0x6db61cb36ef3aeaf), UINT64_C(0xca11c136c7a7b755), UINT64_C(0x3a91f885cd6e3831), UINT64_C(0xf20d35c26a41efd0), UINT64_C(0xc9c8642d1181ad59), UINT64_C(0x64ae3f1407d39a96), UINT64_C(0x5037dcbff9f60dfe), UINT64_C(0xed4396487bae9d2c), UINT64_C(0xcb15c5d82cdfa2e9),
        UINT64_C(0xdf76d606de17ff57), UINT64_C(0x7b14196381c8b194), UINT64_C(0x4f488518d64f5dd5), UINT64_C(0xe7fc1217cd0b04c8), UINT64_C(0x6b04929f539a67e8), UINT64_C(0x48d04684a505aa20), UINT64_C(0x58862291154b315b), UINT64_C(0x26472d9ec9e242d5), UINT64_C(0x8351feec0e3d6ef7), UINT64_C(0x1517af4375805ea3), UINT64_C(0x86e1680e6257a299), UINT64_C(0x35ac8e1d1e325910), UINT64_C(0xb1f7f3c311240074), UINT64_C(0x6469154860fb5882), UINT64_C(0xf6d65e9faa1eb607), UINT64_C(0xe75af107faf9ae85), UINT64_C(0x6debcb48888482bf), UINT64_C(0x774e90bde8ef29f7), UINT64_C(0x054880bb6dba4efb), UINT64_C(0x4f8c5aaf70e02a29),
        UINT64_C(0xf9cb6f35b282278a), UINT64_C(0xa83f6c82b459d523), UINT64_C(0x7288413d9d66ebd7), UINT64_C(0x62d1e2f5ab96d6fa), UINT64_C(0xbbeef791221f721e), UINT64_C(0x22156f0bc3afae36), UINT64_C(0xd0ac7db629376f6d), UINT64_C(0x30a403b74e7284f4), UINT64_C(0xaf648e7017641547), UINT64_C(0xd114b96dbe1104a2), UINT64_C(0x742519bfee0ba1e5), UINT64_C(0x61bb47f9f5bc8f36), UINT64_C(0xa355f37f5920acfa), UINT64_C(0x9d2fe8fa6f6ffeb3), UINT64_C(0x1d5c56f00be4985a), UINT64_C(0x6c0da9b157c54487), UINT64_C(0x2c90e1aa0577d480), UINT64_C(0x9a7f8cdbc879710f), UINT64_C(0x39f3f5f5c6493f4e), UINT64_C(0xeca9a428484c6273),
        UINT64_C(0x38a4d7940aa99d77), UINT64_C(0x573311d1d2f4e453), UINT64_C(0x4c3bdd69644fa03a), UINT64_C(0x249c02adc359f267), UINT64_C(0xc873dd1f831f1f79), UINT64_C(0x4f9b99a67e8e7d8f), UINT64_C(0x18c0a341e4db61ef), UINT64_C(0x75f77cd5f7d03344), UINT64_C(0x4caeea98591c1bc0), UINT64_C(0x985fc00f86270978), UINT64_C(0x198153d2165ebe7f), UINT64_C(0x688d00fc13e5799b), UINT64_C(0x9e1d226c60376692), UINT64_C(0x858c69669118fd54), UINT64_C(0xb4e559ae62e7aaf7), UINT64_C(0xc28cc78069c218ba), UINT64_C(0x1014bd0c2da94377), UINT64_C(0x9281877d354e08c8), UINT64_C(0x05ad4794920b670b), UINT64_C(0x94522c4044af9acb),
    };
    // clang-format on
    if (isLE()) {
        return base_selftest(hash_128<false, true>, &expected[0], sizeof(expected) / sizeof(expected[0]), stripe);
    } else {
        return base_selftest(hash_128<true, true>, &expected[0], sizeof(expected) / sizeof(expected[0]), stripe);
    }
}

/*
def cp(s):
    print("{")
    for i, n in enumerate(s):
        if i % 10 == 0: print(end="        ")
        print(end=f"UINT64_C(0x{n:016x}),")
        if i % 10 != 9: print(end=" ")
        if i % 10 == 9: print()
    print("    }")

def cpl(s):
    print("{")
    for i, n in enumerate(s):
        if i % 10 == 0: print(end="        ")
        print(end=f"UINT64_C(0x{n&((1<<64)-1):016x}), UINT64_C(0x{n>>64:016x}),")
        if i % 10 != 9: print(end=" ")
        if i % 10 == 9: print()
    print("    }")
*/

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
    // ,$.initfn          = hash_selftest
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
    // ,$.initfn          = hash_128_selftest
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
    // ,$.initfn          = hash_bfast_selftest
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
    // ,$.initfn          = hash_bfast_128_selftest
);
