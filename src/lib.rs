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

#![no_std]
#![deny(unsafe_code)]
#![doc = include_str!("../CRATES.IO-README.md")]
#![doc(html_logo_url = "https://github.com/eternal-io/museair/blob/master/MuseAir-icon-light.png?raw=true")]
// #![warn(missing_docs)]

/// Currently algorithm version.
///
/// Note that this is **NOT** the implementation version.
///
/// If you want to see an older version of the algorithm, check out the historical commits
/// for [`museair.cpp`](https://github.com/eternal-io/museair/blob/master/museair.cpp) in repository root.
pub const ALGORITHM_VERSION: &str = "0.4-rc2";

/// MuseAir hash, standard variant, 64-bit output.
#[inline]
pub const fn hash(bytes: &[u8], seed: u64) -> u64 {
    hash_impl_64::<false>(bytes, seed)
}

/// MuseAir hash, standard variant, 128-bit output.
#[inline]
pub const fn hash_128(bytes: &[u8], seed: u64) -> u128 {
    hash_impl_128::<false>(bytes, seed)
}

/// BFast variant.
pub mod bfast {
    use super::*;

    /// MuseAir hash, BFast variant, 64-bit output.
    #[inline]
    pub const fn hash(bytes: &[u8], seed: u64) -> u64 {
        hash_impl_64::<true>(bytes, seed)
    }

    /// MuseAir hash, BFast variant, 128-bit output.
    #[inline]
    pub const fn hash_128(bytes: &[u8], seed: u64) -> u128 {
        hash_impl_128::<true>(bytes, seed)
    }
}

//------------------------------------------------------------------------------

type State = [u64; 6];
type Chunk = [u8; 96];

/// `AiryAi(0)` mantissa calculated by Y-Cruncher.
const CONSTANT: [u64; 7] = [
    0x5ae31e589c56e17a,
    0x96d7bb04e64f6da9,
    0x7ab1006b26f9eb64,
    0x21233394220b8457,
    0x047cb9557c9f3b43,
    0xd24f2590c0bcee28,
    0x33ea8f71bb6016d8,
];

/// Lower 64-bit, then upper 64-bit.
#[inline(always)]
const fn wmul(a: u64, b: u64) -> (u64, u64) {
    u128_to_u64s(a as u128 * b as u128)
}

/// Lower 64-bit, then upper 64-bit.
#[inline(always)]
const fn u128_to_u64s(x: u128) -> (u64, u64) {
    (x as u64, (x >> 64) as u64)
}
/// Lower 64-bit, then upper 64-bit.
#[inline(always)]
const fn u64s_to_u128(lo: u64, hi: u64) -> u128 {
    ((hi as u128) << 64) | lo as u128
}

#[cold]
#[inline(always)]
const fn cold_path() {}

#[inline(always)]
const fn likely(cond: bool) -> bool {
    if !cond {
        cold_path();
    }
    cond
}
#[inline(always)]
const fn unlikely(cond: bool) -> bool {
    if cond {
        cold_path();
    }
    cond
}

macro_rules! u64 {
    ($n:literal) => {
        $n * 8
    };
}

macro_rules! min {
    ( $left:expr, $right:expr $(,)? ) => {
        match ($left, $right) {
            (left_val, right_val) => {
                if left_val < right_val {
                    left_val
                } else {
                    right_val
                }
            }
        }
    };
}

#[inline(always)]
const fn seed_state(seed: u64) -> State {
    [
        CONSTANT[0].wrapping_add(seed),
        CONSTANT[1].wrapping_sub(seed),
        CONSTANT[2] ^ seed,
        CONSTANT[3].wrapping_add(seed),
        CONSTANT[4].wrapping_sub(seed),
        CONSTANT[5] ^ seed,
    ]
}

//------------------------------------------------------------------------------
// MSRV friendly.

#[inline(always)]
const fn read_u32(bytes: &[u8], offset: usize) -> u64 {
    u32::from_le_bytes(match bytes.split_at(offset).1.first_chunk() {
        Some(xs) => *xs,
        None => unreachable!(),
    }) as u64
}
#[inline(always)]
const fn read_u32_r(bytes: &[u8], offset_r: usize) -> u64 {
    u32::from_le_bytes(match bytes.split_at(bytes.len() - offset_r - 4).1.first_chunk() {
        Some(xs) => *xs,
        None => unreachable!(),
    }) as u64
}

#[inline(always)]
const fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(match bytes.split_at(offset).1.first_chunk() {
        Some(xs) => *xs,
        None => unreachable!(),
    }) as u64
}
#[inline(always)]
const fn read_u64_r(bytes: &[u8], offset_r: usize) -> u64 {
    u64::from_le_bytes(match bytes.split_at(bytes.len() - offset_r - 8).1.first_chunk() {
        Some(xs) => *xs,
        None => unreachable!(),
    }) as u64
}

#[inline(always)]
const fn read_short(bytes: &[u8]) -> (u64, u64) {
    debug_assert!(bytes.len() <= u64!(2));

    let len = bytes.len();
    if len >= 4 {
        let off = (len & 24) >> (len >> 3); // len >= 8 ? 4 : 0
        let head = read_u32(bytes, 0);
        let head_off = read_u32(bytes, off);
        let tail = read_u32_r(bytes, 0);
        let tail_off = read_u32_r(bytes, off);

        (head << 32 | tail, head_off << 32 | tail_off)
    } else if len > 0 {
        // MSB <-> LSB
        // [0] [0] [0] @ len == 1 (0b01)
        // [0] [1] [1] @ len == 2 (0b10)
        // [0] [1] [2] @ len == 3 (0b11)
        let fst = bytes[0] as u64;
        let snd = bytes[len >> 1] as u64;
        let thd = bytes[len - 1] as u64;

        (fst << 48 | snd << 24 | thd, 0)
    } else {
        (0, 0)
    }
}

//------------------------------------------------------------------------------

#[inline(always)]
const fn hash_impl_64<const BFAST: bool>(bytes: &[u8], seed: u64) -> u64 {
    if likely(bytes.len() <= u64!(4)) {
        hash_short_64::<BFAST>(bytes, seed)
    } else {
        hash_loong_64::<BFAST>(bytes, seed)
    }
}

#[inline(always)]
const fn hash_impl_128<const BFAST: bool>(bytes: &[u8], seed: u64) -> u128 {
    if likely(bytes.len() <= u64!(4)) {
        hash_short_128(bytes, seed)
    } else {
        hash_loong_128::<BFAST>(bytes, seed)
    }
}

//------------------------------------------------------------------------------

#[inline(always)]
const fn hash_short_64<const BFAST: bool>(bytes: &[u8], seed: u64) -> u64 {
    let (mut i, mut j);
    (i, j) = hash_short_common(bytes, seed);
    if !BFAST {
        let (lo0, hi0) = wmul(i ^ CONSTANT[2], j ^ CONSTANT[3]);
        let (lo1, hi1) = wmul(i ^ CONSTANT[4], j ^ CONSTANT[5]);
        i = i.wrapping_add(lo0 ^ hi1);
        j = j.wrapping_add(lo1 ^ hi0);
        let (lo2, hi2) = wmul(i, j);
        i ^ j ^ lo2 ^ hi2
    } else {
        (i, j) = wmul(i ^ CONSTANT[2], j ^ CONSTANT[3]);
        (i, j) = wmul(i ^ CONSTANT[4], j ^ CONSTANT[5]);
        i ^ j
    }
}

#[inline(always)]
const fn hash_short_128(bytes: &[u8], seed: u64) -> u128 {
    let (mut i, mut j);
    (i, j) = hash_short_common(bytes, seed);
    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(i ^ CONSTANT[2], j ^ CONSTANT[3]);
    (i, j) = (lo0 ^ hi1, lo1 ^ hi0);
    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(i ^ CONSTANT[4], j ^ CONSTANT[5]);
    (i, j) = (lo0 ^ hi1, lo1 ^ hi0);

    u64s_to_u128(i, j)
}

#[inline(always)]
const fn hash_short_common(bytes: &[u8], seed: u64) -> (u64, u64) {
    let len = bytes.len();
    let len_ = bytes.len() as u64;
    let (lo2, hi2) = wmul(seed ^ CONSTANT[0], len_ ^ CONSTANT[1]);

    let (mut i, mut j) = read_short(bytes.split_at(min!(u64!(2), len)).0);
    i ^= len_ ^ lo2;
    j ^= seed ^ hi2;

    if unlikely(len > u64!(2)) {
        let (u, v) = read_short(bytes.split_at(u64!(2)).1);
        let (lo0, hi0) = wmul(CONSTANT[2], CONSTANT[3] ^ u);
        let (lo1, hi1) = wmul(CONSTANT[4], CONSTANT[5] ^ v);
        i ^= lo0 ^ hi1;
        j ^= lo1 ^ hi0;
    }

    (i, j)
}

//------------------------------------------------------------------------------

#[inline(always)]
const fn epilogue_64((i, j, k): (u64, u64, u64)) -> u64 {
    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(j, k);
    let (lo2, hi2) = wmul(k, i);
    (lo0 ^ hi2).wrapping_add(lo1 ^ hi0).wrapping_add(lo2 ^ hi1)
}

#[inline(always)]
const fn epilogue_128((i, j, k): (u64, u64, u64)) -> u128 {
    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(j, k);
    let (lo2, hi2) = wmul(k, i);
    u64s_to_u128(lo0 ^ lo1 ^ hi2, hi0 ^ hi1 ^ lo2)
}

//------------------------------------------------------------------------------

#[inline(never)]
const fn hash_loong_64<const BFAST: bool>(bytes: &[u8], seed: u64) -> u64 {
    epilogue_64(hash_loong_common::<BFAST>(bytes, seed))
}

#[inline(never)]
const fn hash_loong_128<const BFAST: bool>(bytes: &[u8], seed: u64) -> u128 {
    epilogue_128(hash_loong_common::<BFAST>(bytes, seed))
}

#[inline(always)]
const fn hash_loong_common<const BFAST: bool>(bytes: &[u8], seed: u64) -> (u64, u64, u64) {
    debug_assert!(bytes.len() > u64!(4));

    let mut remainder = bytes;
    let mut state = seed_state(seed);
    let [mut lo0, mut lo1, mut lo2, mut lo3, mut lo4, mut lo5];
    let [mut hi0, mut hi1, mut hi2, mut hi3, mut hi4, mut hi5];

    if unlikely(remainder.len() > u64!(12)) {
        lo5 = CONSTANT[6];

        while let Some((chunk, rest)) = remainder.split_first_chunk::<{ u64!(12) }>() {
            remainder = rest;

            if !BFAST {
                state[0] ^= read_u64(chunk, u64!(0));
                state[1] ^= read_u64(chunk, u64!(1));
                (lo0, hi0) = wmul(state[0], state[1]);
                state[0] = state[0].wrapping_add(lo5 ^ hi0);

                state[1] ^= read_u64(chunk, u64!(2));
                state[2] ^= read_u64(chunk, u64!(3));
                (lo1, hi1) = wmul(state[1], state[2]);
                state[1] = state[1].wrapping_add(lo0 ^ hi1);

                state[2] ^= read_u64(chunk, u64!(4));
                state[3] ^= read_u64(chunk, u64!(5));
                (lo2, hi2) = wmul(state[2], state[3]);
                state[2] = state[2].wrapping_add(lo1 ^ hi2);

                state[3] ^= read_u64(chunk, u64!(6));
                state[4] ^= read_u64(chunk, u64!(7));
                (lo3, hi3) = wmul(state[3], state[4]);
                state[3] = state[3].wrapping_add(lo2 ^ hi3);

                state[4] ^= read_u64(chunk, u64!(8));
                state[5] ^= read_u64(chunk, u64!(9));
                (lo4, hi4) = wmul(state[4], state[5]);
                state[4] = state[4].wrapping_add(lo3 ^ hi4);

                state[5] ^= read_u64(chunk, u64!(10));
                state[0] ^= read_u64(chunk, u64!(11));
                (lo5, hi5) = wmul(state[5], state[0]);
                state[5] = state[5].wrapping_add(lo4 ^ hi5);
            } else {
                state[0] ^= read_u64(chunk, u64!(0));
                state[1] ^= read_u64(chunk, u64!(1));
                (lo0, hi0) = wmul(state[0], state[1]);
                state[0] = lo5 ^ hi0;

                state[1] ^= read_u64(chunk, u64!(2));
                state[2] ^= read_u64(chunk, u64!(3));
                (lo1, hi1) = wmul(state[1], state[2]);
                state[1] = lo0 ^ hi1;

                state[2] ^= read_u64(chunk, u64!(4));
                state[3] ^= read_u64(chunk, u64!(5));
                (lo2, hi2) = wmul(state[2], state[3]);
                state[2] = lo1 ^ hi2;

                state[3] ^= read_u64(chunk, u64!(6));
                state[4] ^= read_u64(chunk, u64!(7));
                (lo3, hi3) = wmul(state[3], state[4]);
                state[3] = lo2 ^ hi3;

                state[4] ^= read_u64(chunk, u64!(8));
                state[5] ^= read_u64(chunk, u64!(9));
                (lo4, hi4) = wmul(state[4], state[5]);
                state[4] = lo3 ^ hi4;

                state[5] ^= read_u64(chunk, u64!(10));
                state[0] ^= read_u64(chunk, u64!(11));
                (lo5, hi5) = wmul(state[5], state[0]);
                state[5] = lo4 ^ hi5;
            }
        }

        state[0] ^= lo5; // don't forget this!
    }

    [lo0, lo1, lo2, lo3] = [0; 4];
    [hi0, hi1, hi2, hi3] = [0; 4];

    if likely(remainder.len() > u64!(4)) {
        state[0] ^= read_u64(remainder, u64!(0));
        state[1] ^= read_u64(remainder, u64!(1));
        (lo0, hi0) = wmul(state[0], state[1]);

        if likely(remainder.len() > u64!(6)) {
            state[1] ^= read_u64(remainder, u64!(2));
            state[2] ^= read_u64(remainder, u64!(3));
            (lo1, hi1) = wmul(state[1], state[2]);

            if likely(remainder.len() > u64!(8)) {
                state[2] ^= read_u64(remainder, u64!(4));
                state[3] ^= read_u64(remainder, u64!(5));
                (lo2, hi2) = wmul(state[2], state[3]);

                if likely(remainder.len() > u64!(10)) {
                    state[3] ^= read_u64(remainder, u64!(6));
                    state[4] ^= read_u64(remainder, u64!(7));
                    (lo3, hi3) = wmul(state[3], state[4]);
                }
            }
        }
    }

    state[4] ^= read_u64_r(bytes, u64!(3));
    state[5] ^= read_u64_r(bytes, u64!(2));
    (lo4, hi4) = wmul(state[4], state[5]);

    state[5] ^= read_u64_r(bytes, u64!(1));
    state[0] ^= read_u64_r(bytes, u64!(0));
    (lo5, hi5) = wmul(state[5], state[0]);

    let mut i = state[0].wrapping_sub(state[1]);
    let mut j = state[2].wrapping_sub(state[3]);
    let mut k = state[4].wrapping_sub(state[5]);

    let rot = bytes.len() as u32 & 63;
    i = i.rotate_left(rot);
    j = j.rotate_right(rot);
    k ^= bytes.len() as u64;

    i = i.wrapping_add(lo3 ^ hi3 ^ lo4 ^ hi4);
    j = j.wrapping_add(lo5 ^ hi5 ^ lo0 ^ hi0);
    k = k.wrapping_add(lo1 ^ hi1 ^ lo2 ^ hi2);

    (i, j, k)
}

//------------------------------------------------------------------------------

#[derive(Clone)]
pub struct __IncrementalHasher<const BFAST: bool> {
    state: State,
    ring_prev: u64,
    buffer: Chunk,
    buffered_len: usize,
    processed_len: u64,
}

impl<const BFAST: bool> __IncrementalHasher<BFAST> {
    pub const fn new() -> Self {
        Self::with_seed(0)
    }

    pub const fn with_seed(seed: u64) -> Self {
        Self {
            state: seed_state(seed),
            ring_prev: CONSTANT[6],
            buffer: [0x00; 96],
            buffered_len: 0,
            processed_len: 0,
        }
    }

    pub const fn write(&mut self, bytes: &[u8]) {
        let vacancy = self.buffer.len() - self.buffered_len;

        if bytes.len() < vacancy {
            let mut i = 0;
            while i < bytes.len() {
                self.buffer[self.buffered_len + i] = bytes[i];
                i += 1;
            }
            self.buffered_len += bytes.len();
        } else {
            let mut i = 0;
            while i < vacancy {
                self.buffer[self.buffered_len + i] = bytes[i];
                i += 1;
            }
            self.buffered_len = 0;
            self.compress(bytes.split_at(vacancy).1);
        }
    }

    pub const fn finish(&self) -> u64 {
        let tot_len = self.processed_len.wrapping_add(self.buffered_len as u64);

        if unlikely(tot_len <= u64!(4)) {
            hash_short_64::<BFAST>(self.remainder(), self.restore_seed())
        } else {
            epilogue_64(self.finalize(tot_len))
        }
    }

    pub const fn finish_128(&self) -> u128 {
        let tot_len = self.processed_len.wrapping_add(self.buffered_len as u64);

        if unlikely(tot_len <= u64!(4)) {
            hash_short_128(self.remainder(), self.restore_seed())
        } else {
            epilogue_128(self.finalize(tot_len))
        }
    }

    #[inline(always)]
    const fn restore_seed(&self) -> u64 {
        debug_assert!(self.processed_len == 0);
        self.state[0].wrapping_sub(CONSTANT[0])
    }

    #[inline(always)]
    const fn remainder(&self) -> &[u8] {
        self.buffer.split_at(self.buffered_len).0
    }

    #[inline(never)]
    const fn compress(&mut self, mut remainder: &[u8]) {
        let mut first = true;
        loop {
            let chunk = match first {
                true => {
                    first = false;
                    &self.buffer
                }
                false => match remainder.split_first_chunk::<{ u64!(12) }>() {
                    None => break,
                    Some((chunk, rest)) => {
                        remainder = rest;
                        chunk
                    }
                },
            };

            let mut state = self.state;

            if !BFAST {
                state[0] ^= read_u64(chunk, u64!(0));
                state[1] ^= read_u64(chunk, u64!(1));
                let (lo0, hi0) = wmul(state[0], state[1]);
                state[0] = state[0].wrapping_add(self.ring_prev ^ hi0);

                state[1] ^= read_u64(chunk, u64!(2));
                state[2] ^= read_u64(chunk, u64!(3));
                let (lo1, hi1) = wmul(state[1], state[2]);
                state[1] = state[1].wrapping_add(lo0 ^ hi1);

                state[2] ^= read_u64(chunk, u64!(4));
                state[3] ^= read_u64(chunk, u64!(5));
                let (lo2, hi2) = wmul(state[2], state[3]);
                state[2] = state[2].wrapping_add(lo1 ^ hi2);

                state[3] ^= read_u64(chunk, u64!(6));
                state[4] ^= read_u64(chunk, u64!(7));
                let (lo3, hi3) = wmul(state[3], state[4]);
                state[3] = state[3].wrapping_add(lo2 ^ hi3);

                state[4] ^= read_u64(chunk, u64!(8));
                state[5] ^= read_u64(chunk, u64!(9));
                let (lo4, hi4) = wmul(state[4], state[5]);
                state[4] = state[4].wrapping_add(lo3 ^ hi4);

                state[5] ^= read_u64(chunk, u64!(10));
                state[0] ^= read_u64(chunk, u64!(11));
                let (lo5, hi5) = wmul(state[5], state[0]);
                state[5] = state[5].wrapping_add(lo4 ^ hi5);

                self.ring_prev = lo5;
            } else {
                state[0] ^= read_u64(chunk, u64!(0));
                state[1] ^= read_u64(chunk, u64!(1));
                let (lo0, hi0) = wmul(state[0], state[1]);
                state[0] = self.ring_prev ^ hi0;

                state[1] ^= read_u64(chunk, u64!(2));
                state[2] ^= read_u64(chunk, u64!(3));
                let (lo1, hi1) = wmul(state[1], state[2]);
                state[1] = lo0 ^ hi1;

                state[2] ^= read_u64(chunk, u64!(4));
                state[3] ^= read_u64(chunk, u64!(5));
                let (lo2, hi2) = wmul(state[2], state[3]);
                state[2] = lo1 ^ hi2;

                state[3] ^= read_u64(chunk, u64!(6));
                state[4] ^= read_u64(chunk, u64!(7));
                let (lo3, hi3) = wmul(state[3], state[4]);
                state[3] = lo2 ^ hi3;

                state[4] ^= read_u64(chunk, u64!(8));
                state[5] ^= read_u64(chunk, u64!(9));
                let (lo4, hi4) = wmul(state[4], state[5]);
                state[4] = lo3 ^ hi4;

                state[5] ^= read_u64(chunk, u64!(10));
                state[0] ^= read_u64(chunk, u64!(11));
                let (lo5, hi5) = wmul(state[5], state[0]);
                state[5] = lo4 ^ hi5;

                self.ring_prev = lo5;
            }

            self.state = state;
        }

        let mut i = 0;
        while i < remainder.len() {
            self.buffer[i] = remainder[i];
            i += 1;
        }
    }

    #[inline]
    const fn finalize(&self, tot_len: u64) -> (u64, u64, u64) {
        let [mut lo0, mut lo1, mut lo2, mut lo3, lo4, lo5];
        let [mut hi0, mut hi1, mut hi2, mut hi3, hi4, hi5];

        [lo0, lo1, lo2, lo3] = [0; 4];
        [hi0, hi1, hi2, hi3] = [0; 4];

        let mut state = self.state;
        let remainder = self.remainder();

        if likely(remainder.len() > u64!(4)) {
            state[0] ^= read_u64(remainder, u64!(0));
            state[1] ^= read_u64(remainder, u64!(1));
            (lo0, hi0) = wmul(state[0], state[1]);

            if likely(remainder.len() > u64!(6)) {
                state[1] ^= read_u64(remainder, u64!(2));
                state[2] ^= read_u64(remainder, u64!(3));
                (lo1, hi1) = wmul(state[1], state[2]);

                if likely(remainder.len() > u64!(8)) {
                    state[2] ^= read_u64(remainder, u64!(4));
                    state[3] ^= read_u64(remainder, u64!(5));
                    (lo2, hi2) = wmul(state[2], state[3]);

                    if likely(remainder.len() > u64!(10)) {
                        state[3] ^= read_u64(remainder, u64!(6));
                        state[4] ^= read_u64(remainder, u64!(7));
                        (lo3, hi3) = wmul(state[3], state[4]);
                    }
                }
            }
        }

        state[4] ^= read_u64_r(remainder, u64!(3));
        state[5] ^= read_u64_r(remainder, u64!(2));
        (lo4, hi4) = wmul(state[4], state[5]);

        state[5] ^= read_u64_r(remainder, u64!(1));
        state[0] ^= read_u64_r(remainder, u64!(0));
        (lo5, hi5) = wmul(state[5], state[0]);

        let mut i = state[0].wrapping_sub(state[1]);
        let mut j = state[2].wrapping_sub(state[3]);
        let mut k = state[4].wrapping_sub(state[5]);

        let rot = tot_len as u32 & 63;
        i = i.rotate_left(rot);
        j = j.rotate_right(rot);
        k ^= tot_len;

        i = i.wrapping_add(lo3 ^ hi3 ^ lo4 ^ hi4);
        j = j.wrapping_add(lo5 ^ hi5 ^ lo0 ^ hi0);
        k = k.wrapping_add(lo1 ^ hi1 ^ lo2 ^ hi2);

        (i, j, k)
    }
}

//------------------------------------------------------------------------------

#[cfg(test)]
mod verify {
    use super::*;

    #[test]
    fn hash_verification() {
        assert_eq!(
            0x9BA8FC03,
            hashverify::compute(64, |bytes, seed, out| out
                .copy_from_slice(&hash(bytes, seed).to_le_bytes()))
        );
        assert_eq!(
            0x15C9AC7B,
            hashverify::compute(128, |bytes, seed, out| out
                .copy_from_slice(&hash_128(bytes, seed).to_le_bytes()))
        );
        assert_eq!(
            0x6B7DE711,
            hashverify::compute(64, |bytes, seed, out| out
                .copy_from_slice(&bfast::hash(bytes, seed).to_le_bytes()))
        );
        assert_eq!(
            0x4B7DD85C,
            hashverify::compute(128, |bytes, seed, out| out
                .copy_from_slice(&bfast::hash_128(bytes, seed).to_le_bytes()))
        );
    }
}
