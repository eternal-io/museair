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
#![doc = include_str!("../CRATES.IO-README.md")]
#![doc(html_logo_url = "https://github.com/eternal-io/museair/blob/master/MuseAir-icon-light.png?raw=true")]
#![warn(missing_docs)]

/// Currently algorithm version.
///
/// Note that this is **NOT** the implementation version.
///
/// If you want to see an older version of the algorithm, check out the historical commits
/// for [`museair.cpp`](https://github.com/eternal-io/museair/blob/master/museair.cpp) in repository root.
pub const ALGORITHM_VERSION: &str = "0.4-rc1";

type State = [u64; 6];

//------------------------------------------------------------------------------

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

//------------------------------------------------------------------------------

#[inline(always)]
const fn read_u32(bytes: &[u8]) -> u64 {
    u32::from_le_bytes(*bytes.first_chunk().unwrap()) as u64
}
#[inline(always)]
const fn read_u32_r(bytes: &[u8]) -> u64 {
    u32::from_le_bytes(*bytes.last_chunk().unwrap()) as u64
}

#[inline(always)]
const fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(*bytes.first_chunk().unwrap())
}
#[inline(always)]
const fn read_u64_r(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(*bytes.last_chunk().unwrap())
}

#[inline(always)]
const fn read_short(bytes: &[u8]) -> (u64, u64) {
    let len = bytes.len();
    match len {
        4.. => {
            let off = (len & 24) >> (len >> 3); // len >= 8 ? 4 : 0
            let head = read_u32(bytes);
            let head_off = read_u32(bytes.split_at(off).1);
            let tail = read_u32_r(bytes);
            let tail_off = read_u32_r(bytes.split_at(len - off).0);

            (head << 32 | tail, head_off << 32 | tail_off)
        }

        1..=3 => {
            // MSB <-> LSB
            // [0] [0] [0] @ len == 1 (0b01)
            // [0] [1] [1] @ len == 2 (0b10)
            // [0] [1] [2] @ len == 3 (0b11)
            let fst = bytes[0] as u64;
            let snd = bytes[len >> 1] as u64;
            let thd = bytes[len - 1] as u64;

            (fst << 48 | snd << 24 | thd, 0)
        }

        0 => (0, 0),
    }
}

//------------------------------------------------------------------------------

// #[inline(always)]
// const fn hash_short_64<const BFAST: bool>(bytes: &[u8], seed: u64) -> u64 {
//     let (mut i, mut j) = unsafe { hash_short_common(bytes.as_ptr(), bytes.len(), seed) };

//     let (lo, hi) = wmul(i ^ CONSTANT[2], j ^ CONSTANT[3]);
//     if !BFAST {
//         i ^= lo;
//         j ^= hi;
//     } else {
//         i = lo;
//         j = hi;
//     }

//     let (lo, hi) = wmul(i ^ CONSTANT[4], j ^ CONSTANT[5]);
//     if !BFAST {
//         i ^ j ^ lo ^ hi
//     } else {
//         lo ^ hi
//     }
// }

// #[inline(always)]
// const fn hash_short_common(bytes: *const u8, len: usize, seed: u64) -> (u64, u64) {
//     let len_ = len as u64;
//     let (lo, hi) = wmul(seed ^ CONSTANT[0], len_ ^ CONSTANT[1]);

//     let (mut i, mut j) = read_short(bytes, len.min(u64!(2)));
//     i ^= len_ ^ lo;
//     j ^= seed ^ hi;

//     if unlikely(len > u64!(2)) {
//         let (u, v) = read_short(bytes.add(u64!(2)), len.sub(u64!(2)));
//         let (lo0, hi0) = wmul(CONSTANT[2], CONSTANT[3] ^ u);
//         let (lo1, hi1) = wmul(CONSTANT[4], CONSTANT[5] ^ v);
//         i ^= lo0 ^ hi1;
//         j ^= lo1 ^ hi0;
//     }

//     (i, j)
// }
