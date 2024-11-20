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
// #![doc = include_str!("../CRATES.IO-README.md")]
#![doc = "🚧 ***Under development so no details here.*** 🚧"]
#![doc(html_logo_url = "https://github.com/eternal-io/museair/blob/master/MuseAir-icon-light.png?raw=true")]
#![warn(missing_docs)]

/// Currently algorithm version.
///
/// Note that this is NOT the implementation version.
pub const ALGORITHM_VERSION: &str = "0.3-rc6";

/// One-shot MuseAir hash with 64-bit output.
#[inline]
pub fn hash(bytes: &[u8], seed: u64) -> u64 {
    base_hash_64::<false>(bytes, seed)
}

/// One-shot MuseAir hash with 128-bit output.
///
/// Note that the 128-bit variant is designed to be **as fast as** the 64-bit variant,
/// so you can use it without worrying about performance if necessary.
#[inline]
pub fn hash_128(bytes: &[u8], seed: u64) -> u128 {
    base_hash_128::<false>(bytes, seed)
}

/// The `-BFast` variant is faster but *less* immune to blinding multiplication.
///
/// ("less" here means when it actually happens, it will only result in the most recent state being lost,
/// rather than all the past state of a stripe being catastrophically lost!)
pub mod bfast {
    use super::*;

    /// One-shot MuseAir-BFast hash with 64-bit output.
    #[inline]
    pub fn hash(bytes: &[u8], seed: u64) -> u64 {
        base_hash_64::<true>(bytes, seed)
    }

    /// One-shot MuseAir-BFast hash with 128-bit output.
    ///
    /// Note that the 128-bit variant is designed to be **as fast as** the 64-bit variant,
    /// so you can use it without worrying about performance if necessary.
    #[inline]
    pub fn hash_128(bytes: &[u8], seed: u64) -> u128 {
        base_hash_128::<true>(bytes, seed)
    }
}

//------------------------------------------------------------------------------

/// `AiryAi(0)` calculated by Y-Cruncher.
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

macro_rules! u64x {
    ($n:literal) => {
        $n * 8
    };
}

/*--------------------- 🛰 Safe Rust only slows me down. ---------------------*/

use core::ops::Sub;

#[inline(always)]
unsafe fn read_u32(bytes: *const u8) -> u64 {
    u32::from_le_bytes(*(bytes as *const [u8; 4])) as u64
}

#[inline(always)]
unsafe fn read_u64(bytes: *const u8) -> u64 {
    u64::from_le_bytes(*(bytes as *const [u8; 8]))
}

#[inline(always)]
unsafe fn read_short(bytes: *const u8, len: usize) -> (u64, u64) {
    if len >= 4 {
        let off = (len & 24) >> (len >> 3);
        (
            (read_u32(bytes) << 32) | read_u32(bytes.add(len - 4)),
            (read_u32(bytes.add(off)) << 32) | read_u32(bytes.add(len - 4 - off)),
        )
    } else if len > 0 {
        (
            // MSB <-> LSB
            // [0] [0] [0] @ len == 1 (0b01)
            // [0] [1] [1] @ len == 2 (0b10)
            // [0] [1] [2] @ len == 3 (0b11)
            ((*bytes as u64) << 48) | ((*bytes.add(len >> 1) as u64) << 24) | (*bytes.add(len - 1) as u64),
            0,
        )
    } else {
        (0, 0)
    }
}

#[inline(always)]
fn _mumix(mut state_p: u64, mut state_q: u64, input_p: u64, input_q: u64) -> (u64, u64) {
    state_p ^= input_p;
    state_q ^= input_q;
    let (lo, hi) = wmul(state_p, state_q);
    state_p ^= lo;
    state_q ^= hi;
    (state_p, state_q)
}

//------------------------------------------------------------------------------

#[inline(always)]
fn hash_short_64<const BFAST: bool>(bytes: &[u8], seed: u64) -> u64 {
    let (mut i, mut j) = unsafe { hash_short_inner(bytes.as_ptr(), bytes.len(), seed) };

    i ^= CONSTANT[2];
    j ^= CONSTANT[3];

    let (lo, hi) = wmul(i, j);

    if !BFAST {
        i ^= lo ^ CONSTANT[4];
        j ^= hi ^ CONSTANT[5];
    } else {
        i = lo ^ CONSTANT[4];
        j = hi ^ CONSTANT[5];
    }

    let (lo, hi) = wmul(i, j);

    if !BFAST {
        i ^ j ^ lo ^ hi
    } else {
        lo ^ hi
    }
}

#[inline(always)]
fn hash_short_128(bytes: &[u8], seed: u64) -> u128 {
    let (mut i, mut j) = unsafe { hash_short_inner(bytes.as_ptr(), bytes.len(), seed) };
    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(i ^ CONSTANT[2], j ^ CONSTANT[3]);
    i = lo0 ^ hi1;
    j = lo1 ^ hi0;
    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(i ^ CONSTANT[4], j ^ CONSTANT[5]);
    u64s_to_u128(lo0 ^ hi1, lo1 ^ hi0)
}

#[inline(always)]
unsafe fn hash_short_inner(bytes: *const u8, len: usize, seed: u64) -> (u64, u64) {
    let len_ = len as u64;
    let (lo, hi) = wmul(seed ^ CONSTANT[0], len_ ^ CONSTANT[1]);

    let (mut i, mut j) = read_short(bytes, len.min(u64x!(2)));
    i ^= len_ ^ lo;
    j ^= seed ^ hi;

    if unlikely(len > u64x!(2)) {
        let (u, v) = read_short(bytes.add(u64x!(2)), len.sub(u64x!(2)));
        let (lo0, hi0) = wmul(CONSTANT[2], CONSTANT[3] ^ u);
        let (lo1, hi1) = wmul(CONSTANT[4], CONSTANT[5] ^ v);
        i ^= lo0 ^ hi1;
        j ^= lo1 ^ hi0;
    }

    (i, j)
}

//------------------------------------------------------------------------------

#[inline(never)]
fn hash_loong_64<const BFAST: bool>(bytes: &[u8], seed: u64) -> u64 {
    let (i, j, k) = unsafe { hash_loong_inner::<BFAST>(bytes.as_ptr(), bytes.len(), seed) };
    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(j, k);
    let (lo2, hi2) = wmul(k, i);
    (lo0 ^ hi2).wrapping_add(lo1 ^ hi0).wrapping_add(lo2 ^ hi1)
}

#[inline(never)]
fn hash_loong_128<const BFAST: bool>(bytes: &[u8], seed: u64) -> u128 {
    let (i, j, k) = unsafe { hash_loong_inner::<BFAST>(bytes.as_ptr(), bytes.len(), seed) };
    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(j, k);
    let (lo2, hi2) = wmul(k, i);
    u64s_to_u128(lo0 ^ lo1 ^ hi2, hi0 ^ hi1 ^ lo2)
}

#[inline(always)]
unsafe fn hash_loong_inner<const BFAST: bool>(bytes: *const u8, len: usize, seed: u64) -> (u64, u64, u64) {
    let mut p = bytes;
    let mut q = len;

    let mut state = [
        CONSTANT[0].wrapping_add(seed),
        CONSTANT[1].wrapping_sub(seed),
        CONSTANT[2] ^ seed,
        CONSTANT[3].wrapping_add(seed),
        CONSTANT[4].wrapping_sub(seed),
        CONSTANT[5] ^ seed,
    ];

    if unlikely(q >= u64x!(12)) {
        let mut ring_prev = CONSTANT[6];

        while likely(q >= u64x!(12)) {
            if !BFAST {
                state[0] ^= read_u64(p.add(u64x!(0)));
                state[1] ^= read_u64(p.add(u64x!(1)));
                let (lo0, hi0) = wmul(state[0], state[1]);
                state[0] = state[0].wrapping_add(ring_prev ^ hi0);

                state[1] ^= read_u64(p.add(u64x!(2)));
                state[2] ^= read_u64(p.add(u64x!(3)));
                let (lo1, hi1) = wmul(state[1], state[2]);
                state[1] = state[1].wrapping_add(lo0 ^ hi1);

                state[2] ^= read_u64(p.add(u64x!(4)));
                state[3] ^= read_u64(p.add(u64x!(5)));
                let (lo2, hi2) = wmul(state[2], state[3]);
                state[2] = state[2].wrapping_add(lo1 ^ hi2);

                state[3] ^= read_u64(p.add(u64x!(6)));
                state[4] ^= read_u64(p.add(u64x!(7)));
                let (lo3, hi3) = wmul(state[3], state[4]);
                state[3] = state[3].wrapping_add(lo2 ^ hi3);

                state[4] ^= read_u64(p.add(u64x!(8)));
                state[5] ^= read_u64(p.add(u64x!(9)));
                let (lo4, hi4) = wmul(state[4], state[5]);
                state[4] = state[4].wrapping_add(lo3 ^ hi4);

                state[5] ^= read_u64(p.add(u64x!(10)));
                state[0] ^= read_u64(p.add(u64x!(11)));
                let (lo5, hi5) = wmul(state[5], state[0]);
                state[5] = state[5].wrapping_add(lo4 ^ hi5);

                ring_prev = lo5;
            } else {
                state[0] ^= read_u64(p.add(u64x!(0)));
                state[1] ^= read_u64(p.add(u64x!(1)));
                let (lo0, hi0) = wmul(state[0], state[1]);
                state[0] = ring_prev ^ hi0;

                state[1] ^= read_u64(p.add(u64x!(2)));
                state[2] ^= read_u64(p.add(u64x!(3)));
                let (lo1, hi1) = wmul(state[1], state[2]);
                state[1] = lo0 ^ hi1;

                state[2] ^= read_u64(p.add(u64x!(4)));
                state[3] ^= read_u64(p.add(u64x!(5)));
                let (lo2, hi2) = wmul(state[2], state[3]);
                state[2] = lo1 ^ hi2;

                state[3] ^= read_u64(p.add(u64x!(6)));
                state[4] ^= read_u64(p.add(u64x!(7)));
                let (lo3, hi3) = wmul(state[3], state[4]);
                state[3] = lo2 ^ hi3;

                state[4] ^= read_u64(p.add(u64x!(8)));
                state[5] ^= read_u64(p.add(u64x!(9)));
                let (lo4, hi4) = wmul(state[4], state[5]);
                state[4] = lo3 ^ hi4;

                state[5] ^= read_u64(p.add(u64x!(10)));
                state[0] ^= read_u64(p.add(u64x!(11)));
                let (lo5, hi5) = wmul(state[5], state[0]);
                state[5] = lo4 ^ hi5;

                ring_prev = lo5;
            }

            p = p.add(u64x!(12));
            q = q.sub(u64x!(12));
        }

        state[0] ^= ring_prev;
    }

    if unlikely(q >= u64x!(6)) {
        (state[0], state[1]) = _mumix(state[0], state[1], read_u64(p.add(u64x!(0))), read_u64(p.add(u64x!(1))));
        (state[2], state[3]) = _mumix(state[2], state[3], read_u64(p.add(u64x!(2))), read_u64(p.add(u64x!(3))));
        (state[4], state[5]) = _mumix(state[4], state[5], read_u64(p.add(u64x!(4))), read_u64(p.add(u64x!(5))));

        p = p.add(u64x!(6));
        q = q.sub(u64x!(6));
    }

    if likely(q >= u64x!(2)) {
        (state[0], state[3]) = _mumix(state[0], state[3], read_u64(p.add(u64x!(0))), read_u64(p.add(u64x!(1))));
        if likely(q >= u64x!(4)) {
            (state[1], state[4]) = _mumix(state[1], state[4], read_u64(p.add(u64x!(2))), read_u64(p.add(u64x!(3))));
        }
    }

    (state[2], state[5]) = _mumix(
        state[2],
        state[5],
        read_u64(p.add(q).sub(u64x!(2))),
        read_u64(p.add(q).sub(u64x!(1))),
    );

    /*-------- pre-epilogue --------*/

    let mut i = state[0].wrapping_add(state[1]);
    let mut j = state[2].wrapping_add(state[3]);
    let mut k = state[4].wrapping_add(state[5]);

    let rot = len as u32 & 63;
    i = i.rotate_left(rot);
    j = j.rotate_right(rot);
    k ^= len as u64;

    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(j, k);
    let (lo2, hi2) = wmul(k, i);
    i = lo0 ^ hi2;
    j = lo1 ^ hi0;
    k = lo2 ^ hi1;

    (i, j, k)
}

//------------------------------------------------------------------------------

#[inline(always)]
fn base_hash_64<const BFAST: bool>(bytes: &[u8], seed: u64) -> u64 {
    if likely(bytes.len() <= u64x!(4)) {
        hash_short_64::<BFAST>(bytes, seed)
    } else {
        hash_loong_64::<BFAST>(bytes, seed)
    }
}

#[inline(always)]
fn base_hash_128<const BFAST: bool>(bytes: &[u8], seed: u64) -> u128 {
    if likely(bytes.len() <= u64x!(4)) {
        hash_short_128(bytes, seed)
    } else {
        hash_loong_128::<BFAST>(bytes, seed)
    }
}

//------------------------------------------------------------------------------

#[cfg(all(test, target_endian = "little"))]
mod verify {
    use super::*;

    #[test]
    fn verification_code() {
        assert_eq!(
            0x4F7AF44C,
            hashverify::compute(64, |bytes, seed, out| out
                .copy_from_slice(&hash(bytes, seed).to_le_bytes()))
        );
        assert_eq!(
            0xEFACD140,
            hashverify::compute(128, |bytes, seed, out| out
                .copy_from_slice(&hash_128(bytes, seed).to_le_bytes()))
        );
        assert_eq!(
            0x4E8C0789,
            hashverify::compute(64, |bytes, seed, out| out
                .copy_from_slice(&bfast::hash(bytes, seed).to_le_bytes()))
        );
        assert_eq!(
            0x7CCE23A2,
            hashverify::compute(128, |bytes, seed, out| out
                .copy_from_slice(&bfast::hash_128(bytes, seed).to_le_bytes()))
        );
    }
}
