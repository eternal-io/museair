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
pub const ALGORITHM_VERSION: &str = "0.3";

/// Incremental MuseAir hasher.
///
/// Due to its incremental nature, it's much slower than one-shot functions for small keys.
/// Consider [musemap](https://crates.io/crates/musemap) for hashmap use case.
pub type Hasher = BaseHasher<false>;

/// One-shot MuseAir hash with 64-bit output.
#[inline]
pub fn hash(bytes: &[u8], seed: u64) -> u64 {
    base_hash_64::<false>(bytes, seed)
}

/// One-shot MuseAir hash with 128-bit output.
#[inline]
pub fn hash_128(bytes: &[u8], seed: u64) -> u128 {
    base_hash_128::<false>(bytes, seed)
}

/// The `BFast` variant.
pub mod bfast {
    use super::*;

    /// Incremental MuseAir-BFast hasher.
    ///
    /// Due to its incremental nature, it's much slower than one-shot functions for small keys.
    /// Consider [musemap](https://crates.io/crates/musemap) for hashmap use case.
    pub type Hasher = BaseHasher<true>;

    /// One-shot MuseAir-BFast hash with 64-bit output.
    #[inline]
    pub fn hash(bytes: &[u8], seed: u64) -> u64 {
        base_hash_64::<true>(bytes, seed)
    }

    /// One-shot MuseAir-BFast hash with 128-bit output.
    #[inline]
    pub fn hash_128(bytes: &[u8], seed: u64) -> u128 {
        base_hash_128::<true>(bytes, seed)
    }
}

//--------------------------------------------------------------------------------------------------

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

macro_rules! u64x {
    ($n:literal) => {
        $n * 8
    };
}

/*------------------------------- 🛰 Safe Rust only slows me down. -------------------------------*/

use core::{fmt, ops::Sub};

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
fn _mumix<const BFAST: bool>(mut state_p: u64, mut state_q: u64, input_p: u64, input_q: u64) -> (u64, u64) {
    if !BFAST {
        state_p ^= input_p;
        state_q ^= input_q;
        let (lo, hi) = wmul(state_p, state_q);
        (state_p ^ lo, state_q ^ hi)
    } else {
        wmul(state_p ^ input_p, state_q ^ input_q)
    }
}

//--------------------------------------------------------------------------------------------------

#[inline(always)]
fn hash_short_64<const BFAST: bool>(bytes: &[u8], seed: u64) -> u64 {
    let (mut i, mut j) = unsafe { hash_short_common(bytes.as_ptr(), bytes.len(), seed) };

    let (lo, hi) = wmul(i ^ CONSTANT[2], j ^ CONSTANT[3]);
    if !BFAST {
        i ^= lo;
        j ^= hi;
    } else {
        i = lo;
        j = hi;
    }

    let (lo, hi) = wmul(i ^ CONSTANT[4], j ^ CONSTANT[5]);
    if !BFAST {
        i ^ j ^ lo ^ hi
    } else {
        lo ^ hi
    }
}

#[inline(always)]
fn hash_short_128(bytes: &[u8], seed: u64) -> u128 {
    let (mut i, mut j) = unsafe { hash_short_common(bytes.as_ptr(), bytes.len(), seed) };
    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(i ^ CONSTANT[2], j ^ CONSTANT[3]);
    i = lo0 ^ hi1;
    j = lo1 ^ hi0;
    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(i ^ CONSTANT[4], j ^ CONSTANT[5]);
    u64s_to_u128(lo0 ^ hi1, lo1 ^ hi0)
}

#[inline(always)]
unsafe fn hash_short_common(bytes: *const u8, len: usize, seed: u64) -> (u64, u64) {
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

//--------------------------------------------------------------------------------------------------

#[inline(never)]
fn hash_loong_64<const BFAST: bool>(bytes: &[u8], seed: u64) -> u64 {
    unsafe { epilogue_64(hash_loong_common::<BFAST>(bytes.as_ptr(), bytes.len(), seed)) }
}

#[inline(never)]
fn hash_loong_128<const BFAST: bool>(bytes: &[u8], seed: u64) -> u128 {
    unsafe { epilogue_128(hash_loong_common::<BFAST>(bytes.as_ptr(), bytes.len(), seed)) }
}

#[inline(always)]
unsafe fn hash_loong_common<const BFAST: bool>(bytes: *const u8, len: usize, seed: u64) -> (u64, u64, u64) {
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
            ring_prev = frac_tower::<BFAST>(&mut state, ring_prev, p);
            p = p.add(u64x!(12));
            q = q.sub(u64x!(12));
        }

        state[0] ^= ring_prev;
    }

    frac_final::<BFAST>(&mut state, p, q);

    epilogue_common(state, len)
}

/// Must remainder `u64x!(12)` or more bytes otherwise UB.
#[inline(always)]
unsafe fn frac_tower<const BFAST: bool>(state: &mut [u64; 6], ring_prev: u64, p: *const u8) -> u64 {
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

        lo5
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

        lo5
    }
}

/// Must remainder `u64x!(2)` or more bytes otherwise UB.
#[inline(always)]
unsafe fn frac_final<const BFAST: bool>(state: &mut [u64; 6], mut p: *const u8, mut q: usize) {
    if unlikely(q >= u64x!(6)) {
        (state[0], state[1]) =
            _mumix::<BFAST>(state[0], state[1], read_u64(p.add(u64x!(0))), read_u64(p.add(u64x!(1))));
        (state[2], state[3]) =
            _mumix::<BFAST>(state[2], state[3], read_u64(p.add(u64x!(2))), read_u64(p.add(u64x!(3))));
        (state[4], state[5]) =
            _mumix::<BFAST>(state[4], state[5], read_u64(p.add(u64x!(4))), read_u64(p.add(u64x!(5))));
        p = p.add(u64x!(6));
        q = q.sub(u64x!(6));
    }

    if likely(q >= u64x!(2)) {
        (state[0], state[3]) =
            _mumix::<BFAST>(state[0], state[3], read_u64(p.add(u64x!(0))), read_u64(p.add(u64x!(1))));
        if likely(q >= u64x!(4)) {
            (state[1], state[4]) =
                _mumix::<BFAST>(state[1], state[4], read_u64(p.add(u64x!(2))), read_u64(p.add(u64x!(3))));
        }
    }

    (state[2], state[5]) = _mumix::<BFAST>(
        state[2],
        state[5],
        read_u64(p.add(q).sub(u64x!(2))),
        read_u64(p.add(q).sub(u64x!(1))),
    );
}

// Note that only `_loong` requires separated `epilogue`.

#[inline(always)]
fn epilogue_common(state: [u64; 6], tot_len: usize) -> (u64, u64, u64) {
    let mut i = state[0].wrapping_sub(state[1]);
    let mut j = state[2].wrapping_sub(state[3]);
    let mut k = state[4].wrapping_sub(state[5]);

    let rot = tot_len as u32 & 63;
    i = i.rotate_left(rot);
    j = j.rotate_right(rot);
    k ^= tot_len as u64;

    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(j, k);
    let (lo2, hi2) = wmul(k, i);
    i = lo0 ^ hi2;
    j = lo1 ^ hi0;
    k = lo2 ^ hi1;

    (i, j, k)
}

#[inline(always)]
fn epilogue_64(triple: (u64, u64, u64)) -> u64 {
    let (i, j, k) = triple;
    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(j, k);
    let (lo2, hi2) = wmul(k, i);
    (lo0 ^ hi2).wrapping_add(lo1 ^ hi0).wrapping_add(lo2 ^ hi1)
}

#[inline(always)]
fn epilogue_128(triple: (u64, u64, u64)) -> u128 {
    let (i, j, k) = triple;
    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(j, k);
    let (lo2, hi2) = wmul(k, i);
    u64s_to_u128(lo0 ^ lo1 ^ hi2, hi0 ^ hi1 ^ lo2)
}

//--------------------------------------------------------------------------------------------------

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

/// Common incremental hasher that implemented both `Standard` and `BFast` variants.
/// Use [`Hasher`] or [`bfast::Hasher`] type aliases.
#[repr(C)]
#[derive(Clone)]
pub struct BaseHasher<const BFAST: bool> {
    /// It is guaranteed `buffered_len < 96` after arbitrary write,
    /// that is to say `frac_tower` is eager executed.
    buffer: [u8; 96],
    buffered_len: usize,
    processed_len: u64,

    state: [u64; 6],
    ring_prev: u64,
}

#[allow(missing_docs)]
impl<const BFAST: bool> BaseHasher<BFAST> {
    pub const fn new() -> Self {
        Self::with_seed(0)
    }

    pub const fn with_seed(seed: u64) -> Self {
        Self {
            buffer: [0x00; 96],
            buffered_len: 0,
            processed_len: 0,

            state: [
                CONSTANT[0].wrapping_add(seed),
                CONSTANT[1].wrapping_sub(seed),
                CONSTANT[2] ^ seed,
                CONSTANT[3].wrapping_add(seed),
                CONSTANT[4].wrapping_sub(seed),
                CONSTANT[5] ^ seed,
            ],
            ring_prev: CONSTANT[6],
        }
    }

    #[inline(always)]
    fn restore_seed(&self) -> u64 {
        debug_assert!(self.processed_len == 0);
        self.state[0].wrapping_sub(CONSTANT[0])
    }

    pub fn write(&mut self, mut bytes: &[u8]) {
        let vacancy = u64x!(12) - self.buffered_len;
        if bytes.len() < vacancy {
            self.buffer[self.buffered_len..][..bytes.len()].copy_from_slice(bytes);
            self.buffered_len += bytes.len();
            return;
        } else {
            self.buffer[self.buffered_len..][..vacancy].copy_from_slice(&bytes[..vacancy]);
            self.buffered_len = 0;
            bytes = &bytes[vacancy..];
        }

        self.ring_prev = unsafe { frac_tower::<BFAST>(&mut self.state, self.ring_prev, self.buffer.as_ptr()) };
        self.processed_len = self.processed_len.wrapping_add(u64x!(12));
        while likely(bytes.len() >= u64x!(12)) {
            self.ring_prev = unsafe { frac_tower::<BFAST>(&mut self.state, self.ring_prev, bytes.as_ptr()) };
            self.processed_len = self.processed_len.wrapping_add(u64x!(12));
            bytes = &bytes[u64x!(12)..];
        }

        self.buffer[..bytes.len()].copy_from_slice(bytes);
        self.buffered_len = bytes.len();
    }

    #[inline(always)]
    fn contiguous_remainder(&self) -> ([u8; 96], usize) {
        let (younger, older) = self.buffer.split_at(self.buffered_len);
        let mut buffer = [0x00; 96];
        buffer[..older.len()].copy_from_slice(older);
        buffer[older.len()..].copy_from_slice(younger);
        (buffer, older.len())
    }

    pub fn finish(&self) -> u64 {
        let tot_len = self.processed_len.wrapping_add(self.buffered_len as u64);
        if unlikely(tot_len <= u64x!(4)) {
            hash_short_64::<BFAST>(&self.buffer[..self.buffered_len], self.restore_seed())
        } else {
            let (remainder, delta) = self.contiguous_remainder();
            let mut state = self.state;
            if likely(tot_len >= u64x!(12)) {
                state[0] ^= self.ring_prev;
            }
            unsafe { frac_final::<BFAST>(&mut state, remainder.as_ptr().add(delta), self.buffered_len) };
            epilogue_64(epilogue_common(state, tot_len as usize))
        }
    }

    pub fn finish_128(&self) -> u128 {
        let tot_len = self.processed_len.wrapping_add(self.buffered_len as u64);
        if unlikely(tot_len <= u64x!(4)) {
            hash_short_128(&self.buffer[..self.buffered_len], self.restore_seed())
        } else {
            let (remainder, delta) = self.contiguous_remainder();
            let mut state = self.state;
            if likely(tot_len >= u64x!(12)) {
                state[0] ^= self.ring_prev;
            }
            unsafe { frac_final::<BFAST>(&mut state, remainder.as_ptr().add(delta), self.buffered_len) };
            epilogue_128(epilogue_common(state, tot_len as usize))
        }
    }
}

impl<const BFAST: bool> Default for BaseHasher<BFAST> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BFAST: bool> fmt::Debug for BaseHasher<BFAST> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match !BFAST {
            true => f.write_str("museair::Hasher { ... }"),
            false => f.write_str("museair::bfast::Hasher { ... }"),
        }
    }
}

impl<const BFAST: bool> core::hash::Hasher for BaseHasher<BFAST> {
    fn finish(&self) -> u64 {
        self.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.write(bytes);
    }
}

//--------------------------------------------------------------------------------------------------

#[cfg(all(test, target_endian = "little"))]
mod verify {
    use super::*;
    use rapidhash::rapidrng_fast;
    extern crate std;

    #[test]
    fn verification_code() {
        assert_eq!(
            0xF89F1683,
            hashverify::compute(64, |bytes, seed, out| out
                .copy_from_slice(&hash(bytes, seed).to_le_bytes()))
        );
        assert_eq!(
            0xD3DFE238,
            hashverify::compute(128, |bytes, seed, out| out
                .copy_from_slice(&hash_128(bytes, seed).to_le_bytes()))
        );
        assert_eq!(
            0xC61BEE56,
            hashverify::compute(64, |bytes, seed, out| out
                .copy_from_slice(&bfast::hash(bytes, seed).to_le_bytes()))
        );
        assert_eq!(
            0x27939BF1,
            hashverify::compute(128, |bytes, seed, out| out
                .copy_from_slice(&bfast::hash_128(bytes, seed).to_le_bytes()))
        );
    }

    #[test]
    fn one_shot_eq_streamed() {
        macro_rules! one_shot_vs_streamed {
            ($hash:path, $hasher:ty, $finish:ident) => {
                for n in 0..1024 {
                    let bytes = std::vec![0xAB; n];
                    let one_shot = $hash(&bytes, n as u64);
                    let streamed = {
                        let mut hasher = <$hasher>::with_seed(n as u64);
                        let (x, y, z) = random_split(&bytes);
                        hasher.write(x);
                        hasher.write(y);
                        hasher.write(z);
                        hasher.$finish()
                    };
                    assert_eq!(one_shot, streamed, "len == {}", n);
                }
            };
        }

        one_shot_vs_streamed!(hash, Hasher, finish);
        one_shot_vs_streamed!(hash_128, Hasher, finish_128);
        one_shot_vs_streamed!(bfast::hash, bfast::Hasher, finish);
        one_shot_vs_streamed!(bfast::hash_128, bfast::Hasher, finish_128);
    }

    fn random_split(bytes: &[u8]) -> (&[u8], &[u8], &[u8]) {
        match bytes.len() as u64 {
            0 => (&[], &[], &[]),
            1 => (&bytes[0..1], &[], &[]),
            2 => (&bytes[0..1], &bytes[1..2], &[]),
            3 => (&bytes[0..1], &bytes[1..2], &bytes[2..3]),
            n => {
                let p = rapidrng_fast(&mut n.clone()) % (n - 2);
                let q = rapidrng_fast(&mut !n) % (n - p);
                let (x, y) = bytes.split_at(p as usize);
                let (y, z) = y.split_at(q as usize);
                (x, y, z)
            }
        }
    }
}
