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

use super::*;
use core::fmt;

/// Streamed MuseAir hasher.
pub type Hasher = BaseHasher<false>;

/// ``AiryAi(0)`` calculated by Y-Cruncher. (0..48)
const DEFAULT_SECRET: [u64; 6] = [
    0x5ae31e589c56e17a,
    0x96d7bb04e64f6da9,
    0x7ab1006b26f9eb64,
    0x21233394220b8457,
    0x047cb9557c9f3b43,
    0xd24f2590c0bcee28,
];
/// ``AiryAi(0)`` calculated by Y-Cruncher. (48..56)
const INIT_RING_PREV: u64 = 0x33ea8f71bb6016d8;

type State = [u64; 6];

macro_rules! seg {
    ($n:literal) => {
        $n * 8
    };
}

#[inline(always)]
fn read_u32(bytes: &[u8]) -> u64 {
    u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as u64
}
#[inline(always)]
fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[0..8].try_into().unwrap())
}
#[inline(always)]
fn read_short(bytes: &[u8]) -> (u64, u64) {
    let len = bytes.len();
    if len >= 4 {
        let off = (len & 24) >> (len >> 3);
        (
            (read_u32(&bytes[0..]) << 32) | read_u32(&bytes[len - 4..]),
            (read_u32(&bytes[off..]) << 32) | read_u32(&bytes[len - 4 - off..]),
        )
    } else if len > 0 {
        (
            ((bytes[0] as u64) << 48) | ((bytes[len >> 1] as u64) << 24) | (bytes[len - 1] as u64),
            // [0] [0] [0] @ len == 1 (0b01)
            // [0] [1] [1] @ len == 2 (0b10)
            // [0] [1] [2] @ len == 3 (0b11)
            // MSB <-> LSB
            0,
        )
    } else {
        (0, 0)
    }
}

#[inline(always)]
const fn _frac_6<const BFAST: bool>((mut s, mut t): (u64, u64), (v, w): (u64, u64)) -> (u64, u64) {
    s ^= v;
    t ^= w;
    if !BFAST {
        let (lo, hi) = wmul(s, t);
        (s ^ lo, t ^ hi)
    } else {
        wmul(s, t)
    }
}
#[inline(always)]
const fn _frac_3<const BFAST: bool>((s, mut t): (u64, u64), v: u64) -> (u64, u64) {
    t ^= v;
    if !BFAST {
        let (lo, hi) = wmul(s, t);
        (s ^ lo, t ^ hi)
    } else {
        wmul(s, t)
    }
}
#[inline(always)]
const fn _chixx(t: u64, u: u64, v: u64) -> (u64, u64, u64) {
    (t ^ (!u & v), u ^ (!v & t), v ^ (!t & u))
}

#[inline(always)]
fn _tower_layer_12<const BFAST: bool>(mut state: State, bytes: &[u8], ring_prev: u64) -> (State, u64) {
    if !BFAST {
        state[0] ^= read_u64(&bytes[seg!(0)..]);
        state[1] ^= read_u64(&bytes[seg!(1)..]);
        let (lo0, hi0) = wmul(state[0], state[1]);
        state[0] = state[0].wrapping_add(ring_prev ^ hi0);

        state[1] ^= read_u64(&bytes[seg!(2)..]);
        state[2] ^= read_u64(&bytes[seg!(3)..]);
        let (lo1, hi1) = wmul(state[1], state[2]);
        state[1] = state[1].wrapping_add(lo0 ^ hi1);

        state[2] ^= read_u64(&bytes[seg!(4)..]);
        state[3] ^= read_u64(&bytes[seg!(5)..]);
        let (lo2, hi2) = wmul(state[2], state[3]);
        state[2] = state[2].wrapping_add(lo1 ^ hi2);

        state[3] ^= read_u64(&bytes[seg!(6)..]);
        state[4] ^= read_u64(&bytes[seg!(7)..]);
        let (lo3, hi3) = wmul(state[3], state[4]);
        state[3] = state[3].wrapping_add(lo2 ^ hi3);

        state[4] ^= read_u64(&bytes[seg!(8)..]);
        state[5] ^= read_u64(&bytes[seg!(9)..]);
        let (lo4, hi4) = wmul(state[4], state[5]);
        state[4] = state[4].wrapping_add(lo3 ^ hi4);

        state[5] ^= read_u64(&bytes[seg!(10)..]);
        state[0] ^= read_u64(&bytes[seg!(11)..]);
        let (lo5, hi5) = wmul(state[5], state[0]);
        state[5] = state[5].wrapping_add(lo4 ^ hi5);

        (state, lo5)
    } else {
        state[0] ^= read_u64(&bytes[seg!(0)..]);
        state[1] ^= read_u64(&bytes[seg!(1)..]);
        let (lo0, hi0) = wmul(state[0], state[1]);
        state[0] = ring_prev ^ hi0;

        state[1] ^= read_u64(&bytes[seg!(2)..]);
        state[2] ^= read_u64(&bytes[seg!(3)..]);
        let (lo1, hi1) = wmul(state[1], state[2]);
        state[1] = lo0 ^ hi1;

        state[2] ^= read_u64(&bytes[seg!(4)..]);
        state[3] ^= read_u64(&bytes[seg!(5)..]);
        let (lo2, hi2) = wmul(state[2], state[3]);
        state[2] = lo1 ^ hi2;

        state[3] ^= read_u64(&bytes[seg!(6)..]);
        state[4] ^= read_u64(&bytes[seg!(7)..]);
        let (lo3, hi3) = wmul(state[3], state[4]);
        state[3] = lo2 ^ hi3;

        state[4] ^= read_u64(&bytes[seg!(8)..]);
        state[5] ^= read_u64(&bytes[seg!(9)..]);
        let (lo4, hi4) = wmul(state[4], state[5]);
        state[4] = lo3 ^ hi4;

        state[5] ^= read_u64(&bytes[seg!(10)..]);
        state[0] ^= read_u64(&bytes[seg!(11)..]);
        let (lo5, hi5) = wmul(state[5], state[0]);
        state[5] = lo4 ^ hi5;

        (state, lo5)
    }
}
#[inline(always)]
fn _tower_layer_6<const BFAST: bool>(mut state: State, bytes: &[u8]) -> State {
    (state[0], state[1]) = _frac_6::<BFAST>(
        (state[0], state[1]),
        (read_u64(&bytes[seg!(0)..]), read_u64(&bytes[seg!(1)..])),
    );
    (state[2], state[3]) = _frac_6::<BFAST>(
        (state[2], state[3]),
        (read_u64(&bytes[seg!(2)..]), read_u64(&bytes[seg!(3)..])),
    );
    (state[4], state[5]) = _frac_6::<BFAST>(
        (state[4], state[5]),
        (read_u64(&bytes[seg!(4)..]), read_u64(&bytes[seg!(5)..])),
    );
    state
}
#[inline(always)]
fn _tower_layer_3<const BFAST: bool>(mut state: State, bytes: &[u8]) -> State {
    (state[0], state[3]) = _frac_3::<BFAST>((state[0], state[3]), read_u64(&bytes[seg!(0)..]));
    (state[1], state[4]) = _frac_3::<BFAST>((state[1], state[4]), read_u64(&bytes[seg!(1)..]));
    (state[2], state[5]) = _frac_3::<BFAST>((state[2], state[5]), read_u64(&bytes[seg!(2)..]));
    state
}
#[inline(always)]
fn _tower_layer_0(mut state: State, bytes: &[u8], tot_len: u64) -> (u64, u64, u64) {
    let (mut i, mut j, mut k);

    let len = bytes.len();
    debug_assert!(len <= seg!(3));
    if len <= seg!(2) {
        (i, j) = read_short(bytes);
        k = 0;
    } else {
        i = read_u64(&bytes[seg!(0)..]);
        j = read_u64(&bytes[seg!(1)..]);
        k = read_u64(&bytes[len - seg!(1)..]);
    }

    if tot_len >= seg!(3) {
        (state[0], state[2], state[4]) = _chixx(state[0], state[2], state[4]);
        (state[1], state[3], state[5]) = _chixx(state[1], state[3], state[5]);
        i ^= state[0].wrapping_add(state[1]);
        j ^= state[2].wrapping_add(state[3]);
        k ^= state[4].wrapping_add(state[5]);
    } else {
        i ^= state[0];
        j ^= state[1];
        k ^= state[2];
    }

    (i, j, k)
}
#[inline(always)]
fn _tower_layer_x<const BFAST: bool>((mut i, mut j, mut k): (u64, u64, u64), tot_len: u64) -> (u64, u64, u64) {
    let rot = tot_len as u32 & 0b11_1111;
    (i, j, k) = _chixx(i, j, k);
    i = i.rotate_left(rot);
    j = j.rotate_right(rot);
    k ^= tot_len;
    if !BFAST {
        let (lo0, hi0) = wmul(i ^ DEFAULT_SECRET[3], j);
        let (lo1, hi1) = wmul(j ^ DEFAULT_SECRET[4], k);
        let (lo2, hi2) = wmul(k ^ DEFAULT_SECRET[5], i);
        (i ^ lo0 ^ hi2, j ^ lo1 ^ hi0, k ^ lo2 ^ hi1)
    } else {
        let (lo0, hi0) = wmul(i, j);
        let (lo1, hi1) = wmul(j, k);
        let (lo2, hi2) = wmul(k, i);
        (lo0 ^ hi2, lo1 ^ hi0, lo2 ^ hi1)
    }
}

#[inline(never)]
fn tower_loong<const BFAST: bool>(bytes: &[u8], seed: u64) -> (u64, u64, u64) {
    let tot_len = bytes.len() as u64;
    debug_assert!(tot_len > 16);
    let mut off = 0;
    let mut rem = tot_len;
    let mut state = DEFAULT_SECRET;

    state[0] = state[0].wrapping_add(seed);
    state[1] = state[1].wrapping_sub(seed);
    state[2] ^= seed;

    if rem >= seg!(12) {
        state[3] = state[3].wrapping_add(seed);
        state[4] = state[4].wrapping_sub(seed);
        state[5] ^= seed;

        let mut ring_prev = INIT_RING_PREV;
        loop {
            (state, ring_prev) = _tower_layer_12::<BFAST>(state, &bytes[off..], ring_prev);
            off += seg!(12);
            rem -= seg!(12);
            if unlikely(rem < seg!(12)) {
                break;
            }
        }

        state[0] ^= ring_prev; // If we replace this xor with add, we will lost ~1.7% performance for BFast!! (p < 0.05)
    }

    if rem >= seg!(6) {
        state = _tower_layer_6::<BFAST>(state, &bytes[off..]);
        off += seg!(6);
        rem -= seg!(6);
    }

    if rem >= seg!(3) {
        state = _tower_layer_3::<BFAST>(state, &bytes[off..]);
        off += seg!(3);
    }

    _tower_layer_x::<BFAST>(_tower_layer_0(state, &bytes[off..], tot_len), tot_len)
}
#[inline(always)]
fn tower_short(bytes: &[u8], seed: u64) -> (u64, u64) {
    let len = bytes.len() as u64;
    let (i, j) = read_short(bytes);
    let (lo, hi) = wmul(seed ^ DEFAULT_SECRET[0], len ^ DEFAULT_SECRET[1]);
    (i ^ lo ^ len, j ^ hi ^ seed)
}

#[inline(always)]
fn epi_short((mut i, mut j): (u64, u64)) -> u64 {
    i ^= DEFAULT_SECRET[2];
    j ^= DEFAULT_SECRET[3];
    let (lo, hi) = wmul(i, j);
    i ^= lo ^ DEFAULT_SECRET[4];
    j ^= hi ^ DEFAULT_SECRET[5];
    let (lo, hi) = wmul(i, j);
    i ^ j ^ lo ^ hi
}
#[inline(always)]
fn epi_short_128<const BFAST: bool>((mut i, mut j): (u64, u64)) -> u128 {
    if !BFAST {
        let (lo0, hi0) = wmul(i ^ DEFAULT_SECRET[2], j);
        let (lo1, hi1) = wmul(i, j ^ DEFAULT_SECRET[3]);
        i ^= lo0 ^ hi1;
        j ^= lo1 ^ hi0;
        let (lo0, hi0) = wmul(i ^ DEFAULT_SECRET[4], j);
        let (lo1, hi1) = wmul(i, j ^ DEFAULT_SECRET[5]);
        u64s_to_u128(i ^ lo0 ^ hi1, j ^ lo1 ^ hi0)
    } else {
        let (lo0, hi0) = wmul(i, j);
        let (lo1, hi1) = wmul(i ^ DEFAULT_SECRET[2], j ^ DEFAULT_SECRET[3]);
        i = lo0 ^ hi1;
        j = lo1 ^ hi0;
        let (lo0, hi0) = wmul(i, j);
        let (lo1, hi1) = wmul(i ^ DEFAULT_SECRET[4], j ^ DEFAULT_SECRET[5]);
        u64s_to_u128(lo0 ^ hi1, lo1 ^ hi0)
    }
}

#[inline(always)]
fn epi_loong<const BFAST: bool>((mut i, mut j, mut k): (u64, u64, u64)) -> u64 {
    if !BFAST {
        let (lo0, hi0) = wmul(i ^ DEFAULT_SECRET[0], j);
        let (lo1, hi1) = wmul(j ^ DEFAULT_SECRET[1], k);
        let (lo2, hi2) = wmul(k ^ DEFAULT_SECRET[2], i);
        i ^= lo0 ^ hi2;
        j ^= lo1 ^ hi0;
        k ^= lo2 ^ hi1;
    } else {
        let (lo0, hi0) = wmul(i, j);
        let (lo1, hi1) = wmul(j, k);
        let (lo2, hi2) = wmul(k, i);
        i = lo0 ^ hi2;
        j = lo1 ^ hi0;
        k = lo2 ^ hi1;
    }
    i.wrapping_add(j).wrapping_add(k)
}
#[inline(always)]
fn epi_loong_128<const BFAST: bool>((mut i, mut j, k): (u64, u64, u64)) -> u128 {
    if !BFAST {
        let (lo0, hi0) = wmul(i ^ DEFAULT_SECRET[0], j);
        let (lo1, hi1) = wmul(j ^ DEFAULT_SECRET[1], k);
        let (lo2, hi2) = wmul(k ^ DEFAULT_SECRET[2], i);
        i ^= lo0 ^ lo1 ^ hi2;
        j ^= hi0 ^ hi1 ^ lo2;
    } else {
        let (lo0, hi0) = wmul(i, j);
        let (lo1, hi1) = wmul(j, k);
        let (lo2, hi2) = wmul(k, i);
        i = lo0 ^ lo1 ^ hi2;
        j = hi0 ^ hi1 ^ lo2;
    }
    u64s_to_u128(i, j)
}

#[inline(always)]
fn base_hash<const BFAST: bool>(bytes: &[u8], seed: u64) -> u64 {
    if likely(bytes.len() <= seg!(2)) {
        epi_short(tower_short(bytes, seed))
    } else {
        epi_loong::<BFAST>(tower_loong::<BFAST>(bytes, seed))
    }
}
#[inline(always)]
fn base_hash_128<const BFAST: bool>(bytes: &[u8], seed: u64) -> u128 {
    if likely(bytes.len() <= seg!(2)) {
        epi_short_128::<BFAST>(tower_short(bytes, seed))
    } else {
        epi_loong_128::<BFAST>(tower_loong::<BFAST>(bytes, seed))
    }
}

/// One-shot MuseAir hash with 64-bit output.
#[inline]
pub fn hash(bytes: &[u8], seed: u64) -> u64 {
    base_hash::<false>(bytes, seed)
}
/// One-shot MuseAir hash with 128-bit output.
///
/// Note that the 128-bit variant is designed to be **as fast as** the 64-bit variant,
/// so you can use it if necessary without worrying about performance.
#[inline]
pub fn hash_128(bytes: &[u8], seed: u64) -> u128 {
    base_hash_128::<false>(bytes, seed)
}

/// The `-BFast` variant is faster but *less* immune to blinding multiplication.
///
/// ("less" here means when it actually happens, it will only result in the most recent state being lost, rather than all the past state of a stripe being catastrophically lost!)
pub mod bfast {
    use super::*;

    /// Streamed MuseAir-BFast hasher.
    pub type Hasher = BaseHasher<true>;

    /// One-shot MuseAir-BFast hash with 64-bit output.
    #[inline]
    pub fn hash(bytes: &[u8], seed: u64) -> u64 {
        base_hash::<true>(bytes, seed)
    }
    /// One-shot MuseAir-BFast hash with 128-bit output.
    ///
    /// Note that the 128-bit variant is designed to be **as fast as** the 64-bit variant,
    /// so you can use it if necessary without worrying about performance.
    #[inline]
    pub fn hash_128(bytes: &[u8], seed: u64) -> u128 {
        base_hash_128::<true>(bytes, seed)
    }
}

/// Base hasher that supports both `-Standard` and `-BFast` variants.
///
/// You should always like to use [`Hasher`] or [`bfast::Hasher`] type alias instead.
#[repr(align(8))]
#[derive(Clone)]
pub struct BaseHasher<const BFAST: bool> {
    buffer: [u8; seg!(12)],
    buffered_len: usize,
    tot_len: u64,

    state: State,
    ring_prev: u64,
}
#[allow(missing_docs)]
impl<const BFAST: bool> BaseHasher<BFAST> {
    pub const fn new() -> Self {
        Self::with_seed(0)
    }
    pub const fn with_seed(seed: u64) -> Self {
        Self {
            buffer: [0; seg!(12)],
            buffered_len: 0,
            tot_len: 0,
            state: [
                DEFAULT_SECRET[0].wrapping_add(seed),
                DEFAULT_SECRET[1].wrapping_sub(seed),
                DEFAULT_SECRET[2] ^ seed,
                DEFAULT_SECRET[3],
                DEFAULT_SECRET[4],
                DEFAULT_SECRET[5],
            ],
            ring_prev: INIT_RING_PREV,
        }
    }

    fn restore_seed(&self) -> u64 {
        debug_assert!(self.tot_len == 0);
        self.state[2] ^ DEFAULT_SECRET[2] // 😂
    }

    pub fn write(&mut self, bytes: &[u8]) {
        let off = self.buffered_len;
        let this_len = bytes.len();
        let complete = seg!(12) - off;
        if unlikely(this_len < complete) {
            self.buffer[off..off + this_len].copy_from_slice(bytes);
            self.buffered_len += this_len;
            return;
        }

        let mut state = self.state;
        if self.tot_len == 0 {
            let seed = self.restore_seed();
            state[3] = state[3].wrapping_add(seed);
            state[4] = state[4].wrapping_sub(seed);
            state[5] ^= seed;
        }

        self.buffer[off..].copy_from_slice(&bytes[..complete]);
        (state, self.ring_prev) = _tower_layer_12::<BFAST>(state, &self.buffer, self.ring_prev);
        self.tot_len = self.tot_len.wrapping_add(seg!(12));

        let blocks = bytes[complete..].chunks_exact(seg!(12));
        let remainder = blocks.remainder();
        for block in blocks {
            (state, self.ring_prev) = _tower_layer_12::<BFAST>(state, block, self.ring_prev);
            self.tot_len = self.tot_len.wrapping_add(seg!(12));
        }

        self.buffer[0..remainder.len()].copy_from_slice(remainder);
        self.buffered_len = remainder.len();

        self.state = state;
    }

    pub fn finish(&self) -> u64 {
        let bytes = &self.buffer[..self.buffered_len];
        let tot_len = self.tot_len.wrapping_add(self.buffered_len as u64);
        if unlikely(tot_len <= seg!(2)) {
            epi_short(tower_short(bytes, self.restore_seed()))
        } else {
            epi_loong::<BFAST>(Self::tower_loong(self.state, bytes, self.ring_prev, tot_len))
        }
    }

    pub fn finish_128(&self) -> u128 {
        let bytes = &self.buffer[..self.buffered_len];
        let tot_len = self.tot_len.wrapping_add(self.buffered_len as u64);
        if unlikely(tot_len <= seg!(2)) {
            epi_short_128::<BFAST>(tower_short(bytes, self.restore_seed()))
        } else {
            epi_loong_128::<BFAST>(Self::tower_loong(self.state, bytes, self.ring_prev, tot_len))
        }
    }

    fn tower_loong(mut state: State, bytes: &[u8], mut ring_prev: u64, tot_len: u64) -> (u64, u64, u64) {
        let mut off = 0;
        let mut rem = bytes.len();

        if rem == seg!(12) {
            (state, ring_prev) = _tower_layer_12::<BFAST>(state, &bytes[off..], ring_prev);
            off += seg!(12);
            rem -= seg!(12);
        }
        if tot_len >= seg!(12) {
            state[0] ^= ring_prev;
        }
        if rem >= seg!(6) {
            state = _tower_layer_6::<BFAST>(state, &bytes[off..]);
            off += seg!(6);
            rem -= seg!(6);
        }
        if rem >= seg!(3) {
            state = _tower_layer_3::<BFAST>(state, &bytes[off..]);
            off += seg!(3);
        }

        _tower_layer_x::<BFAST>(_tower_layer_0(state, &bytes[off..], tot_len), tot_len)
    }
}
impl<const BFAST: bool> Default for BaseHasher<BFAST> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const BFAST: bool> fmt::Debug for BaseHasher<BFAST> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("museair::Hasher")?;
        if BFAST {
            f.write_str("<BFast>")?;
        }
        f.write_str(" { ... }")
    }
}
impl<const BFAST: bool> core::hash::Hasher for BaseHasher<BFAST> {
    fn finish(&self) -> u64 {
        self.finish()
    }
    fn write(&mut self, bytes: &[u8]) {
        self.write(bytes)
    }
}

#[cfg(test)]
mod test_vectors {
    use super::*;
    extern crate std;
    use std::{vec, vec::Vec};

    macro_rules! one_shot_vs_streamed {
        ($hash:path, $hasher:ty, $finish:ident) => {
            (0..1024).map(|n| (n, vec![0xAB; n])).for_each(|(i, bytes)| {
                let one_shot = $hash(&bytes, 42);
                let streamed = {
                    let mut hasher = <$hasher>::with_seed(42);
                    let (x, y, z) = random_split(&bytes);
                    hasher.write(x);
                    hasher.write(y);
                    hasher.write(z);
                    hasher.$finish()
                };
                assert_eq!((i, one_shot), (i, streamed));
            })
        };
    }

    #[test]
    fn one_shot_eq_streamed() {
        fn random_split(bytes: &[u8]) -> (&[u8], &[u8], &[u8]) {
            match bytes.len() as u64 {
                0 => (&[], &[], &[]),
                1 => (&bytes[0..1], &[], &[]),
                2 => (&bytes[0..1], &bytes[1..2], &[]),
                3 => (&bytes[0..1], &bytes[1..2], &bytes[2..3]),
                n => {
                    let p = wyhash::wyrng(&mut n.clone()) % (n - 2);
                    let q = wyhash::wyrng(&mut !n) % (n - p);
                    let (x, y) = bytes.split_at(p as usize);
                    let (y, z) = y.split_at(q as usize);
                    (x, y, z)
                }
            }
        }

        one_shot_vs_streamed!(hash, Hasher, finish);
        one_shot_vs_streamed!(hash_128, Hasher, finish_128);
        one_shot_vs_streamed!(bfast::hash, bfast::Hasher, finish);
        one_shot_vs_streamed!(bfast::hash_128, bfast::Hasher, finish_128);
    }

    fn tester<T: Eq + fmt::Debug>(h: fn(&[u8], u64) -> T, res: &[T]) {
        let mut msgs = vec![vec![]];
        msgs.extend((1..=199).map(|n| vec![0xAB; n]));

        let ans = msgs.iter().map(|msg| h(&msg, 0)).collect::<Vec<_>>();
        std::println!("{:?}", ans);

        res.iter().zip(ans.into_iter()).for_each(|(e, a)| assert_eq!(*e, a));
    }

    #[test]
    fn test_hash() {
        #[rustfmt::skip] const RESULTS: &[u64] = &[
            0x0b6d39af88433ee6, 0x9cc00eea41bd3bc9, 0x32b27bb7bb9f736a, 0x4feb8452bd56e235, 0xa5114a825618597c, 0x0bdef0a3ea34a1a6, 0x956881a26db0cf30, 0x2990f2b2e70c7d05, 0x07d1c1d80535f006, 0xe86d73ddb3754d7c,
            0x31fa0d6e44a0f27e, 0x5013736ed17cbc5e, 0x69cc4eb7af802701, 0x4b1091c1d43ab72c, 0x216c965fc9ab9751, 0xc18056db002f3bbc, 0xa8aa59e62173ed5d, 0x4373103b94387939, 0xde99771e9bbd8d4c, 0xc7c381341387c5fe,
            0x90b57f4f1c69c5a7, 0xecf7fa79cb53429b, 0xcff4bfdab0f71f1e, 0xe140d89a0ff60541, 0x8a19c7f2f6b7bd61, 0x474598eb56bd2aeb, 0x79f275aa8bf11687, 0xd5cf4b1e78f89c0e, 0xac3a38a616c8915c, 0x797bb417a3babafe,
            0xc0ad6a59cafbc53b, 0x4422fdc8d2a69cda, 0x16fd16590ff35926, 0xd71e0ba325bae5c4, 0xe2b7be25a0aae8da, 0x046d5d46126d073d, 0x810f5b449ede45fe, 0x887b27b975632388, 0xc49aac01b4356752, 0x5600c945ea8879c5,
            0x44769c263bc51c7f, 0xce5c5f515d74bf6c, 0x71618f721452e5b1, 0xa8c8b07b7adef460, 0xd836ea88450d9baf, 0xb4f219fec42c4191, 0x9c3cef0e3b8e98f4, 0x91082be3b45729b2, 0x93ed7bd9a8d36eea, 0x35b244af83f67a31,
            0x106e71fb71e4b5ea, 0x8d1af305ffde3421, 0xbe531e4932b96f36, 0x9df6da515dfcd450, 0x1daab0778e5d984a, 0x67d4120e933cb3b5, 0xdad7a58655531478, 0xc2ff34ad10282834, 0xa0011cef8b776acb, 0x5229868a14c856ef,
            0x0570225833d90c84, 0xf5e06cc158c5a432, 0x95569d58b1de557f, 0xde7aa3a4c3e70c5d, 0x25cc5b90a027e55c, 0x2e04d82214d8ee43, 0xd02a2ede714419b8, 0x148443abe1bc757d, 0xe029ba152ddc730f, 0x6f5a394519dc5e54,
            0xd54b2fd27e6be0b2, 0xf5b84e22530f6688, 0x57963c7346ea2353, 0x5715fc0c0917d7b6, 0x5f017ca00fac2f89, 0x3344fb798b726bcd, 0x3a9ff40746656206, 0x881e2c878a94b333, 0xd02cf90c6eb96976, 0x5d0e5d28a6324c4f,
            0x28fa1744fd995e3e, 0x1e0a4ae1444fa083, 0x60a55c6d5bbc2e7a, 0xac10edea386252cb, 0x79cb84af3a9d545a, 0x006e2d57351e6640, 0xeec9fd7a41925a70, 0x0b052945cce0f715, 0x729dd450d1a009e7, 0x15ad5c4f271b1498,
            0xe8b7cc8ccf647f81, 0x76fb1916a3d8f1bc, 0x5b9490c401bb1aa9, 0xa9d5018ac77afb14, 0xe401b269b091a67b, 0xd29a938f15e10c69, 0x883817996fb97020, 0x6d25ba0149938550, 0x3b251625aaa5dae1, 0xe13e1433d0d37e76,
            0x9061b9682d20bf25, 0xfd52b41cca311b3f, 0xaf27913c70e55474, 0x3c2cba85c85d918c, 0xbf31a47e6ee1e8d2, 0x65985a82a3e412a7, 0x0cdca9cda47c7d74, 0xaa047b5dd0feac60, 0x4c63b05d1b17e834, 0x37ff6ed87810d587,
            0xd05c5b008a3da500, 0x0bb5d32d6b80e6f6, 0x6a353fbef065631e, 0x70418e1878a519c5, 0xa23b42432f4a0e7c, 0x55908aee6ec2471a, 0x6e29ad311d0c039c, 0x979bfc2ae961b9b7, 0xd08a19e9658d56fc, 0x0319c861c157ee31,
            0xe68f99dd83fee865, 0xedd922733236650a, 0x62fd38e95fc39ca1, 0xcc022a4cdc495f7c, 0x3f93691daef7d612, 0xcadea7461ea5198d, 0xc5cba273c3005193, 0x87a7499b259360c4, 0x20770edff90ccf64, 0x36ebc4b5e494d671,
            0xf35f2e1f4101e943, 0xf1b19c5c6d0d1783, 0xe0d5835d7fda9c29, 0x8600e0b26e87ca59, 0x6bb5e20ad197b591, 0x1b3f795851f6e760, 0xa56749a88ae64a3d, 0xb3000dcef0e4693d, 0x3c25270d129d952c, 0x5fe27b6f5dbb2a2a,
            0x03af431fcba272ae, 0xb9afd6946dd9bc6d, 0xc7da40e06ca6f656, 0xec64fca3ae5e3704, 0x656cf372d990caf7, 0x03e58a2afd46198b, 0xe70ff8e867eee089, 0x05bb6ac84e1e7d08, 0xff3d3c2dff5ef23a, 0x4c4cf6465f5c1643,
            0x168a500bf56ffa05, 0x41c2b5a2d3574bb5, 0xa1b868f2663a0a0f, 0xef122f010e71d4b3, 0x70d0072ae39e5222, 0xbae7466760eddd47, 0xed52313d88559aab, 0x200edc42416cde9c, 0x8d28ac3005e50a57, 0xcf830a27ce8f03a5,
            0xb7124e7e8cd7914b, 0x54dd44e32ee41af9, 0xd5608193f75353b9, 0xf0dcda47d16a4cf9, 0xc19f2971120466ac, 0xcd385d1a237580ac, 0x6cc6bc17eccd2487, 0x01fd83e8a58b6c0f, 0xecd9d0ca24a03780, 0xe84dec6f27d762b1,
            0x36a54eac0d6db1ce, 0x61261987c6f96a6f, 0xa623f7b12ee1db55, 0x64164064b4d06f53, 0xffec3687ddbbbb38, 0xfa342281291ae94b, 0x50b6fc812193c0b1, 0xe20ca499aead2dd1, 0x3de464e3a6ad761f, 0x0a2a66ee137b6a53,
            0x1285acdee14adf20, 0xd3b61f73e8dbf7ce, 0xcf4f3e4ad56dd560, 0x0e6d9f0ca6e5b87a, 0x9845cc3bee70b0b1, 0xe0dc0633035d3c20, 0x7609981f49ffdbc0, 0xe7be2ec3c4704cb0, 0xd3bcecdf0370c5b0, 0xf23e37e9bae6f609,
            0xad582d409cba1c16, 0x381a4dbb0b675792, 0x71e379de8107157a, 0x8a1f6e28058c5f3c, 0xed7c2ba7e7a751a6, 0x0d665751df9f4275, 0xe7f83a916d3369c8, 0x402650585a8ec912, 0x0e4cb5cb030f8675, 0x457716ad2e5ca034,
        ];
        tester(hash, RESULTS);
    }

    #[test]
    fn test_hash_128() {
        #[rustfmt::skip] const RESULTS: &[u128] = &[
            0xebf383f81508a6f4881dd5945be152c9, 0xb726c94cba19391dc067c23663b6b5c3, 0x325d07ccad00839f59a219f6f2b97dbd, 0xd2127ff17a7d6f8750030dff83d55547, 0x96b9ce52a2f325c45751e4a9843313c1, 0x21c0fbf55c21fd7e3b905b0868c84294, 0xc707e581d691e37111d521d2b4224dcc, 0xa69b7a290ab7318929c5e75f31b83ab6, 0xcf3d172cee861a284985e1755f9e3808, 0x8bf378fee653b3271d3483b785305ec2,
            0x5fc15615e9eb7ca8b2d0ff7179fccf45, 0xbb9f187ab46986985955038b824b4d3d, 0x9414fbfccdf5328bfe07ca36b022eecd, 0xba9c5035e3de21aa0aee9bf705be28fd, 0xb4e8e0b3cc4b0ea93be4df79d5753c68, 0x2ff3de7a9a5af187455b6ffe2eda72de, 0xbdfc8ef937c4a0fd3084e7740c21ac43, 0x0f8d7255ca5310e48476510e1279e2a5, 0x559f911c0cdd011dbf38996719368bc4, 0x4ca0bbd60fcc782de245ed39a23bc141,
            0x389eccc620e04abb5386c3f220d04b6e, 0x532560a76d15fca42deaef611d1b03b7, 0x0af2c1f319a1624e51866728ebf1e02e, 0x91a12536d6d55dbb3c77c229a49d1029, 0x39a78ce99784d5cfb3cf422093b515a7, 0x9d935a362b7e3ccbe8068bdfd379f50e, 0x58218afbfdef01ab5e24697e491e371a, 0xbef1e2d8cd0eaa5a2692794bfa7612e9, 0x929be0ddeb3fa8fa25322c158774a9a4, 0xf93a7068c3fc7409481e7f514d64242b,
            0xa15498b10744829d90c9aee8ccbd578b, 0x73a6eb425da7bed044aae4095c384254, 0x365bb35c22599091ee1a745df8b34331, 0x9089e0b39f2f4f36a7b9746722459c1b, 0x9907dc9c75423a85c66e8b1444bb9002, 0x79f8b31d1afe58d17881ebb1da5d6d28, 0x337a15be55ba16ba00f358f0e71afdd3, 0x17ef3060061a4185b54820a63a4db854, 0xa3db5a00f03eec337bfd802937cc8045, 0xd3ea97153d73751a336074ca00c78f91,
            0x165a893fd97c5cabc7c7309dbed0e3a6, 0x42fee43b319e114a10f680d01bb06b31, 0xa5779d8268fa2b3f5b97969540230156, 0x3adf42c18bf1b5ef6a1cb8db984c9dcb, 0xb2f96fc99093174d11bd65c126531290, 0x2ffc2f769921facab091db751c950e4e, 0x31a435e1d44a2ecb8ea387f847a3b889, 0x90f676d26601568a83ad6e3103345b9b, 0x5ad4fe108f18ca1b0c8cf0e3536749e3, 0xd64b5a7b8af2394beeaeb1037c4ba6ec,
            0xac3ad91689b32012e3ba47e1009e2a47, 0xee78f128fee18a1822f950488b72d44c, 0x8d7b101fdea07fe3da4f88d700145ad8, 0x80850b1705a91df046745735b69fbae0, 0xc2d9efc0f2b93b96c9d020dcd4c0cdf1, 0x048482f701562aa2ec27ba5133ca47d0, 0x8df004cfd2b6f9ee11b93f2172b619f8, 0x0a71177f74e2b966719d4a51e8e41a25, 0x79efa1844abe4659eaac9a5b4bd4b983, 0xc1e2db5d27d192adb01311ce9f620ecd,
            0xa41686d99c3aaed138105b2958ce4589, 0xa46e7a718d3d4381400cc896da95a3ee, 0x4758ea4507a909ce7df0706b763a0416, 0xcd2f3d45dda37e0b33fcd18b6deddd6e, 0x6c33d8748ad4644e9117cf1a7d3b9fe1, 0x3cc73045ff7a71121a0ddf646f3afbdf, 0x08624b610e4aabf694def6e5da54b1fc, 0xaa16f645bf7c167e579660e049826893, 0x74640162c6009400f4aa00b79aa2457b, 0xa110420d99436b8b0fb48e486552181c,
            0x3f5484516d8fe5466a71d8782396c2fe, 0xafa53696408c7fce90463a58ecca708f, 0x75b4867608b2715c128f529463122a58, 0x484bb29c0d254d767204b0340569320e, 0xfbb9b2a396e6b174f6f1d48809d5b341, 0x706ecbca8cd3b1cb2396b8f522aa57a4, 0x4200421bccd0eeefe208d0f1ac4624f0, 0x037ac8cce8af1bb7d4a8b31a2d46a498, 0x0ca19ac0111e8ad4c3edd3467f5a857e, 0xb854f7c6508c82f75964c03cc6e0a5bb,
            0xfae5613026b9e70641bc1fcf700cfa45, 0xb68de4343bcd6dbac689b40f7e80406a, 0xdfd8fe7b3085de865021fc5bda3d2597, 0xcd0f05f68bc39fa9a803e8e1ba362314, 0x84ac002bf90b076dc23c8b97fa0a2cfc, 0x8f3d427a030105a4314ea22f4104393a, 0xe6fbd10d920a2468a21673f29ec60f8b, 0xdb10cf3b185c490445bcae9bd7904874, 0x1c6a22abe09dff05b311d378c28ac53d, 0x4265eb76ae1fc6898dc625302a4076fd,
            0xebe0a1e750dff5f623b9e1c76ef72ca6, 0x6a24ef2bec678569401844a64f56fb95, 0xc8f0693be63c1d17a350aaec249fd8b7, 0x2e469f0eca046a3881c342778b026c6e, 0xc2fe3ca0083488a3124a8a9a0aae46b3, 0xc6f436d7e36dd65a177f88c2343bd9f4, 0x4cafa069328deebd31808223a73a4b36, 0xed618c6ab10c11bed99cbf464e1abaf0, 0xe59de80990c805b75d483268971025a7, 0xccd97a98a4356a919169ee83a7ed1a64,
            0xa4f70d78a7ad147212f1efbd08a89682, 0xbdd96a0863da93b0f7d4549a8babf55e, 0x1dcafce6478437ec00503e41da508be7, 0x0a250c0142ba56e0d8afe201efb29282, 0xd432ccfd946c664d404e58b01f5b2b34, 0xf72ed37b445e5306d18a1a1f0525dbd8, 0x561508d9b1121a02670f92661c7f19d5, 0x6583d6519e2cb22aee2d2390b041089e, 0x93db8c8eaf628cc445e0136043669e07, 0xabb4482e80ca20eabde1e45509b61afd,
            0x4cba9ba69bdcbce89f3c3dced1a4c363, 0xd87bdf7d82710f76e982764ac2ae683b, 0x6e1a0330ca4f4cfe3891790b3565c613, 0xaae364aa152973b89ba6ff371fda5d27, 0x9918e9d15600d62ce6cdd5e83bfa43c2, 0x7eb818749b24d476367982f6972e80ce, 0x28251c78b3c8e38a2be94d25aed2d173, 0x68d97f645e2d676549426d350cc7204d, 0xf8cbb331c838dc7d416a23a66b583a05, 0x4d344d51004fa05d8c7d51261e2bacf7,
            0xa6f077c3de5d81c2ace65832bb4d1d85, 0xfce7cfd2d73cb073669e562e321ba45a, 0xcf0515355ff3a04c97e842c0c509ad25, 0xfb3e0448cd0b24e465f27c6bafa90d97, 0x2061c2eefc707fba65a8b539387238ea, 0xc0b22106f04b7af0096a17cef40ef322, 0x71e6b50c4dc053604f0ba33d5c6eaa9a, 0x7d7b45adbce32ba93261bff8a969105c, 0xe0c1095bdb625c8b598529f77d9e7df3, 0x13c9b495ffe0adc2ad55b130f9473d14,
            0xaa145c6b704527118e4a24eed984ad73, 0x544e3b2bc7d940164e05fb2eb05e11e0, 0x6acf567a6dff4612089c313be686c229, 0x5aa59d231b08e830b9e0f828d3a8456d, 0x3a5956a4fb14b2af0c07f260e1c70cc2, 0x973bbc3426ac866ed569b098752c7e27, 0x33558dadac5c84ee03cb051bff33ab94, 0x287c293e779fe8ce74ff542d4c8376fb, 0x75f4103daf403c3aaf1f23e8d77c2dad, 0x60e9b36426a619b8054af00bbaa130bc,
            0x98b14a48cb19455787be3850566e1575, 0x5df715b7d3232fa7ff6e3626718ebf81, 0x8b8ed1098bb91ebe6bc3a4be9da219dd, 0xea919de6172611ee08901ddbc1ce46e9, 0x0a04599e222b2a0c6973d832c41a097f, 0x10035351f7a865e2556647f85b95082c, 0x8c71e0027ceae00400dbe17534677079, 0x700f9c67df40cde2eacf368440173393, 0xbdeb791e0768a5ae9a311855608d2ba1, 0x0c010430de07eb34b1c24cfba937519d,
            0xce79484a2d3d3350952e7fe9f77eafb0, 0x9356cf950c8e0fc29cc91198b074c9fa, 0x752308bf679e00c26552718ee66a76ef, 0x2e9608ed0547aa438f8fedd52658043f, 0x779434465f44a5ac3cd591b22d0546fd, 0x73798aa6daa998d0b34874e99ff97a09, 0x8f04d94dd1227a2a326f983ac426ef0e, 0xd2091a44ee88f4ca93039b028293a051, 0x5148c3435029ade7d10aeb3169cb79e5, 0x0a6af4f59d09ee79bc94c182aacfe72d,
            0xb5f6f3befac3c341214fad70b2e2180e, 0x84ec55cb27aea7090e858e5c3ccb4ba4, 0xbb4cd2daaa03f6107ef26e946f8722fe, 0xafde9666c7f98278f169d32f185f413c, 0x699afa7156a260d09d75cc2ab212c1af, 0xf0ff8e0d1ec79affe12377b4f255709b, 0x0d03eae0d097234dc8cea75c1cb43813, 0x6ef62a40d8e9393187ffe852ab56f458, 0x6b96fe09f378d4b1151561abdf9f4666, 0x287e1a3d0f2e732445f092dae764df74,
            0xea9d77061f89952b3bb3d727a12b6d67, 0xbb4edd248babec42adf7ef23d098a08f, 0xa0568ccb8466e06a6b00142ebf081c54, 0xbaa1c6586d6f616ace88c5fafda97b8a, 0x219a0584f0eeffdca49e005d0c4834d6, 0x72d45893fcb725e1173d9b75525f2707, 0x96ab5f5175496bd059d93dd86b3c8847, 0xb8cc57241f1b489b337111d981c26273, 0x6a281f0c014a3ac973ee5d6e27b917af, 0xa0b9a46501eff346488e4985211e14b7,
            0x409d0a4368cae56be3a8ee4b10c73515, 0x2c41ce665bb709627f24c08eb8d6c23d, 0xe50774d55a8780864d6c451f1aa75a34, 0x415f66b510ee943790d98c93637fc84f, 0xf7d5c7957f03355f794378c909642882, 0xdc7f5afdae4be2fdf74eca5ebcb2d437, 0x8eeccc59d7e0707c6de15dc78b360df5, 0xf557f84297f0ccb685acda330641b8db, 0x8f8ad32127b7ea7c4775b38083dd809f, 0x3ef21fa2b26450827ab933aeec45047b,
            0x0239077f60195d69ee20d2f15c9f0088, 0x3436b893b8a15fbbf35d7c2496bff68f, 0xe4c0306aaf8397a7d3dc712e69f94ae4, 0xe961d6d87bd5678ce1d17c307ec52edc, 0x33c51e10ff9c530d07c3e79281955adb, 0x61efbbd142385cb5fcccb8abd7bb2818, 0x2131693c6bad1ec5277f31ea0c0f4590, 0xe53805f3ba937eb6053cfa5cec4922a8, 0x67a6bd55ff22345b16c1cc7889b5858b, 0x58b66b21e91ea418f223a3701772d284,
        ];
        tester(hash_128, RESULTS);
    }

    #[test]
    fn test_hash_bfast() {
        #[rustfmt::skip] const RESULTS: &[u64] = &[
            0x0b6d39af88433ee6, 0x9cc00eea41bd3bc9, 0x32b27bb7bb9f736a, 0x4feb8452bd56e235, 0xa5114a825618597c, 0x0bdef0a3ea34a1a6, 0x956881a26db0cf30, 0x2990f2b2e70c7d05, 0x07d1c1d80535f006, 0xe86d73ddb3754d7c,
            0x31fa0d6e44a0f27e, 0x5013736ed17cbc5e, 0x69cc4eb7af802701, 0x4b1091c1d43ab72c, 0x216c965fc9ab9751, 0xc18056db002f3bbc, 0xa8aa59e62173ed5d, 0xd1f945707666cb0b, 0x4f843f2ed84831d0, 0xb4f204617908520f,
            0x761b1ce504ecbc7a, 0x2c9ae95cf08e51e5, 0x9311b23672c4f9a7, 0x3fa807d332331578, 0x7ed8195a6e8d81dd, 0x859c4514fb1ac098, 0x2171ad42e5d9d2b5, 0x4c83c4438d1eda0f, 0x239a7c0e6eed5701, 0xac647c08274c5306,
            0x58d9d6387c2aa8a0, 0xdcec6dd90d44c2fc, 0x6e2e7d5f32889f94, 0xdedd61d7192e0e70, 0x4b5f3b63c12eb9ef, 0x26beb607f763c8a5, 0x745ac7b800d604d6, 0x3d2597a8e27d7c2e, 0xef1196bc0e6d5355, 0x640e72b5451a2ed8,
            0xa52a4108ba6b4e2d, 0xdfa37eca2b03429b, 0xb9c4d979a043ec23, 0xbde7fbed95a70441, 0x3e5616e4eb9be2a7, 0xc86f229e341e09c9, 0x70a166b7d1afc716, 0x80fcdacffd877084, 0xd2cc99d98b1f4fcd, 0x6a51d0a703f0583a,
            0xc2a73cc2d09309a0, 0x67ada5ce28bb9b02, 0xb8328f9ceeb7de63, 0x8e261a84f601b132, 0xcf67b3e1e877e509, 0x6fc0279cec76d661, 0xe2ea6d27cce7e887, 0x78134a0cbc885755, 0x1742c70a5bc96d6a, 0x2cf63eb1cc348edf,
            0xfd75faf2bae7d5e3, 0x5e7db2744df1c09a, 0xa88a626b873daf1d, 0x6f93f30310e4443b, 0x0e42cb6837d89165, 0x135bdc8f37e58ae2, 0xb3de57613abe2300, 0x72e2d5a9dfaed673, 0x6282c537fa811eaa, 0x4d2ace8f07c4d2d5,
            0x07acb2b78bdfecdc, 0x77b807a49dc030e5, 0x3f8b71af6644ca93, 0xa2ff3fe38e187cd8, 0xcec88d459a76e40b, 0x1a470bb4a7b439a0, 0x3ce3c336bfce7f57, 0x321731db6f0d50b1, 0x481b7a6de257e27a, 0x6bd556eae247bc63,
            0x7c0e45b45a195fdf, 0xad5a2aa2a520c67d, 0x98d3c2186e0ded1f, 0x1821468cbed31af4, 0x7ac70eac95252b4f, 0x632bf674dd4614e2, 0xc1d03a7b1f26f010, 0x04101ee555439ba1, 0xb1afa00affd77250, 0xd71a67f780c09741,
            0xbea4cd33ecb0cf09, 0x21e5be1d99cb9528, 0xe2c4ac753de88b26, 0xb29328cc62133faa, 0xaabb5e4edf2357c6, 0xc58023ec1aae3ead, 0xbf266223e9c3ed98, 0x183175de5285088b, 0x347e3812e53a6bb2, 0x94fa935cde0e0a5f,
            0x1a9288250f3d1d46, 0xbdb5115865d4a2eb, 0x7ed89138ede7c49b, 0x419977ef68cef709, 0xbb8fb25714c72f3f, 0x7907686750d9812c, 0x2ddaf1ae03fd2325, 0x3eebf3ae4dd11a4a, 0xac6a1e12cd45b432, 0xada55af3f260ded5,
            0x10d115d1362656d1, 0x16eed6afa9615702, 0x5ea9bcf51a47bf49, 0x7d2dc77a54ddf5a1, 0x54fd5c9419a3c05c, 0xdb011e0d0ff3af88, 0xfda2af2b0516833e, 0x2f5a42242b68b46b, 0x94de6c766cb555da, 0x460dbc8afa11e753,
            0xffe46c8d859d0919, 0xbc1936f8fd9278a2, 0xe0e61b4524580d92, 0x666a10c08a43d3ce, 0x63627c61e0f91386, 0xc7d64346e39e0b60, 0x3d094923731c93e3, 0xb29ff264552e3ec3, 0xa90e2712f57a122b, 0x00f4afa95cb5aca4,
            0xc8fd230bbdacec1c, 0xcee72d73ec69fb15, 0xab2245fd5661fd72, 0x350130316b180fe1, 0x2640ac7ff164db12, 0x6b709b18d2f84738, 0xead969f045fb937a, 0x30842bff221720cd, 0x8572cb2f642b4e57, 0x8cdd96bd217bed40,
            0x67ae42369674dc8f, 0x6ed95f9bb0a033a3, 0x59bcbf0cd480aa14, 0x32c7cba603fa61e3, 0x2989b7889ae7fe66, 0xf9c5884cc32e5ea1, 0x7dfe9b4ff8ed61b6, 0x6fc10ba1b90380fb, 0xc3ac30b84a3bcae8, 0xe58b27f0c62c1ee5,
            0x6a7b39aa3e4cda42, 0x8906cf98e50d7da0, 0x1109ebf49e23c814, 0x42d719da0b9d5d3e, 0x4b57152509030bb4, 0x2d83414907afead8, 0x79a66a5ca0bbe06e, 0x7e776a15ba0d65b6, 0x1a1f79c0e9bf11a7, 0x21a62beb08ed2c28,
            0x017460b48dc5db50, 0x6d011b92dc943a17, 0xee3379c4b3da7216, 0x858baa5ff3751d77, 0x6f1fb6b5fed96f73, 0x4ff5e541b1759bb1, 0xab7b567c650e34da, 0xd536b0a7c9df9535, 0xbb201cb00e17378e, 0xddb56bd6b87dc3e5,
            0xa26b116480a111b1, 0x984530ef64bb5df9, 0x0cec20a896f16746, 0x0f2571182458e638, 0xde08aa2fa5a327a6, 0xcc4a05eee36a146b, 0x21a11983ce4ea106, 0xee8b5159af20b730, 0xf4d5a4d1981c38c2, 0xfd3bd9ea409f9eb0,
            0x5e11df5cf8dff375, 0xdfb1f643cd89ead1, 0x3e065a9d1f4ca3b4, 0x1ef82cfad86694f5, 0xc9d028e62d8aee13, 0xdb623599e848c52d, 0xc1ca0076c92fa191, 0x505f27ab31432341, 0x4918908aaaf0d67f, 0x4ab4ee227d02b2c1,
            0x12482868a02186e2, 0xa792704240e7edc1, 0x2218234b3166c138, 0x5cb7dff1dc749d63, 0x2a8d99702027ec3c, 0x8af28b59e5c7409a, 0x846f2cad2cd17a3c, 0x09a28151f4da8dad, 0xf58a860eef09b449, 0x2e00a42bc197ca2e,
        ];
        tester(bfast::hash, RESULTS);
    }

    #[test]
    fn test_hash_bfast_128() {
        #[rustfmt::skip] const RESULTS: &[u128] = &[
            0x702894363ff40815c23b5ed54b4832bb, 0x00bceb6a4a1f300e400d0527c8be4293, 0x11d82a1b09d2dad6f43c1e8f942ccc26, 0x5fcdb5e02b6cf19070f0f9e742eeb5a5, 0xce84231a4afbf113ca00b56f87489f8d, 0x4e9201106c75af605f4fedf85fb20af8, 0xd3ba1a83edcdfbb8d7d042b162e6a071, 0x4bb04d8a9a15f0531d07be95963c9cb9, 0x5e4e3c31478967d6055524dcb16b0aae, 0xbe6a2284f6bc638d17934a2a8ef65260,
            0x4f1671824200de098c80f416b9df2363, 0xbe163dbea4d3a29adc1a9a488af58602, 0x215fb5577fb7ae5f6d992f402e34d4d8, 0x522eeefc60e0a35c8d6e386f8aa20258, 0x8e7337bc4dac8aefd7bae3d1bacff555, 0x6d7f2f39e711f688daf256d8345318f2, 0x972cc14c28d4c68b27ba957901102a00, 0xc017b8597efe7dcfec2e02f637af2918, 0x04bf1279fe037fe58804cca8dab4c9eb, 0x1478f2acc9c86f725ee30e336ce8c28b,
            0x2bac57a939e9a1073138959242ffe48b, 0x1a7f22e8d1fd9abbd15dfb081dbe4d62, 0xc60914a5ac0023e132f74754384f013a, 0xca1a8458898efd84346a74741ffd5992, 0xb6f6f527057167db0dd1325e65071ada, 0x930152c7c039d10fc761f6bd05ed0c49, 0x7888259a87baad4eb6d46f1fad1f8865, 0xd01a56e76eeabb1b63650b147c2a7df4, 0x6e519fde4e96b1f642105feff1a00ebd, 0x6ccd267eca36ede6476a641967bd5090,
            0x0e787135c004e1700b6fcab20659f62e, 0xd64f4555784c3ecd25a51b7264b6f1cf, 0xbe54c04d46f1b9f72d84b5d194665cb9, 0x0f077b749d67c876d63e22dff896c978, 0xd8100337efc515c46c8ea193cc541fd9, 0x1831875fb844f916c950ceb73ac7ce4d, 0x5e7efed18f3ae630d5f8aa1611131e08, 0x6f918b50b8b7ac4fd389e53a1d344e07, 0x1cba576ad0ffb4bccc375e46a1690815, 0x0a461873de9b0abc95ef052c25b2c4b6,
            0x60f1b59bd119dc73bd35067c90ebf93a, 0xef6d011685b6c01cf2b1c1a1614e1f7b, 0x6e076b1aea2ef1f52e384b7347921a28, 0x3d4ddbec75387ba20735a3deda68005f, 0xef427e04094531056de3b71d3864ec24, 0xefeffba0f5855184977f16fb7bf495b1, 0xe2015939fa1cd0243d7fc1b6c81c660c, 0x00a2cbad81317f05470dee81b3452fff, 0xd8a9d97f0d7a93fab00abf69861adbcb, 0x3eda38ec5cef7e5ca30c49f4973cd99a,
            0x81ac6dc6a7acea9d9df43e8bc6501fef, 0x70b12a5336287756e0c35035e1681752, 0x0b91094f968464f33cbef12c15e0f9b0, 0xf7cbc7019de009901c12127a9c16353c, 0x3221cc6027b6c04e9c3b03a6083adafb, 0x7d228b861c311ce2e51dd5dd4b68254d, 0x4845eea8783eae63744cfdfa5f3ab01c, 0x14cc330ddf9096a8992605fea41f7841, 0x6a06a18c6df06081aabff879f6c63ad5, 0x7f182b8696a368152f51965b256c9964,
            0x5d547b33ab69ff15a6dd7fe129ea6d48, 0xd3acdadda15f775b30d0fbb1d34a0ff7, 0x43a8597d200b4087c35efaaf86496c56, 0xd47c9c2b81fb8eeddc0354d445c74616, 0x8236dfbc59cadbb863fff927dbce35a1, 0x924ce6c5a990d6e30edd2257aa3a62df, 0xbaa5990a755be369f086fd16b1ec7c17, 0x66208cd1feec01860a2176abf6dd0cdb, 0xddae16201bd5539740235de01e2a7e83, 0x08001a622b7b1f038ad56c122141c22a,
            0xe58c6c8268e5ad39fddd66c62cc5bf53, 0x65f0d1a55a42d41605bf270ab83d16c3, 0x42121a86503f1edb067a8cc6e9e1a310, 0xca5532bd55bc54f89356d2b1c5f537ee, 0x907b52a8f4e4b770c74cc1e751fbab4d, 0x5b43d02b1286ca8e8ffb270f018a0e50, 0x3329f9ba41f4c36881bd419f61e4e3c1, 0x369057438d4fab68a1549ae8dd56a435, 0xa850e156d92e04a708b500c6abc13d03, 0x7b9aeb83c3b41966ec224a87640055fd,
            0x9ffbc48bc96861d4fc721e04f0bff9c5, 0xb17ee3d8c1f3ed4e939b328c986c34af, 0xd2f308837aa80a0fdbf9254b08019940, 0x8b03b8069894faf77c7f4121b8b818f5, 0x8bd66aaccdd14ef38e8f1bf7694c1a5c, 0x4112c0d6580bf8a01be6c995beb205bc, 0x2a36123b5c737651141897bb7ee199af, 0x67ce7095e3d22d319d2d2dbb096fcfcc, 0x94182474f0e384a6e6504461ff761848, 0x83ffd0dd2149418fbbbb672b47f7c9a2,
            0x41d5279066eace168383145bf9c5ff03, 0xd08536260c704984191dbbe45c24c658, 0xfe2556150a1a0603e2ae257dd80166df, 0x5619e66005c53b65a373124254298907, 0xe144f70ee6790a58bd005abfe79dd220, 0xa31cd42192d31214ed9f0da5f5a2db67, 0x02f45d6ed9a5fa58c621c3b8c3d88c56, 0xe5cefeee0d6ffccb226c7ceca38f747c, 0x05289804b98f6d3dc6895f28a7caf961, 0xb52c8922a09f17b0e65965c7b179762f,
            0xd2ce22ab4ebe93f9f7b256e3be4c73cf, 0x5eef9d65c593f46e58e5928c53b8bbd1, 0xf8b75a58f6f58e9c61a3e2da3cdc35fb, 0x6e0f9a2aad06d25b296efdea1927d6be, 0x4fc50bad70ed908e7fa9460b9bea3557, 0xdca7aad065b54a7d55bf3d54c619cebf, 0x1da1b6d75556ee969fc1fda52f45b27f, 0x041d9d792431eeb8c76b960e94033692, 0xd969b2070ed44242aaf35bfa3c6c561c, 0x27baf7b02d5c1a2270e256659eb97a23,
            0x9f912f7882e89b35373f4c8f4abb331a, 0x1a1b65584a810400031c4e189d5ea2ee, 0xecbed39690ef368a6f29aa9c70cb0edd, 0xe4307c5bccfeb272516de7d651ffa337, 0x20ca7cc42a486c278f08e6e7cdd32ca3, 0x83a33b93e4b62762e2afd9a390aec404, 0x81ca481d06fbaa518327198d7e02d2a9, 0xc3b5e144b860766b92e224a36cf8bdf8, 0x530e9fa2af324d6b386d0db73c38a54f, 0xf33f5b50b8ac9d797953b8ddc960a9d2,
            0xa157b6895ab76a61b9ee8a1566d01cc4, 0x00e52d46c663e807b90bdbc1c41c635b, 0x80979fa6de0f12bb7f86fb1282a56527, 0x25cdec63264c3b899dbc293b997017b9, 0x49f74dff88657d130bf2d1e4696795ab, 0x8251078a5adaf77bd874da732a8135ed, 0x4c6df205cc4888aefb9a5499009feb33, 0xafca6c27fecf83ac3bad0ab9751c4295, 0x6d5e0baeeed13ffe1bb4d3520b54d22d, 0x408ade7701097a98be0e112242232fcc,
            0x3f978abf88d5be8e3e92588bea96f56e, 0x04b13b8e241b9722b389cdc237a1b3c9, 0xf235547c9a5db5e42ce96eee6363b76c, 0xb107d72e7d0228d2f000a75879c254d7, 0xd14d59981c2f898ab9b444d81134c860, 0x448983b9dbf623e5efc6e45f76619321, 0x35d4ecc066ab83501cb87b0fc47d2f36, 0x481434ab816d06ed909fe75f6ef9e7dc, 0x406e1598dffa2d841bc76534247c8423, 0x6ffb4d07bf394b26f2f325247bcd3820,
            0xa44137cd43885a3a5b034a3efc0b3953, 0x8f0d018937a7bd5f626bdd6d79fc68b2, 0x4169a729827c175e44db3be2ad03c974, 0x3b66c2ad83850bc8915ef6b3980a97d3, 0x28d9c7dcddc634caf69e827b96d60352, 0x3b18475069a1f4cff1e23afb26d1e982, 0x253d9a5a10e82e2c36c67ef416faf0e4, 0x9cab4410cb651729d31537069c5f6fa4, 0x91330b626c74210ae260f229e79a10ec, 0xe2ac61b27da5214df818fdc158785d94,
            0x0a47f9b72128d2381f334de2906db4c0, 0x4c0ab3040d3e030b1733c36e17d84657, 0xd675228c1bf5746f594352e6bdcb23bd, 0x7dc7990f8f8f8352baff4fa147710b94, 0xb5cefee7f2bcdcbb7977c48912453891, 0x6a6b70af8c21e706b6d694097c6e6a62, 0xc6a5651a947436064c5cf03dcb360988, 0xd10374b71420a73fba6fc0dc3a123dd9, 0xb7cc7bf93100a50d2e0df936c8e38b0a, 0xc98789812cb3346e9fc2fdbdcbb3fef6,
            0x6b77fdb8c83ce2365579baf3b595de98, 0xc20b91f370d4813aa1a5758fdc69455b, 0x952728c15c8894d286de92baf469f99a, 0x9a22381f5e6734c5e8526684d2f9d682, 0xd7082a4e6b04a0809e5b0a05bc02280b, 0x6db61cb36ef3aeaf83bce609207d6566, 0x3a91f885cd6e3831ca11c136c7a7b755, 0xc9c8642d1181ad59f20d35c26a41efd0, 0x5037dcbff9f60dfe64ae3f1407d39a96, 0xcb15c5d82cdfa2e9ed4396487bae9d2c,
            0x7b14196381c8b194df76d606de17ff57, 0xe7fc1217cd0b04c84f488518d64f5dd5, 0x48d04684a505aa206b04929f539a67e8, 0x26472d9ec9e242d558862291154b315b, 0x1517af4375805ea38351feec0e3d6ef7, 0x35ac8e1d1e32591086e1680e6257a299, 0x6469154860fb5882b1f7f3c311240074, 0xe75af107faf9ae85f6d65e9faa1eb607, 0x774e90bde8ef29f76debcb48888482bf, 0x4f8c5aaf70e02a29054880bb6dba4efb,
            0xa83f6c82b459d523f9cb6f35b282278a, 0x62d1e2f5ab96d6fa7288413d9d66ebd7, 0x22156f0bc3afae36bbeef791221f721e, 0x30a403b74e7284f4d0ac7db629376f6d, 0xd114b96dbe1104a2af648e7017641547, 0x61bb47f9f5bc8f36742519bfee0ba1e5, 0x9d2fe8fa6f6ffeb3a355f37f5920acfa, 0x6c0da9b157c544871d5c56f00be4985a, 0x9a7f8cdbc879710f2c90e1aa0577d480, 0xeca9a428484c627339f3f5f5c6493f4e,
            0x573311d1d2f4e45338a4d7940aa99d77, 0x249c02adc359f2674c3bdd69644fa03a, 0x4f9b99a67e8e7d8fc873dd1f831f1f79, 0x75f77cd5f7d0334418c0a341e4db61ef, 0x985fc00f862709784caeea98591c1bc0, 0x688d00fc13e5799b198153d2165ebe7f, 0x858c69669118fd549e1d226c60376692, 0xc28cc78069c218bab4e559ae62e7aaf7, 0x9281877d354e08c81014bd0c2da94377, 0x94522c4044af9acb05ad4794920b670b,
        ];
        tester(bfast::hash_128, RESULTS);
    }
}

/*
def pp(s):
    print("&[")
    for i, n in enumerate(s):
        if i % 10 == 0: print(end="        ")
        print(end=f"0x{n:016x},")
        if i % 10 != 9: print(end=" ")
        if i % 10 == 9: print()
    print("    ]")

def ppl(s):
    print("&[")
    for i, n in enumerate(s):
        if i % 10 == 0: print(end="        ")
        print(end=f"0x{n:032x},")
        if i % 10 != 9: print(end=" ")
        if i % 10 == 9: print()
    print("    ]")
*/
