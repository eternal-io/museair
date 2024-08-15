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
#![warn(missing_docs)]

mod hash;
pub use hash::*;

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
