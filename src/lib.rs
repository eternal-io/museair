#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![doc = include_str!("../CRATES.IO-README.md")]
#![doc(html_logo_url = "https://github.com/eternal-io/museair/blob/master/MuseAir-icon-light.png?raw=true")]
#![warn(missing_docs)]

/// Computes the 64-bit MuseAir v1 hash for a byte slice. *(standard variant)*
#[inline]
pub const fn hash(bytes: &[u8], seed: u64) -> u64 {
    impls::hash::<false, false>(bytes, seed)
}

/// Computes a 32-bit MuseAir v1 hash for a byte slice, by XOR-folding the underlying 64-bit result. *(standard variant)*
#[inline]
pub const fn hash_folded(bytes: &[u8], seed: u64) -> u32 {
    impls::hash_folded::<false, false>(bytes, seed)
}

/// Computes the 128-bit MuseAir v1 hash for a byte slice. *(standard variant)*
#[inline]
pub const fn hash128(bytes: &[u8], seed_a: u64, seed_b: u64) -> u128 {
    impls::hash128::<false, false>(bytes, seed_a, seed_b)
}

/// Computes a 64-bit MuseAir v1 hash for a byte slice, by ADD-folding the underlying 128-bit result. *(standard variant)*
#[inline]
pub const fn hash128_folded(bytes: &[u8], seed_a: u64, seed_b: u64) -> u64 {
    impls::hash128_folded::<false, false>(bytes, seed_a, seed_b)
}

/// A 64-bit MuseAir v1 incremental hasher. *(standard variant)*
///
/// See [the crate level documentation](crate#incremental-hasher) for more.
pub type Hasher = impls::IncrementalHasher<false>;

/// A 128-bit MuseAir v1 incremental hasher. *(standard variant)*
///
/// See [the crate level documentation](crate#incremental-hasher) for more.
pub type Hasher128 = impls::IncrementalHasher128<false>;

/// A common MuseAir v1 incremental hasher with fixed seed 0. *(standard variant)*
///
/// This supports both 64-bit (non-folded) and 128-bit hash outputs.
///
/// See [the crate level documentation](crate#incremental-hasher) for more.
pub type CommonHasher = impls::CommonIncrementalHasher<false>;

/// The *BFast* variant of the MuseAir hashing algorithm.
///
/// The *BFast* variant is faster than *Standard*, matching the speed of [wyhash] and [rapidhash].
/// While those are susceptible to blinding multiplication, MuseAir-BFast is significantly less so.
///
/// In summary, when the seed/secret is public, constructing a blinding multiplication against MuseAir-BFast
/// for long inputs requires a different sequence per prefix and only corrupts the most recent 8 bytes,
/// whereas for [wyhash] and [rapidhash] (without `protected` mode), a fixed sequence works for any prefix
/// and corrupts a moderate portion of past bytes. See the [algorithm analysis] in the repository for details.
///
/// Thus, in most cases where MuseAir-Standard is acceptable, MuseAir-BFast can be used to improve performance
/// without noticeable quality degradation.
///
/// Note, however, that for the 64-bit version of MuseAir-BFast ([`bfast::hash`]), with a fixed seed and inputs of 9-16 bytes,
/// there always exists a fixed 8-byte prefix such that the content of bytes 9-16 does not affect the hash output.
/// Consider using the 128-bit version of MuseAir-BFast and ADD-folding the result down ([`bfast::hash128_folded`])
/// to obtain a 64-bit hash output while avoiding this issue.
///
/// [wyhash]: https://github.com/wangyi-fudan/wyhash
/// [rapidhash]: https://github.com/Nicoshev/rapidhash
/// [algorithm analysis]: https://github.com/eternal-io/museair#algorithm-analysis
pub mod bfast {
    use super::*;

    /// Computes the 64-bit MuseAir v1 hash for a byte slice. *(BFast variant)*
    #[inline]
    pub const fn hash(bytes: &[u8], seed: u64) -> u64 {
        impls::hash::<true, true>(bytes, seed)
    }

    /// Computes a 32-bit MuseAir v1 hash for a byte slice, by XOR-folding the underlying 64-bit result. *(BFast variant)*
    #[inline]
    pub const fn hash_folded(bytes: &[u8], seed: u64) -> u32 {
        impls::hash_folded::<true, true>(bytes, seed)
    }

    /// Computes the 128-bit MuseAir v1 hash for a byte slice. *(BFast variant)*
    #[inline]
    pub const fn hash128(bytes: &[u8], seed_a: u64, seed_b: u64) -> u128 {
        impls::hash128::<true, true>(bytes, seed_a, seed_b)
    }

    /// Computes a 64-bit MuseAir v1 hash for a byte slice, by ADD-folding the underlying 128-bit result. *(BFast variant)*
    #[inline]
    pub const fn hash128_folded(bytes: &[u8], seed_a: u64, seed_b: u64) -> u64 {
        impls::hash128_folded::<true, true>(bytes, seed_a, seed_b)
    }

    /// A 64-bit MuseAir v1 incremental hasher. *(BFast variant)*
    ///
    /// See [the crate level documentation](crate#incremental-hasher) for more.
    pub type Hasher = impls::IncrementalHasher<true>;

    /// A 128-bit MuseAir v1 incremental hasher. *(BFast variant)*
    ///
    /// See [the crate level documentation](crate#incremental-hasher) for more.
    pub type Hasher128 = impls::IncrementalHasher128<true>;

    /// A common MuseAir v1 incremental hasher with fixed seed 0. *(BFast variant)*
    ///
    /// This supports both 64-bit (non-folded) and 128-bit hash outputs.
    ///
    /// See [the crate level documentation](crate#incremental-hasher) for more.
    pub type CommonHasher = impls::CommonIncrementalHasher<true>;
}

//==================================================================================================

type State = [u64; 6];
type Chunk = [u8; 96];
type Tail = [u8; 32];

/// `AiryAi(0)` fractional part calculated by Y-Cruncher.
const CONSTANT: [u64; 13] = [
    0x5ae31e589c56e17a,
    0x96d7bb04e64f6da9,
    0x7ab1006b26f9eb64,
    0x21233394220b8457,
    0x047cb9557c9f3b43,
    0xd24f2590c0bcee28,
    0x33ea8f71bb6016d8,
    0xb5d2697595d0a01f,
    0x9bb30a32f00e2b4f,
    0x4acea09317a429d1,
    0xc2b2435dfdd545c6,
    0xfda811a785572a42,
    0xe5f50676bf67137b,
];

const MASK_A: u64 = 0xAAAAAAAAAAAAAAAA;
const MASK_B: u64 = 0x5555555555555555;
const MASK_I: u64 = 0o1555555555555555555555;
const MASK_J: u64 = 0o1333333333333333333333;
const MASK_K: u64 = 0o0666666666666666666666;

/// Lower 64-bit, then upper 64-bit.
#[inline(always)]
const fn u64s_to_u128(lo: u64, hi: u64) -> u128 {
    (hi as u128) << 64 | lo as u128
}
/// Lower 64-bit, then upper 64-bit.
#[inline(always)]
const fn u128_to_u64s(x: u128) -> (u64, u64) {
    (x as u64, (x >> 64) as u64)
}

/// Lower 64-bit, then upper 64-bit.
#[inline(always)]
const fn wmul(a: u64, b: u64) -> (u64, u64) {
    u128_to_u64s(a as u128 * b as u128)
}

#[inline(always)]
const fn xor_fold(x: u64) -> u32 {
    x as u32 ^ (x >> 32) as u32
}
#[inline(always)]
const fn add_fold(x: u128) -> u64 {
    (x as u64).wrapping_add((x >> 64) as u64)
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

#[inline(always)]
const fn u64x(n: usize) -> usize {
    n * 8
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
const fn state_seed64(seed: u64) -> State {
    [
        CONSTANT[0] ^ (seed & MASK_A),
        CONSTANT[1] ^ (seed & MASK_B),
        CONSTANT[2] ^ (seed & MASK_A),
        CONSTANT[3] ^ (seed & MASK_B),
        CONSTANT[4] ^ (seed & MASK_A),
        CONSTANT[5] ^ (seed & MASK_B),
    ]
}

#[inline(always)]
const fn state_seed128(seed_a: u64, seed_b: u64) -> State {
    [
        CONSTANT[0] ^ (seed_a & MASK_I),
        CONSTANT[1] ^ (seed_b & MASK_J),
        CONSTANT[2] ^ (seed_a & MASK_K),
        CONSTANT[3] ^ (seed_b & MASK_I),
        CONSTANT[4] ^ (seed_a & MASK_J),
        CONSTANT[5] ^ (seed_b & MASK_K),
    ]
}

//------------------------------------------------------------------------------
// REMARK: Use `match first_chunk` instead `last_chunk.unwrap` for MSRV-friendly.

#[inline(always)]
const fn read_u32(bytes: &[u8], offset: usize) -> u64 {
    match bytes.split_at(offset).1.first_chunk() {
        Some(&chunk) => u32::from_le_bytes(chunk) as u64,
        None => panic!(),
    }
}

#[inline(always)]
const fn read_u32_r(bytes: &[u8], offset_r: usize) -> u64 {
    match bytes.split_at(bytes.len() - offset_r - 4).1.first_chunk() {
        Some(&chunk) => u32::from_le_bytes(chunk) as u64,
        None => panic!(),
    }
}

#[inline(always)]
const fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    match bytes.split_at(offset).1.first_chunk() {
        Some(&chunk) => u64::from_le_bytes(chunk),
        None => panic!(),
    }
}

#[inline(always)]
const fn read_u64_r(bytes: &[u8], offset_r: usize) -> u64 {
    match bytes.split_at(bytes.len() - offset_r - 8).1.first_chunk() {
        Some(&chunk) => u64::from_le_bytes(chunk),
        None => panic!(),
    }
}

#[inline(always)]
const fn read_short(bytes: &[u8]) -> (u64, u64) {
    debug_assert!(bytes.len() <= u64x(2));

    let len = bytes.len();
    match len {
        8.. => (read_u64(bytes, 0), read_u64_r(bytes, 0)),
        4.. => (read_u32(bytes, 0), read_u32_r(bytes, 0)),
        1.. => ((bytes[0] as u64) << 48 | bytes[len - 1] as u64, bytes[len >> 1] as u64),
        0.. => (0, 0),
    }
}

//------------------------------------------------------------------------------

#[inline(always)]
const fn hash_short_64<const BFAST: bool>(bytes: &[u8], seed: u64) -> u64 {
    debug_assert!(bytes.len() <= u64x(4));

    let len = bytes.len() as u64;
    let (mut i, mut j) = read_short(bytes.split_at(min!(u64x(2), bytes.len())).0);
    let (lo2, hi2) = wmul(CONSTANT[2] ^ seed ^ len, CONSTANT[3] ^ len);
    i ^= lo2;
    j ^= hi2;

    if unlikely(bytes.len() > u64x(2)) {
        let (u, v) = read_short(bytes.split_at(u64x(2)).1);
        let (lo0, hi0) = wmul(CONSTANT[4] ^ u, CONSTANT[5]);
        let (lo1, hi1) = wmul(CONSTANT[6] ^ v, CONSTANT[7]);
        i ^= lo0 ^ hi1;
        j ^= lo1 ^ hi0;
    }

    if !BFAST {
        let (lo2, hi2) = wmul(i ^ CONSTANT[8], j ^ CONSTANT[9]);
        i = i.wrapping_sub(lo2);
        j = j.wrapping_sub(hi2);
        let (lo2, hi2) = wmul(i ^ CONSTANT[10], j ^ CONSTANT[11]);
        i = i.wrapping_sub(lo2);
        j = j.wrapping_sub(hi2);
        i ^ j
    } else {
        (i, j) = wmul(i ^ CONSTANT[8], j ^ CONSTANT[9]);
        (i, j) = wmul(i ^ CONSTANT[10], j ^ CONSTANT[11]);
        i ^ j
    }
}

#[inline(always)]
const fn hash_short_128<const BFAST: bool>(bytes: &[u8], seed_a: u64, seed_b: u64) -> u128 {
    debug_assert!(bytes.len() <= u64x(4));

    let len = bytes.len() as u64;
    let (mut i, mut j) = read_short(bytes.split_at(min!(u64x(2), bytes.len())).0);
    let (lo0, hi0) = wmul(CONSTANT[0].wrapping_add(seed_a).wrapping_add(len), CONSTANT[1] ^ len);
    let (lo1, hi1) = wmul(CONSTANT[2].wrapping_sub(seed_b).wrapping_sub(len), CONSTANT[3] ^ len);
    i ^= lo0 ^ hi1;
    j ^= lo1 ^ hi0;

    if unlikely(bytes.len() > u64x(2)) {
        let (u, v) = read_short(bytes.split_at(u64x(2)).1);
        let (lo0, hi0) = wmul(CONSTANT[4] ^ u, CONSTANT[5]);
        let (lo1, hi1) = wmul(CONSTANT[6] ^ v, CONSTANT[7]);
        i ^= lo0 ^ hi1;
        j ^= lo1 ^ hi0;
    }

    if !BFAST {
        let (lo0, hi0) = wmul(i ^ CONSTANT[8], j ^ CONSTANT[9]);
        let (lo1, hi1) = wmul(i ^ CONSTANT[11], j ^ CONSTANT[10]);
        let (lo0, hi0) = wmul(lo0 ^ CONSTANT[10], hi0 ^ CONSTANT[11]);
        let (lo1, hi1) = wmul(lo1 ^ CONSTANT[9], hi1 ^ CONSTANT[8]);
        u64s_to_u128(lo0 ^ hi1, lo1 ^ hi0)
    } else {
        let (lo0, hi0) = wmul(i ^ CONSTANT[8], j ^ CONSTANT[9]);
        let (lo1, hi1) = wmul(i, j);
        let (lo0, hi0) = wmul(lo0 ^ CONSTANT[10], hi0 ^ CONSTANT[11]);
        let (lo1, hi1) = wmul(lo1, hi1);
        u64s_to_u128(lo0 ^ hi1, lo1 ^ hi0)
    }
}

#[inline(never)]
const fn hash_loong_64<const BFAST: bool, const UNROLL: bool>(bytes: &[u8], seed: u64) -> u64 {
    hash_loong_epi64(hash_loong_common::<BFAST, UNROLL>(bytes, state_seed64(seed)))
}

#[inline(never)]
const fn hash_loong_128<const BFAST: bool, const UNROLL: bool>(bytes: &[u8], seed_a: u64, seed_b: u64) -> u128 {
    hash_loong_epi128(hash_loong_common::<BFAST, UNROLL>(bytes, state_seed128(seed_a, seed_b)))
}

#[inline(always)]
const fn hash_loong_epi64((i, j, k): (u64, u64, u64)) -> u64 {
    i.wrapping_add(j).wrapping_add(k)
}

#[inline(always)]
const fn hash_loong_epi128((i, j, k): (u64, u64, u64)) -> u128 {
    let (lo3, hi3) = wmul(i, CONSTANT[10]);
    let (lo4, hi4) = wmul(j, CONSTANT[11]);
    let (lo5, hi5) = wmul(k, CONSTANT[12]);
    u64s_to_u128(lo3 ^ hi4 ^ lo5, hi3 ^ lo4 ^ hi5)
}

#[inline(always)]
const fn hash_loong_common<const BFAST: bool, const UNROLL: bool>(bytes: &[u8], mut state: State) -> (u64, u64, u64) {
    debug_assert!(bytes.len() > u64x(4));

    let mut rest = bytes;
    let mut circular = CONSTANT[6];

    if unlikely(rest.len() > u64x(12)) {
        loop {
            if UNROLL && likely(rest.len() > u64x(24)) {
                let (chunks, remainder) = rest.split_at(u64x(24));
                let (chunk0, chunk1) = chunks.split_at(u64x(12));
                let (Some(chunk0), Some(chunk1)) = (chunk0.first_chunk(), chunk1.first_chunk()) else {
                    unreachable!()
                };
                rest = remainder;
                (state, circular) = hash_loong_compress::<BFAST>(chunk0, state, circular);
                (state, circular) = hash_loong_compress::<BFAST>(chunk1, state, circular);
            } else if likely(rest.len() > u64x(12)) {
                let Some((chunk, remainder)) = rest.split_first_chunk() else {
                    unreachable!()
                };
                rest = remainder;
                (state, circular) = hash_loong_compress::<BFAST>(chunk, state, circular);
            } else {
                break;
            }
        }
        state[0] ^= circular; /* Don't forget this! */
    }

    hash_loong_finalize::<BFAST>(
        state,
        rest,
        match bytes.split_at(bytes.len() - u64x(4)).1.first_chunk() {
            Some(chunk) => chunk,
            None => unreachable!(),
        },
        bytes.len() as u64,
    )
}

#[inline(always)]
const fn hash_loong_compress<const BFAST: bool>(chunk: &Chunk, mut state: State, circular: u64) -> (State, u64) {
    if !BFAST {
        state[0] ^= read_u64(chunk, u64x(0));
        state[1] ^= read_u64(chunk, u64x(1));
        let (lo0, hi0) = wmul(state[0], state[1]);
        state[0] = state[0].wrapping_sub(lo0 ^ circular);

        state[1] ^= read_u64(chunk, u64x(2));
        state[2] ^= read_u64(chunk, u64x(3));
        let (lo1, hi1) = wmul(state[1], state[2]);
        state[1] = state[1].wrapping_sub(lo1 ^ hi0);

        state[2] ^= read_u64(chunk, u64x(4));
        state[3] ^= read_u64(chunk, u64x(5));
        let (lo2, hi2) = wmul(state[2], state[3]);
        state[2] = state[2].wrapping_sub(lo2 ^ hi1);

        state[3] ^= read_u64(chunk, u64x(6));
        state[4] ^= read_u64(chunk, u64x(7));
        let (lo3, hi3) = wmul(state[3], state[4]);
        state[3] = state[3].wrapping_sub(lo3 ^ hi2);

        state[4] ^= read_u64(chunk, u64x(8));
        state[5] ^= read_u64(chunk, u64x(9));
        let (lo4, hi4) = wmul(state[4], state[5]);
        state[4] = state[4].wrapping_sub(lo4 ^ hi3);

        state[5] ^= read_u64(chunk, u64x(10));
        state[0] ^= read_u64(chunk, u64x(11));
        let (lo5, hi5) = wmul(state[5], state[0]);
        state[5] = state[5].wrapping_sub(lo5 ^ hi4);

        (state, hi5)
    } else {
        state[0] ^= read_u64(chunk, u64x(0));
        state[1] ^= read_u64(chunk, u64x(1));
        let (lo0, hi0) = wmul(state[0], state[1]);
        state[0] = circular ^ hi0;

        state[1] ^= read_u64(chunk, u64x(2));
        state[2] ^= read_u64(chunk, u64x(3));
        let (lo1, hi1) = wmul(state[1], state[2]);
        state[1] = lo0 ^ hi1;

        state[2] ^= read_u64(chunk, u64x(4));
        state[3] ^= read_u64(chunk, u64x(5));
        let (lo2, hi2) = wmul(state[2], state[3]);
        state[2] = lo1 ^ hi2;

        state[3] ^= read_u64(chunk, u64x(6));
        state[4] ^= read_u64(chunk, u64x(7));
        let (lo3, hi3) = wmul(state[3], state[4]);
        state[3] = lo2 ^ hi3;

        state[4] ^= read_u64(chunk, u64x(8));
        state[5] ^= read_u64(chunk, u64x(9));
        let (lo4, hi4) = wmul(state[4], state[5]);
        state[4] = lo3 ^ hi4;

        state[5] ^= read_u64(chunk, u64x(10));
        state[0] ^= read_u64(chunk, u64x(11));
        let (lo5, hi5) = wmul(state[5], state[0]);
        state[5] = lo4 ^ hi5;

        (state, lo5)
    }
}

#[inline(always)]
const fn hash_loong_finalize<const BFAST: bool>(
    mut state: State,
    rest: &[u8],
    tail: &Tail,
    tot_len: u64,
) -> (u64, u64, u64) {
    let [mut lo0, mut lo1, mut lo2, mut lo3, lo4, lo5];
    let [mut hi0, mut hi1, mut hi2, mut hi3, hi4, hi5];

    [lo0, lo1, lo2, lo3] = [0, 0, 0, 0];
    [hi0, hi1, hi2, hi3] = [state[1], state[2], state[3], state[4]];

    if rest.len() > u64x(4) {
        state[0] ^= read_u64(rest, u64x(0));
        state[1] ^= read_u64(rest, u64x(1));
        (lo0, hi0) = wmul(state[0], state[1]);

        if rest.len() > u64x(6) {
            state[1] ^= read_u64(rest, u64x(2));
            state[2] ^= read_u64(rest, u64x(3));
            (lo1, hi1) = wmul(state[1], state[2]);

            if rest.len() > u64x(8) {
                state[2] ^= read_u64(rest, u64x(4));
                state[3] ^= read_u64(rest, u64x(5));
                (lo2, hi2) = wmul(state[2], state[3]);

                if rest.len() > u64x(10) {
                    state[3] ^= read_u64(rest, u64x(6));
                    state[4] ^= read_u64(rest, u64x(7));
                    (lo3, hi3) = wmul(state[3], state[4]);
                }
            }
        }
    }

    state[4] ^= read_u64(tail, u64x(0));
    state[5] ^= read_u64(tail, u64x(1));
    (lo4, hi4) = wmul(state[4], state[5]);

    state[5] ^= read_u64(tail, u64x(2));
    state[0] ^= read_u64(tail, u64x(3));
    (lo5, hi5) = wmul(state[5], state[0]);

    let mut i = state[0].wrapping_sub(state[1]) ^ CONSTANT[7];
    let mut j = state[2].wrapping_sub(state[3]) ^ CONSTANT[8];
    let mut k = state[4].wrapping_sub(state[5]) ^ CONSTANT[9];

    let rot = tot_len as u32 & 63;
    i = i.rotate_left(rot);
    j = j.rotate_right(rot);
    k = k.wrapping_sub(tot_len);

    i = i.wrapping_sub(lo3 ^ hi3).wrapping_sub(lo4 ^ hi4);
    j = j.wrapping_sub(lo5 ^ hi5).wrapping_sub(lo0 ^ hi0);
    k = k.wrapping_sub(lo1 ^ hi1).wrapping_sub(lo2 ^ hi2);

    let (lo0, hi0) = wmul(i, j);
    let (lo1, hi1) = wmul(j, k);
    let (lo2, hi2) = wmul(k, i);

    if !BFAST {
        i ^= lo0 ^ hi2;
        j ^= lo1 ^ hi0;
        k ^= lo2 ^ hi1;
    } else {
        i = lo2 ^ hi0;
        j = lo0 ^ hi1;
        k = lo1 ^ hi2;
    }

    (i, j, k)
}

//------------------------------------------------------------------------------

/// Implementation details of MuseAir v1.
///
/// Const generic parameters:
///
/// - `UNROLL` - Unrolls the loop for higher throughput on some platforms, at the cost of more instructions.
pub mod impls {
    use super::*;

    /// Computes the 64-bit MuseAir v1 hash for a byte slice.
    ///
    /// For most use cases, prefer [`hash`](crate::hash) or [`bfast::hash`] instead.
    #[inline(always)]
    pub const fn hash<const BFAST: bool, const UNROLL: bool>(bytes: &[u8], seed: u64) -> u64 {
        if likely(bytes.len() <= u64x(4)) {
            hash_short_64::<BFAST>(bytes, seed)
        } else {
            hash_loong_64::<BFAST, UNROLL>(bytes, seed)
        }
    }

    /// Computes a 32-bit MuseAir v1 hash for a byte slice, by XOR-folding the underlying 64-bit result.
    ///
    /// For most use cases, prefer [`hash_folded`](crate::hash_folded) or [`bfast::hash_folded`] instead.
    #[inline(always)]
    pub const fn hash_folded<const BFAST: bool, const UNROLL: bool>(bytes: &[u8], seed: u64) -> u32 {
        xor_fold(hash::<BFAST, UNROLL>(bytes, seed))
    }

    /// Computes the 128-bit MuseAir v1 hash for a byte slice.
    ///
    /// For most use cases, prefer [`hash128`](crate::hash128) or [`bfast::hash128`] instead.
    #[inline(always)]
    pub const fn hash128<const BFAST: bool, const UNROLL: bool>(bytes: &[u8], seed_a: u64, seed_b: u64) -> u128 {
        if likely(bytes.len() <= u64x(4)) {
            hash_short_128::<BFAST>(bytes, seed_a, seed_b)
        } else {
            hash_loong_128::<BFAST, UNROLL>(bytes, seed_a, seed_b)
        }
    }

    /// Computes a 64-bit MuseAir v1 hash for a byte slice, by ADD-folding the underlying 128-bit result.
    ///
    /// For most use cases, prefer [`hash128_folded`](crate::hash128_folded) or [`bfast::hash128_folded`] instead.
    #[inline(always)]
    pub const fn hash128_folded<const BFAST: bool, const UNROLL: bool>(bytes: &[u8], seed_a: u64, seed_b: u64) -> u64 {
        add_fold(hash128::<BFAST, UNROLL>(bytes, seed_a, seed_b))
    }

    //------------------------------------------------------------------------------

    /// The 64-bit MuseAir v1 incremental hasher.
    ///
    /// For most use cases, prefer [`Hasher`] or [`bfast::Hasher`] instead.
    ///
    /// See [the crate level documentation](crate#incremental-hasher) for more.
    #[derive(Clone)]
    pub struct IncrementalHasher<const BFAST: bool> {
        inner: IncrementalHasherState<false>,
    }
    impl<const BFAST: bool> IncrementalHasher<BFAST> {
        /// Constructs a new, 64-bit MuseAir v1 incremental hasher.
        pub const fn with_seed(x: u64) -> Self {
            Self {
                inner: IncrementalHasherState::with_seed64(x),
            }
        }
        /// Writes bytes into this incremental hasher.
        pub fn write(&mut self, bytes: &[u8]) {
            self.inner.write::<BFAST>(bytes);
        }
        /// Returns the 64-bit hash value for the bytes written so far.
        pub fn finish(&self) -> u64 {
            self.inner.finish64::<BFAST>()
        }
        /// Returns a 32-bit hash value for the bytes written so far, by XOR-folding the underlying 64-bit result.
        pub fn finish_folded(&self) -> u32 {
            xor_fold(self.inner.finish64::<BFAST>())
        }
        /// Returns the total bytes written so far.
        pub fn total_bytes_written(&self) -> u64 {
            self.inner.total_bytes_written()
        }
    }
    impl<const BFAST: bool> core::hash::Hasher for IncrementalHasher<BFAST> {
        fn finish(&self) -> u64 {
            self.finish()
        }
        fn write(&mut self, bytes: &[u8]) {
            self.write(bytes);
        }
    }
    impl<const BFAST: bool> core::fmt::Debug for IncrementalHasher<BFAST> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct(match BFAST {
                false => "museair::IncrementalHasher",
                true => "museair::bfast::IncrementalHasher",
            })
            .field("total_bytes_written", &self.total_bytes_written())
            .finish_non_exhaustive()
        }
    }

    /// The 128-bit MuseAir v1 incremental hasher.
    ///
    /// For most use cases, prefer [`Hasher128`] or [`bfast::Hasher128`] instead.
    ///
    /// See [the crate level documentation](crate#incremental-hasher) for more.
    #[derive(Clone)]
    pub struct IncrementalHasher128<const BFAST: bool> {
        inner: IncrementalHasherState<true>,
    }
    impl<const BFAST: bool> IncrementalHasher128<BFAST> {
        /// Constructs a new, 128-bit MuseAir v1 incremental hasher.
        pub const fn with_seed(a: u64, b: u64) -> Self {
            Self {
                inner: IncrementalHasherState::with_seed128(a, b),
            }
        }
        /// Writes bytes into this incremental hasher.
        pub fn write(&mut self, bytes: &[u8]) {
            self.inner.write::<BFAST>(bytes);
        }
        /// Returns the 128-bit hash value for the bytes written so far.
        pub fn finish128(&self) -> u128 {
            self.inner.finish128::<BFAST>()
        }
        /// Returns a 64-bit hash value for the bytes written so far, by ADD-folding the underlying 128-bit result.
        pub fn finish128_folded(&self) -> u64 {
            add_fold(self.inner.finish128::<BFAST>())
        }
        /// Returns the total bytes written so far.
        pub fn total_bytes_written(&self) -> u64 {
            self.inner.total_bytes_written()
        }
    }
    impl<const BFAST: bool> core::hash::Hasher for IncrementalHasher128<BFAST> {
        fn finish(&self) -> u64 {
            self.finish128_folded()
        }
        fn write(&mut self, bytes: &[u8]) {
            self.write(bytes);
        }
    }
    impl<const BFAST: bool> core::fmt::Debug for IncrementalHasher128<BFAST> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct(match BFAST {
                false => "museair::IncrementalHasher128",
                true => "museair::bfast::IncrementalHasher128",
            })
            .field("total_bytes_written", &self.total_bytes_written())
            .finish_non_exhaustive()
        }
    }

    /// The common MuseAir v1 incremental hasher with fixed seed 0.
    ///
    /// This supports both 64-bit (non-folded) and 128-bit hash outputs.
    ///
    /// For most use cases, prefer [`CommonHasher`] or [`bfast::CommonHasher`] instead.
    ///
    /// See [the crate level documentation](crate#incremental-hasher) for more.
    #[derive(Clone)]
    pub struct CommonIncrementalHasher<const BFAST: bool> {
        inner: IncrementalHasherState<false>,
    }
    impl<const BFAST: bool> CommonIncrementalHasher<BFAST> {
        /// Constructs a new, common MuseAir v1 incremental hasher with fixed seed 0.
        pub const fn new() -> Self {
            Self {
                inner: IncrementalHasherState::with_seed64(0),
            }
        }
        /// Writes bytes into this incremental hasher.
        pub fn write(&mut self, bytes: &[u8]) {
            self.inner.write::<BFAST>(bytes);
        }
        /// Returns the 64-bit hash value for the bytes written so far.
        pub fn finish(&self) -> u64 {
            self.inner.finish64::<BFAST>()
        }
        /// Returns a 32-bit hash value for the bytes written so far, by XOR-folding the underlying 64-bit result.
        pub fn finish_folded(&self) -> u32 {
            xor_fold(self.inner.finish64::<BFAST>())
        }
        /// Returns the 128-bit hash value for the bytes written so far.
        pub fn finish128(&self) -> u128 {
            self.inner.finish128::<BFAST>()
        }
        /// Returns a 64-bit hash value for the bytes written so far, by ADD-folding the underlying 128-bit result.
        pub fn finish128_folded(&self) -> u64 {
            add_fold(self.inner.finish128::<BFAST>())
        }
        /// Returns the total bytes written so far.
        pub fn total_bytes_written(&self) -> u64 {
            self.inner.total_bytes_written()
        }
    }
    impl<const BFAST: bool> core::fmt::Debug for CommonIncrementalHasher<BFAST> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct(match BFAST {
                false => "museair::CommonIncrementalHasher",
                true => "museair::bfast::CommonIncrementalHasher",
            })
            .field("total_bytes_written", &self.total_bytes_written())
            .finish_non_exhaustive()
        }
    }
    impl<const BFAST: bool> Default for CommonIncrementalHasher<BFAST> {
        fn default() -> Self {
            Self::new()
        }
    }

    //------------------------------------------------------------------------------

    #[derive(Clone)]
    enum IncrementalHasherState<const B128: bool> {
        Short {
            seed_a: u64,
            seed_b: u64,
            buffer: Tail,
            buffered_len: u8,
        },
        Loong {
            state: State,
            circular: u64,
            buffer: Chunk,
            buffered_len: u8,
            compressed: bool,
            compressed_len: u64,
        },
    }

    impl<const B128: bool> IncrementalHasherState<B128> {
        #[inline(always)]
        const fn with_seed64(seed: u64) -> Self {
            Self::Short {
                seed_a: seed,
                seed_b: 0,
                buffer: [0x00; 32],
                buffered_len: 0,
            }
        }
        #[inline(always)]
        fn finish64<const BFAST: bool>(&self) -> u64 {
            match self {
                Self::Short {
                    seed_a,
                    buffer,
                    buffered_len,
                    ..
                } => hash_short_64::<BFAST>(&buffer[..*buffered_len as usize], *seed_a),

                Self::Loong { .. } => {
                    let mut buf = Tail::default();
                    let tot_len = self.total_bytes_written();
                    hash_loong_epi64(hash_loong_finalize::<BFAST>(
                        self.state(),
                        self.rest(),
                        self.tail(&mut buf),
                        tot_len,
                    ))
                }
            }
        }

        #[inline(always)]
        const fn with_seed128(seed_a: u64, seed_b: u64) -> Self {
            Self::Short {
                seed_a,
                seed_b,
                buffer: [0x00; 32],
                buffered_len: 0,
            }
        }
        #[inline(always)]
        fn finish128<const BFAST: bool>(&self) -> u128 {
            match self {
                Self::Short {
                    seed_a,
                    seed_b,
                    buffer,
                    buffered_len,
                } => hash_short_128::<BFAST>(&buffer[..*buffered_len as usize], *seed_a, *seed_b),

                Self::Loong { .. } => {
                    let mut buf = Tail::default();
                    let tot_len = self.total_bytes_written();
                    hash_loong_epi128(hash_loong_finalize::<BFAST>(
                        self.state(),
                        self.rest(),
                        self.tail(&mut buf),
                        tot_len,
                    ))
                }
            }
        }

        #[inline(always)]
        fn write<const BFAST: bool>(&mut self, bytes: &[u8]) {
            match self {
                IncrementalHasherState::Short {
                    seed_a,
                    seed_b,
                    buffer,
                    buffered_len,
                } => {
                    if let remainder @ [_, ..] = Self::fill_buffer(bytes, buffer, buffered_len) {
                        let mut chunk = [0x00; 96];
                        chunk[..buffer.len()].copy_from_slice(buffer);

                        *self = Self::Loong {
                            state: if B128 {
                                state_seed128(*seed_a, *seed_b)
                            } else {
                                state_seed64(*seed_a)
                            },
                            circular: CONSTANT[6],
                            buffer: chunk,
                            buffered_len: *buffered_len,
                            compressed: false,
                            compressed_len: 0,
                        };

                        self.write::<BFAST>(remainder);
                    }
                }

                IncrementalHasherState::Loong {
                    state,
                    circular,
                    buffer,
                    buffered_len,
                    compressed,
                    compressed_len,
                } => {
                    if let remainder @ [_, ..] = Self::fill_buffer(bytes, buffer, buffered_len) {
                        let mut first = Some(&*buffer);
                        let mut rest = remainder;

                        *buffered_len = 0;
                        *compressed = true;

                        loop {
                            let chunk = if let Some(chunk) = first.take() {
                                chunk
                            } else if let Some((chunk, remainder)) = rest.split_first_chunk() {
                                rest = remainder;
                                chunk
                            } else {
                                unreachable!()
                            };

                            (*state, *circular) = hash_loong_compress::<BFAST>(chunk, *state, *circular);
                            *compressed_len = compressed_len.wrapping_add(u64x(12) as u64);

                            if unlikely(rest.len() <= u64x(12)) {
                                *buffer = *chunk; // This is important so that `tail()` can restore the correct data.
                                break;
                            }
                        }

                        Self::fill_buffer(rest, buffer, buffered_len);
                    }
                }
            }
        }

        #[inline(always)]
        fn fill_buffer<'a>(bytes: &'a [u8], buffer: &mut [u8], buffered_len: &mut u8) -> &'a [u8] {
            let cursor = *buffered_len as usize;
            let vacancy = buffer.len() - cursor;
            let (head, remainder) = bytes.split_at(bytes.len().min(vacancy));
            buffer[cursor..][..head.len()].copy_from_slice(head);
            *buffered_len += head.len() as u8;
            remainder
        }

        #[inline(always)]
        fn state(&self) -> State {
            let Self::Loong {
                state,
                circular,
                compressed,
                ..
            } = self
            else {
                unreachable!()
            };
            let mut state = *state;
            if likely(*compressed) {
                state[0] ^= circular; /* Don't forget this! */
            }
            state
        }

        #[inline(always)]
        fn rest(&self) -> &[u8] {
            let Self::Loong {
                buffer, buffered_len, ..
            } = self
            else {
                unreachable!()
            };
            buffer.split_at(*buffered_len as usize).0
        }

        #[inline(always)]
        fn tail<'a>(&self, buf: &'a mut Tail) -> &'a Tail {
            let Self::Loong {
                buffer, buffered_len, ..
            } = self
            else {
                unreachable!()
            };
            let end = *buffered_len as usize;
            if end >= u64x(4) {
                buf.copy_from_slice(&buffer[end - u64x(4)..][..u64x(4)]);
            } else {
                let (older, newer) = buf.split_at_mut(u64x(4) - end);
                older.copy_from_slice(&buffer[buffer.len() + end - u64x(4)..]);
                newer.copy_from_slice(&buffer[..end]);
            }
            buf
        }

        #[inline(always)]
        fn total_bytes_written(&self) -> u64 {
            match self {
                IncrementalHasherState::Short { buffered_len, .. } => *buffered_len as u64,
                IncrementalHasherState::Loong {
                    buffered_len,
                    compressed_len,
                    ..
                } => compressed_len.wrapping_add(*buffered_len as u64),
            }
        }
    }
}

//==================================================================================================

#[cfg(test)]
mod verify {
    use super::*;
    use rapidhash::rng::rapidrng_fast as rand;
    extern crate std;

    #[test]
    fn stability_v1() {
        let expected = vec![
            0xFB919A7D, 0x7F558188, 0x4041FF27, 0xD5B53A4E, 0x79B92E70, 0xF3B0F5C2, 0x0B4953E9, 0x14474887,
        ];
        let calculated = vec![
            hashverify::compute(64, |bytes, seed, out| {
                out.copy_from_slice(&hash(bytes, seed).to_le_bytes())
            }),
            hashverify::compute(32, |bytes, seed, out| {
                out.copy_from_slice(&hash_folded(bytes, seed).to_le_bytes())
            }),
            hashverify::compute(128, |bytes, seed, out| {
                out.copy_from_slice(&hash128(bytes, seed, seed).to_le_bytes())
            }),
            hashverify::compute(64, |bytes, seed, out| {
                out.copy_from_slice(&hash128_folded(bytes, seed, seed).to_le_bytes())
            }),
            hashverify::compute(64, |bytes, seed, out| {
                out.copy_from_slice(&bfast::hash(bytes, seed).to_le_bytes())
            }),
            hashverify::compute(32, |bytes, seed, out| {
                out.copy_from_slice(&bfast::hash_folded(bytes, seed).to_le_bytes())
            }),
            hashverify::compute(128, |bytes, seed, out| {
                out.copy_from_slice(&bfast::hash128(bytes, seed, seed).to_le_bytes())
            }),
            hashverify::compute(64, |bytes, seed, out| {
                out.copy_from_slice(&bfast::hash128_folded(bytes, seed, seed).to_le_bytes())
            }),
        ];

        println!("[");
        calculated.iter().for_each(|v| println!("    0x{v:08X},"));
        println!("]");

        assert_eq!(expected, calculated);
    }

    #[test]
    fn incremental_hashing() {
        macro_rules! wrap_fn64 {
            ($hash:path) => {
                |bytes: &[u8], seed: u128| $hash(bytes, seed as u64)
            };
        }
        macro_rules! wrap_fn128 {
            ($hash:path) => {
                |bytes: &[u8], seed: u128| {
                    let (seed_a, seed_b) = u128_to_u64s(seed);
                    $hash(bytes, seed_a, seed_b)
                }
            };
        }
        macro_rules! wrap_hasher64 {
            ($hasher:ty, $finish:ident) => {
                |byte_chunks: &[Vec<u8>], seed: u128| {
                    let mut hasher = <$hasher>::with_seed(seed as u64);
                    for bytes in byte_chunks {
                        hasher.write(bytes);
                    }
                    hasher.$finish()
                }
            };
        }
        macro_rules! wrap_hasher128 {
            ($hasher:ty, $finish:ident) => {
                |byte_chunks: &[Vec<u8>], seed: u128| {
                    let (seed_a, seed_b) = u128_to_u64s(seed);
                    let mut hasher = <$hasher>::with_seed(seed_a, seed_b);
                    for bytes in byte_chunks {
                        hasher.write(bytes);
                    }
                    hasher.$finish()
                }
            };
        }
        let rng_seed = &mut 1123;
        #[rustfmt::skip]
        let _ = for _ in 0..4 {
            one_shot_eq_streamed(wrap_fn64! (hash),                  wrap_hasher64! (Hasher, finish),                     rng_seed);
            one_shot_eq_streamed(wrap_fn64! (hash_folded),           wrap_hasher64! (Hasher, finish_folded),              rng_seed);
            one_shot_eq_streamed(wrap_fn128!(hash128),               wrap_hasher128!(Hasher128, finish128),               rng_seed);
            one_shot_eq_streamed(wrap_fn128!(hash128_folded),        wrap_hasher128!(Hasher128, finish128_folded),        rng_seed);
            one_shot_eq_streamed(wrap_fn64! (bfast::hash),           wrap_hasher64! (bfast::Hasher, finish),              rng_seed);
            one_shot_eq_streamed(wrap_fn64! (bfast::hash_folded),    wrap_hasher64! (bfast::Hasher, finish_folded),       rng_seed);
            one_shot_eq_streamed(wrap_fn128!(bfast::hash128),        wrap_hasher128!(bfast::Hasher128, finish128),        rng_seed);
            one_shot_eq_streamed(wrap_fn128!(bfast::hash128_folded), wrap_hasher128!(bfast::Hasher128, finish128_folded), rng_seed);
        };
    }

    #[test]
    fn common_incremental_hashing() {
        macro_rules! wrap_fn64 {
            ($hash:path) => {
                |bytes, _| $hash(bytes, 0)
            };
        }
        macro_rules! wrap_fn128 {
            ($hash:path) => {
                |bytes, _| $hash(bytes, 0, 0)
            };
        }
        macro_rules! wrap_hasher {
            ($hasher:ty, $finish:ident) => {
                |byte_chunks, _| {
                    let mut hasher = <$hasher>::new();
                    for bytes in byte_chunks {
                        hasher.write(bytes);
                    }
                    hasher.$finish()
                }
            };
        }
        let rng_seed = &mut 8128;
        #[rustfmt::skip]
        let _ = for _ in 0..4 {
            one_shot_eq_streamed(wrap_fn64! (hash),                  wrap_hasher!(CommonHasher, finish),                  rng_seed);
            one_shot_eq_streamed(wrap_fn64! (hash_folded),           wrap_hasher!(CommonHasher, finish_folded),           rng_seed);
            one_shot_eq_streamed(wrap_fn128!(hash128),               wrap_hasher!(CommonHasher, finish128),               rng_seed);
            one_shot_eq_streamed(wrap_fn128!(hash128_folded),        wrap_hasher!(CommonHasher, finish128_folded),        rng_seed);
            one_shot_eq_streamed(wrap_fn64! (bfast::hash),           wrap_hasher!(bfast::CommonHasher, finish),           rng_seed);
            one_shot_eq_streamed(wrap_fn64! (bfast::hash_folded),    wrap_hasher!(bfast::CommonHasher, finish_folded),    rng_seed);
            one_shot_eq_streamed(wrap_fn128!(bfast::hash128),        wrap_hasher!(bfast::CommonHasher, finish128),        rng_seed);
            one_shot_eq_streamed(wrap_fn128!(bfast::hash128_folded), wrap_hasher!(bfast::CommonHasher, finish128_folded), rng_seed);
        };
    }

    fn one_shot_eq_streamed<T>(
        one_shot: impl Fn(&[u8], u128) -> T,
        streamed: impl Fn(&[Vec<u8>], u128) -> T,
        rng_seed: &mut u64,
    ) where
        T: PartialEq,
    {
        let bytes = Vec::<u8>::from_iter((0..256).flat_map(|_| rand(rng_seed).to_le_bytes()));
        for i in 0..=bytes.len() {
            let msg = &bytes[..i];
            let msg_chunks = random_split(&msg, rng_seed);
            let hash_seed = u64s_to_u128(rand(rng_seed), rand(rng_seed));
            if one_shot(&msg, hash_seed) != streamed(&msg_chunks, hash_seed) {
                println!("msg_length: {i}");
                println!(
                    "msg_chunks_lengths: {:?}",
                    &msg_chunks.iter().map(|frag| frag.len()).collect::<Vec<_>>(),
                );
                assert_eq!(msg, msg_chunks.iter().flatten().copied().collect::<Vec<u8>>());
                panic!()
            }
        }
    }

    fn random_split(bytes: &[u8], rng_seed: &mut u64) -> Vec<Vec<u8>> {
        const POSSIBILITY: u64 = ((1u128 << 64) / 64) as u64;
        let mut cursor = 0;
        let mut chunks = Vec::new();
        for i in 0..bytes.len() {
            if rand(rng_seed) < POSSIBILITY / 4 {
                chunks.push(Vec::new());
            }
            if rand(rng_seed) < POSSIBILITY {
                chunks.push(bytes[cursor..i].to_owned());
                cursor = i;
            }
        }
        chunks.push(bytes[cursor..].to_owned());
        chunks
    }

    #[test]
    fn popcount_preservation() {
        let mut n = 0;
        n += dbg!((CONSTANT[0] & !MASK_A).count_ones());
        n += dbg!((CONSTANT[1] & !MASK_B).count_ones());
        n += dbg!((CONSTANT[2] & !MASK_A).count_ones());
        n += dbg!((CONSTANT[3] & !MASK_B).count_ones());
        n += dbg!((CONSTANT[4] & !MASK_A).count_ones());
        n += dbg!((CONSTANT[5] & !MASK_B).count_ones());
        println!("{}", n);

        let mut n = 0;
        n += dbg!((CONSTANT[0] & !MASK_I).count_ones());
        n += dbg!((CONSTANT[1] & !MASK_J).count_ones());
        n += dbg!((CONSTANT[2] & !MASK_K).count_ones());
        n += dbg!((CONSTANT[3] & !MASK_I).count_ones());
        n += dbg!((CONSTANT[4] & !MASK_J).count_ones());
        n += dbg!((CONSTANT[5] & !MASK_K).count_ones());
        println!("{}", n);
    }
}
