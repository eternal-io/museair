# MuseAir

[![](https://img.shields.io/crates/v/museair)](https://crates.io/crates/museair)
[![](https://img.shields.io/crates/d/museair)](https://crates.io/crates/museair)
[![](https://img.shields.io/crates/l/museair)](#)
[![](https://img.shields.io/docsrs/museair)](https://docs.rs/museair)


MuseAir is the top-performing portable hashing algorithm to date.

- **Improved quality** -
  Not vulnerable to blinding multiplication attacks that hinder public use (which affect [wyhash] and [rapidhash]);
  passed all [SMHasher3] tests, the de facto non-crypto hash quality standard;
  ideal for checksums such as in communication protocols and persistent file formats.
  See the [algorithm analysis](https://github.com/eternal-io/museair#algorithm-analysis) in the repository for details.

- **Blazing fast** - The fastest portable hashing algorithm not affected by such attacks.

- **Various widths** - Providing 64-bit and 128-bit hash outputs with essentially the same overhead.

- **Portable** - Has no dependency on hardware-specific instructions, produces stable hash output on all platforms, and runs optimally on most 64-bit architectures.

- Compile-time hashing, as the implementation is fully `const`.

- Compatible with no-std and no-alloc, with zero dependencies and zero unsafe code.

MuseAir is **not designed for cryptographic security** and must not be used for security-critical purposes, such as protecting against malicious tampering. For such cases, consider using KangarooTwelve (K12), BLAKE3, or Ascon.

[wyhash]: https://github.com/wangyi-fudan/wyhash
[rapidhash]: https://github.com/Nicoshev/rapidhash
[SMHasher3]: https://gitlab.com/fwojcik/smhasher3


## Stability

The currently stable version of the algorithm is **v1**.

For stable versions of the algorithm, the hash output is guaranteed not to change with the crate version.


## Usage

```rust
let seed: u64 = 1123;
let p1: u64 = museair::hash(b"K--Aethiax", seed);
let p2: u64 = {
    let mut hasher = museair::Hasher::with_seed(seed);
    hasher.write(b"K--Ae");
    hasher.write(b"thiax");
    hasher.finish()
};

let seed_a: u64 = 1093;
let seed_b: u64 = 3511;
let p3: u128 = museair::hash128(b"K--Aethiax", seed_a, seed_b);
let p4: u128 = {
    let mut hasher = museair::Hasher128::with_seed(seed_a, seed_b);
    hasher.write(b"K--Ae");
    hasher.write(b"thiax");
    hasher.finish128()
};

assert_eq!(p1, p2);
assert_eq!(p3, p4);
```

### Incremental hasher

This crate provides incremental hashers.

However, incremental hashers are often slower in places where a [`Hasher`] is needed (e.g., [`HashMap`]), since the trait [`Hasher`] does not mandate incremental behavior, incremental hashers cannot take advantage of it to improve performance.

If you simply want to replace the [`DefaultHasher`] (the much slower SipHash) or get a faster [`HashMap`], without needing a stable hash output, then you only need an in-memory hasher; consider using [ahash] or [foldhash], which are better suited for such cases.

[`Hasher`]: std::hash::Hasher
[`HashMap`]: std::collections::HashMap
[`DefaultHasher`]: std::collections::hash_map::DefaultHasher
[ahash]: https://crates.io/crates/ahash
[foldhash]: https://crates.io/crates/foldhash


## Benchmarks

Benchmarks conducted on AMD Ryzen 7 5700G desktop, with frequency locked at 4.0 GHz.

<p align="center">
<img width="90%" src="https://github.com/eternal-io/museair/blob/fd8a65772ae03824b17015bd5496f528458e43b3/results/bench-bulkdata.png?raw=true" alt="Throughput for bulk data" /></p>
<p align="center">
<img width="80%" src="https://github.com/eternal-io/museair/blob/fd8a65772ae03824b17015bd5496f528458e43b3/results/bench-smallkeys.png?raw=true" alt="Latency for small keys" /></p>


## Crate versioning

The current MSRV (Minimum Supported Rust Version) is 1.77.0. MSRV bumps are considered breaking changes.

Everything else follows the SemVer.
