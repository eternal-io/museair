# MuseAir

[![](https://img.shields.io/crates/v/museair)](https://crates.io/crates/museair)
[![](https://img.shields.io/crates/d/museair)](https://crates.io/crates/museair)
[![](https://img.shields.io/crates/l/museair)](#)
[![](https://img.shields.io/docsrs/museair)](https://docs.rs/museair)
[![](https://img.shields.io/github/stars/eternal-io/museair?style=social)](https://github.com/eternal-io/museair)


MuseAir is a portable hashing algorithm that heavily optimized for [performance](#benchmarks) and [quality](#quality), incorporating structures never before implemented. Complete [algorithm analysis](https://github.com/eternal-io/museair#algorithm-analysis) is available in the repository.

- **Even faster**, outperforming previous fastest wyhash and rapidhash.

- **Improved quality**, not vulnerable to *blinding multiplication* like wyhash or rapidhash, making it ideal for persistent file formats or communication protocols (though note the algorithm is not yet stable).

- **Platform independent**, no dependencies on specialized instruction sets like cryptography or vectorization, runs optimally on most 64-bit architectures.

- **Compile-time hashing**, as the implementation is fully `const`.

- **No-std compatible**, **zero unsafe code** and **zero dependencies**.

- **Non-cryptographic**, not intended for security-critical applications.



## Usage

```rust
let seed: u64 = 1123;

let v1: u64 = museair::hash("K--Aethiax".as_bytes(), seed);
let v2: u64 = {
    let mut hasher = museair::Hasher::new(seed);
    hasher.write("K--Ae".as_bytes());
    hasher.write("thiax".as_bytes());
    hasher.finish()
};

let v3: u128 = museair::hash_128("K--Aethiax".as_bytes(), seed);
let v4: u128 = {
    let mut hasher = museair::Hasher::new(seed);
    hasher.write("K--Ae".as_bytes());
    hasher.write("thiax".as_bytes());
    hasher.finish_128()
};

assert_eq!(v1, v2);
assert_eq!(v3, v4);
```

###### Use with hashmap

This crate provides helper types that require enabling the `std` feature.

```rust
use museair::{HashMap, FixedState};

let mut map = HashMap::default();
map.insert("hello", "world");

let mut map = HashMap::with_hasher(FixedState::new(42));
map.insert("hello", "world");
```



## Feature flags

- `std` *(enabled by default)* - Enables [`HashMap`] and [`HashSet`] helper types.



## Benchmarks

Benchmarks conducted on AMD Ryzen 7 5700G desktop.

### Hashing bulk datas

<table width="100%"><tr>
<td><img width="100%" src="https://github.com/eternal-io/museair/blob/e9307db76cec53073c1502c5f6f9040953866382/results/bench-bulkdatas-smhasher3.png?raw=true" alt="Bench bulk datas (using SMHasher3)" /></td>
<td><img width="100%" src="https://github.com/eternal-io/museair/blob/e9307db76cec53073c1502c5f6f9040953866382/results/bench-bulkdatas-crit.rs.png?raw=true" alt="Bench bulk datas (using Criterion.rs)" /></td>
</tr></table>

### Hashing small keys

<img width="100%" src="https://github.com/eternal-io/museair/blob/e9307db76cec53073c1502c5f6f9040953866382/results/bench-smallkeys.png?raw=true" alt="Bench small keys (using SMHasher3)" />
<p align="center"><sup>For common 1-32 byte keys, MuseAir has a significant speed advantage (avg. 13.0 cycles/hash), even outperforming fxhash.</sup></p>



## Quality

All MuseAir variants have passed the complete [SMHasher3](https://gitlab.com/fwojcik/smhasher3) extended test suite (with `--extra` flag). As the de facto standard for non-cryptographic hashing quality, passing these tests confirms production readiness. See full [results](https://github.com/eternal-io/museair/tree/master/results) in the repository.



## Versioning

The current MSRV (Minimum Supported Rust Version) is 1.83.0. MSRV changes are considered breaking changes.
