# MuseAir

[![](https://img.shields.io/crates/v/museair)](https://crates.io/crates/museair)
[![](https://img.shields.io/crates/d/museair)](https://crates.io/crates/museair)
[![](https://img.shields.io/crates/l/museair)](#)
[![](https://img.shields.io/docsrs/museair)](https://docs.rs/museair)
[![](https://img.shields.io/github/stars/eternal-io/museair?style=social)](https://github.com/eternal-io/museair)


A fast portable hash algorithm with highest bulk throughput and lowest small key latency (1-32 bytes) among portable hashes listed in SMHasher3,
and made improvements for quality and usability. See [repository](https://github.com/eternal-io/museair) for details.

It provides two variants: `Standard` (items listed in crate root) and `BFast`.
The former offers better quality and the latter offers better performance.
Both variants offer 64-bit and 128-bit output with essentially the same overhead.


## Usage

```rust
let seed: u64 = 42;

let one_shot = museair::hash_128("K--Aethiax".as_bytes(), seed);
let streamed = {
    let mut hasher = museair::Hasher::with_seed(seed);
    hasher.write("K--Ae".as_bytes());
    hasher.write("thiax".as_bytes());
    hasher.finish_128()
};

assert_eq!(one_shot, streamed);
```


## Security

MuseAir is **NOT** designed for cryptographic security. You shouldn't use this for security purposes,
such as ensuring that files have not been maliciously tampered with. For these use cases, consider SHA-3, Ascon or Blake3.

Besides, MuseAir-`Standard` is planned to be stable after some time (1.0.0).
Due to its improved quality, it will then be available for the following purposes:

- Persistent file format
- Communication protocol
- ...

_Until then, it should only be used for local sessions!_


## Benchmarks

| Hash               | Digest length |      Throughput   |
|:------------------ | -------------:| -----------------:|
| MuseAir            |        64-bit |      30.5 GiB/s   |
| MuseAir-128        |       128-bit |      30.4 GiB/s   |
| MuseAir-BFast      |        64-bit |    **36.4 GiB/s** |
| MuseAir-BFast-128  |       128-bit |    **36.3 GiB/s** |
| [wyhash] 4.2       |        64-bit |      28.4 GiB/s   |
|  wyhash.condom 4.2 |        64-bit |      22.8 GiB/s   |
| [komihash] 5.10    |        64-bit |      26.8 GiB/s   |

<img src="https://github.com/eternal-io/museair/blob/master/results/bench-smallkeys.png?raw=true" alt="Bench small keys" width="100%" />


[wyhash]: https://crates.io/crates/wyhash-final4
[komihash]: https://crates.io/crates/komihash
