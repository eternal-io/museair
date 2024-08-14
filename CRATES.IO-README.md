[![](https://img.shields.io/crates/v/museair)](https://crates.io/crates/museair)
[![](https://img.shields.io/crates/d/museair)](https://crates.io/crates/museair)
[![](https://img.shields.io/crates/l/museair)](#)
[![](https://img.shields.io/docsrs/museair)](https://docs.rs/museair)
[![](https://img.shields.io/github/stars/eternal-io/museair?style=social)](https://github.com/eternal-io/museair)

This is the new fastest portable hash: immune to blinding multiplication, even faster then wyhash, SMHasher3 passed.

See [repository](https://github.com/eternal-io/museair) for details.


## Usage

```
let seed: u64 = 42;

let one_shot = museair::hash_128("MuseAir hash!".as_bytes(), seed);
let streamed = {
    let mut hasher = museair::Hasher::with_seed(seed);
    hasher.write("MuseAir".as_bytes());
    hasher.write(" hash!".as_bytes());
    hasher.finish_128()
};

assert_eq!(one_shot, streamed);
```


## Benchmarks

| Hash              | Digest length |                      Throughput |
|:----------------- | -------------:| -------------------------------:|
| MuseAir           |        64-bit |  29.1 GiB/s   <sub>(0.88)</sub> |
| MuseAir-128       |       128-bit |  29.0 GiB/s   <sub>(0.88)</sub> |
| MuseAir-BFast     |        64-bit |**33.0 GiB/s** <sub>(1.00)</sub> |
| MuseAir-BFast-128 |       128-bit |**33.0 GiB/s** <sub>(1.00)</sub> |
| [WyHash]          |        64-bit |  29.0 GiB/s   <sub>(0.88)</sub> |
| [WyHash]-condom   |        64-bit |  24.3 GiB/s   <sub>(0.74)</sub> |
| [KomiHash]        |        64-bit |  27.7 GiB/s   <sub>(0.84)</sub> |

(These results are obtained by running `cargo bench` on AMD Ryzen 7 5700G 4.6GHz Desktop.)

[WyHash]: https://crates.io/crates/wyhash-final4
[KomiHash]: https://crates.io/crates/komihash


## Security

MuseAir is ***NOT*** intended for cryptographic security.

- To resist HashDoS, your hash must comes with a private seed.
- To ensure the protection of your data, it is recommended to use a well-established algorithm, such as SHA-3.


## Versioning policy

The `-Standard` variant (functions listed in the crate root) is not scheduled to be stable until version 1.0.0 is released.
That is, the result of the hash may change from minor version to minor version. Don't use it for persistent storage yet.

The `-BFast` variant will never be stable, you should only use this on local sessions.
For persistent storage, you should always use the `-Standard` variant (after it is stable).

