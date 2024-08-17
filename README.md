# <img src="MuseAir-icon-light.png" style="height:1em" /> MuseAir

[![](https://img.shields.io/crates/v/museair)](https://crates.io/crates/museair)
[![](https://img.shields.io/crates/d/museair)](https://crates.io/crates/museair)
[![](https://img.shields.io/crates/l/museair)](#)
[![](https://img.shields.io/docsrs/museair)](https://docs.rs/museair)
[![](https://img.shields.io/github/stars/eternal-io/museair?style=social)](https://github.com/eternal-io/museair)

- Completely **immune to blinding multiplication**, and accumulates the full 128-bit multiplication results instead of prematurely "compressing" them into 64-bit, this results in *better confusion*.

- **As fast as [WyHash] and its successor [RapidHash]** on bulks, but they suffer from blinding multiplication.

- Inputs are never simply mixed with constants, and the algorithm correctly implements seeding. This [**prevents seed-independent attacks**](https://github.com/Cyan4973/xxHash/issues/180) and does not require additional `secret[]` to be remedied.

- Inputs are not divided into stripes while processing, this results in *better diffusion*.

- Produces either **64-bit or 128-bit** results with nearly the **same performance overhead**.


Actually, MuseAir has two variants: `-Standard` (this suffix is ​​usually omitted) and `-BFast`.

As its name suggests, the `-BFast` variant is faster but *less* immune to blinding multiplication.
("less" here means when it actually happens, it will only result in the most recent state being lost, rather than all the past state of a stripe being catastrophically lost!)


## Benchmarks

### Bulk datas

| Hash              | Digest length |   Throughput (C++ - [SMHasher3]) | Throughput (Rust - Criterion.rs) |
|:----------------- | -------------:| --------------------------------:| --------------------------------:|
| MuseAir           |        64-bit |   31.8 GiB/s   <sub>(0.96)</sub> |   29.1 GiB/s   <sub>(0.88)</sub> |
| MuseAir-128       |       128-bit |   31.8 GiB/s   <sub>(0.96)</sub> |   29.0 GiB/s   <sub>(0.88)</sub> |
| MuseAir-BFast     |        64-bit | **33.2 GiB/s** <sub>(1.00)</sub> | **33.0 GiB/s** <sub>(1.00)</sub> |
| MuseAir-BFast-128 |       128-bit | **33.2 GiB/s** <sub>(1.00)</sub> | **33.0 GiB/s** <sub>(1.00)</sub> |
| WyHash            |        64-bit |   31.9 GiB/s   <sub>(0.96)</sub> |   29.0 GiB/s   <sub>(0.88)</sub> |
| WyHash-condom     |        64-bit |   25.3 GiB/s   <sub>(0.76)</sub> |   24.3 GiB/s   <sub>(0.74)</sub> |
| KomiHash          |        64-bit |   25.5 GiB/s   <sub>(0.77)</sub> |   27.7 GiB/s   <sub>(0.84)</sub> |

(These results are obtained by running `./SMHasher3 --test=Speed <HASH>` and `cargo bench` on AMD Ryzen 7 5700G 4.6GHz Desktop.)

### Small datas

Currently there is no targeted design, it is simply modified from rapidhash.

Therefore, for short inputs no more than 16 bytes, the performance is similar to rapidhash.

For short inputs larger than 16 bytes, the function call overhead makes them slower because there is a function that should not be inlined
(otherwise the entire hash performance will be slower on all input sizes). This is the next step to focus on optimization.


## Quality

They all passed [SMHasher3] with `--extra` option.

- [MuseAir](results/SMHasher3_MuseAir_--extra.txt)
- [MuseAir-128](results/SMHasher3_MuseAir-128_--extra.txt)
- [MuseAir-BFast](results/SMHasher3_MuseAir-BFast_--extra.txt)
  (While testing this variant, I was gaming, so the `[[[ Speed Tests ]]]` result were actually on the small side :P)
- [MuseAir-BFast-128](results/SMHasher3_MuseAir-BFast-128_--extra.txt)

And no bad seeds were found (took too long, so only [MuseAir-BFast](./results/SMHasher3_MuseAir-BFast_--extra_--test=BadSeeds.txt) was searched).

The `museair.cpp` in the repository root is for use with SMHasher3, so you can reproduce these results on your computer.
Since it relies on the entire SMHasher3, it is not very usable in production.

#### Update: They also passed [SMHasher] with `--extra` option, with only a few false positives.

- [MuseAir](results/SMHasher_MuseAir_--extra.txt)
- [MuseAir-128](results/SMHasher_MuseAir-128_--extra.txt)
- [MuseAir-BFast](results/SMHasher_MuseAir-BFast_--extra.txt)
- [MuseAir-BFast-128](results/SMHasher_MuseAir-BFast-128_--extra.txt)

## Security

MuseAir is ***NOT*** intended for cryptographic security.

- To resist HashDoS, your hash must comes with a private seed.
- To ensure the protection of your data, it is recommended to use a well-established algorithm, such as SHA-3.


## Versioning policy

The `-Standard` variant (functions listed in the crate root) is not scheduled to be stable until version 1.0.0 is released.
That is, the result of the hash may change from minor version to minor version. Don't use it for persistent storage yet.

The `-BFast` variant will never be stable, you should only use this on local sessions.
For persistent storage, you should always use the `-Standard` variant (after it is stable).


## Implementations

This repository provides the official Rust implementation of MuseAir. You can find this crate on [crates.io](https://crates.io/crates/museair).

Here is the official C implementation of MuseAir: [museair-c](https://github.com/eternal-io/museair-c).

### Third-party

#### C++

- [museair-cpp](https://github.com/Twilight-Dream-Of-Magic/museair-cpp) (@Twilight-Dream-Of-Magic)


## License

MuseAir algorithm itself is released into the public domain under the CC0 license.

These codes (implementation) in this repository are released under the MIT or Apache 2.0 dual license, at your option.


[WyHash]: https://github.com/wangyi-fudan/wyhash
[RapidHash]: https://github.com/Nicoshev/rapidhash
[SMHasher3]: https://gitlab.com/fwojcik/smhasher3
[SMHasher]: https://github.com/rurban/smhasher
