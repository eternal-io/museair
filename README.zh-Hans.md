# <img src="MuseAir-icon-light.png" style="height:1em" /> MuseAir

[![](https://img.shields.io/crates/v/museair)](https://crates.io/crates/museair)
[![](https://img.shields.io/crates/d/museair)](https://crates.io/crates/museair)
[![](https://img.shields.io/crates/l/museair)](#)
[![](https://img.shields.io/docsrs/museair)](https://docs.rs/museair)
[![](https://img.shields.io/github/stars/eternal-io/museair?style=social)](https://github.com/eternal-io/museair)

<p align="right"><sup><b><i>简体中文</i></b> 丨 <a href="README.md">English</a></sup></p>


MuseAir 是一个快速便携（portable）散列算法，拥有便携散列中最高的吞吐量，并且在短键上也能提供不俗的表现（详见“*基准测试*”）。她还针对质量和可用性进行了改进（详见“*算法分析*”），并且能够[*通过*](results)完整的 [SMHasher3] 扩展测试。

MuseAir 提供了两种变体：`Standard`（默认）和 `BFast`。前者提供更好的质量，后者提供更好的性能。

- 两种变体都提供 64 位和 128 位输出，并且开销基本一致。

MuseAir **不是**为了密码学安全而设计的，你不应将其用于安全用途，例如，保证文件未经恶意篡改。对于这类用途，请考虑 SHA-3，Ascon 或 Blake3。

此外，MuseAir-`Standard` 计划在一段时间（1.0.0）之后稳定。由于她已提升的质量，届时，她将可以用于以下用途：

- 持久文件格式
- 通信协议
- ……

在此之前，她应该只用于本地会话。


## 基准测试 <sub>/ Benchmarks</sub>

    AMD Ryzen 7 5700G 4.6GHz Desktop, Windows 10 22H2, rustc 1.82.0 (f6e511eec 2024-10-15)

    - SMHasher3 (34093a3 2024-06-17) runs in WSL 2 with clang 14.0.0-1ubuntu1.1


### 大块数据 <sub>/ Bulk datas</sub>

| Hash              | Digest length | Throughput (C++ - SMHasher3) | Throughput (Rust - Criterion.rs) |
|:----------------- | -------------:| ----------------------------:| --------------------------------:|
| MuseAir           |        64-bit |                   28.5 GiB/s |                       30.5 GiB/s |
| MuseAir-128       |       128-bit |                   28.5 GiB/s |                       30.4 GiB/s |
| MuseAir-BFast     |        64-bit |                   33.3 GiB/s |                       36.4 GiB/s |
| MuseAir-BFast-128 |       128-bit |                   33.3 GiB/s |                       36.3 GiB/s |
| rapidhash         |        64-bit |                   31.9 GiB/s |                       29.4 GiB/s |
| wyhash 4.2        |        64-bit |                   31.9 GiB/s |                       28.4 GiB/s |
| wyhash.condom 4.2 |        64-bit |                   25.3 GiB/s |                       22.8 GiB/s |
| komihash 5.7      |        64-bit |                   25.5 GiB/s |                              N/A |
| komihash 5.10     |        64-bit |                          N/A |                       26.8 GiB/s |

<sup>*(These results are obtained by running `./SMHasher3 --test=Speed <HASH>` and `cargo bench`)*</sup>

峰值吞吐量与具体实现有关。但不论如何，对于大块数据，MuseAir 都是便携散列当中最快的，可以达到先前最快（wyhash）的 1.14 倍。


### 短键 <sub>/ Small keys</sub>

<img src="results/bench-smallkeys.png" alt="Bench small keys" width="100%" />

<sup>*(These results are obtained by running `./SMHasher3 --test=Speed <HASH>`)*</sup>

对于更加常见的 1-32 bytes 短键，MuseAir 系列算法拥有显著的性能优势。在这个范围内，平均而言，她仍是最快的。


## 实现 <sub>/ Implementations</sub>

这个存储库提供 MuseAir 的官方 Rust 实现，你可以在 [crates.io](https://crates.io/crates/museair) 上找到这个 crate。

| Language | Link
|:-------- |:----
| **C**    | [eternal-io/museair-c](https://github.com/eternal-io/museair-c)
| **C++**  | [Twilight-Dream-Of-Magic/museair-cpp](https://github.com/Twilight-Dream-Of-Magic/museair-cpp)


## 算法分析 <sub>/ Algorithm analysis</sub>

首先定义 `wide_mul` 和 `fold_mul`：

```rust
/// 64 x 64 -> 128 multiplication, returns lower 64-bit, then upper 64-bit.
fn wide_mul(a: u64, b: u64) -> (u64, u64) {
    x = a as u128 * b as u128;
    (x as u64, (x >> 64) as u64)
}

/// XOR-fold the lower half and the upper half of the multiplication result.
fn fold_mul(a: u64, b: u64) -> u64 {
    let (lo, hi) = wide_mul(a, b);
    lo ^ hi
}
```

**对于短键**，之所以对 16-32 字节长度有显著提速，主要是因为解决了数据依赖问题，使得那部分的乘法运算不需要等待先前数据，有效地利用了 CPU 流水线：

```rust
/* not what they actually read, just to simplify the situation. */

let mut acc_i = read_u64(&bytes[0..8]);
let mut acc_j = read_u64(&bytes[8..16]);

if bytes.len() > 16 {
    let (lo0, hi0) = wide_mul(CONSTANT[2], CONSTANT[3] ^ read_u64(&bytes[16..24]));
    let (lo1, hi1) = wide_mul(CONSTANT[4], CONSTANT[5] ^ read_u64(&bytes[24..32]));
    acc_i ^= lo0 ^ hi1;
    acc_j ^= lo1 ^ hi0;
}
```

**对于大块数据**，考虑 wyhash 的核心循环：

```rust
acc0 = fold_mul(acc0 ^ read_u64(&bytes[8 * 0..]), SECRET[0] ^ read_u64(&bytes[8 * 1..]));
acc1 = fold_mul(acc1 ^ read_u64(&bytes[8 * 2..]), SECRET[1] ^ read_u64(&bytes[8 * 3..]));
acc2 = fold_mul(acc2 ^ read_u64(&bytes[8 * 4..]), SECRET[2] ^ read_u64(&bytes[8 * 5..]));
                                /* Left side */                        /* Right side */
```

实际上有以下问题：

1. 将输入划分为多个条带分别处理，条带之间没有扩散（diffusion）。
2. 宽乘法后直接折叠，尽管有利于混淆（confusion）和进一步扩散，但也会造成一定的*熵损失*，有可能依此设计出碰撞。
3. 当*右侧*输入恰好与 `SECRET[n]` 相同时，会导致其中一个乘数为零。由于乘法的性质“零乘以任何数都等于零”，当前条带的累加器将被毁灭性清零，过去的所有状态都将不复存在。这一情形也被称作“致盲乘法”——在这里，设计碰撞实际上非常容易，它的安全性完全来自于 `SECRET[..]` 的保密，一组与种子（seed）无关的常数。因此这类攻击也被称作“种子无关攻击”。这限制了它在通信协议、持久文件格式等方面的应用。

实际上，为了缓解问题 3，wyhash 还提出了 `condom` 模式，使用修改的折叠乘法：

```rust
fn fold_mul(a: u64, b: u64) -> u64 {
    let (lo, hi) = wide_mul(a, b);
    a ^ b ^ lo ^ hi
}
```

显然能够避免致盲乘法问题。但当*右侧*持续为零时，*左侧*的输入将完全不会扩散，还将被后来的输入反复覆盖。此外，还有超过 20% 的性能下降。此时已有其它算法比它快且好了，比如 [komihash]。

为了解决上述所有问题，MuseAir 提出了**环形累加器组**结构：

```rust
/* `wrapping_add` omitted. */

state[0] ^= read_u64(&bytes[8 * 0..]);
state[1] ^= read_u64(&bytes[8 * 1..]);
let (lo0, hi0) = wide_mul(state[0], state[1]);
state[0] += ring_prev ^ hi0;

state[1] ^= read_u64(&bytes[8 * 2..]);
state[2] ^= read_u64(&bytes[8 * 3..]);
let (lo1, hi1) = wide_mul(state[1], state[2]);
state[1] += lo0 ^ hi1;

...

state[5] ^= read_u64(&bytes[8 * 10..]);
state[0] ^= read_u64(&bytes[8 * 11..]);
let (lo5, hi5) = wide_mul(state[5], state[0]);
state[5] += lo4 ^ hi5;

ring_prev = lo5;
```

这是 `Standard` 变体的累加器组。对于 `BFast` 变体，直接将 `+=` 替换成 `=` 即是。

对于问题 1 和 2：所有累加器的更新皆来自于本次乘法的高 64 位结果和上次乘法的低 64 位结果，拥有良好的扩散性质。

对于问题 3：由于乘数总是动态的，且得益于良好的扩散，MuseAir 不会遭受种子无关攻击。至于致盲乘法，`Standard` 变体没有对累加器的覆写，因此不受此影响。`BFast` 变体有对累加器的覆写，需要进行简单讨论：

- 若在某次读入之后，`state[0] == 0 && state[1] != 0`，则接下来覆写累加器时，不会导致任何数据丢失。同时，由于乘法结果的滞后混入，`state[0]` 几乎不会陷入全零状态。
- 若在某次读入之后，`state[0] != 0 && state[1] == 0`，则接下来覆写累加器时，会导致读入`state[0]`的那部分数据（8 字节）丢失。至于更先前的数据，则早已被扩散至整个状态中，不受影响。同样，`state[0]` 几乎不会陷入全零状态，但对于`state[1]`：
  - 如果接下来的读取不幸碰上了全零块，或是前七个字节都是零，最后一个字节是 `0x01`（对于普遍输入而言，只有 $2^{-127}$ 概率能走到这里），那么它在这一轮内都会保持全零。
  - 当然，它更有可能碰上非全零块。在接下来的乘法完成之后，拥有宝贵混合的高 64 位乘法结果还会立刻让它从低熵状态中恢复。

综上，对于普遍输入，MuseAir-BFast 只有 $2^{-64}$ 概率导致某 8 个字节的输入不影响输出。参考 wyhash，有 $2^{-63}$ 概率导致过去三分之一的输入不影响输出。

至于性能，它的提升主要来自对指令级并行（ILP）的深入理解。基准测试表明 MuseAir-Standard 与 wyhash 的性能差异在 6% 以下。

MuseAir-Standard 将是能够用于通信协议/持久文件格式的最快的便携散列。

<sub>_扩展资料：MuseAir 0.2 算法介绍，[B站专栏](https://www.bilibili.com/read/cv37413023) 或 [知乎文章](https://zhuanlan.zhihu.com/p/715753300)。尽管介绍的是老版本，但其中有一些未在此处提及的设计动机，没有太大变动，仍具有一定参考性。_</sub>


## 许可 <sub>/ License</sub>

MuseAir 散列算法本身及其参考实现 `museair.cpp` 以 CC0 1.0 许可发布到公共领域。

除此之外，该存储库下的其它所有代码以 MIT 和 Apache 2.0 双许可发布。


[komihash]: https://github.com/avaneev/komihash
[SMHasher3]: https://gitlab.com/fwojcik/smhasher3
