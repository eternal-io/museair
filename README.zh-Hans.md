# <img src="MuseAir-icon-light.png" style="height:1em" /> MuseAir

[![](https://img.shields.io/crates/v/museair)](https://crates.io/crates/museair)
[![](https://img.shields.io/crates/d/museair)](https://crates.io/crates/museair)
[![](https://img.shields.io/crates/l/museair)](#)
[![](https://img.shields.io/docsrs/museair)](https://docs.rs/museair)
[![](https://img.shields.io/github/stars/eternal-io/museair?style=social)](https://github.com/eternal-io/museair)

<p align="right"><sup><b><i>简体中文</i></b> 丨 <a href="README.md">English</a></sup></p>


MuseAir 是一个便携散列函数，针对[性能](#性能)和[质量](#质量)进行了大量优化，拥有新的高效结构。它提供两个变体：`Standard`和`BFast`。后者会更快一些，但质量会稍微*差*那么一点。具体的区别请看下方的[算法分析](#算法分析)。

MuseAir 不是为了密码学安全而设计的，不得将其用于安全用途（例如：保证文件未经恶意篡改）。对于这类用途，请考虑 SHA-3，Ascon 或 Blake3。

MuseAir 目前还未稳定，它的输出将在小版本之间变化。因此，暂不建议将其应用于持久格式。



## 性能

    AMD Ryzen 7 5700G 4.6GHz Desktop, Windows 10 22H2, rustc 1.87.0 (17067e9ac 2025-05-09)

    - SMHasher3 (4568f81 2025-3-22) runs in WSL 2 with clang 14.0.0-1ubuntu1.1

目前只有这些简单的图表。如果你希望得到更详细的比较，并且愿意提供帮助，就去开一个 issue 吧（GitHub 上请使用英文），或者私信我。

### 大型输入

<table width="100%"><tr>
<td><img width="100%" src="results/bench-bulkdatas-smhasher3.png" alt="Bench bulk datas (using SMHasher3)" /></td>
<td><img width="100%" src="results/bench-bulkdatas-crit.rs.png" alt="Bench bulk datas (using Criterion.rs)" /></td>
</tr></table>

- wyhash: [repo](https://github.com/wangyi-fudan/wyhash), [rust-impl](https://github.com/thynson/wyhash-final4)
- rapidhash: [repo](https://github.com/Nicoshev/rapidhash), [rust-impl](https://github.com/hoxxep/rapidhash)
- komihash: [repo](https://github.com/avaneev/komihash), [rust-impl](https://github.com/thynson/rust-komihash)

### 小型输入

<img width="100%" src="results/bench-smallkeys.png" alt="Bench small keys (using SMHasher3)" />
<p align="center"><i>在更常见的 1-32 字节输入上，MuseAir 具有显著的速度优势 (avg. 13.0 cycles/hash)，甚至比 fxhash 更快</i></p>



## 质量

MuseAir 的所有变体均通过了完整的 [SMHasher3](https://gitlab.com/fwojcik/smhasher3) 扩展测试（使用`--extra`标志）。该测试套件是非加密散列函数质量的事实标准，通过该测试意味着散列函数的质量已经足以投入生产。完整的测试输出可以在 [results](results) 目录下找到。

> *由于核心算法的质量已被验证，且在 0.4 版本之后没有引入任何重大变更，因此后续只更新了`BFast_64-bit`的测试结果。*

对于更深入的质量保证，请看[算法分析](#算法分析)。



## 实现

该存储库提供官方 Rust 实现，你可以在 [crates.io](https://crates.io/crates/museair) 上找到它。

#### 第三方实现

| Language | Repository | Note
|:-------- |:---------- |:----
| **C**    | [eternal-io/museair-c](https://github.com/eternal-io/museair-c) | *已弃坑，欢迎来人填坑*
| **C++**  | [Twilight-Dream-Of-Magic/museair-cpp](https://github.com/Twilight-Dream-Of-Magic/museair-cpp)



## 算法分析

### TL;DR

- 即便是质量稍差的`BFast`变体也拥有比其它竞争者更好的质量，同时拥有顶尖的性能表现，这就是你选择 MuseAir 的理由。
- 质量更好的`Standard`变体则完全不受致盲乘法的影响，同时也有相当好的性能表现，非常适合用于持久文件格式或通信协议（*然而，算法还尚未稳定*）。


### 对小型输入的处理

在图表中，你可以看到 MuseAir 对 16-32 字节输入的处理显著快于其它竞争者。这是因为它解决了数据依赖（_data hazard_）问题：对第 16-32 字节的处理不需要等待第 0-16 字节的完成，有效利用了流水线，显著降低了延迟。


### 对大块数据的处理

MuseAir 的核心步骤依赖于*宽乘法*，也就是`64位 × 64位 → 128位`的乘法。

从计算原理上看，乘法可以分解为一系列移位与加法的组合，这使得乘法天生具备一定的混淆（confusion）与扩散（diffusion）性质。在大多数现代处理器上，乘法只需要一条指令即可完成。相较于手动组合其它位运算，宽乘法在性能和实现复杂度上具有显著优势。因此，近年来推出的非加密散列函数大多依赖于宽乘法，如 [wyhash]，[rapidhash] 和 [komihash] 等。

`wyhash`和`rapidhash`的核心步骤是这样的：在一个循环中，大块输入被划分为多个条带……

```rust
lane0 = fold_mul( input[0] ^ lane0, input[1] ^ CONSTANT[0] );
lane1 = fold_mul( input[2] ^ lane1, input[3] ^ CONSTANT[1] );
lane2 = fold_mul( input[4] ^ lane2, input[5] ^ CONSTANT[2] );
// ...可能有更多条带...
```

其中，`fold_mul`叫*折叠乘法*，它的作用是执行 128 位宽乘法，并将乘法结果的高 64 位与低 64 位进行异或，然后返回。`CONSTANT`是一组魔法常数，用于给状态提供一些熵。

乍一看，这一切好像没有问题。借助宽乘法，输入的每一位都有机会在条带内完全扩散。输入又被划分为多个条带、分别处理，以便有效利用流水线进行指令级并行。对吗？

如果一切都这么顺利就好了。我们不应该忽略任何一种情形，尤其是众所周知的、与乘法的基本性质相关的情形。在上述例子中，如果`input[1] ^ CONSTANT[0] == 0`会怎么样？嘭！一阵魔法烟雾过后，你会发现`lane0`的值变成了零。也就是说，这一条带上的所有信息都消失了，条带上先前的任何输入都不会影响最终的结果！这一情形又被称为*致盲乘法*。增加条带数量不过是缓兵之计，因为所有条带都有可能遭遇致盲乘法。

> 该死，我们不该忘了“*零乘以任何数都等于零*”的！

从这一角度上来说，若`CONSTANT`s不得不公开，那么即便是 CRCs（循环冗余校验）也能提供更好的安全属性（即便它们都是非加密的）。假设你设计了自己的持久文件格式或通信协议，并且希望添加一个简单的校验和，那么你是不论如何都不会希望使用`wyhash`或`rapidhash`的——在这种用途上，它们实在是*太容易*被破解了！提供一个没有这些显著问题的快速散列函数，也是 MuseAir 的设计动机。

---

为了解决上述问题，MuseAir 提出了**环形累加器组**结构：

```rust
state[0] ^= input[0];
state[1] ^= input[1];
(lo0, hi0) = wide_mul(state[0], state[1]);
state[0] = lo5 ^ hi0;

state[1] ^= input[2];
state[2] ^= input[3];
(lo1, hi1) = wide_mul(state[1], state[2]);
state[1] = lo0 ^ hi1;

state[2] ^= input[4];
state[3] ^= input[5];
(lo1, hi1) = wide_mul(state[2], state[3]);
state[2] = lo1 ^ hi2;

...

state[5] ^= input[10];
state[0] ^= input[11];
(lo5, hi5) = wide_mul(state[5], state[0]);
state[5] = lo4 ^ hi5;
```

这是`BFast`变体的累加器组。其中，`wide_mul`执行 128 位宽乘法，返回一个二元组，依次是乘法的低 64 位结果和高 64 位结果。

1. 输入**没有被划分为多个条带**，因而具有更好的扩散性质：每一位输入最终都会影响所有累加器。而不像`wyhash`和`rapidhash`那样，至多只能影响三分之一的累加器。

2. 输入**没有与常数或种子的直接混合**，刻意设计致盲乘法的难度大大提高了：即便种子和常数是公开的，攻击者也必须追踪先前的所有输入如何作用于累加器。而不像`wyhash`和`rapidhash`那样，一碰就碎。

由于更早的输入早已扩散至其余累加器，因此，即便确实遭遇了致盲乘法，通常也只会导致最近的 **8 个字节**不影响输出。而不像`wyhash`和`rapidhash`那样，轻松就能导致过去**三分之一**的输入不影响输出！

3. 该结构交错使用了乘法结果。因此，对于普遍输入，致盲乘法导致累加器归零的概率只有 $2^{-127}$，远低于`wyhash`和`rapidhash`的 $2^{-63}$。推导如下：

  - 对于普遍输入，`input[N]`可以被视为一个独立的随机变量，其状态总数为 $2^{64}$。
  - 对于`wyhash`和`rapidhash`，一旦`input[0] == lane0`或`input[1] == CONSTANT[0]`，这两个输入便无法对最终输出产生影响，其概率为 $2^{-64} \times 2 = 2^{-63}$。随后：
    - `lane0`会立刻陷入全零。由于缺乏条带间扩散，这还会导致过去三分之一的输入不影响输出。
  - 对于`BFast`变体，仅当`input[1] == state[1]`时，才会导致`input[0]`失去对最终输出的影响，其概率为 $2^{-64}$。然而：
    - `state[0]`几乎不会陷入全零，这得益于乘法结果的滞后混入。
    - 要使`state[0]`陷入全零，则`lo5`必须同时为零。这要求前一步也遭遇致盲乘法（即要求`input[-2] == state[5]`或`input[-1] == state[0]`），其概率为 $2^{-63}$。
    - 因此`state[0]`陷入全零的累积概率仅为 $2^{-64} \times 2^{-63} = 2^{-127}$。
    - 而即便陷入了全零，其影响也是局部的，因为更早的输入早已扩散至其余累加器。

4. 该结构的设计对指令级并行非常有利，吞吐量应该达到了现代处理器的上限（纯标量，每 16 字节执行 1 次乘法和 3 次异或）。

最后，`Standard`变体只是将累加器组中的所有`=`替换成了`+=`，以最小的代价彻底免受了致盲乘法的影响。

于是，结合[性能表现](#性能)，我们得到了结论：

- 即便是质量稍差的`BFast`变体也拥有比其它竞争者更好的质量，同时拥有顶尖的性能表现，这就是你选择 MuseAir 的理由。
- 质量更好的`Standard`变体则完全不受致盲乘法的影响，同时也有相当好的性能表现，非常适合用于持久文件格式或通信协议（*然而，算法还尚未稳定*）。



## 开源协议

MuseAir 散列算法本身及其参考实现[`museair.cpp`](museair.cpp)以 CC0 1.0 许可发布到公共领域。

除此之外，该存储库下的所有代码以 MIT 和 Apache 2.0 双许可发布。


[wyhash]: https://github.com/wangyi-fudan/wyhash
[rapidhash]: https://github.com/Nicoshev/rapidhash
[komihash]: https://github.com/avaneev/komihash
