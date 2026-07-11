use criterion::{criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, Criterion, Throughput};
use rapidhash::rng::rapidrng_fast as rand;
use std::{sync::Mutex, time::Duration};

static SEED: Mutex<u64> = Mutex::new(8128);

#[inline(never)]
fn profile_bytes(group: &mut BenchmarkGroup<'_, WallTime>, cate: &str, len: usize, hash: fn(&[u8], u64)) {
    let mut bytes = Vec::with_capacity(len);
    bytes.extend(
        (0..len.div_ceil(8))
            .flat_map(|_| rand(&mut SEED.lock().unwrap()).to_le_bytes())
            .take(len),
    );
    group.throughput(Throughput::Bytes(len as u64));
    group.bench_function(format!("{cate}_{len}"), |b| b.iter(|| hash(&bytes, 0xABCDEF1234567890)));
}

#[inline(never)]
fn bench_group_bulkdata(c: &mut Criterion, name: &str, hash: fn(&[u8], u64)) {
    let mut group = c.benchmark_group(name);
    for size in [
        /* sorted({1 << i for i in range(8, 19)}.union(int((1 << i) * 1.5) for i in range(8, 18))) */
        256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304,
        131072, 196608, 262144,
    ] {
        profile_bytes(&mut group, "bulk", size, hash);
    }
}

#[inline(never)]
fn bench_group_smallkeys(c: &mut Criterion, name: &str, hash: fn(&[u8], u64)) {
    let mut group = c.benchmark_group(name);
    for size in 0..33 {
        profile_bytes(&mut group, "small", size, hash);
    }
}

fn bench_main(c: &mut Criterion) {
    bench_group_bulkdata(c, "MuseAir", g::museair);
    bench_group_bulkdata(c, "MuseAir-BFast", g::museair_bfast);
    bench_group_bulkdata(c, "MuseAir-128", g::museair_128);
    bench_group_bulkdata(c, "MuseAir-BFast-128", g::museair_bfast_128);
    bench_group_bulkdata(c, "rapidhash-v3", g::rapid_v3);
    bench_group_bulkdata(c, "rapidhash-v3.protected", g::rapid_v3_protected);
    bench_group_bulkdata(c, "wyhash-v4.2", g::wy_v4_2);
    bench_group_bulkdata(c, "wyhash-v4.2.protected", g::wy_v4_2_protected);
    bench_group_bulkdata(c, "komihash-v5.10", g::komi_v5_10);
    bench_group_bulkdata(c, "seahash-v4", g::sea_v4);
    bench_group_bulkdata(c, "xxh-64", g::xxh_64);

    bench_group_smallkeys(c, "MuseAir", g::museair);
    bench_group_smallkeys(c, "MuseAir-BFast", g::museair_bfast);
    bench_group_smallkeys(c, "MuseAir-128", g::museair_128);
    bench_group_smallkeys(c, "MuseAir-BFast-128", g::museair_bfast_128);
    bench_group_smallkeys(c, "rapidhash-v3", g::rapid_v3);
    bench_group_smallkeys(c, "rapidhash-v3.protected", g::rapid_v3_protected);
    bench_group_smallkeys(c, "rust-fxhash64", g::fx64);
}

mod g {
    use core::hint::black_box;
    use rapidhash::v3::{self, rapidhash_v3_inline};
    use wyhash_final4::{generics::WyHashVariant as _, WyHash64, WyHash64Condom};

    #[inline(always)]
    pub fn rapid_v3(bytes: &[u8], seed: u64) {
        black_box(rapidhash_v3_inline::<true, false, false>(
            black_box(bytes),
            &v3::RapidSecrets::seed_cpp(black_box(seed)),
        ));
    }
    #[inline(always)]
    pub fn rapid_v3_protected(bytes: &[u8], seed: u64) {
        black_box(rapidhash_v3_inline::<true, false, true>(
            black_box(bytes),
            &v3::RapidSecrets::seed_cpp(black_box(seed)),
        ));
    }

    #[inline(always)]
    pub fn wy_v4_2(bytes: &[u8], seed: u64) {
        black_box(WyHash64::hash_with_seed(black_box(bytes), black_box(seed)));
    }
    #[inline(always)]
    pub fn wy_v4_2_protected(bytes: &[u8], seed: u64) {
        black_box(WyHash64Condom::hash_with_seed(black_box(bytes), black_box(seed)));
    }

    #[inline(always)]
    pub fn komi_v5_10(bytes: &[u8], seed: u64) {
        black_box(komihash::komihash(black_box(bytes), black_box(seed)));
    }

    #[inline(always)]
    pub fn sea_v4(bytes: &[u8], seed: u64) {
        let seed = black_box(seed);
        black_box(seahash::hash_seeded(black_box(bytes), seed, seed, seed, seed));
    }
    #[inline(always)]
    pub fn xxh_64(bytes: &[u8], seed: u64) {
        black_box(twox_hash::XxHash64::oneshot(black_box(seed), black_box(bytes)));
    }

    #[inline(always)]
    pub fn fx64(bytes: &[u8], seed: u64) {
        let _ = black_box(seed);
        black_box(fxhash::hash64(black_box(bytes)));
    }

    #[inline(always)]
    pub fn museair(bytes: &[u8], seed: u64) {
        black_box(museair::hash(black_box(bytes), black_box(seed)));
    }
    #[inline(always)]
    pub fn museair_128(bytes: &[u8], seed: u64) {
        let seed = black_box(seed);
        black_box(museair::hash128(black_box(bytes), seed, seed));
    }

    #[inline(always)]
    pub fn museair_bfast(bytes: &[u8], seed: u64) {
        black_box(museair::bfast::hash(black_box(bytes), black_box(seed)));
    }
    #[inline(always)]
    pub fn museair_bfast_128(bytes: &[u8], seed: u64) {
        let seed = black_box(seed);
        black_box(museair::bfast::hash128(black_box(bytes), seed, seed));
    }
}

criterion_group! {
    name=benches;
    config=Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_millis(1000))
        .without_plots()
        ;
    targets=bench_main
}
criterion_main!(benches);
