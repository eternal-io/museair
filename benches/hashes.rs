use core::time::Duration;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use wyhash_final4::{generics::WyHashVariant, WyHash64, WyHash64Condom};

#[rustfmt::skip]
fn criterion_benchmark(c: &mut Criterion) {
    const SIZE: u64 = 256 * 1024;
    let msg = vec![0xABu8; SIZE as usize];

    c.benchmark_group("MuseAir")
        .throughput(Throughput::Bytes(SIZE))
        .bench_function("museair", |b| {
            b.iter(|| {
                black_box(museair::hash(&msg, 42));
            })
        })
        .bench_function("museair-128", |b| {
            b.iter(|| {
                black_box(museair::hash_128(&msg, 42));
            })
        })
        .bench_function("museair-bfast", |b| {
            b.iter(|| {
                black_box(museair::bfast::hash(&msg, 42));
            })
        })
        .bench_function("museair-bfast-128", |b| {
            b.iter(|| {
                black_box(museair::bfast::hash_128(&msg, 42));
            })
        })
        ;

    c.benchmark_group("wyhash")
        .throughput(Throughput::Bytes(SIZE))
        .bench_function("wyhash-final4", |b| {
            b.iter(|| {
                black_box(WyHash64::with_seed(42).hash(&msg));
            })
        })
        .bench_function("wyhash-final4.strict", |b| {
            b.iter(|| {
                black_box(WyHash64Condom::with_seed(42).hash(&msg));
            })
        })
        ;

    c.benchmark_group("rapidhash")
        .throughput(Throughput::Bytes(SIZE))
        .bench_function("rapidhash", |b| {
            b.iter(|| {
                black_box(rapidhash::rapidhash_seeded(&msg, 42)); // faster than `rapidhash_inline` that force inlined.
            })
        })
        ;

    c.benchmark_group("komihash")
        .throughput(Throughput::Bytes(SIZE))
        .bench_function("komihash", |b| {
            b.iter(|| {
                black_box(komihash::komihash(&msg, 42));
            })
        })
        ;
}

criterion_group! {
    name=benches;
    config=Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_millis(1000));
    targets=criterion_benchmark
}
criterion_main!(benches);
