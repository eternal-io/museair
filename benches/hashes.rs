use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use wyhash_final4::{generics::WyHashVariant, WyHash64, WyHash64Condom};

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
        });

    c.benchmark_group("WyHash")
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
        });

    c.benchmark_group("KomiHash")
        .throughput(Throughput::Bytes(SIZE))
        .bench_function("komihash", |b| {
            b.iter(|| {
                black_box(komihash::komihash(&msg, 42));
            })
        });
}

criterion_group! {
    name=benches;
    config=Criterion::default();
    targets=criterion_benchmark
}
criterion_main!(benches);
