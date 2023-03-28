use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ibs::{
    gg,
    gg::{Identity, Signer, Verifier},
};

use rand::prelude::*;

pub fn criterion_benchmark_ibs(c: &mut Criterion) {
    let mut rng = thread_rng();

    let (pk, sk) = gg::setup(&mut rng);
    let id = Identity::from("Johny");

    let usk_id = gg::keygen(&sk, &id, &mut rng);
    let sig = Signer::new().chain(b"Some message").sign(&usk_id, &mut rng);

    c.bench_function("setup", |b| b.iter(|| gg::setup(&mut rng)));
    c.bench_function("keygen", |b| {
        b.iter(|| gg::keygen(black_box(&sk), black_box(&id), &mut rng))
    });

    let mut group = c.benchmark_group("GG sign/verify");
    group.sample_size(10);

    for l in (10..22).step_by(2) {
        let size: u64 = 2u64.pow(l);
        group.throughput(criterion::Throughput::Bytes(size));

        let mut msg = vec![0u8; size as usize];
        rng.fill_bytes(&mut msg);

        group.bench_function(format!("sign {size}"), |b| {
            b.iter(|| {
                Signer::new()
                    .chain(black_box(&msg))
                    .sign(black_box(&usk_id), &mut rng)
            })
        });

        group.bench_function(format!("verify {size}"), |b| {
            b.iter(|| {
                Verifier::new().chain(black_box(&msg)).verify(
                    black_box(&pk),
                    black_box(&sig),
                    black_box(&id),
                )
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark_ibs);
criterion_main!(benches);
