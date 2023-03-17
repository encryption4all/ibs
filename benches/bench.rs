use criterion::{criterion_group, criterion_main, Criterion};
use ibs::{
    gg,
    gg::{Identity, Signer, Verifier},
};

use rand::prelude::*;

pub fn criterion_benchmark_ibs(c: &mut Criterion) {
    let mut rng = thread_rng();

    let (pk, sk) = gg::setup(&mut rng);
    let id = Identity::from("Johnny");

    let usk_id = gg::keygen(&sk, &id, &mut rng);
    let sig = Signer::new()
        .chain(b"The eagle has landed")
        .sign(&usk_id, &mut rng);

    c.bench_function("setup", |b| {
        let mut rng = thread_rng();
        b.iter(|| gg::setup(&mut rng))
    });

    c.bench_function("keygen", |b| {
        let mut rng = thread_rng();
        b.iter(|| gg::keygen(&sk, &id, &mut rng))
    });

    c.bench_function("sign", |b| {
        let mut rng = thread_rng();

        b.iter(|| {
            Signer::new()
                .chain(b"The eagle has landed")
                .sign(&usk_id, &mut rng)
        })
    });

    c.bench_function("verify", |b| {
        b.iter(|| {
            Verifier::new()
                .chain("The eagle has landed")
                .verify(&pk, &sig, &id)
        })
    });
}

criterion_group!(benches, criterion_benchmark_ibs);
criterion_main!(benches);
