use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::rand::Rng;
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use batch_encryption_short::nizk_dlog::{
    prove, verify, verify_batch, Sha512Oracle, Statement,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_instance<E: Pairing>(rng: &mut impl Rng) -> (Statement<E>, E::ScalarField) {
    let w = E::ScalarField::rand(rng);
    let h = (E::G1::generator() * w).into_affine();
    (Statement::<E> { h }, w)
}

/// Batch sizes used for the verify_batch benchmark.
const BATCH_ELL: &[usize] = &[4, 16, 64, 256, 512];

// ---------------------------------------------------------------------------
// Criterion groups -- most-optimized algorithms only.
// ---------------------------------------------------------------------------

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("nizk_dlog_prove");
    group.sample_size(10);
    let rng = &mut test_rng();
    let (stmt, w) = sample_instance::<Bls12_381>(rng);
    group.bench_function("bls12_381", |b| {
        b.iter(|| prove::<Bls12_381, Sha512Oracle>(&stmt, &w, &mut test_rng()))
    });
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("nizk_dlog_verify");
    group.sample_size(10);
    let rng = &mut test_rng();
    let (stmt, w) = sample_instance::<Bls12_381>(rng);
    let proof = prove::<Bls12_381, Sha512Oracle>(&stmt, &w, rng);
    group.bench_function("bls12_381", |b| {
        b.iter(|| verify::<Bls12_381, Sha512Oracle>(&stmt, &proof))
    });
    group.finish();
}

fn bench_verify_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("nizk_dlog_verify_batch");
    group.sample_size(10);

    for &ell in BATCH_ELL {
        let rng = &mut test_rng();
        let mut stmts = Vec::with_capacity(ell);
        let mut proofs = Vec::with_capacity(ell);
        for _ in 0..ell {
            let (s, w) = sample_instance::<Bls12_381>(rng);
            let p = prove::<Bls12_381, Sha512Oracle>(&s, &w, rng);
            stmts.push(s);
            proofs.push(p);
        }
        group.bench_with_input(BenchmarkId::new("bls12_381", ell), &ell, |b, _| {
            b.iter(|| verify_batch::<Bls12_381, Sha512Oracle>(&stmts, &proofs, &mut test_rng()))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_prove, bench_verify, bench_verify_batch);
criterion_main!(benches);
