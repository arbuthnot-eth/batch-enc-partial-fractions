use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::rand::Rng;
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};

use batch_encryption::nizk::{prove, verify, NizkParams, Proof, Sha256Oracle, Statement};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_instance<E: Pairing>(rng: &mut impl Rng) -> (NizkParams<E>, Statement<E>, E::ScalarField)
{
    let alpha = E::ScalarField::rand(rng);
    let x0 = (E::G1::generator() * alpha).into_affine();
    let params = NizkParams::<E> { x0 };

    let w = E::ScalarField::rand(rng);
    let x1 = (E::G1::generator() * w).into_affine();
    let x2 = (x0 * w).into_affine();
    let statement = Statement::<E> { x1, x2 };

    (params, statement, w)
}

// ---------------------------------------------------------------------------
// Correctness tests
// ---------------------------------------------------------------------------

fn correctness_e2e<E: Pairing>() {
    let rng = &mut test_rng();
    let (params, stmt, w) = sample_instance::<E>(rng);
    let proof = prove::<E, Sha256Oracle>(&params, &stmt, &w, rng);
    assert!(verify::<E, Sha256Oracle>(&params, &stmt, &proof));
}

fn correctness_bad_witness<E: Pairing>() {
    let rng = &mut test_rng();
    let (params, stmt, _w) = sample_instance::<E>(rng);
    let bad_w = E::ScalarField::rand(rng);
    let proof = prove::<E, Sha256Oracle>(&params, &stmt, &bad_w, rng);
    assert!(!verify::<E, Sha256Oracle>(&params, &stmt, &proof));
}

fn correctness_tampered_w_hat<E: Pairing>() {
    let rng = &mut test_rng();
    let (params, stmt, w) = sample_instance::<E>(rng);
    let mut proof = prove::<E, Sha256Oracle>(&params, &stmt, &w, rng);
    proof.w_hat += E::ScalarField::from(1u64);
    assert!(!verify::<E, Sha256Oracle>(&params, &stmt, &proof));
}

fn correctness_tampered_x1_prime<E: Pairing>() {
    let rng = &mut test_rng();
    let (params, stmt, w) = sample_instance::<E>(rng);
    let mut proof = prove::<E, Sha256Oracle>(&params, &stmt, &w, rng);
    proof.x1_prime = (E::G1::from(proof.x1_prime) + E::G1::generator()).into_affine();
    assert!(!verify::<E, Sha256Oracle>(&params, &stmt, &proof));
}

fn correctness_tampered_x2_prime<E: Pairing>() {
    let rng = &mut test_rng();
    let (params, stmt, w) = sample_instance::<E>(rng);
    let mut proof = prove::<E, Sha256Oracle>(&params, &stmt, &w, rng);
    proof.x2_prime = (E::G1::from(proof.x2_prime) + E::G1::generator()).into_affine();
    assert!(!verify::<E, Sha256Oracle>(&params, &stmt, &proof));
}

fn correctness_wrong_statement<E: Pairing>() {
    let rng = &mut test_rng();
    let (params, stmt, w) = sample_instance::<E>(rng);
    let proof = prove::<E, Sha256Oracle>(&params, &stmt, &w, rng);
    let bad_stmt = Statement::<E> {
        x1: stmt.x1,
        x2: (E::G1::generator() * E::ScalarField::rand(rng)).into_affine(),
    };
    assert!(!verify::<E, Sha256Oracle>(&params, &bad_stmt, &proof));
}

fn correctness_wrong_params<E: Pairing>() {
    let rng = &mut test_rng();
    let (params, stmt, w) = sample_instance::<E>(rng);
    let proof = prove::<E, Sha256Oracle>(&params, &stmt, &w, rng);
    let bad_params = NizkParams::<E> {
        x0: (E::G1::generator() * E::ScalarField::rand(rng)).into_affine(),
    };
    assert!(!verify::<E, Sha256Oracle>(&bad_params, &stmt, &proof));
}

fn correctness_serde_roundtrip<E: Pairing>() {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    let rng = &mut test_rng();
    let (params, stmt, w) = sample_instance::<E>(rng);
    let proof = prove::<E, Sha256Oracle>(&params, &stmt, &w, rng);
    let mut buf = Vec::new();
    proof.serialize_compressed(&mut buf).unwrap();
    let deserialized = Proof::<E>::deserialize_compressed(&buf[..]).unwrap();
    assert!(verify::<E, Sha256Oracle>(&params, &stmt, &deserialized));
}

fn correctness_multiple_proofs<E: Pairing>() {
    let rng = &mut test_rng();
    let alpha = E::ScalarField::rand(rng);
    let x0 = (E::G1::generator() * alpha).into_affine();
    let params = NizkParams::<E> { x0 };
    for _ in 0..10 {
        let w = E::ScalarField::rand(rng);
        let x1 = (E::G1::generator() * w).into_affine();
        let x2 = (x0 * w).into_affine();
        let stmt = Statement::<E> { x1, x2 };
        let proof = prove::<E, Sha256Oracle>(&params, &stmt, &w, rng);
        assert!(verify::<E, Sha256Oracle>(&params, &stmt, &proof));
    }
}

// ---------------------------------------------------------------------------
// Criterion groups
// ---------------------------------------------------------------------------

fn correctness_tests(c: &mut Criterion) {
    let mut group = c.benchmark_group("nizk_correctness");
    group.sample_size(10);

    group.bench_function("e2e", |b| b.iter(correctness_e2e::<Bls12_381>));
    group.bench_function("bad_witness", |b| b.iter(correctness_bad_witness::<Bls12_381>));
    group.bench_function("tampered_w_hat", |b| b.iter(correctness_tampered_w_hat::<Bls12_381>));
    group.bench_function("tampered_x1_prime", |b| b.iter(correctness_tampered_x1_prime::<Bls12_381>));
    group.bench_function("tampered_x2_prime", |b| b.iter(correctness_tampered_x2_prime::<Bls12_381>));
    group.bench_function("wrong_statement", |b| b.iter(correctness_wrong_statement::<Bls12_381>));
    group.bench_function("wrong_params", |b| b.iter(correctness_wrong_params::<Bls12_381>));
    group.bench_function("serde_roundtrip", |b| b.iter(correctness_serde_roundtrip::<Bls12_381>));
    group.bench_function("multiple_proofs", |b| b.iter(correctness_multiple_proofs::<Bls12_381>));

    group.finish();
}

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("nizk_prove");
    group.sample_size(10);
    let rng = &mut test_rng();
    let (params, stmt, w) = sample_instance::<Bls12_381>(rng);
    group.bench_function("bls12_381", |b| {
        b.iter(|| prove::<Bls12_381, Sha256Oracle>(&params, &stmt, &w, &mut test_rng()))
    });
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("nizk_verify");
    group.sample_size(10);
    let rng = &mut test_rng();
    let (params, stmt, w) = sample_instance::<Bls12_381>(rng);
    let proof = prove::<Bls12_381, Sha256Oracle>(&params, &stmt, &w, rng);
    group.bench_function("bls12_381", |b| {
        b.iter(|| verify::<Bls12_381, Sha256Oracle>(&params, &stmt, &proof))
    });
    group.finish();
}

criterion_group!(benches, correctness_tests, bench_prove, bench_verify);
criterion_main!(benches);
