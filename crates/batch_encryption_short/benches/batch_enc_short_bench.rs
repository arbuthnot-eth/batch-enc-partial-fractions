use ark_bls12_381::Bls12_381;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::rand::Rng;
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use batch_encryption_short::batch_enc_short::{
    decrypt, encrypt, pre_decrypt, setup, Ciphertext, DecryptionKey, EncryptionKey,
    PreDecryptionKey, SecretKey,
};
use batch_encryption_short::nizk_dlog::Sha512Oracle;

// ---------------------------------------------------------------------------
// Configurable batch sizes for benchmarks
// ---------------------------------------------------------------------------

/// Batch sizes used for correctness tests (mirrors `batch_encryption`).
const CORRECTNESS_ELL: &[usize] = &[1, 2, 4, 8];

/// Batch sizes used for performance benchmarks (mirrors `batch_encryption`
/// so side-by-side comparison is straightforward).
const PERF_ELL: &[usize] = &[4, 16, 64, 128, 256, 512];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(clippy::type_complexity)]
fn full_pipeline<E: Pairing>(
    ell: usize,
    rng: &mut impl Rng,
) -> (
    EncryptionKey<E>,
    SecretKey<E>,
    DecryptionKey<E>,
    Vec<PairingOutput<E>>,
    Vec<Ciphertext<E>>,
    PreDecryptionKey<E>,
) {
    let out = setup::<E>(ell, rng);
    let messages: Vec<PairingOutput<E>> =
        (0..ell).map(|_| PairingOutput::<E>::rand(rng)).collect();
    let cts: Vec<Ciphertext<E>> = messages
        .iter()
        .map(|m| encrypt::<E, Sha512Oracle>(&out.ek, m, rng))
        .collect();
    let sbk = pre_decrypt::<E, Sha512Oracle>(&out.sk, &cts, rng).unwrap();
    (out.ek, out.sk, out.dk, messages, cts, sbk)
}

// ---------------------------------------------------------------------------
// Correctness tests
// ---------------------------------------------------------------------------

fn correctness_e2e(ell: usize) {
    let rng = &mut test_rng();
    let (_, _, dk, messages, cts, sbk) = full_pipeline::<Bls12_381>(ell, rng);
    let decrypted = decrypt(&dk, &sbk, &cts);
    assert_eq!(messages, decrypted, "e2e mismatch (ell={ell})");
}

fn correctness_pre_decrypt_rejects_tampered() {
    let rng = &mut test_rng();
    let out = setup::<Bls12_381>(4, rng);
    let mut cts: Vec<Ciphertext<Bls12_381>> = (0..4)
        .map(|_| encrypt::<Bls12_381, Sha512Oracle>(&out.ek, &PairingOutput::rand(rng), rng))
        .collect();
    // Tamper with ct1 of one ciphertext: flips the DLOG statement out from under
    // the Fiat-Shamir-bound proof.
    cts[2].ct1 = (<Bls12_381 as Pairing>::G1::from(cts[2].ct1)
        + <Bls12_381 as Pairing>::G1::generator())
    .into_affine();
    assert!(pre_decrypt::<Bls12_381, Sha512Oracle>(&out.sk, &cts, rng).is_none());
}

fn correctness_zero_message() {
    use ark_std::Zero;
    let rng = &mut test_rng();
    let out = setup::<Bls12_381>(4, rng);
    let messages = vec![
        PairingOutput::<Bls12_381>::zero(),
        PairingOutput::<Bls12_381>::rand(rng),
        PairingOutput::<Bls12_381>::zero(),
        PairingOutput::<Bls12_381>::rand(rng),
    ];
    let cts: Vec<_> = messages
        .iter()
        .map(|m| encrypt::<Bls12_381, Sha512Oracle>(&out.ek, m, rng))
        .collect();
    let sbk = pre_decrypt::<Bls12_381, Sha512Oracle>(&out.sk, &cts, rng).unwrap();
    assert_eq!(decrypt(&out.dk, &sbk, &cts), messages);
}

fn correctness_serde_roundtrip() {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    let rng = &mut test_rng();
    let (_, _, dk, messages, cts, sbk) = full_pipeline::<Bls12_381>(4, rng);
    let mut buf = Vec::new();
    sbk.serialize_compressed(&mut buf).unwrap();
    let sbk2 = PreDecryptionKey::<Bls12_381>::deserialize_compressed(&buf[..]).unwrap();
    assert_eq!(decrypt(&dk, &sbk2, &cts), messages);
}

fn correctness_tests(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_enc_short_correctness");
    group.sample_size(10);

    for &ell in CORRECTNESS_ELL {
        group.bench_with_input(BenchmarkId::new("e2e", ell), &ell, |b, &ell| {
            b.iter(|| correctness_e2e(ell))
        });
    }

    group.bench_function("reject_tampered", |b| {
        b.iter(correctness_pre_decrypt_rejects_tampered)
    });
    group.bench_function("zero_message", |b| b.iter(correctness_zero_message));
    group.bench_function("serde_roundtrip", |b| b.iter(correctness_serde_roundtrip));

    group.finish();
}

// ---------------------------------------------------------------------------
// Performance benchmarks
// ---------------------------------------------------------------------------

fn bench_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_enc_short_setup");
    group.sample_size(10);
    for &ell in PERF_ELL {
        group.bench_with_input(BenchmarkId::new("bls12_381", ell), &ell, |b, &ell| {
            b.iter(|| setup::<Bls12_381>(ell, &mut test_rng()))
        });
    }
    group.finish();
}

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_enc_short_encrypt");
    group.sample_size(10);
    let rng = &mut test_rng();
    let out = setup::<Bls12_381>(4, rng);
    let m = PairingOutput::<Bls12_381>::rand(rng);
    group.bench_function("bls12_381", |b| {
        b.iter(|| encrypt::<Bls12_381, Sha512Oracle>(&out.ek, &m, &mut test_rng()))
    });
    group.finish();
}

fn bench_pre_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_enc_short_pre_decrypt");
    group.sample_size(10);
    for &ell in PERF_ELL {
        let rng = &mut test_rng();
        let (_, sk, _, _, cts, _) = full_pipeline::<Bls12_381>(ell, rng);
        group.bench_with_input(BenchmarkId::new("bls12_381", ell), &ell, |b, _| {
            b.iter(|| pre_decrypt::<Bls12_381, Sha512Oracle>(&sk, &cts, &mut test_rng()))
        });
    }
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_enc_short_decrypt");
    group.sample_size(10);
    for &ell in PERF_ELL {
        let rng = &mut test_rng();
        let (_, _, dk, _, cts, sbk) = full_pipeline::<Bls12_381>(ell, rng);
        group.bench_with_input(BenchmarkId::new("bls12_381", ell), &ell, |b, _| {
            b.iter(|| decrypt(&dk, &sbk, &cts))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    correctness_tests,
    bench_setup,
    bench_encrypt,
    bench_pre_decrypt,
    bench_decrypt,
);
criterion_main!(benches);
