//! Construction 6: SE-NIZK for the discrete logarithm relation R^DLOG.

use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::UniformRand;
use sha2::{Digest, Sha512};

pub trait TranscriptOracle<E: Pairing> {
    fn challenge(h: &E::G1Affine, x_prime: &E::G1Affine) -> E::ScalarField;
}

/// Domain separation tag for the Construction-6 Fiat-Shamir challenge.
const NIZK_DOMAIN_SEP: &[u8] = b"BatchEncryption-NIZK-Construction6-DLOG";

pub struct Sha512Oracle;

impl<E: Pairing> TranscriptOracle<E> for Sha512Oracle {
    fn challenge(h: &E::G1Affine, x_prime: &E::G1Affine) -> E::ScalarField {
        let mut hasher = Sha512::new();
        hasher.update(NIZK_DOMAIN_SEP);

        let mut buf = Vec::new();
        for pt in [h, x_prime] {
            buf.clear();
            pt.serialize_compressed(&mut buf)
                .expect("serialization should not fail");
            hasher.update(&buf);
        }

        let hash_output = hasher.finalize();
        E::ScalarField::from_le_bytes_mod_order(&hash_output)
    }
}

/// Statement: a group element `h` in G1 claimed to equal `[w]_1` for some `w` in Fp.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Statement<E: Pairing> {
    pub h: E::G1Affine,
}

/// Proof: pi = (w_hat, x_prime) in Fp x G1.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: Pairing> {
    pub w_hat: E::ScalarField,
    pub x_prime: E::G1Affine,
}

/// Prove knowledge of `w` such that `h = [w]_1`.
///
/// 1. Sample `w' <- Fp`
/// 2. `x_prime := [w']_1`
/// 3. `c := H(h, x_prime)`
/// 4. `w_hat := w' + c * w`
/// 5. Output `pi := (w_hat, x_prime)`
pub fn prove<E: Pairing, H: TranscriptOracle<E>>(
    statement: &Statement<E>,
    witness: &E::ScalarField,
    rng: &mut impl Rng,
) -> Proof<E> {
    let w_prime = E::ScalarField::rand(rng);
    let x_prime = (E::G1::generator() * w_prime).into_affine();
    let c = H::challenge(&statement.h, &x_prime);
    let w_hat = w_prime + c * witness;
    Proof { w_hat, x_prime }
}

/// Verify a proof `pi` for statement `h`.
///
/// 1. `c := H(h, x_prime)`
/// 2. Accept iff `x_prime + c * h == [w_hat]_1`
pub fn verify<E: Pairing, H: TranscriptOracle<E>>(
    statement: &Statement<E>,
    proof: &Proof<E>,
) -> bool {
    let c = H::challenge(&statement.h, &proof.x_prime);
    let lhs = E::G1::from(proof.x_prime) + statement.h * c;
    let rhs = E::G1::generator() * proof.w_hat;
    lhs == rhs
}

/// Batch-verify many DLOG proofs via one randomized MSM check.
pub fn verify_batch<E: Pairing, H: TranscriptOracle<E>>(
    statements: &[Statement<E>],
    proofs: &[Proof<E>],
    rng: &mut impl Rng,
) -> bool {
    assert_eq!(
        statements.len(),
        proofs.len(),
        "statements and proofs must have the same length"
    );
    if statements.is_empty() {
        return true;
    }

    let ell = statements.len();
    let gammas: Vec<E::ScalarField> = (0..ell).map(|_| E::ScalarField::rand(rng)).collect();

    let cs: Vec<E::ScalarField> = statements
        .iter()
        .zip(proofs)
        .map(|(s, p)| H::challenge(&s.h, &p.x_prime))
        .collect();
    let gamma_c: Vec<E::ScalarField> = gammas.iter().zip(&cs).map(|(g, c)| *g * c).collect();

    let sum_gamma_w: E::ScalarField = gammas.iter().zip(proofs).map(|(g, p)| *g * p.w_hat).sum();

    let x_primes: Vec<E::G1Affine> = proofs.iter().map(|p| p.x_prime).collect();
    let hs: Vec<E::G1Affine> = statements.iter().map(|s| s.h).collect();

    // Sum gamma_j * x'_j + Sum gamma_j * c_j * h_j == (Sum gamma_j * w_hat_j) * [1]_1
    let lhs = E::G1::msm(&x_primes, &gammas).expect("msm size mismatch")
        + E::G1::msm(&hs, &gamma_c).expect("msm size mismatch");
    let rhs = E::G1::generator() * sum_gamma_w;

    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381 as E;
    use ark_std::test_rng;

    type Fr = <E as Pairing>::ScalarField;
    type G1 = <E as Pairing>::G1;

    fn sample_instance(rng: &mut impl Rng) -> (Statement<E>, Fr) {
        let w = Fr::rand(rng);
        let h = (G1::generator() * w).into_affine();
        (Statement::<E> { h }, w)
    }

    #[test]
    fn test_honest_proof_verifies() {
        let rng = &mut test_rng();
        let (stmt, w) = sample_instance(rng);
        let proof = prove::<E, Sha512Oracle>(&stmt, &w, rng);
        assert!(verify::<E, Sha512Oracle>(&stmt, &proof));
    }

    #[test]
    fn test_wrong_witness_fails() {
        let rng = &mut test_rng();
        let (stmt, _w) = sample_instance(rng);
        let bad_w = Fr::rand(rng);
        let proof = prove::<E, Sha512Oracle>(&stmt, &bad_w, rng);
        assert!(!verify::<E, Sha512Oracle>(&stmt, &proof));
    }

    #[test]
    fn test_tampered_w_hat_fails() {
        let rng = &mut test_rng();
        let (stmt, w) = sample_instance(rng);
        let mut proof = prove::<E, Sha512Oracle>(&stmt, &w, rng);
        proof.w_hat += Fr::from(1u64);
        assert!(!verify::<E, Sha512Oracle>(&stmt, &proof));
    }

    #[test]
    fn test_tampered_x_prime_fails() {
        let rng = &mut test_rng();
        let (stmt, w) = sample_instance(rng);
        let mut proof = prove::<E, Sha512Oracle>(&stmt, &w, rng);
        proof.x_prime = (G1::from(proof.x_prime) + G1::generator()).into_affine();
        assert!(!verify::<E, Sha512Oracle>(&stmt, &proof));
    }

    #[test]
    fn test_wrong_statement_fails() {
        let rng = &mut test_rng();
        let (stmt, w) = sample_instance(rng);
        let proof = prove::<E, Sha512Oracle>(&stmt, &w, rng);
        let bad_stmt = Statement::<E> {
            h: (G1::generator() * Fr::rand(rng)).into_affine(),
        };
        assert!(!verify::<E, Sha512Oracle>(&bad_stmt, &proof));
    }

    #[test]
    fn test_serde_roundtrip() {
        let rng = &mut test_rng();
        let (stmt, w) = sample_instance(rng);
        let proof = prove::<E, Sha512Oracle>(&stmt, &w, rng);

        let mut buf = Vec::new();
        proof.serialize_compressed(&mut buf).unwrap();
        let deserialized = Proof::<E>::deserialize_compressed(&buf[..]).unwrap();
        assert!(verify::<E, Sha512Oracle>(&stmt, &deserialized));
    }

    #[test]
    fn test_batch_verify_all_honest() {
        let rng = &mut test_rng();
        let ell = 16;
        let mut stmts = Vec::with_capacity(ell);
        let mut proofs = Vec::with_capacity(ell);
        for _ in 0..ell {
            let (s, w) = sample_instance(rng);
            let p = prove::<E, Sha512Oracle>(&s, &w, rng);
            stmts.push(s);
            proofs.push(p);
        }
        assert!(verify_batch::<E, Sha512Oracle>(&stmts, &proofs, rng));
    }

    #[test]
    fn test_batch_verify_detects_one_bad_w_hat() {
        let rng = &mut test_rng();
        let ell = 8;
        let mut stmts = Vec::with_capacity(ell);
        let mut proofs = Vec::with_capacity(ell);
        for _ in 0..ell {
            let (s, w) = sample_instance(rng);
            let p = prove::<E, Sha512Oracle>(&s, &w, rng);
            stmts.push(s);
            proofs.push(p);
        }
        proofs[3].w_hat += Fr::from(1u64);
        assert!(!verify_batch::<E, Sha512Oracle>(&stmts, &proofs, rng));
    }

    #[test]
    fn test_batch_verify_detects_one_bad_x_prime() {
        let rng = &mut test_rng();
        let ell = 8;
        let mut stmts = Vec::with_capacity(ell);
        let mut proofs = Vec::with_capacity(ell);
        for _ in 0..ell {
            let (s, w) = sample_instance(rng);
            let p = prove::<E, Sha512Oracle>(&s, &w, rng);
            stmts.push(s);
            proofs.push(p);
        }
        proofs[5].x_prime = (G1::from(proofs[5].x_prime) + G1::generator()).into_affine();
        assert!(!verify_batch::<E, Sha512Oracle>(&stmts, &proofs, rng));
    }

    #[test]
    fn test_batch_verify_empty() {
        let rng = &mut test_rng();
        let stmts: Vec<Statement<E>> = Vec::new();
        let proofs: Vec<Proof<E>> = Vec::new();
        assert!(verify_batch::<E, Sha512Oracle>(&stmts, &proofs, rng));
    }

    #[test]
    fn test_batch_verify_singleton_matches_single() {
        let rng = &mut test_rng();
        let (s, w) = sample_instance(rng);
        let p = prove::<E, Sha512Oracle>(&s, &w, rng);
        assert!(verify::<E, Sha512Oracle>(&s, &p));
        assert!(verify_batch::<E, Sha512Oracle>(
            std::slice::from_ref(&s),
            std::slice::from_ref(&p),
            rng,
        ));
    }
}
