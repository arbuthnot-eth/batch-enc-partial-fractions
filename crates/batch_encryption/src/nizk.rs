//! Construction 4: SE-NIZK for the ciphertext relation R_{x0}.

use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::UniformRand;
use sha2::{Digest, Sha512};

/// Trait abstracting the random oracle H(x0, x1, x2, x1', x2') -> Fp
/// used for the Fiat-Shamir challenge in the NIZK.
pub trait TranscriptOracle<E: Pairing> {
    fn challenge(
        x0: &E::G1Affine,
        x1: &E::G1Affine,
        x2: &E::G1Affine,
        x1_prime: &E::G1Affine,
        x2_prime: &E::G1Affine,
    ) -> E::ScalarField;
}

/// Domain separation tag for the NIZK Fiat-Shamir challenge.
const NIZK_DOMAIN_SEP: &[u8] = b"BatchEncryption-NIZK-Construction4";

pub struct Sha512Oracle;

pub type Sha256Oracle = Sha512Oracle;

impl<E: Pairing> TranscriptOracle<E> for Sha512Oracle {
    fn challenge(
        x0: &E::G1Affine,
        x1: &E::G1Affine,
        x2: &E::G1Affine,
        x1_prime: &E::G1Affine,
        x2_prime: &E::G1Affine,
    ) -> E::ScalarField {
        let mut hasher = Sha512::new();
        hasher.update(NIZK_DOMAIN_SEP);

        let mut buf = Vec::new();
        for pt in [x0, x1, x2, x1_prime, x2_prime] {
            buf.clear();
            pt.serialize_compressed(&mut buf)
                .expect("serialization should not fail");
            hasher.update(&buf);
        }

        let hash_output = hasher.finalize();
        E::ScalarField::from_le_bytes_mod_order(&hash_output)
    }
}

/// The public parameter for the NIZK: the group element x0 = ek[1] in G1.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct NizkParams<E: Pairing> {
    pub x0: E::G1Affine,
}

/// A statement for the NIZK: x = (x1, x2) in G1^2.
/// Corresponds to (ct[1], ct[2]) in the batch encryption scheme.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Statement<E: Pairing> {
    pub x1: E::G1Affine,
    pub x2: E::G1Affine,
}

/// A proof pi = (w_hat, x1_prime, x2_prime) in Zp x G1 x G1.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: Pairing> {
    pub w_hat: E::ScalarField,
    pub x1_prime: E::G1Affine,
    pub x2_prime: E::G1Affine,
}

/// Prove knowledge of w such that x1 = [w]_1 and x2 = w * x0.
///
/// 1. Sample w' <- Zp
/// 2. Compute x1' = [w']_1 and x2' = w' * x0
/// 3. c = H(x0, x1, x2, x1', x2')
/// 4. w_hat = w' + c * w
/// 5. Output pi = (w_hat, x1', x2')
pub fn prove<E: Pairing, H: TranscriptOracle<E>>(
    params: &NizkParams<E>,
    statement: &Statement<E>,
    witness: &E::ScalarField,
    rng: &mut impl Rng,
) -> Proof<E> {
    let w_prime = E::ScalarField::rand(rng);

    let x1_prime = (E::G1::generator() * w_prime).into_affine();
    let x2_prime = (params.x0 * w_prime).into_affine();

    let c = H::challenge(
        &params.x0,
        &statement.x1,
        &statement.x2,
        &x1_prime,
        &x2_prime,
    );

    let w_hat = w_prime + c * witness;

    Proof {
        w_hat,
        x1_prime,
        x2_prime,
    }
}

/// Verify a proof pi for statement x = (x1, x2).
///
/// 1. c = H(x0, x1, x2, x1', x2')
/// 2. Check: x1' + c * x1 == [w_hat]_1
/// 3. Check: x2' + c * x2 == w_hat * x0
pub fn verify<E: Pairing, H: TranscriptOracle<E>>(
    params: &NizkParams<E>,
    statement: &Statement<E>,
    proof: &Proof<E>,
) -> bool {
    let c = H::challenge(
        &params.x0,
        &statement.x1,
        &statement.x2,
        &proof.x1_prime,
        &proof.x2_prime,
    );

    let lhs1 = E::G1::from(proof.x1_prime) + statement.x1 * c;
    let rhs1 = E::G1::generator() * proof.w_hat;
    if lhs1 != rhs1 {
        return false;
    }

    let lhs2 = E::G1::from(proof.x2_prime) + statement.x2 * c;
    let rhs2 = params.x0 * proof.w_hat;
    if lhs2 != rhs2 {
        return false;
    }

    true
}

/// Batch-verify many proofs sharing the same `params` in two MSM-based checks.
pub fn verify_batch<E: Pairing, H: TranscriptOracle<E>>(
    params: &NizkParams<E>,
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
        .map(|(s, p)| H::challenge(&params.x0, &s.x1, &s.x2, &p.x1_prime, &p.x2_prime))
        .collect();
    let gamma_c: Vec<E::ScalarField> = gammas.iter().zip(&cs).map(|(g, c)| *g * c).collect();

    let sum_gamma_w: E::ScalarField = gammas.iter().zip(proofs).map(|(g, p)| *g * p.w_hat).sum();

    // Collect bases once for each of the four MSMs.
    let x1_primes: Vec<E::G1Affine> = proofs.iter().map(|p| p.x1_prime).collect();
    let x1_points: Vec<E::G1Affine> = statements.iter().map(|s| s.x1).collect();
    let x2_primes: Vec<E::G1Affine> = proofs.iter().map(|p| p.x2_prime).collect();
    let x2_points: Vec<E::G1Affine> = statements.iter().map(|s| s.x2).collect();

    // Check 1: Σ γ_j·x'_1 + Σ γ_j·c_j·x_1 == (Σ γ_j·ŵ_j) · [1]_1
    let lhs1 = E::G1::msm(&x1_primes, &gammas).expect("msm size mismatch")
        + E::G1::msm(&x1_points, &gamma_c).expect("msm size mismatch");
    let rhs1 = E::G1::generator() * sum_gamma_w;
    if lhs1 != rhs1 {
        return false;
    }

    // Check 2: Σ γ_j·x'_2 + Σ γ_j·c_j·x_2 == (Σ γ_j·ŵ_j) · x_0
    let lhs2 = E::G1::msm(&x2_primes, &gammas).expect("msm size mismatch")
        + E::G1::msm(&x2_points, &gamma_c).expect("msm size mismatch");
    let rhs2 = params.x0 * sum_gamma_w;
    if lhs2 != rhs2 {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381 as E;
    use ark_std::test_rng;

    type Fr = <E as Pairing>::ScalarField;
    type G1 = <E as Pairing>::G1;

    /// Helper to build a valid (params, statement, witness) tuple.
    fn sample_instance(rng: &mut impl Rng) -> (NizkParams<E>, Statement<E>, Fr) {
        let alpha = Fr::rand(rng);
        let x0 = (G1::generator() * alpha).into_affine();
        let params = NizkParams::<E> { x0 };

        let w = Fr::rand(rng);
        let x1 = (G1::generator() * w).into_affine();
        let x2 = (x0 * w).into_affine();
        let statement = Statement::<E> { x1, x2 };

        (params, statement, w)
    }

    #[test]
    fn test_honest_proof_verifies() {
        let rng = &mut test_rng();
        let (params, statement, w) = sample_instance(rng);

        let proof = prove::<E, Sha256Oracle>(&params, &statement, &w, rng);
        assert!(verify::<E, Sha256Oracle>(&params, &statement, &proof));
    }

    #[test]
    fn test_wrong_witness_fails() {
        let rng = &mut test_rng();
        let (params, statement, _w) = sample_instance(rng);

        // Prove with wrong witness
        let bad_w = Fr::rand(rng);
        let proof = prove::<E, Sha256Oracle>(&params, &statement, &bad_w, rng);
        assert!(!verify::<E, Sha256Oracle>(&params, &statement, &proof));
    }

    #[test]
    fn test_tampered_proof_fails() {
        let rng = &mut test_rng();
        let (params, statement, w) = sample_instance(rng);

        let mut proof = prove::<E, Sha256Oracle>(&params, &statement, &w, rng);
        // Tamper with w_hat
        proof.w_hat += Fr::from(1u64);
        assert!(!verify::<E, Sha256Oracle>(&params, &statement, &proof));
    }

    #[test]
    fn test_wrong_statement_fails() {
        let rng = &mut test_rng();
        let (params, statement, w) = sample_instance(rng);

        let proof = prove::<E, Sha256Oracle>(&params, &statement, &w, rng);

        // Verify against a different statement
        let bad_statement = Statement::<E> {
            x1: statement.x1,
            x2: (G1::generator() * Fr::rand(rng)).into_affine(),
        };
        assert!(!verify::<E, Sha256Oracle>(&params, &bad_statement, &proof));
    }
}
