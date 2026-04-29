//! Construction 5: Batch Encryption with Shorter Ciphertexts (Section 5).

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::Field;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::{One, UniformRand, Zero};
use rayon::prelude::*;

use crate::nizk_dlog::{self, TranscriptOracle};
use be_common::fft::circulant_mul;
use be_common::partial_fractions::{get_extra_index, get_omega, partial_fraction_at};

/// Public encryption key.
///
/// Stores `[p0(x)]_T` in GT (rather than `[p0(x)]_1` in G1 so that Enc
/// avoids a pairing.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct EncryptionKey<E: Pairing> {
    pub p0_t: PairingOutput<E>,
}

/// Secret key: x in Fp.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey<E: Pairing> {
    pub x: E::ScalarField,
}

/// Public decryption key (the bulk of the setup output).
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DecryptionKey<E: Pairing> {
    pub p2_vec: Vec<E::G2Affine>,
    pub w_vec: Vec<E::G2Affine>,
    pub p0_plus_pg_2: E::G2Affine,
}

/// A ciphertext with attached DLOG NIZK proof.
///
/// - `ct1 = [r]_1`.
/// - `ct2 = r · [p_0(x)]_T + m` in GT.
/// - `proof`: Construction-6 SE-NIZK proving knowledge of `r`.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Ciphertext<E: Pairing> {
    pub ct1: E::G1Affine,
    pub ct2: PairingOutput<E>,
    pub proof: nizk_dlog::Proof<E>,
}

/// Pre-decryption key: `sbk = Σ_j p_{ω^j}(sk) · ct_j[1]` in G1 (one element).
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreDecryptionKey<E: Pairing> {
    pub sbk: E::G1Affine,
}

/// Bundle returned by [`setup`].
pub struct SetupOutput<E: Pairing> {
    pub ek: EncryptionKey<E>,
    pub sk: SecretKey<E>,
    pub dk: DecryptionKey<E>,
}

/// Setup(1^λ, 1^ell): generate keys for batch size `ell`.
///
/// Panics if `ell` is not a power of two.
pub fn setup<E: Pairing>(ell: usize, rng: &mut impl Rng) -> SetupOutput<E> {
    assert!(ell.is_power_of_two(), "ell must be a power of two");

    let omega = get_omega::<E::ScalarField>(ell);
    let gamma = get_extra_index::<E::ScalarField>(ell);
    let x = E::ScalarField::rand(rng);
    let zero = E::ScalarField::zero();

    let p0_scalar = partial_fraction_at(&x, &zero);
    let pgamma_scalar = partial_fraction_at(&x, &gamma);

    let p0_t = E::pairing(E::G1::generator() * p0_scalar, E::G2::generator());

    let p0_plus_pg_2 = (E::G2::generator() * (p0_scalar + pgamma_scalar)).into_affine();

    let mut p2_vec = Vec::with_capacity(ell);
    let mut w_vec = Vec::with_capacity(ell);
    let mut omega_j = E::ScalarField::one();
    for _ in 0..ell {
        let p_oj = partial_fraction_at(&x, &omega_j);
        let p_oj_2 = (E::G2::generator() * p_oj).into_affine();

        // q_{ω^j}(x) = p_{ω^j}(x)² = 1/(x + ω^j)²
        let q_oj = p_oj * p_oj;

        let omega_j_inv = omega_j.inverse().expect("ω^j ≠ 0");
        let oj_minus_gamma_inv = (omega_j - gamma).inverse().expect("ω^j − γ ≠ 0");

        let w_oj_scalar = q_oj + omega_j_inv * p0_scalar + oj_minus_gamma_inv * pgamma_scalar;
        let w_oj_2 = (E::G2::generator() * w_oj_scalar).into_affine();

        p2_vec.push(p_oj_2);
        w_vec.push(w_oj_2);
        omega_j *= omega;
    }

    SetupOutput {
        ek: EncryptionKey { p0_t },
        sk: SecretKey { x },
        dk: DecryptionKey {
            p2_vec,
            w_vec,
            p0_plus_pg_2,
        },
    }
}

/// Enc(ek, m): encrypt a message `m` in GT.
///
/// The ciphertext is `(ct1 = [r]_1,  ct2 = r · [p_0(x)]_T + m)` together with
/// a DLOG NIZK proof of knowledge of `r` (Construction 6).
pub fn encrypt<E: Pairing, H: TranscriptOracle<E>>(
    ek: &EncryptionKey<E>,
    m: &PairingOutput<E>,
    rng: &mut impl Rng,
) -> Ciphertext<E> {
    let r = E::ScalarField::rand(rng);
    let ct1 = (E::G1::generator() * r).into_affine();
    let ct2 = ek.p0_t * r + m;

    let statement = nizk_dlog::Statement::<E> { h: ct1 };
    let proof = nizk_dlog::prove::<E, H>(&statement, &r, rng);

    Ciphertext { ct1, ct2, proof }
}

/// PreDec(sk, cts): batch-verify the DLOG NIZK proofs and compute `sbk`.
///
/// Returns `None` iff batch verification rejects (re-run per-proof
/// [`nizk_dlog::verify`] to locate a bad proof).
///
/// Panics if `cts.len()` is not a power of two.
pub fn pre_decrypt<E: Pairing, H: TranscriptOracle<E>>(
    sk: &SecretKey<E>,
    cts: &[Ciphertext<E>],
    rng: &mut impl Rng,
) -> Option<PreDecryptionKey<E>> {
    let ell = cts.len();
    assert!(ell.is_power_of_two(), "cts.len() must be a power of two");
    let omega = get_omega::<E::ScalarField>(ell);

    // 1. Batch-verify all NIZK proofs via the randomized-MSM check.
    let statements: Vec<nizk_dlog::Statement<E>> = cts
        .iter()
        .map(|ct| nizk_dlog::Statement::<E> { h: ct.ct1 })
        .collect();
    let proofs: Vec<nizk_dlog::Proof<E>> = cts.iter().map(|ct| ct.proof.clone()).collect();
    if !nizk_dlog::verify_batch::<E, H>(&statements, &proofs, rng) {
        return None;
    }

    // 2. sbk = Σ_{j=0..ell−1} p_{ω^j}(sk) · ct_j[1].
    let mut sbk = E::G1::zero();
    let mut omega_j = E::ScalarField::one();
    for ct in cts {
        sbk += ct.ct1 * partial_fraction_at(&sk.x, &omega_j);
        omega_j *= omega;
    }

    Some(PreDecryptionKey {
        sbk: sbk.into_affine(),
    })
}

/// Dec(dk, sbk, cts): batch-decrypt all `ell` ciphertexts.
///
/// Panics if `dk.p2_vec`, `dk.w_vec`, and `cts` lengths disagree.
pub fn decrypt<E: Pairing>(
    dk: &DecryptionKey<E>,
    sbk: &PreDecryptionKey<E>,
    cts: &[Ciphertext<E>],
) -> Vec<PairingOutput<E>> {
    let ell = cts.len();
    assert_eq!(
        dk.p2_vec.len(),
        ell,
        "dk.p2_vec length must match cts.len()"
    );
    assert_eq!(dk.w_vec.len(), ell, "dk.w_vec length must match cts.len()");

    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(ell)
        .expect("ell must be a power of two within the field's two-adicity");
    let omega: E::ScalarField = domain.group_gen();
    let gamma = get_extra_index::<E::ScalarField>(ell);
    let gamma_inv = gamma.inverse().expect("gamma must be invertible");

    let d: Vec<E::ScalarField> = (0..ell)
        .map(|r| {
            if r == 0 {
                E::ScalarField::zero()
            } else {
                let omega_neg_r = omega.pow([(ell - r) as u64]); // ω^{ell-r} = ω^{-r}
                (E::ScalarField::one() - omega_neg_r)
                    .inverse()
                    .expect("1 − ω^{-r} ≠ 0 for r ∈ [1, ell-1]")
            }
        })
        .collect();
    let d_hat = domain.fft(&d);

    let tm: Vec<PairingOutput<E>> = (0..ell)
        // .into_par_iter()
        .map(|j| E::pairing(cts[j].ct1, dk.p2_vec[j]))
        .collect();

    let ct1_proj: Vec<E::G1> = cts.iter().map(|ct| E::G1::from(ct.ct1)).collect();
    let conv_g1: Vec<E::G1> = circulant_mul(&d_hat, &ct1_proj, omega);
    let conv_gt: Vec<PairingOutput<E>> = circulant_mul(&d_hat, &tm, omega);

    let mut omega_pows = Vec::with_capacity(ell);
    let mut acc = E::ScalarField::one();
    for _ in 0..ell {
        omega_pows.push(acc);
        acc *= omega;
    }

    let sbk_proj = E::G1::from(sbk.sbk);
    let p0pg_2_proj = E::G2::from(dk.p0_plus_pg_2);

    (0..ell)
        // .into_par_iter()
        .map(|j| {
            let omega_j = omega_pows[j];
            let s2 = omega_j * gamma_inv;
            let s1 = s2 * (omega_j - gamma);

            let g1_a = cts[j].ct1;
            let g1_b = (sbk_proj + conv_g1[j]).into_affine();
            let g2_a = (p0pg_2_proj * s2 - E::G2::from(dk.w_vec[j]) * s1).into_affine();
            let g2_b = (E::G2::from(dk.p2_vec[j]) * s1).into_affine();

            let paired = E::multi_pairing([g1_a, g1_b], [g2_a, g2_b]);
            let r_val = paired - conv_gt[j] * s1;
            cts[j].ct2 - r_val
        })
        .collect()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381 as E;
    use ark_std::test_rng;

    type Fr = <E as Pairing>::ScalarField;
    type G1 = <E as Pairing>::G1;
    type G2 = <E as Pairing>::G2;

    // --- Helper tests ---

    #[test]
    fn test_omega_is_primitive_root() {
        for &n in &[1usize, 2, 4, 8] {
            let omega = get_omega::<Fr>(n);
            assert_eq!(omega.pow([n as u64]), Fr::one(), "ω^n = 1 for n={n}");
            if n > 1 {
                assert_ne!(omega.pow([(n / 2) as u64]), Fr::one());
            }
        }
    }

    #[test]
    fn test_extra_index_not_root_of_unity() {
        for &n in &[1usize, 2, 4, 8] {
            let gamma = get_extra_index::<Fr>(n);
            assert_ne!(gamma, Fr::zero());
            assert_ne!(gamma.pow([n as u64]), Fr::one());
        }
    }

    // --- Setup tests ---

    #[test]
    fn test_setup_ek_p0_t_correct() {
        let rng = &mut test_rng();
        let out = setup::<E>(4, rng);
        let expected = E::pairing(
            G1::generator() * partial_fraction_at(&out.sk.x, &Fr::zero()),
            G2::generator(),
        );
        assert_eq!(out.ek.p0_t, expected);
    }

    #[test]
    fn test_setup_p2_vec_correct() {
        let rng = &mut test_rng();
        let ell = 4;
        let out = setup::<E>(ell, rng);
        let omega = get_omega::<Fr>(ell);
        let mut omega_j = Fr::one();
        for j in 0..ell {
            let expected =
                (G2::generator() * partial_fraction_at(&out.sk.x, &omega_j)).into_affine();
            assert_eq!(out.dk.p2_vec[j], expected, "p2_vec[{j}] mismatch");
            omega_j *= omega;
        }
    }

    #[test]
    fn test_setup_p0_plus_pg_correct() {
        let rng = &mut test_rng();
        let ell = 4;
        let out = setup::<E>(ell, rng);
        let gamma = get_extra_index::<Fr>(ell);
        let expected_scalar =
            partial_fraction_at(&out.sk.x, &Fr::zero()) + partial_fraction_at(&out.sk.x, &gamma);
        assert_eq!(
            out.dk.p0_plus_pg_2,
            (G2::generator() * expected_scalar).into_affine()
        );
    }

    #[test]
    fn test_setup_w_vec_correct() {
        // w_{ω^j}(x) = p_{ω^j}(x)² + (1/ω^j)·p_0(x) + (1/(ω^j − γ))·p_γ(x)
        let rng = &mut test_rng();
        let ell = 4;
        let out = setup::<E>(ell, rng);
        let omega = get_omega::<Fr>(ell);
        let gamma = get_extra_index::<Fr>(ell);
        let x = out.sk.x;
        let p0 = partial_fraction_at(&x, &Fr::zero());
        let pg = partial_fraction_at(&x, &gamma);

        let mut omega_j = Fr::one();
        for j in 0..ell {
            let p_oj = partial_fraction_at(&x, &omega_j);
            let expected_scalar = p_oj * p_oj
                + omega_j.inverse().unwrap() * p0
                + (omega_j - gamma).inverse().unwrap() * pg;
            let expected = (G2::generator() * expected_scalar).into_affine();
            assert_eq!(out.dk.w_vec[j], expected, "w_vec[{j}] mismatch");
            omega_j *= omega;
        }
    }

    #[test]
    fn test_setup_dk_sizes() {
        let rng = &mut test_rng();
        for &ell in &[1usize, 2, 4, 8] {
            let out = setup::<E>(ell, rng);
            assert_eq!(out.dk.p2_vec.len(), ell);
            assert_eq!(out.dk.w_vec.len(), ell);
        }
    }

    #[test]
    fn test_setup_deterministic_with_same_rng() {
        let out1 = setup::<E>(4, &mut test_rng());
        let out2 = setup::<E>(4, &mut test_rng());
        assert_eq!(out1.sk.x, out2.sk.x);
        assert_eq!(out1.ek.p0_t, out2.ek.p0_t);
        assert_eq!(out1.dk.p0_plus_pg_2, out2.dk.p0_plus_pg_2);
    }

    // --- Encrypt tests ---

    #[test]
    fn test_encrypt_nizk_verifies() {
        use crate::nizk_dlog::Sha512Oracle;
        let rng = &mut test_rng();
        let out = setup::<E>(4, rng);
        let m = PairingOutput::<E>::rand(rng);
        let ct = encrypt::<E, Sha512Oracle>(&out.ek, &m, rng);
        let stmt = nizk_dlog::Statement::<E> { h: ct.ct1 };
        assert!(nizk_dlog::verify::<E, Sha512Oracle>(&stmt, &ct.proof));
    }

    #[test]
    fn test_encrypt_randomized() {
        use crate::nizk_dlog::Sha512Oracle;
        let rng = &mut test_rng();
        let out = setup::<E>(4, rng);
        let m = PairingOutput::<E>::rand(rng);
        let ct1 = encrypt::<E, Sha512Oracle>(&out.ek, &m, rng);
        let ct2 = encrypt::<E, Sha512Oracle>(&out.ek, &m, rng);
        assert_ne!(ct1.ct1, ct2.ct1, "ct1 should differ due to fresh r");
        assert_ne!(ct1.ct2, ct2.ct2, "ct2 should differ due to fresh r");
    }

    // --- PreDecrypt tests ---

    #[test]
    fn test_pre_decrypt_valid() {
        use crate::nizk_dlog::Sha512Oracle;
        let rng = &mut test_rng();
        let out = setup::<E>(4, rng);
        let cts: Vec<_> = (0..4)
            .map(|_| encrypt::<E, Sha512Oracle>(&out.ek, &PairingOutput::rand(rng), rng))
            .collect();
        assert!(pre_decrypt::<E, Sha512Oracle>(&out.sk, &cts, rng).is_some());
    }

    #[test]
    fn test_pre_decrypt_rejects_tampered_proof() {
        use crate::nizk_dlog::Sha512Oracle;
        let rng = &mut test_rng();
        let out = setup::<E>(4, rng);
        let mut cts: Vec<_> = (0..4)
            .map(|_| encrypt::<E, Sha512Oracle>(&out.ek, &PairingOutput::rand(rng), rng))
            .collect();
        cts[2].proof.w_hat += Fr::from(1u64);
        assert!(pre_decrypt::<E, Sha512Oracle>(&out.sk, &cts, rng).is_none());
    }

    #[test]
    fn test_pre_decrypt_rejects_swapped_ct1() {
        // Swapping ct1 between two ciphertexts invalidates the DLOG proofs
        // (the proof is bound to ct1 via the Fiat-Shamir challenge).
        use crate::nizk_dlog::Sha512Oracle;
        let rng = &mut test_rng();
        let out = setup::<E>(4, rng);
        let mut cts: Vec<_> = (0..4)
            .map(|_| encrypt::<E, Sha512Oracle>(&out.ek, &PairingOutput::rand(rng), rng))
            .collect();
        let tmp = cts[0].ct1;
        cts[0].ct1 = cts[1].ct1;
        cts[1].ct1 = tmp;
        assert!(pre_decrypt::<E, Sha512Oracle>(&out.sk, &cts, rng).is_none());
    }

    #[test]
    fn test_pre_decrypt_sbk_matches_manual_computation() {
        // sbk = Σ_j (1/(x + ω^j)) · ct_j[1]. We can verify by recomputing
        // directly with sk.
        use crate::nizk_dlog::Sha512Oracle;
        let rng = &mut test_rng();
        let ell = 4;
        let out = setup::<E>(ell, rng);
        let cts: Vec<_> = (0..ell)
            .map(|_| encrypt::<E, Sha512Oracle>(&out.ek, &PairingOutput::rand(rng), rng))
            .collect();
        let sbk = pre_decrypt::<E, Sha512Oracle>(&out.sk, &cts, rng).unwrap();

        let omega = get_omega::<Fr>(ell);
        let mut expected = G1::zero();
        let mut omega_j = Fr::one();
        for ct in &cts {
            expected += ct.ct1 * partial_fraction_at(&out.sk.x, &omega_j);
            omega_j *= omega;
        }
        assert_eq!(sbk.sbk, expected.into_affine());
    }

    #[test]
    fn test_encrypt_structure() {
        // Roundtrip check: recover m from ct2 by subtracting r·p0_T computed
        // with sk. r·p0_T = p_0(x) · e(ct1, [1]_2).
        use crate::nizk_dlog::Sha512Oracle;
        let rng = &mut test_rng();
        let out = setup::<E>(4, rng);
        let m = PairingOutput::<E>::rand(rng);
        let ct = encrypt::<E, Sha512Oracle>(&out.ek, &m, rng);
        let p0 = partial_fraction_at(&out.sk.x, &Fr::zero());
        let r_p0t = E::pairing(ct.ct1, G2::generator()) * p0;
        assert_eq!(ct.ct2 - r_p0t, m);
    }

    // --- End-to-end tests ---

    fn e2e_test(ell: usize) {
        use crate::nizk_dlog::Sha512Oracle;
        let rng = &mut test_rng();
        let out = setup::<E>(ell, rng);
        let messages: Vec<_> = (0..ell).map(|_| PairingOutput::<E>::rand(rng)).collect();
        let cts: Vec<_> = messages
            .iter()
            .map(|m| encrypt::<E, Sha512Oracle>(&out.ek, m, rng))
            .collect();
        let sbk = pre_decrypt::<E, Sha512Oracle>(&out.sk, &cts, rng).unwrap();
        let decrypted = decrypt(&out.dk, &sbk, &cts);
        assert_eq!(messages, decrypted, "e2e mismatch at ell={ell}");
    }

    #[test]
    fn test_e2e_ell_1() {
        e2e_test(1);
    }
    #[test]
    fn test_e2e_ell_2() {
        e2e_test(2);
    }
    #[test]
    fn test_e2e_ell_4() {
        e2e_test(4);
    }
    #[test]
    fn test_e2e_ell_8() {
        e2e_test(8);
    }

    #[test]
    fn test_e2e_zero_messages() {
        use crate::nizk_dlog::Sha512Oracle;
        let rng = &mut test_rng();
        let out = setup::<E>(4, rng);
        let messages = vec![
            PairingOutput::<E>::zero(),
            PairingOutput::<E>::rand(rng),
            PairingOutput::<E>::zero(),
            PairingOutput::<E>::rand(rng),
        ];
        let cts: Vec<_> = messages
            .iter()
            .map(|m| encrypt::<E, Sha512Oracle>(&out.ek, m, rng))
            .collect();
        let sbk = pre_decrypt::<E, Sha512Oracle>(&out.sk, &cts, rng).unwrap();
        assert_eq!(decrypt(&out.dk, &sbk, &cts), messages);
    }

    #[test]
    fn test_decrypt_is_deterministic_given_fixed_inputs() {
        // Decrypt takes no randomness — twice on the same (dk, sbk, cts) must
        // produce identical outputs.
        use crate::nizk_dlog::Sha512Oracle;
        let rng = &mut test_rng();
        let ell = 4;
        let out = setup::<E>(ell, rng);
        let messages: Vec<_> = (0..ell).map(|_| PairingOutput::<E>::rand(rng)).collect();
        let cts: Vec<_> = messages
            .iter()
            .map(|m| encrypt::<E, Sha512Oracle>(&out.ek, m, rng))
            .collect();
        let sbk = pre_decrypt::<E, Sha512Oracle>(&out.sk, &cts, rng).unwrap();
        let first = decrypt(&out.dk, &sbk, &cts);
        let second = decrypt(&out.dk, &sbk, &cts);
        assert_eq!(first, second);
    }
}
