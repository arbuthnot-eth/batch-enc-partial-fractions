//! Construction 1: Batch Encryption using Partial Fractions (Section 4.1).

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::Field;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::{One, UniformRand, Zero};
use rayon::prelude::*;

use crate::nizk::{self, TranscriptOracle};
use be_common::fft::circulant_mul;
use be_common::partial_fractions::{get_extra_index, get_omega, partial_fraction_at};

/// Encryption key published during setup.
///
/// - `ek_sum`: Σ_{i ∈ S} [p_i(x)]_1 in G1 (S = {0, γ} ∪ H).
/// - `p0_t`: [p₀(x)]_T = e([1/x]_1, [1]_2), the one-time pad base stored in GT
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct EncryptionKey<E: Pairing> {
    pub ek_sum: E::G1Affine,
    pub p0_t: PairingOutput<E>,
}

/// Secret key: x in Fp
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey<E: Pairing> {
    pub x: E::ScalarField,
}

/// Decryption key published during setup.
///
/// - `dk[j]` = [1/(x + ω^j)]_2 for j = 0, …, ell−1.
/// - `dk_sum`: precomputed Σ dk[j].
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DecryptionKey<E: Pairing> {
    pub dk: Vec<E::G2Affine>,
    pub dk_sum: E::G2Affine,
}

/// A ciphertext with attached NIZK proof of well-formedness.
///
/// - ct1 = [r]_1
/// - ct2 = r · ek_sum
/// - ct3 = r · [p₀(x)]_T + m
/// - proof: SE-NIZK proving knowledge of r.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Ciphertext<E: Pairing> {
    pub ct1: E::G1Affine,
    pub ct2: E::G1Affine,
    pub ct3: PairingOutput<E>,
    pub proof: nizk::Proof<E>,
}

/// Pre-decryption key: sbk = Σ_j [1/(sk + ω^j)] · ct_j[1] in G1.
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

    // ek_sum = [1/x]_1 + [1/(x+γ)]_1 + Σ_{j=0}^{ell-1} [1/(x+ω^j)]_1
    let zero = E::ScalarField::zero();
    let mut ek_sum = E::G1::zero();
    ek_sum += E::G1::generator() * partial_fraction_at(&x, &zero);
    ek_sum += E::G1::generator() * partial_fraction_at(&x, &gamma);
    let mut omega_j = E::ScalarField::one();
    for _ in 0..ell {
        ek_sum += E::G1::generator() * partial_fraction_at(&x, &omega_j);
        omega_j *= omega;
    }

    // p0_T = e([1/x]_1, [1]_2) stored in GT to avoid a pairing during Enc.
    let p0_t = E::pairing(
        E::G1::generator() * partial_fraction_at(&x, &zero),
        E::G2::generator(),
    );

    let ek = EncryptionKey {
        ek_sum: ek_sum.into_affine(),
        p0_t,
    };
    let sk = SecretKey { x };

    // dk[j] = [1/(x + ω^j)]_2
    let mut dk_vec = Vec::with_capacity(ell);
    let mut dk_sum = E::G2::zero();
    let mut omega_j = E::ScalarField::one();
    for _ in 0..ell {
        let dk_j = (E::G2::generator() * partial_fraction_at(&x, &omega_j)).into_affine();
        dk_sum += E::G2::from(dk_j);
        dk_vec.push(dk_j);
        omega_j *= omega;
    }

    let dk = DecryptionKey {
        dk: dk_vec,
        dk_sum: dk_sum.into_affine(),
    };

    SetupOutput { ek, sk, dk }
}

/// Enc(ek, m): encrypt a message m in GT.
pub fn encrypt<E: Pairing, H: TranscriptOracle<E>>(
    ek: &EncryptionKey<E>,
    m: &PairingOutput<E>,
    rng: &mut impl Rng,
) -> Ciphertext<E> {
    let r = E::ScalarField::rand(rng);
    let ct1 = (E::G1::generator() * r).into_affine();
    let ct2 = (ek.ek_sum * r).into_affine();
    let ct3 = ek.p0_t * r + m;

    let nizk_params = nizk::NizkParams::<E> { x0: ek.ek_sum };
    let nizk_stmt = nizk::Statement::<E> { x1: ct1, x2: ct2 };
    let proof = nizk::prove::<E, H>(&nizk_params, &nizk_stmt, &r, rng);

    Ciphertext {
        ct1,
        ct2,
        ct3,
        proof,
    }
}

/// PreDec(sk, ek, cts): batch-verify NIZK proofs and compute the pre-decryption key.
///
/// Returns `None` if the batch verification rejects (i.e. at least one proof
/// is invalid — re-run with the per-proof [`nizk::verify`] to identify which).
///
/// Takes an `rng` because batch verification samples random weights γ_j that
/// combine the ell per-proof equations into two MSM-sized checks.
pub fn pre_decrypt<E: Pairing, H: TranscriptOracle<E>>(
    sk: &SecretKey<E>,
    ek: &EncryptionKey<E>,
    cts: &[Ciphertext<E>],
    rng: &mut impl Rng,
) -> Option<PreDecryptionKey<E>> {
    let ell = cts.len();
    let omega = get_omega::<E::ScalarField>(ell);
    let nizk_params = nizk::NizkParams::<E> { x0: ek.ek_sum };

    // Step 1: batch-verify all NIZK proofs.
    let statements: Vec<nizk::Statement<E>> = cts
        .iter()
        .map(|ct| nizk::Statement::<E> {
            x1: ct.ct1,
            x2: ct.ct2,
        })
        .collect();
    let proofs: Vec<nizk::Proof<E>> = cts.iter().map(|ct| ct.proof.clone()).collect();
    if !nizk::verify_batch::<E, H>(&nizk_params, &statements, &proofs, rng) {
        return None;
    }

    // Step 2: sbk = Σ_j [1/(sk + ω^j)] · ct_j[1]
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

/// Dec(dk, sbk, cts): batch-decrypt all ell ciphertexts.
pub fn decrypt<E: Pairing>(
    dk: &DecryptionKey<E>,
    sbk: &PreDecryptionKey<E>,
    cts: &[Ciphertext<E>],
) -> Vec<PairingOutput<E>> {
    let ell = cts.len();
    assert_eq!(
        dk.dk.len(),
        ell,
        "dk length must match number of ciphertexts"
    );

    let domain =
        Radix2EvaluationDomain::<E::ScalarField>::new(ell).expect("ell must be a power of two");
    let omega: E::ScalarField = domain.group_gen();
    let omega_inv = omega.inverse().expect("omega must be invertible");
    let gamma = get_extra_index::<E::ScalarField>(ell);
    let gamma_inv = gamma.inverse().expect("gamma must be invertible");

    // Build the circulant kernel d and FFT it.
    //   d[0]   = 0
    //   d[r]   = 1 / (1 − ω^{−r})   for r = 1, …, n−1
    // d_hat = FFT(d) is shared across all three convolutions below.
    let d: Vec<E::ScalarField> = (0..ell)
        .map(|r| {
            if r == 0 {
                E::ScalarField::zero()
            } else {
                let omega_neg_r = omega.pow([(ell - r) as u64]); // ω^{n−r} = ω^{−r}
                (E::ScalarField::one() - omega_neg_r)
                    .inverse()
                    .expect("1 − ω^{−r} ≠ 0 for r ∈ [1, n−1]")
            }
        })
        .collect();
    let d_hat = domain.fft(&d);

    // Precompute tm_j = e(ct_j[1], dk_j) for all j.  (ell pairings)
    let tm: Vec<PairingOutput<E>> = (0..ell)
        // .into_par_iter()
        .map(|j| E::pairing(cts[j].ct1, dk.dk[j]))
        .collect();

    // Three O(n log n) FFT convolutions.
    //   conv_g1[j] = Σ_k M_{jk} · ct_k[1]   (G1)
    //   conv_g2[j] = Σ_k M_{jk} · dk_k       (G2)
    //   conv_gt[j] = Σ_k M_{jk} · tm_k       (GT)
    // Because d_0 = 0 we have M_{jj} = 0, so the diagonal is naturally excluded.
    let ct1_proj: Vec<E::G1> = cts.iter().map(|ct| E::G1::from(ct.ct1)).collect();
    let dk_proj: Vec<E::G2> = dk.dk.iter().map(|&d| E::G2::from(d)).collect();

    let conv_g1: Vec<E::G1> = circulant_mul(&d_hat, &ct1_proj, omega);
    let conv_g2: Vec<E::G2> = circulant_mul(&d_hat, &dk_proj, omega);
    let conv_gt: Vec<PairingOutput<E>> = circulant_mul(&d_hat, &tm, omega);

    // Coefficient vector (O(n).
    //   coeffs[j] = ω^{−j} · (n+1)/2  +  1/(ω^j − γ)
    let half_np1 =
        E::ScalarField::from((ell + 1) as u64) * E::ScalarField::from(2u64).inverse().unwrap();

    let mut coeffs = Vec::with_capacity(ell);
    let mut omega_j = E::ScalarField::one();
    let mut omega_inv_j = E::ScalarField::one();
    for _ in 0..ell {
        coeffs.push(omega_inv_j * half_np1 + (omega_j - gamma).inverse().unwrap());
        omega_j *= omega;
        omega_inv_j *= omega_inv;
    }

    // g2 generator (affine), reused in every pairing against [1]_2.
    let g2_gen = E::G2::generator().into_affine();

    let dk_sum_proj = E::G2::from(dk.dk_sum);
    let sbk_proj = E::G1::from(sbk.sbk);

    // Precompute ω^j for all j so the per-j work is a pure map (no carry).
    let mut omega_pows = Vec::with_capacity(ell);
    let mut acc = E::ScalarField::one();
    for _ in 0..ell {
        omega_pows.push(acc);
        acc *= omega;
    }

    (0..ell)
        // .into_par_iter()
        .map(|j| {
            let omega_j = omega_pows[j];

            // A = ct_j[2] − sbk + coeffs[j]·ct_j[1] − conv_g1[j]
            let a = E::G1::from(cts[j].ct2) - sbk_proj + ct1_proj[j] * coeffs[j] - conv_g1[j];

            let s2 = omega_j * gamma_inv;
            let s1 = s2 * (omega_j - gamma);

            let s2_ct2 = (cts[j].ct2 * s2).into_affine();
            let neg_s1_a = (-(a * s1)).into_affine();
            let g2_mix = (conv_g2[j] * s1 - dk_sum_proj * s2).into_affine();

            let paired =
                E::multi_pairing([s2_ct2, neg_s1_a, cts[j].ct1], [g2_gen, dk.dk[j], g2_mix]);
            let r_val = paired - conv_gt[j] * s1;
            cts[j].ct3 - r_val
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
                assert_ne!(
                    omega.pow([(n / 2) as u64]),
                    Fr::one(),
                    "ω^{{n/2}} ≠ 1 for n={n}"
                );
            }
        }
    }

    #[test]
    fn test_extra_index_not_root_of_unity() {
        for &n in &[1usize, 2, 4, 8] {
            let gamma = get_extra_index::<Fr>(n);
            assert_ne!(gamma, Fr::zero());
            assert_ne!(gamma.pow([n as u64]), Fr::one(), "γ^n ≠ 1 for n={n}");
        }
    }

    #[test]
    fn test_partial_fraction_at() {
        use ark_ff::One;
        let rng = &mut test_rng();
        let x = Fr::rand(rng);
        let omega = get_omega::<Fr>(4);
        let mut omega_j = Fr::one();
        for _ in 0..4 {
            let pf = partial_fraction_at(&x, &omega_j);
            assert_eq!(pf * (x + omega_j), Fr::one());
            omega_j *= omega;
        }
        let pf0 = partial_fraction_at(&x, &Fr::zero());
        assert_eq!(pf0 * x, Fr::one());
    }

    // --- Setup tests ---

    #[test]
    fn test_setup_dk_sum() {
        let rng = &mut test_rng();
        let out = setup::<E>(4, rng);
        assert_eq!(out.dk.dk.len(), 4);
        let sum: G2 = out.dk.dk.iter().map(|&d| G2::from(d)).sum();
        assert_eq!(sum.into_affine(), out.dk.dk_sum);
    }

    #[test]
    fn test_setup_ek_sum_correct() {
        let rng = &mut test_rng();
        let ell = 4;
        let out = setup::<E>(ell, rng);
        let omega = get_omega::<Fr>(ell);
        let gamma = get_extra_index::<Fr>(ell);
        let x = out.sk.x;

        let mut expected = G1::zero();
        expected += G1::generator() * partial_fraction_at(&x, &Fr::zero());
        expected += G1::generator() * partial_fraction_at(&x, &gamma);
        let mut omega_j = Fr::one();
        for _ in 0..ell {
            expected += G1::generator() * partial_fraction_at(&x, &omega_j);
            omega_j *= omega;
        }
        assert_eq!(expected.into_affine(), out.ek.ek_sum);
    }

    #[test]
    fn test_setup_p0_t_correct() {
        let rng = &mut test_rng();
        let out = setup::<E>(4, rng);
        let expected = E::pairing(
            G1::generator() * partial_fraction_at(&out.sk.x, &Fr::zero()),
            G2::generator(),
        );
        assert_eq!(out.ek.p0_t, expected);
    }

    #[test]
    fn test_setup_dk_correct() {
        let rng = &mut test_rng();
        let ell = 4;
        let out = setup::<E>(ell, rng);
        let omega = get_omega::<Fr>(ell);
        let mut omega_j = Fr::one();
        for j in 0..ell {
            let expected =
                (G2::generator() * partial_fraction_at(&out.sk.x, &omega_j)).into_affine();
            assert_eq!(out.dk.dk[j], expected, "dk[{j}] mismatch");
            omega_j *= omega;
        }
    }

    #[test]
    fn test_setup_deterministic() {
        let out1 = setup::<E>(4, &mut test_rng());
        let out2 = setup::<E>(4, &mut test_rng());
        assert_eq!(out1.ek.ek_sum, out2.ek.ek_sum);
        assert_eq!(out1.sk.x, out2.sk.x);
    }

    // --- Encrypt tests ---

    #[test]
    fn test_encrypt_nizk_verifies() {
        use crate::nizk::Sha256Oracle;
        let rng = &mut test_rng();
        let out = setup::<E>(4, rng);
        let ct = encrypt::<E, Sha256Oracle>(&out.ek, &PairingOutput::rand(rng), rng);
        let params = nizk::NizkParams::<E> { x0: out.ek.ek_sum };
        let stmt = nizk::Statement::<E> {
            x1: ct.ct1,
            x2: ct.ct2,
        };
        assert!(nizk::verify::<E, Sha256Oracle>(&params, &stmt, &ct.proof));
    }

    #[test]
    fn test_encrypt_randomized() {
        use crate::nizk::Sha256Oracle;
        let rng = &mut test_rng();
        let out = setup::<E>(4, rng);
        let m = PairingOutput::<E>::rand(rng);
        let ct1 = encrypt::<E, Sha256Oracle>(&out.ek, &m, rng);
        let ct2 = encrypt::<E, Sha256Oracle>(&out.ek, &m, rng);
        assert_ne!(ct1.ct1, ct2.ct1);
        assert_ne!(ct1.ct3, ct2.ct3);
    }

    // --- PreDecrypt tests ---

    #[test]
    fn test_pre_decrypt_valid() {
        use crate::nizk::Sha256Oracle;
        let rng = &mut test_rng();
        let out = setup::<E>(4, rng);
        let cts: Vec<_> = (0..4)
            .map(|_| encrypt::<E, Sha256Oracle>(&out.ek, &PairingOutput::rand(rng), rng))
            .collect();
        assert!(pre_decrypt::<E, Sha256Oracle>(&out.sk, &out.ek, &cts, rng).is_some());
    }

    #[test]
    fn test_pre_decrypt_rejects_tampered() {
        use crate::nizk::Sha256Oracle;
        let rng = &mut test_rng();
        let out = setup::<E>(4, rng);
        let mut cts: Vec<_> = (0..4)
            .map(|_| encrypt::<E, Sha256Oracle>(&out.ek, &PairingOutput::rand(rng), rng))
            .collect();
        cts[0].proof.w_hat += Fr::from(1u64);
        assert!(pre_decrypt::<E, Sha256Oracle>(&out.sk, &out.ek, &cts, rng).is_none());
    }

    // --- End-to-end tests ---

    fn e2e_test(ell: usize) {
        use crate::nizk::Sha256Oracle;
        let rng = &mut test_rng();
        let out = setup::<E>(ell, rng);
        let messages: Vec<_> = (0..ell).map(|_| PairingOutput::<E>::rand(rng)).collect();
        let cts: Vec<_> = messages
            .iter()
            .map(|m| encrypt::<E, Sha256Oracle>(&out.ek, m, rng))
            .collect();
        let sbk = pre_decrypt::<E, Sha256Oracle>(&out.sk, &out.ek, &cts, rng).unwrap();
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
        use crate::nizk::Sha256Oracle;
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
            .map(|m| encrypt::<E, Sha256Oracle>(&out.ek, m, rng))
            .collect();
        let sbk = pre_decrypt::<E, Sha256Oracle>(&out.sk, &out.ek, &cts, rng).unwrap();
        assert_eq!(decrypt(&out.dk, &sbk, &cts), messages);
    }
}
