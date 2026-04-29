//! FFT utilities for group elements over finite fields.

use ark_ff::FftField;
use std::ops::{Add, Mul, Sub};

use ark_std::Zero;

// ---------------------------------------------------------------------------
// Bit-reversal permutation
// ---------------------------------------------------------------------------

fn reverse_bits(x: usize, log_n: u32) -> usize {
    x.reverse_bits() >> (usize::BITS - log_n)
}

/// In-place radix-2 DIT FFT for group elements.
///
/// Computes: `out[m] = sum_{r=0}^{n-1} vals[r] * omega^{m*r}`
///
/// where `omega` is a primitive n-th root of unity and the "multiply" is
/// scalar multiplication of a group element by a field element.
///
/// Panics if `vals.len()` is not a power of two.
pub fn group_fft_in_place<F, G>(vals: &mut [G], omega: F)
where
    F: FftField,
    G: Clone + Zero + Add<G, Output = G> + Sub<G, Output = G> + Mul<F, Output = G>,
{
    let n = vals.len();
    if n <= 1 {
        return;
    }
    assert!(n.is_power_of_two(), "FFT size must be a power of two");

    let log_n = n.trailing_zeros();

    // Bit-reversal permutation
    for i in 0..n {
        let j = reverse_bits(i, log_n);
        if i < j {
            vals.swap(i, j);
        }
    }

    // Butterfly stages
    let mut half = 1usize;
    while half < n {
        let step = half * 2;
        // omega_step = omega^{n/step} = primitive step-th root of unity
        let omega_step = omega.pow([(n / step) as u64]);

        let mut k = 0;
        while k < n {
            let mut w = F::one();
            for j in 0..half {
                let t = vals[k + j + half].clone() * w;
                let u = vals[k + j].clone();
                vals[k + j] = u.clone() + t.clone();
                vals[k + j + half] = u - t;
                w *= omega_step;
            }
            k += step;
        }
        half *= 2;
    }
}

/// In-place inverse FFT for group elements.
///
/// Computes: `out[r] = (1/n) * sum_{m=0}^{n-1} vals[m] * omega^{-m*r}`
///
/// This is the inverse of [`group_fft_in_place`].
pub fn group_ifft_in_place<F, G>(vals: &mut [G], omega: F)
where
    F: FftField,
    G: Clone + Zero + Add<G, Output = G> + Sub<G, Output = G> + Mul<F, Output = G>,
{
    let omega_inv = omega.inverse().expect("omega must be nonzero");
    group_fft_in_place(vals, omega_inv);

    let n_inv = F::from(vals.len() as u64)
        .inverse()
        .expect("n must be nonzero in the field");
    for v in vals.iter_mut() {
        *v = v.clone() * n_inv;
    }
}

// ---------------------------------------------------------------------------
// Circulant matrix-vector product via FFT
// ---------------------------------------------------------------------------

/// Compute the product `M * a` where `M_{jk} = omega^{-j} * d_{j-k}`.
///
/// This is equivalent to `result[j] = omega^{-j} * (d * a)[j]` where `d * a`
/// denotes cyclic convolution. The convolution is computed via:
///
/// 1. `a_hat = FFT(a)`
/// 2. `c_hat[m] = d_hat[m] * a_hat[m]`  (pointwise scalar multiply)
/// 3. `c = IFFT(c_hat)`
/// 4. `result[j] = omega^{-j} * c[j]`
///
/// # Arguments
/// - `d_hat`: the FFT of the kernel vector `d` (precomputed field elements)
/// - `a`: the input vector of group elements
/// - `omega`: the primitive n-th root of unity
///
/// # Returns
/// Vector `result` where `result[j] = sum_{k=0}^{n-1} M_{jk} * a[k]`.
pub fn circulant_mul<F, G>(d_hat: &[F], a: &[G], omega: F) -> Vec<G>
where
    F: FftField,
    G: Clone + Zero + Add<G, Output = G> + Sub<G, Output = G> + Mul<F, Output = G>,
{
    let n = a.len();
    assert_eq!(d_hat.len(), n, "d_hat and a must have the same length");

    // Step 1: FFT of the group-element vector
    let mut a_hat = a.to_vec();
    group_fft_in_place(&mut a_hat, omega);

    // Step 2: pointwise scalar multiply c_hat[m] = d_hat[m] * a_hat[m]
    let mut c_hat: Vec<G> = a_hat
        .into_iter()
        .zip(d_hat.iter())
        .map(|(a_m, &d_m)| a_m * d_m)
        .collect();

    // Step 3: IFFT
    group_ifft_in_place(&mut c_hat, omega);
    // c_hat is now `c`

    // Step 4: multiply by omega^{-j}
    let omega_inv = omega.inverse().expect("omega must be nonzero");
    let mut omega_inv_j = F::one();
    for v in c_hat.iter_mut() {
        *v = v.clone() * omega_inv_j;
        omega_inv_j *= omega_inv;
    }

    c_hat
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::pairing::Pairing;
    use ark_ec::PrimeGroup;
    use ark_ff::Field;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use ark_std::{test_rng, One, UniformRand, Zero};

    type G1 = <Bls12_381 as Pairing>::G1;

    fn primitive_root(n: usize) -> Fr {
        Radix2EvaluationDomain::<Fr>::new(n).unwrap().group_gen()
    }

    /// Group FFT then IFFT recovers the original vector, for both scalar and
    /// group-element inputs.
    #[test]
    fn fft_ifft_roundtrip() {
        let rng = &mut test_rng();

        for &n in &[1usize, 2, 4, 8, 16, 32] {
            let omega = primitive_root(n);

            // Scalar case: operate directly on Fr.
            let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();
            let mut work = scalars.clone();
            group_fft_in_place(&mut work, omega);
            group_ifft_in_place(&mut work, omega);
            assert_eq!(work, scalars, "scalar roundtrip mismatch at n={n}");

            // Group case: operate on random G1 points.
            let points: Vec<G1> = (0..n).map(|_| G1::rand(rng)).collect();
            let mut work = points.clone();
            group_fft_in_place(&mut work, omega);
            group_ifft_in_place(&mut work, omega);
            assert_eq!(work, points, "group roundtrip mismatch at n={n}");
        }
    }

    /// The group FFT commutes with scalar multiplication: FFT of (g·s_i) equals
    /// g·FFT(s_i).
    #[test]
    fn group_fft_agrees_with_scalar_fft_via_generator() {
        let rng = &mut test_rng();
        for &n in &[2usize, 4, 8, 16, 32] {
            let omega = primitive_root(n);
            let domain = Radix2EvaluationDomain::<Fr>::new(n).unwrap();
            let g = G1::generator();

            let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();

            // Reference: scalar FFT from ark_poly, then lift to G1.
            let scalar_fft = domain.fft(&scalars);
            let expected: Vec<G1> = scalar_fft.iter().map(|s| g * s).collect();

            // Under test: lift to G1 first, then group FFT.
            let mut points: Vec<G1> = scalars.iter().map(|s| g * s).collect();
            group_fft_in_place(&mut points, omega);

            assert_eq!(points, expected, "group FFT ≠ scalar FFT at n={n}");
        }
    }

    /// Naive O(n²) circulant matrix-vector product, as a correctness oracle.
    /// Computes `result[j] = Σ_k M_{jk}·a_k` where `M_{jk} = ω^{-j}·d_{j-k}`
    /// with `d[0] = 0`, `d[r] = 1/(1 − ω^{-r})` — i.e. `M_{jk} = 1/(ω^j − ω^k)`
    /// for `j ≠ k` and `M_{jj} = 0`.
    fn naive_circulant_mul(a: &[G1], omega: Fr) -> Vec<G1> {
        let n = a.len();
        let omega_inv = omega.inverse().unwrap();

        // Build d in cyclic index order: d[r] for r = 0, 1, ..., n-1.
        let d: Vec<Fr> = (0..n)
            .map(|r| {
                if r == 0 {
                    Fr::zero()
                } else {
                    (Fr::one() - omega_inv.pow([r as u64])).inverse().unwrap()
                }
            })
            .collect();

        (0..n)
            .map(|j| {
                let omega_neg_j = omega_inv.pow([j as u64]);
                let mut acc = G1::zero();
                for (k, a_k) in a.iter().enumerate() {
                    let r = (j + n - k) % n;
                    acc += *a_k * (omega_neg_j * d[r]);
                }
                acc
            })
            .collect()
    }

    /// `circulant_mul` matches the naive O(n²) computation.
    #[test]
    fn circulant_mul_matches_naive() {
        let rng = &mut test_rng();
        for &n in &[2usize, 4, 8, 16] {
            let omega = primitive_root(n);
            let domain = Radix2EvaluationDomain::<Fr>::new(n).unwrap();

            // Build d and its FFT exactly as `decrypt` does.
            let omega_inv = omega.inverse().unwrap();
            let d: Vec<Fr> = (0..n)
                .map(|r| {
                    if r == 0 {
                        Fr::zero()
                    } else {
                        (Fr::one() - omega_inv.pow([r as u64])).inverse().unwrap()
                    }
                })
                .collect();
            let d_hat = domain.fft(&d);

            let a: Vec<G1> = (0..n).map(|_| G1::rand(rng)).collect();

            let got = circulant_mul(&d_hat, &a, omega);
            let expected = naive_circulant_mul(&a, omega);

            assert_eq!(got, expected, "circulant_mul mismatch at n={n}");
        }
    }
}
