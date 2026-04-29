//! Helpers for the roots-of-unity + partial-fraction index convention shared
//! by both batch encryption schemes.
//!
//! The partial-fraction convention is `p_i(X) := 1/(X + i), and batch indices are the n-th roots of unity in Fp.

use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

/// Return the primitive n-th root of unity in `F`.
///
/// Requires `n` to be a power of two not exceeding `2^TWO_ADICITY`.
pub fn get_omega<F: FftField>(n: usize) -> F {
    Radix2EvaluationDomain::<F>::new(n)
        .expect("n must be a power of two within the field's two-adicity")
        .group_gen()
}

/// Return a field element γ ∉ H ∪ {0} for use as the second extra index.
///
/// Tries `2, 3, …` until finding a candidate whose n-th power ≠ 1. For all
/// cryptographic scalar fields and practical batch sizes, γ = 2.
pub fn get_extra_index<F: FftField>(n: usize) -> F {
    for candidate in 2u64.. {
        let f = F::from(candidate);
        if f.pow([n as u64]) != F::one() {
            return f;
        }
    }
    unreachable!("could not find extra index (field too small)")
}

/// Compute the partial fraction `1/(x + index)` as a field element.
///
/// Panics if `x + index = 0`
pub fn partial_fraction_at<F: PrimeField>(x: &F, index: &F) -> F {
    (*x + index).inverse().expect("x + index must be nonzero")
}
