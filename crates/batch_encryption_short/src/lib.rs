//! # Modules
//!
//! - [`nizk_dlog`]: Construction 6 -- Schnorr-style SE-NIZK for the discrete
//!   logarithm relation. Used by BE_short (Construction 5) to prove that
//!   `ct[1] = [r]_1` is well-formed. Proof size `|G1| + |Fp|`.
//! - [`batch_enc_short`]: Construction 5 -- Batch Encryption with ciphertext
//!   size `|G1| + |G_T|`. Setup, Enc, PreDec, Dec.

pub mod batch_enc_short;
pub mod nizk_dlog;
