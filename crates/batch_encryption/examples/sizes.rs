//! Utility to print serialized sizes for the batch encryption scheme.

use ark_bls12_381::Bls12_381 as E;
use ark_ec::pairing::PairingOutput;
use ark_serialize::CanonicalSerialize;
use ark_std::{test_rng, UniformRand};

use batch_encryption::batch_enc::*;
use batch_encryption::nizk::Sha256Oracle;

fn compressed_size(obj: &impl CanonicalSerialize) -> usize {
    let mut buf = Vec::new();
    obj.serialize_compressed(&mut buf).unwrap();
    buf.len()
}

fn main() {
    let rng = &mut test_rng();

    println!("=== Serialized Sizes (BLS12-381, compressed) ===\n");

    for &ell in &[4, 16, 64, 128, 256, 512] {
        let out = setup::<E>(ell, rng);

        // CRS = ek + dk (public parameters)
        let ek_size = compressed_size(&out.ek);
        let dk_size = compressed_size(&out.dk);
        let crs_size = ek_size + dk_size;

        // Encrypt one message
        let m = PairingOutput::<E>::rand(rng);
        let ct = encrypt::<E, Sha256Oracle>(&out.ek, &m, rng);
        let ct_size = compressed_size(&ct);
        let proof_size = compressed_size(&ct.proof);
        let ct_no_proof = ct_size - proof_size;

        // Pre-decryption key
        let cts: Vec<_> = (0..ell)
            .map(|_| encrypt::<E, Sha256Oracle>(&out.ek, &PairingOutput::rand(rng), rng))
            .collect();
        let sbk = pre_decrypt::<E, Sha256Oracle>(&out.sk, &out.ek, &cts, rng).unwrap();
        let sbk_size = compressed_size(&sbk);

        println!("ell = {ell}:");
        println!("  CRS (ek + dk):        {crs_size} bytes  (ek: {ek_size}, dk: {dk_size})");
        println!("  Ciphertext (total):    {ct_size} bytes");
        println!("    NIZK proof:          {proof_size} bytes");
        println!("    ct without proof:    {ct_no_proof} bytes");
        println!("  Pre-decryption key:    {sbk_size} bytes");
        println!();
    }
}
