use ark_bls12_381::Bls12_381;
use ark_ec::pairing::PairingOutput;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use batch_encryption_short::batch_enc_short;
use batch_encryption_short::nizk_dlog::Sha512Oracle;
use wasm_bindgen::prelude::*;

type E = Bls12_381;
type Oracle = Sha512Oracle;

#[wasm_bindgen]
pub fn version() -> String {
    format!(
        "darkrai-wasm {} (BE_short, BLS12-381)",
        env!("CARGO_PKG_VERSION")
    )
}

/// Run the full benchmark cycle for batch size `ell` and return a JSON string
/// with all timings (ms) plus serialized sizes (bytes).
///
/// `ell` must be a power of two within the field's two-adicity.
#[wasm_bindgen]
pub fn bench_batch(ell: usize) -> Result<String, JsValue> {
    if !ell.is_power_of_two() {
        return Err(JsValue::from_str("ell must be a power of two"));
    }
    let mut rng = StdRng::from_entropy();

    // ---- Setup
    let t0 = now();
    let setup = batch_enc_short::setup::<E>(ell, &mut rng);
    let setup_ms = now() - t0;

    // ---- Generate ell random messages in GT
    let messages: Vec<PairingOutput<E>> =
        (0..ell).map(|_| PairingOutput::<E>::rand(&mut rng)).collect();

    // ---- Encrypt (ell messages, time per-message)
    let t0 = now();
    let cts: Vec<_> = messages
        .iter()
        .map(|m| batch_enc_short::encrypt::<E, Oracle>(&setup.ek, m, &mut rng))
        .collect();
    let encrypt_total_ms = now() - t0;
    let encrypt_per_ms = encrypt_total_ms / ell as f64;

    // ---- Pre-decrypt
    let t0 = now();
    let sbk = batch_enc_short::pre_decrypt::<E, Oracle>(&setup.sk, &cts, &mut rng)
        .ok_or_else(|| JsValue::from_str("pre_decrypt: NIZK batch verification rejected"))?;
    let pre_decrypt_ms = now() - t0;

    // ---- Decrypt
    let t0 = now();
    let recovered = batch_enc_short::decrypt::<E>(&setup.dk, &sbk, &cts);
    let decrypt_ms = now() - t0;

    // ---- Verify correctness
    if recovered.len() != messages.len() {
        return Err(JsValue::from_str("decrypt returned wrong message count"));
    }
    for (i, (m, r)) in messages.iter().zip(recovered.iter()).enumerate() {
        if m != r {
            return Err(JsValue::from_str(&format!(
                "decrypt mismatch at index {i}"
            )));
        }
    }

    // ---- Sizes
    let mut ct_buf = Vec::new();
    cts[0].serialize_compressed(&mut ct_buf).unwrap();
    let ct_bytes = ct_buf.len();

    let mut sbk_buf = Vec::new();
    sbk.serialize_compressed(&mut sbk_buf).unwrap();
    let sbk_bytes = sbk_buf.len();

    let mut dk_buf = Vec::new();
    setup.dk.serialize_compressed(&mut dk_buf).unwrap();
    let dk_bytes = dk_buf.len();

    let mut ek_buf = Vec::new();
    setup.ek.serialize_compressed(&mut ek_buf).unwrap();
    let ek_bytes = ek_buf.len();

    Ok(format!(
        r#"{{"ell":{ell},"setup_ms":{setup_ms:.3},"encrypt_total_ms":{encrypt_total_ms:.3},"encrypt_per_ms":{encrypt_per_ms:.3},"pre_decrypt_ms":{pre_decrypt_ms:.3},"decrypt_ms":{decrypt_ms:.3},"ct_bytes":{ct_bytes},"sbk_bytes":{sbk_bytes},"dk_bytes":{dk_bytes},"ek_bytes":{ek_bytes}}}"#
    ))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance, js_name = now)]
    fn perf_now() -> f64;
}

fn now() -> f64 {
    perf_now()
}
