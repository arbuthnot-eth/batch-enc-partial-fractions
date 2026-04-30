use ark_bls12_381::Bls12_381;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use batch_encryption_short::batch_enc_short;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn version() -> String {
    format!("darkrai-wasm {} (BE_short, BLS12-381)", env!("CARGO_PKG_VERSION"))
}

/// Run Setup with batch size `ell` and return wall time in milliseconds.
/// Smoke test for Move 2 — confirms upstream links cleanly under wasm32.
#[wasm_bindgen]
pub fn smoke_setup(ell: usize) -> Result<f64, JsValue> {
    if !ell.is_power_of_two() {
        return Err(JsValue::from_str("ell must be a power of two"));
    }
    let mut rng = StdRng::from_entropy();
    let start = now_ms();
    let _setup = batch_enc_short::setup::<Bls12_381>(ell, &mut rng);
    Ok(now_ms() - start)
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance)]
    fn now() -> f64;
}

fn now_ms() -> f64 {
    now()
}
