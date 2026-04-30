//! Darkrai WASM — browser bindings for batch threshold encryption.
//!
//! Architecture: Seal stays the trust layer (committee holds Storm `sk`).
//! Darkrai is the efficiency layer (one batch decrypt per epoch).
//!
//! Byte-level API surface for JS:
//!   setup(ell)                       → SetupBundle { ek, sk, dk }
//!   encrypt(ek_bytes, pad_bytes)     → ct_bytes (704 B per CT)
//!   pre_decrypt(sk, cts_concat, ell) → sbk_bytes (48 B)
//!   decrypt(dk, sbk, cts_concat, ell)→ pads_concat (576 B × ell)
//!
//! All structures are arkworks-canonical-serialized (compressed). Sizes are
//! fixed for BLS12-381 except `dk` which scales with `ell`.

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::PairingOutput;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use batch_encryption_short::batch_enc_short;
use batch_encryption_short::nizk_dlog::Sha512Oracle;
use wasm_bindgen::prelude::*;

type E = Bls12_381;
type Oracle = Sha512Oracle;

const CT_BYTES: usize = 704;
const SBK_BYTES: usize = 48;
const PAD_BYTES: usize = 576; // GT element compressed
const EK_BYTES: usize = 576;
const SK_BYTES: usize = 32;

#[wasm_bindgen]
pub fn version() -> String {
    format!(
        "darkrai-wasm {} (BE_short, BLS12-381)",
        env!("CARGO_PKG_VERSION")
    )
}

// ─── Setup ────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct SetupBundle {
    ek: Vec<u8>,
    sk: Vec<u8>,
    dk: Vec<u8>,
    ell: usize,
}

#[wasm_bindgen]
impl SetupBundle {
    #[wasm_bindgen(getter)]
    pub fn ek(&self) -> Vec<u8> {
        self.ek.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn sk(&self) -> Vec<u8> {
        self.sk.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn dk(&self) -> Vec<u8> {
        self.dk.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn ell(&self) -> usize {
        self.ell
    }
}

fn ser<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut buf = Vec::with_capacity(t.compressed_size());
    t.serialize_compressed(&mut buf).unwrap();
    buf
}

fn de<T: CanonicalDeserialize>(bytes: &[u8], what: &str) -> Result<T, JsValue> {
    T::deserialize_compressed(bytes)
        .map_err(|e| JsValue::from_str(&format!("deserialize {what}: {e}")))
}

#[wasm_bindgen]
pub fn setup(ell: usize) -> Result<SetupBundle, JsValue> {
    if !ell.is_power_of_two() {
        return Err(JsValue::from_str("ell must be a power of two"));
    }
    let mut rng = StdRng::from_entropy();
    let s = batch_enc_short::setup::<E>(ell, &mut rng);
    Ok(SetupBundle {
        ek: ser(&s.ek),
        sk: ser(&s.sk),
        dk: ser(&s.dk),
        ell,
    })
}

// ─── Encrypt one slot ─────────────────────────────────────────────────

/// Generate a fresh GT pad (576 B) — caller hashes this to derive an AES key.
#[wasm_bindgen]
pub fn random_pad() -> Vec<u8> {
    let mut rng = StdRng::from_entropy();
    ser(&PairingOutput::<E>::rand(&mut rng))
}

#[wasm_bindgen]
pub fn encrypt(ek_bytes: &[u8], pad_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    if ek_bytes.len() != EK_BYTES {
        return Err(JsValue::from_str(&format!(
            "ek must be {EK_BYTES} bytes, got {}",
            ek_bytes.len()
        )));
    }
    if pad_bytes.len() != PAD_BYTES {
        return Err(JsValue::from_str(&format!(
            "pad must be {PAD_BYTES} bytes (GT element), got {}",
            pad_bytes.len()
        )));
    }
    let ek: batch_enc_short::EncryptionKey<E> = de(ek_bytes, "ek")?;
    let pad: PairingOutput<E> = de(pad_bytes, "pad")?;
    let mut rng = StdRng::from_entropy();
    let ct = batch_enc_short::encrypt::<E, Oracle>(&ek, &pad, &mut rng);
    Ok(ser(&ct))
}

// ─── Pre-decrypt + Decrypt over batches ───────────────────────────────

fn split_cts(cts_concat: &[u8], ell: usize) -> Result<Vec<batch_enc_short::Ciphertext<E>>, JsValue> {
    let expected = ell * CT_BYTES;
    if cts_concat.len() != expected {
        return Err(JsValue::from_str(&format!(
            "cts_concat length must be ell * {CT_BYTES} = {expected}, got {}",
            cts_concat.len()
        )));
    }
    let mut out = Vec::with_capacity(ell);
    for i in 0..ell {
        let slice = &cts_concat[i * CT_BYTES..(i + 1) * CT_BYTES];
        out.push(de(slice, "ciphertext")?);
    }
    Ok(out)
}

#[wasm_bindgen]
pub fn pre_decrypt(sk_bytes: &[u8], cts_concat: &[u8], ell: usize) -> Result<Vec<u8>, JsValue> {
    if sk_bytes.len() != SK_BYTES {
        return Err(JsValue::from_str(&format!(
            "sk must be {SK_BYTES} bytes, got {}",
            sk_bytes.len()
        )));
    }
    if !ell.is_power_of_two() {
        return Err(JsValue::from_str("ell must be a power of two"));
    }
    let sk: batch_enc_short::SecretKey<E> = de(sk_bytes, "sk")?;
    let cts = split_cts(cts_concat, ell)?;
    let mut rng = StdRng::from_entropy();
    let sbk = batch_enc_short::pre_decrypt::<E, Oracle>(&sk, &cts, &mut rng)
        .ok_or_else(|| JsValue::from_str("pre_decrypt: NIZK batch verification rejected"))?;
    Ok(ser(&sbk))
}

#[wasm_bindgen]
pub fn decrypt(
    dk_bytes: &[u8],
    sbk_bytes: &[u8],
    cts_concat: &[u8],
    ell: usize,
) -> Result<Vec<u8>, JsValue> {
    if sbk_bytes.len() != SBK_BYTES {
        return Err(JsValue::from_str(&format!(
            "sbk must be {SBK_BYTES} bytes, got {}",
            sbk_bytes.len()
        )));
    }
    let dk: batch_enc_short::DecryptionKey<E> = de(dk_bytes, "dk")?;
    let sbk: batch_enc_short::PreDecryptionKey<E> = de(sbk_bytes, "sbk")?;
    let cts = split_cts(cts_concat, ell)?;
    let pads = batch_enc_short::decrypt::<E>(&dk, &sbk, &cts);

    let mut out = Vec::with_capacity(ell * PAD_BYTES);
    for p in &pads {
        let mut buf = Vec::with_capacity(PAD_BYTES);
        p.serialize_compressed(&mut buf).unwrap();
        if buf.len() != PAD_BYTES {
            return Err(JsValue::from_str("internal: pad length drift"));
        }
        out.extend_from_slice(&buf);
    }
    Ok(out)
}

// ─── Legacy bench function (kept for the smoke test) ──────────────────

#[wasm_bindgen]
pub fn bench_batch(ell: usize) -> Result<String, JsValue> {
    if !ell.is_power_of_two() {
        return Err(JsValue::from_str("ell must be a power of two"));
    }
    let mut rng = StdRng::from_entropy();

    let t0 = perf_now();
    let s = batch_enc_short::setup::<E>(ell, &mut rng);
    let setup_ms = perf_now() - t0;

    let messages: Vec<PairingOutput<E>> =
        (0..ell).map(|_| PairingOutput::<E>::rand(&mut rng)).collect();

    let t0 = perf_now();
    let cts: Vec<_> = messages
        .iter()
        .map(|m| batch_enc_short::encrypt::<E, Oracle>(&s.ek, m, &mut rng))
        .collect();
    let encrypt_total_ms = perf_now() - t0;

    let t0 = perf_now();
    let sbk = batch_enc_short::pre_decrypt::<E, Oracle>(&s.sk, &cts, &mut rng)
        .ok_or_else(|| JsValue::from_str("pre_decrypt rejected"))?;
    let pre_decrypt_ms = perf_now() - t0;

    let t0 = perf_now();
    let _recovered = batch_enc_short::decrypt::<E>(&s.dk, &sbk, &cts);
    let decrypt_ms = perf_now() - t0;

    Ok(format!(
        r#"{{"ell":{ell},"setup_ms":{setup_ms:.3},"encrypt_total_ms":{encrypt_total_ms:.3},"encrypt_per_ms":{:.3},"pre_decrypt_ms":{pre_decrypt_ms:.3},"decrypt_ms":{decrypt_ms:.3},"ct_bytes":{CT_BYTES},"sbk_bytes":{SBK_BYTES},"dk_bytes":{},"ek_bytes":{EK_BYTES}}}"#,
        encrypt_total_ms / ell as f64,
        ser(&s.dk).len()
    ))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance, js_name = now)]
    fn perf_now_js() -> f64;
}

fn perf_now() -> f64 {
    perf_now_js()
}
