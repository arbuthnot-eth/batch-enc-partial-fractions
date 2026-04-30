//! Thunder × batch-threshold sim — improved sui-stack-messaging.
//!
//! Models a Storm (conversation) with mixed text + attachment messages.
//! All messages in one epoch are encrypted as a single batch under the
//! Storm's encryption key. Recipient pre-decrypts at storm-open and gets
//! every message + media key in one operation.
//!
//! Layering:
//!
//!   batch CT (704 B, BE_short)  encrypts a fresh GT pad per slot
//!         │
//!         └─→ HKDF/SHA-256 → 256-bit AES key
//!                                 │
//!                                 └─→ AES-256-GCM(payload_bytes)
//!                                       payload = bincode({
//!                                          sender, ts, body | attachment_ref })
//!
//! Attachment refs point to a Walrus blob. The blob itself is independently
//! AES-GCM encrypted with a per-blob key carried *inside* the AEAD payload —
//! so the batch-CT reveals the message metadata + the blob key, and the
//! recipient fetches+decrypts the blob in a separate step (parallelizable).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::PairingOutput;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::RngCore;
use batch_encryption_short::batch_enc_short;
use batch_encryption_short::nizk_dlog::Sha512Oracle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

type E = Bls12_381;
type Oracle = Sha512Oracle;

const ELL: usize = 8; // messages per Storm epoch

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct AttachmentRef {
    blob_id: [u8; 32],     // Walrus blob id
    blob_key: [u8; 32],    // AES-256-GCM key for the blob
    blob_nonce: [u8; 12],
    mime: String,
    size: usize,           // bytes
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
enum Body {
    Text(String),
    Attachment(AttachmentRef),
    TextWithAttachment(String, AttachmentRef),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct Thunder {
    sender: [u8; 32],
    ts_ms: u64,
    body: Body,
}

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn ser_bytes<T: CanonicalSerialize>(t: &T) -> usize {
    let mut buf = Vec::new();
    t.serialize_compressed(&mut buf).unwrap();
    buf.len()
}

/// Derive a 256-bit AES key from a GT element by hashing its compressed bytes.
fn gt_to_aes_key(gt: &PairingOutput<E>) -> [u8; 32] {
    let mut buf = Vec::new();
    gt.serialize_compressed(&mut buf).unwrap();
    let h = Sha256::digest(&buf);
    let mut k = [0u8; 32];
    k.copy_from_slice(&h);
    k
}

fn fixed_nonce(slot: usize) -> [u8; 12] {
    // The GT pad is fresh per slot, so a deterministic nonce is fine here:
    // (key, nonce) is unique because key is unique. In production we'd still
    // randomize for defense-in-depth.
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&(slot as u64).to_le_bytes());
    n
}

fn encrypt_payload(key: &[u8; 32], slot: usize, msg: &Thunder) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = fixed_nonce(slot);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plain = bincode::serialize(msg).unwrap();
    cipher.encrypt(nonce, plain.as_ref()).unwrap()
}

fn decrypt_payload(key: &[u8; 32], slot: usize, ct: &[u8]) -> Thunder {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = fixed_nonce(slot);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plain = cipher.decrypt(nonce, ct).expect("AEAD decrypt failed");
    bincode::deserialize(&plain).unwrap()
}

fn mock_message(slot: usize, rng: &mut StdRng) -> Thunder {
    let mut sender = [0u8; 32];
    rng.fill_bytes(&mut sender);
    let ts_ms = 1_730_000_000_000 + slot as u64 * 60_000;

    let body = match slot % 4 {
        0 => Body::Text(format!("hey, slot {slot} text-only message ⚡")),
        1 => {
            let mut blob_id = [0u8; 32];
            let mut blob_key = [0u8; 32];
            let mut blob_nonce = [0u8; 12];
            rng.fill_bytes(&mut blob_id);
            rng.fill_bytes(&mut blob_key);
            rng.fill_bytes(&mut blob_nonce);
            Body::Attachment(AttachmentRef {
                blob_id,
                blob_key,
                blob_nonce,
                mime: "image/jpeg".into(),
                size: 245_000, // ~240 KB photo
            })
        }
        2 => Body::Text(format!("slot {slot}: just a longer thought-stream message that takes up some real bytes so we're not benching tiny payloads only")),
        _ => {
            let mut blob_id = [0u8; 32];
            let mut blob_key = [0u8; 32];
            let mut blob_nonce = [0u8; 12];
            rng.fill_bytes(&mut blob_id);
            rng.fill_bytes(&mut blob_key);
            rng.fill_bytes(&mut blob_nonce);
            Body::TextWithAttachment(
                format!("check this out — slot {slot}"),
                AttachmentRef {
                    blob_id,
                    blob_key,
                    blob_nonce,
                    mime: "video/mp4".into(),
                    size: 4_800_000, // ~4.6 MB clip
                },
            )
        }
    };

    Thunder { sender, ts_ms, body }
}

fn main() {
    println!("Thunder × batch-threshold-encryption sim");
    println!("  Storm epoch = {ELL} messages, mixed text + media\n");

    let mut rng = StdRng::from_entropy();

    // ---- Storm setup. Recipient is their own keeper.
    let t = Instant::now();
    let setup = batch_enc_short::setup::<E>(ELL, &mut rng);
    println!(
        "[storm-open] Setup: {:.2} ms  (ek={} B, sk={} B, dk={} B)",
        ms(t.elapsed()),
        ser_bytes(&setup.ek),
        ser_bytes(&setup.sk),
        ser_bytes(&setup.dk),
    );

    // ---- Senders compose ELL messages.
    let messages: Vec<Thunder> = (0..ELL).map(|i| mock_message(i, &mut rng)).collect();

    // ---- For each message: random GT pad, AES-GCM the bincode payload, batch-encrypt the pad.
    let pads: Vec<PairingOutput<E>> =
        (0..ELL).map(|_| PairingOutput::<E>::rand(&mut rng)).collect();

    let t = Instant::now();
    let payload_aeads: Vec<Vec<u8>> = pads
        .iter()
        .zip(messages.iter())
        .enumerate()
        .map(|(i, (pad, m))| encrypt_payload(&gt_to_aes_key(pad), i, m))
        .collect();
    let aead_ms = ms(t.elapsed());

    let t = Instant::now();
    let cts: Vec<_> = pads
        .iter()
        .map(|m| batch_enc_short::encrypt::<E, Oracle>(&setup.ek, m, &mut rng))
        .collect();
    let batch_enc_ms = ms(t.elapsed());

    let total_aead_bytes: usize = payload_aeads.iter().map(|v| v.len()).sum();
    let ct_size = ser_bytes(&cts[0]);
    println!(
        "\n[senders] AEAD payloads: {aead_ms:.2} ms total ({} B avg per msg)",
        total_aead_bytes / ELL
    );
    println!(
        "[senders] Batch encrypt {ELL} pads: {batch_enc_ms:.2} ms ({ct_size} B per CT)"
    );

    // ---- Storm closes (epoch boundary). Recipient pre-decrypts.
    let t = Instant::now();
    let sbk = batch_enc_short::pre_decrypt::<E, Oracle>(&setup.sk, &cts, &mut rng)
        .expect("pre_decrypt failed");
    let pre_ms = ms(t.elapsed());
    println!(
        "\n[recipient] Pre-decrypt: {pre_ms:.2} ms, sbk = {} B (the magic 48 bytes)",
        ser_bytes(&sbk)
    );

    // ---- Recipient decrypts the whole batch + AEAD-unwraps payloads.
    let t = Instant::now();
    let recovered_pads = batch_enc_short::decrypt::<E>(&setup.dk, &sbk, &cts);
    let dec_ms = ms(t.elapsed());

    let t = Instant::now();
    let recovered_msgs: Vec<Thunder> = recovered_pads
        .iter()
        .zip(payload_aeads.iter())
        .enumerate()
        .map(|(i, (pad, ae))| decrypt_payload(&gt_to_aes_key(pad), i, ae))
        .collect();
    let unwrap_ms = ms(t.elapsed());

    let all_ok = recovered_msgs == messages;
    println!(
        "[recipient] Batch decrypt: {dec_ms:.2} ms ({:.2} ms/msg)",
        dec_ms / ELL as f64
    );
    println!(
        "[recipient] AEAD unwrap all {ELL}: {unwrap_ms:.2} ms — match originals: {all_ok}"
    );
    assert!(all_ok, "round-trip mismatch");

    // ---- Footprint accounting
    let onchain_per_msg = ct_size + payload_aeads.iter().map(|v| v.len()).sum::<usize>() / ELL;
    let onchain_epoch = ELL * ct_size + total_aead_bytes + ser_bytes(&sbk);
    let media_bytes_to_walrus: usize = messages
        .iter()
        .map(|m| match &m.body {
            Body::Attachment(a) | Body::TextWithAttachment(_, a) => a.size,
            _ => 0,
        })
        .sum();

    println!("\n=== Storm epoch footprint ===");
    println!(
        "  Sui shared object: {ELL} CTs ({ELL}×{ct_size} = {} B) + AEAD payloads ({total_aead_bytes} B) + sbk ({} B)",
        ELL * ct_size,
        ser_bytes(&sbk)
    );
    println!(
        "                    = {onchain_epoch} B  (~{:.1} KB per epoch)",
        onchain_epoch as f64 / 1024.0
    );
    println!(
        "  Walrus blobs:     {media_bytes_to_walrus} B media for the 4 attachments  (~{:.1} MB)",
        media_bytes_to_walrus as f64 / 1_048_576.0
    );
    println!(
        "  Per-message avg:  {onchain_per_msg} B on Sui (excluding media on Walrus)"
    );

    // ---- Why this beats per-message Seal
    println!("\n=== vs naive per-message Seal ===");
    println!(
        "  Per-message Seal: each msg has its own envelope + on-chain reveal event"
    );
    println!(
        "  Batch threshold:  one sbk reveal unlocks the entire epoch atomically"
    );
    println!(
        "  Recipient cost:   1 pre_decrypt + 1 batch decrypt vs {ELL} independent Seal decrypts"
    );
    println!(
        "  Privacy:          batch boundaries are public; WHICH message is which slot is hidden"
    );
    println!(
        "  Media:            each AEAD payload carries its own blob_key — recipient parallel-fetches all media after one batch reveal"
    );

    println!("\nMetal Claw verified.");
}
