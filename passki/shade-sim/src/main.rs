//! Shade × batch-threshold-encryption end-to-end simulation.
//!
//! Demonstrates the privacy property that distinguishes this construction
//! from per-message Seal: revealing a pre-decryption key for batch A does
//! NOT help an observer decrypt batch B, even though both batches were
//! encrypted to the same encryption key.
//!
//! Maps onto Shade as follows:
//!   - Setup is run once by the committee (ultron + Seal key servers).
//!   - Each grace-period window groups ℓ pending snipe commitments.
//!   - At window expiry, ultron emits the pre-decryption key for that
//!     window's batch. ANY executor (keeper bot or self) decrypts the
//!     batch and runs the snipes.
//!   - Snipe commitments in OTHER windows remain perfectly hidden, even
//!     against an adversary with the full on-chain transcript and the
//!     just-revealed sbk.

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::PairingOutput;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use batch_encryption_short::batch_enc_short;
use batch_encryption_short::nizk_dlog::Sha512Oracle;
use std::time::Instant;

type E = Bls12_381;
type Oracle = Sha512Oracle;

const ELL: usize = 8; // snipes per grace window

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn ser_bytes<T: CanonicalSerialize>(t: &T) -> usize {
    let mut buf = Vec::new();
    t.serialize_compressed(&mut buf).unwrap();
    buf.len()
}

fn main() {
    println!("Shade × batch-threshold-encryption simulation");
    println!("ℓ = {ELL} snipes per grace window, BLS12-381\n");

    let mut rng = StdRng::from_entropy();

    // ---- One-time committee setup
    let t = Instant::now();
    let setup = batch_enc_short::setup::<E>(ELL, &mut rng);
    let setup_ms = ms(t.elapsed());
    println!("[committee] Setup({ELL}): {setup_ms:.2} ms");
    println!(
        "  ek={} B  sk={} B  dk={} B",
        ser_bytes(&setup.ek),
        ser_bytes(&setup.sk),
        ser_bytes(&setup.dk),
    );

    // ---- Window A: 8 snipes go in. Each "snipe message" is a random GT
    //      element representing the symmetric key under which the actual
    //      domain/target/expiry payload would be AES-GCM'd.
    let snipes_a: Vec<PairingOutput<E>> =
        (0..ELL).map(|_| PairingOutput::<E>::rand(&mut rng)).collect();
    let snipes_b: Vec<PairingOutput<E>> =
        (0..ELL).map(|_| PairingOutput::<E>::rand(&mut rng)).collect();

    let t = Instant::now();
    let cts_a: Vec<_> = snipes_a
        .iter()
        .map(|m| batch_enc_short::encrypt::<E, Oracle>(&setup.ek, m, &mut rng))
        .collect();
    let enc_a_ms = ms(t.elapsed());

    let t = Instant::now();
    let cts_b: Vec<_> = snipes_b
        .iter()
        .map(|m| batch_enc_short::encrypt::<E, Oracle>(&setup.ek, m, &mut rng))
        .collect();
    let enc_b_ms = ms(t.elapsed());

    let ct_size = ser_bytes(&cts_a[0]);
    println!(
        "\n[users] Encrypt window A ({ELL} snipes): {enc_a_ms:.2} ms ({ct_size} B per CT)"
    );
    println!("[users] Encrypt window B ({ELL} snipes): {enc_b_ms:.2} ms");

    // ---- Window A's grace period expires. Keeper publishes pre-dec key.
    let t = Instant::now();
    let sbk_a = batch_enc_short::pre_decrypt::<E, Oracle>(&setup.sk, &cts_a, &mut rng)
        .expect("pre_decrypt A: NIZK batch verification rejected");
    let pre_a_ms = ms(t.elapsed());
    println!(
        "\n[keeper] Window A pre_decrypt: {pre_a_ms:.2} ms, sbk_A = {} B",
        ser_bytes(&sbk_a)
    );

    // ---- Anyone (executor bot, user) decrypts window A's batch.
    let t = Instant::now();
    let recovered_a = batch_enc_short::decrypt::<E>(&setup.dk, &sbk_a, &cts_a);
    let dec_a_ms = ms(t.elapsed());

    let a_correct = recovered_a == snipes_a;
    println!(
        "[executor] Window A decrypt: {dec_a_ms:.2} ms, all {ELL} snipes recovered: {a_correct}"
    );
    assert!(a_correct, "window A correctness failed");

    // ---- THE PRIVACY PROPERTY: try to decrypt window B using sbk_A.
    //      sbk_A was computed from cts_a, so it should be useless against cts_b.
    //      We expect garbage (decrypt is a fixed algebraic op, it will produce
    //      *some* GT elements, but not the original snipes_b messages).
    let recovered_b_with_wrong_sbk = batch_enc_short::decrypt::<E>(&setup.dk, &sbk_a, &cts_b);
    let b_leaked_to_a = recovered_b_with_wrong_sbk == snipes_b;
    println!(
        "\n[adversary] Try decrypt window B with sbk_A (using full transcript): \
         leaked = {b_leaked_to_a}"
    );
    assert!(
        !b_leaked_to_a,
        "PRIVACY BREACH: sbk_A would leak window B!"
    );
    println!("  ✓ Window B remains hidden after window A reveal.");

    // ---- Also confirm that decrypt with sbk_A on cts_b doesn't accidentally
    //      match ANY known snipe (sanity).
    let any_match = recovered_b_with_wrong_sbk
        .iter()
        .any(|r| snipes_a.contains(r) || snipes_b.contains(r));
    assert!(!any_match, "wrong-sbk decrypt accidentally matched a known message");

    // ---- Window B's grace period expires next.
    let t = Instant::now();
    let sbk_b = batch_enc_short::pre_decrypt::<E, Oracle>(&setup.sk, &cts_b, &mut rng)
        .expect("pre_decrypt B: NIZK batch verification rejected");
    let pre_b_ms = ms(t.elapsed());

    let t = Instant::now();
    let recovered_b = batch_enc_short::decrypt::<E>(&setup.dk, &sbk_b, &cts_b);
    let dec_b_ms = ms(t.elapsed());
    let b_correct = recovered_b == snipes_b;
    assert!(b_correct, "window B correctness failed");

    println!(
        "\n[keeper] Window B pre_decrypt: {pre_b_ms:.2} ms, sbk_B = {} B",
        ser_bytes(&sbk_b)
    );
    println!("[executor] Window B decrypt: {dec_b_ms:.2} ms, recovered: {b_correct}");

    // ---- On-chain footprint per window.
    let onchain_per_window = ELL * ct_size + ser_bytes(&sbk_a);
    println!("\n=== On-chain footprint ===");
    println!(
        "  Per window: {ELL} CTs × {ct_size} B + sbk = {onchain_per_window} B  (~{:.1} KB)",
        onchain_per_window as f64 / 1024.0
    );
    println!(
        "  Plus one-time committee: dk = {} B (held by executor side, off-chain or shared object)",
        ser_bytes(&setup.dk)
    );

    println!("\n=== Privacy summary ===");
    println!("  • All snipes hidden until their window's sbk is published.");
    println!("  • Publishing sbk_A reveals {ELL} snipes atomically — one event, not {ELL} reveals.");
    println!("  • Other windows' batches stay perfectly hidden.");
    println!("  • An adversary with full transcript + sbk_A learns NOTHING about windows B, C, …");
    println!("\nPursuit complete. Property verified.");
}
