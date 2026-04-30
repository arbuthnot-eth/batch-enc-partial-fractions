# Thunder × Batch Threshold Encryption — design

> **Goal:** improved sui-stack-messaging that handles attachments seamlessly.
>
> **Mechanism:** group all messages in a Storm epoch (text + media references)
> into one batch-threshold-encrypted bundle. Recipient opens the whole epoch
> with one tiny `sbk` reveal.

## Why this beats per-message Seal (sui-stack-messaging-sdk today)

| | Per-message Seal | Batch threshold (Darkrai) |
|---|---|---|
| Recipient catch-up cost (8 unread) | ~400 ms (8× decrypt) | ~62 ms (1 pre-decrypt + 1 batch decrypt) |
| Per-message overhead | one Seal envelope + one DEK | 704 B CT + variable AEAD payload |
| Atomic reveal across messages | ❌ | ✅ — entire epoch unlocks together |
| Media handling | per-blob Seal envelope | one blob_key per AEAD payload, recipient parallel-fetches |
| sbk size for whole epoch | n/a | 48 B |

## Layering

```
                              ┌────────────────────────────────┐
on Sui (StormEpoch object)    │ ek (576 B, set once)          │
                              │ cts: [704 B × ℓ]              │
                              │ payloads: [AEAD bytes × ℓ]    │
                              │ sbk: Option<48 B>             │
                              │ walrus_blob_ids: [ID]         │
                              └────────────────────────────────┘
                                          │
                       sbk publication ───┴──→ atomic epoch reveal
                                          │
                              ┌────────────────────────────────┐
recipient device              │ pre_decrypt(sk, cts) ─→ sbk    │
                              │ decrypt(dk, sbk, cts) ─→ pads  │
                              │ for each pad:                  │
                              │   AES-256-GCM(pad → key, ad)   │
                              │     → Thunder { sender, ts,    │
                              │                 body }         │
                              │ if Attachment: parallel-fetch  │
                              │   walrus_blob_id, decrypt with │
                              │   blob_key from AEAD payload   │
                              └────────────────────────────────┘
```

The batch-CT carries a fresh GT pad per slot. The pad is hashed (SHA-256) into
an AES-256-GCM key. The actual `Thunder { sender, ts_ms, body }` is bincode-
serialized and AEAD-encrypted under that key. So the on-chain CT is fixed-size
(704 B), and the variable-size message metadata + attachment_ref lives in the
AEAD payload alongside it.

For attachments, the AEAD payload contains `{ blob_id, blob_key, blob_nonce,
mime, size }`. The blob itself is in Walrus, AES-GCM'd under `blob_key`. After
the recipient pre-decrypts the epoch, they get every `blob_key` in one shot
and parallel-fetch all media.

## Move-side shape (sketch)

```move
module passki::storm {
    use sui::object::{UID, ID};
    use sui::transfer;

    public struct Storm has key {
        id: UID,
        participants: vector<address>,    // SuiNS-resolved addresses
        ek_compressed: vector<u8>,         // 576 B, set once at storm-open
        current_epoch: u64,
    }

    public struct StormEpoch has key {
        id: UID,
        storm: ID,
        epoch_no: u64,
        cts: vector<vector<u8>>,           // ℓ × 704 B
        payloads: vector<vector<u8>>,      // AEAD ciphertexts
        walrus_blob_ids: vector<vector<u8>>,
        sbk: vector<u8>,                   // empty until sealed
        sealed_at_ms: u64,                 // 0 until sealed
    }

    public fun open_storm(
        participants: vector<address>,
        ek_compressed: vector<u8>,
        ctx: &mut TxContext,
    ): Storm { /* ... */ }

    public fun post_thunder(
        storm: &mut Storm,
        epoch: &mut StormEpoch,
        ct: vector<u8>,
        payload: vector<u8>,
        walrus_blob_id: vector<u8>,
    ) { /* ... ensure not sealed, append ... */ }

    public fun seal_epoch(
        epoch: &mut StormEpoch,
        sbk: vector<u8>,
        clock: &Clock,
    ) { /* ... ensure not already sealed, set sbk + ts ... */ }

    public fun rotate_epoch(
        storm: &mut Storm,
        prev: &StormEpoch,            // must be sealed
        ctx: &mut TxContext,
    ): StormEpoch { /* ... bump epoch_no ... */ }
}
```

Move never decrypts (no native pairings). It only stores and gates publication.

## Open questions for SKI integration

1. **Who holds `sk`?** Per the user redirect (2026-04-30): single-keeper is
   fine for Thunder. The recipient is their own keeper. `sk` lives in the
   recipient's IKA dWallet user-share, encrypted to the user's WaaP login.
   No DKG required for v1.
2. **Epoch size ℓ.** Power of two; needs to be set at Setup. Tradeoff:
   small ℓ = faster to seal (less waiting) but more setups; large ℓ = bigger
   `dk`, longer wait to fill, more privacy padding. Start with **ℓ = 16**
   (one-time setup ~80 ms, decrypt ~480 ms in browser wasm).
3. **Time vs count rotation.** Seal an epoch when full (ℓ messages) OR after
   24h, whichever first. Empty-slot padding for time-based rotation.
4. **Forward secrecy across epochs.** Each Storm has one long-lived ek.
   Compromising `sk` exposes ALL past + future epochs. Mitigation: rotate
   `(ek, sk, dk)` per epoch (extra setup cost ~12 ms native, ~80 ms wasm
   for ℓ=16).
5. **Multi-recipient.** Group Storms: each participant's IKA dWallet derives
   a shared `(ek, sk, dk)` via 2PC-MPC. Same primitive, different keygen.

## Numbers (this sim, native release on Linux)

| Phase | Time |
|---|---|
| Storm setup (ℓ=8) | 11.5 ms |
| Sender batch encrypt (8 msgs) | 7.7 ms |
| Sender AEAD wrap all | 0.02 ms |
| Recipient pre-decrypt | 2.2 ms |
| Recipient batch decrypt | 60 ms (~7.5 ms/msg) |
| Recipient AEAD unwrap all | 0.02 ms |
| **Total recipient cost (Storm-open)** | **~62 ms** |

Browser wasm scaling factor (~6×) → ~370 ms recipient cost in-browser. Fine.

## Move 7 candidates

- **Bad Dreams:** wire `passki/darkrai-wasm` into the actual Thunder client
  (load the wasm module on storm-open, decrypt the epoch, AEAD-unwrap, render).
- **Nightmare Realm:** Move package for `Storm` + `StormEpoch` types,
  scribe to mainnet, hook into existing Aggron quilting.
- **Hypnosis Field:** epoch-rotation strategy + multi-recipient keygen.
