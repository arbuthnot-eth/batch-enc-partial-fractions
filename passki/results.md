# Darkrai — browser WASM bench results

Construction 5 (BE_short) from [ePrint 2026/674](https://eprint.iacr.org/2026/674),
compiled to `wasm32-unknown-unknown` via `wasm-pack`, run from a single tab in
Chrome Headless 148. BLS12-381, single-threaded, no SIMD shims.

Hardware: Linux 6.17 / Brandon's box (matches user-confirmed run on their
machine to within ~5% — see [issue comment](https://github.com/arbuthnot-eth/passki/issues/200)).

## Timings

| ℓ   | Setup     | Encrypt total | Encrypt /msg | Pre-decrypt | Decrypt    |
|----:|----------:|--------------:|-------------:|------------:|-----------:|
| 4   | 25.7 ms   | 13.3 ms       | 3.33 ms      | 7.1 ms      | 99.2 ms    |
| 16  | 78.5 ms   | 52.7 ms       | 3.29 ms      | 19.2 ms     | 480.1 ms   |
| 64  | 290.4 ms  | 216.5 ms      | 3.38 ms      | 64.8 ms     | 2,303.9 ms |
| 128 | 574.5 ms  | 426.1 ms      | 3.33 ms      | 120.2 ms    | 4,993.0 ms |
| 256 | 1,167 ms  | 868.4 ms      | 3.39 ms      | 227.7 ms    | 10,785 ms  |

## Sizes

| ℓ   | CT (each) | sbk | ek    | dk         |
|----:|----------:|----:|------:|-----------:|
| 4   | 704 B     | 48 B | 576 B | 880 B      |
| 16  | 704 B     | 48 B | 576 B | 3,184 B    |
| 64  | 704 B     | 48 B | 576 B | 12,400 B   |
| 128 | 704 B     | 48 B | 576 B | 24,688 B   |
| 256 | 704 B     | 48 B | 576 B | 49,264 B   |

CT and sbk match the paper exactly; ek/dk match upstream's native bench.

## vs upstream native (M4 single-threaded)

| ℓ   | Decrypt (native) | Decrypt (wasm) | wasm slowdown |
|----:|-----------------:|---------------:|--------------:|
| 4   | 15.3 ms          | 99.2 ms        | 6.5×          |
| 64  | 364 ms           | 2,304 ms       | 6.3×          |
| 256 | 1,690 ms         | 10,785 ms      | 6.4×          |

Roughly constant **~6.4× slowdown** in the browser — consistent with
arkworks pairing-heavy code on wasm32 without SIMD.

## What's actually shippable

| Flow                            | Batch shape | Decrypt budget | Verdict |
|---------------------------------|-------------|---------------:|---------|
| Thunder "open one message"      | ℓ=1 (no batch needed) | < 100 ms | ✅ Use existing Seal — batch buys nothing here |
| Thunder "open inbox" (16 unread)| ℓ=16        | 480 ms         | ✅ Acceptable with spinner |
| Thunder "catch-up" (64 unread)  | ℓ=64        | 2.3 s          | ⚠️ Loading state required, not interactive |
| SUIAMI roster reveal (128)      | ℓ=128       | 5.0 s          | ❌ Too slow for a roster expansion UX |
| Mempool-scale (256+)            | ℓ≥256       | 10 s+          | ❌ Validator-side primitive, not browser |

## Bundle size

- `darkrai_wasm_bg.wasm` (release, `wasm-opt -Oz`): **289 KB**
- Estimated gzipped over the wire: **~95 KB**

For comparison, `@mysten/seal`'s entire JS bundle is ~150 KB minified. Adding
Darkrai is a non-trivial bundle hit (~2/3 of Seal's footprint) and only worth
it if there's a real batch flow that needs it.

## Where this could matter for SKI today

**Real fit:** Thunder inbox catch-up for offline users. When `ultron.sui` has
been quilting messages while you were offline and you come back to 16+ unread
pieces, batch decrypt is the right primitive. Encrypt happens server-side
(cheap), pre-decrypt happens once on the IKA/Seal committee per inbox flush
(cheap), and decrypt happens on your device once with a spinner.

**Bad fit:**
- Per-message Thunder open — no batch, just use Seal.
- Shade execution — keeper bot is server-side, can't run pairings in CF Workers anyway.
- Mempool-style encrypted intents — that's a Mysten-protocol-level integration, not a browser primitive.

## Path forward

1. **License first** — upstream still has no `LICENSE`; nothing ships without that. Tracked at [entrohpy/batch-enc-partial-fractions#1](https://github.com/entrohpy/batch-enc-partial-fractions/issues/1).
2. **If green-lit:** wait for `@mysten/seal` to expose this as a mode, then swap. Don't build a parallel committee infra.
3. **If not green-lit yet:** the harness is here, the numbers are recorded, the wasm bundle compiles. We can revisit when license + Mysten SDK land.

**Decision (Nightmare → Dark Pulse):** shelve the SKI integration arc until
upstream licenses and Mysten productizes. Keep the harness as a reference
point. Dark Pulse not pulled.
