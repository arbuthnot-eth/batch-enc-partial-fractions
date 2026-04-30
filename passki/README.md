# Passki integration — Darkrai arc

WASM bench harness + Passki integration scaffolding for the upstream
`batch_encryption_short` crate.

This subtree lives **only on the `passki` branch**. `main` tracks upstream
unchanged so we can `git pull upstream main` cleanly.

Tracking issue: [arbuthnot-eth/passki#200](https://github.com/arbuthnot-eth/passki/issues/200)

## Layout

```
passki/
  darkrai-wasm/        wasm-bindgen wrapper around batch_encryption_short
  web/                 (later) browser harness page
  results.md           (later) empirical timings
```

## Why a separate Cargo project (not a workspace member)

The upstream workspace activates `parallel` features on every arkworks
dependency, which pulls `rayon`. `rayon` does not compile to
`wasm32-unknown-unknown` without a `wasm-bindgen-rayon` shim.

Keeping `darkrai-wasm` as a standalone Cargo project lets us depend on
`batch_encryption_short` via path while overriding feature flags locally.

## Build

```bash
cd passki/darkrai-wasm
wasm-pack build --target web --release
```
