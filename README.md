# Batch Threshold Encryption Using Partial Fraction Techniques

Protoypical Rust implementation in arkworks of the batch (threshold) encryption schemes in [ePrint 2026/674](https://ia.cr/2026/674).

This repository implements both the (1) batch encryption and (2) batch encryption with shorter ciphertexts as separate crates. They are generic over arkworks pairing curves.


| crate | Constructions | Ciphertext size | NIZK proof | Dec pairings |
|---|---|---|---|---|
| `batch_encryption` | 1 (§4.1) + 4 (§4.3, ciphertext-relation NIZK) | `2·\|G1\| + \|GT\|` | `2·\|G1\| + \|Fp\|` | 4·ell |
| `batch_encryption_short` | 5 (§5, BE_short) + 6 (Schnorr DLOG NIZK) | `\|G1\| + \|GT\|` | `\|G1\| + \|Fp\|` | 3·ell |

## Project Layout

```
crates/
  be_common/
    src/fft.rs                   Group-element FFT + circulant_mul (radix-2
                                 Cooley-Tukey, generic over Add + Sub + Mul<F>)
    src/partial_fractions.rs     Index helpers (roots of unity, γ, 1/(x+i))

  batch_encryption/              Original scheme (Constructions 1 & 4)
    src/nizk.rs                  Construction 4: SE-NIZK for R_{ek[1]}
    src/batch_enc.rs             Construction 1: Setup, Enc, PreDec, Dec
    benches/{nizk_bench, batch_enc_bench}.rs
    examples/sizes.rs

  batch_encryption_short/        Shorter ciphertexts (Constructions 5 & 6)
    src/nizk_dlog.rs             Construction 6: Schnorr SE-NIZK for R^DLOG
    src/batch_enc_short.rs       Construction 5: Setup, Enc, PreDec, Dec
    benches/{nizk_dlog_bench, batch_enc_short_bench}.rs
    examples/sizes_short.rs

results.md            Benchmark timings and size measurements
```


## Build / Test / Bench

Rust 1.70+ (2021 edition). All commands run from the repo root; use
`-p <crate>` to target one member.

```bash
cargo test                                                # 56 tests, ~2 s
cargo test -p batch_encryption                            # Constructions 1 / 4
cargo test -p batch_encryption_short                      # Constructions 5 / 6
cargo test -p be_common                                   # FFT correctness

cargo bench --bench batch_enc_bench                       # Construction 1 full
cargo bench --bench batch_enc_short_bench                 # Construction 5 full
cargo bench --bench nizk_bench                            # Construction 4 NIZK
cargo bench --bench nizk_dlog_bench                       # Construction 6 NIZK
cargo bench --bench batch_enc_bench -- decrypt            # just Construction 1 decrypt

cargo run -p batch_encryption --example sizes             # sizes for BE
cargo run -p batch_encryption_short --example sizes_short # sizes for BE_short
```

## Disclaimer

This code is being provided as is. No guarantee, representation or warranty is being made, express or implied, as to the safety or correctness of the code. It has not been audited and as such there can be no assurance it will work as intended, and users may experience delays, failures, errors, omissions or loss of transmitted information. Nothing in this repo should be construed as investment advice or legal advice for any particular facts or circumstances and is not meant to replace competent counsel. It is strongly advised for you to contact a reputable attorney in your jurisdiction for any questions or concerns with respect thereto. a16z is not liable for any use of the foregoing, and users should proceed with caution and use at their own risk. See a16z.com/disclosures for more info.
