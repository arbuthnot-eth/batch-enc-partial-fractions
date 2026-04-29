# Experiment Results

All benchmarks use **BLS12-381** (`ark-bls12-381` v0.5) on Apple Silicon. Timings
are collected by Criterion with a 3-second warm-up phase followed by 10 samples
per benchmark; Criterion auto-tunes the number of iterations per sample to fill
the measurement window. Values reported are mean over the 10 samples with a 95%
confidence interval.

## Batch Encryption

Let $\ell$ be the batch size.

### Setup

| $\ell$ | Construction 1 | Construction 5 |
|----:|---:|---:|
| 4   | 2.05 ms [2.03, 2.09] | 3.13 ms [3.11, 3.16] |
| 16  | 6.44 ms [6.39, 6.49] | 10.4 ms [10.3, 10.4] |
| 64  | 24.2 ms [24.0, 24.4] | 39.2 ms [39.1, 39.3] |
| 128 | 47.5 ms [47.3, 47.8] | 77.4 ms [77.0, 77.8] |
| 256 | 93.9 ms [93.7, 94.0] | 153 ms  [153, 153]   |
| 512 | 186 ms  [186, 186]   | 305 ms  [304, 306]   |


### Encryption

| scheme | time |
|---|---:|
| Construction 1 | 599 µs [596, 605] |
| Construction 5 | 437 µs [437, 438] |


### Pre-decryption

| $\ell$ | Construction 1 | Construction 5 |
|----:|---:|---:|
| 4   | 1.53 ms [1.41, 1.67] | 0.82 ms [0.80, 0.85] |
| 16  | 2.83 ms [2.80, 2.89] | 1.93 ms [1.91, 1.96] |
| 64  | 8.12 ms [7.99, 8.20] | 6.93 ms [6.89, 7.01] |
| 128 | 14.5 ms [14.4, 14.5] | 13.2 ms [13.2, 13.3] |
| 256 | 27.9 ms [27.5, 28.4] | 25.6 ms [25.5, 25.8] |
| 512 | 54.3 ms [53.5, 55.3] | 50.1 ms [50.0, 50.5] |

Both implementations use randomized-MSM batch verification of the NIZK proofs.

### Decryption

| $\ell$ | Construction 1  | Construction 5  | ratio |
|----:|---:|---:|---:|
| 4   | 19.2 ms [19.2, 19.3]  | 15.3 ms [15.2, 15.4]  | 0.79× |
| 16  | 101 ms  [101, 102]    | 76.3 ms [76.1, 76.6]  | 0.75× |
| 64  | 501 ms  [499, 505]    | 364 ms  [364, 365]    | 0.73× |
| 128 | 1.09 s  [1.09, 1.09]  | 787 ms  [786, 788]    | 0.72× |
| 256 | 2.38 s  [2.38, 2.39]  | 1.69 s  [1.69, 1.69]  | 0.71× |
| 512 | 5.12 s  [5.11, 5.13]  | 3.61 s  [3.60, 3.61]  | 0.70× |

Note: the per-ciphertext decrypt loop is currently single-threaded (the
`par_iter` in `decrypt` is commented out.

## NIZK (standalone)

| | Construction 4 (`nizk`, R_{ek[1]}) | Construction 6 (`nizk_dlog`, R^DLOG) |
|---|---:|---:|
| Prove  | 135 µs [133, 137] | 57.8 µs [57.5, 58.0] |
| Verify (single) | 276 µs [275, 277] | 134 µs [131, 141] |


Construction 6 batch verification via one randomized MSM check:

| $\ell$ | Construction 6 batch verify | per proof |
|----:|---:|---:|
| 4   | 546 µs  | 137 µs |
| 16  | 681 µs  | 42.6 µs |
| 64  | 1.08 ms | 16.9 µs |
| 256 | 2.05 ms | 8.0 µs |
| 512 | 3.29 ms | 6.4 µs |


## Serialized Sizes (BLS12-381, compressed)

`|G1| = 48 B`, `|G2| = 96 B`, `|GT| = 576 B`, `|Fp| = 32 B`.

### Ciphertext + keys

| | Construction 1 | Construction 5 |
|---|---:|---:|
| Ciphertext (total) | 800 B | **704 B** |
| NIZK proof | 128 B (2 G1 + 1 Fp) | 80 B (1 G1 + 1 Fp) |
| Ciphertext without proof | 672 B (2 G1 + GT) | 624 B (1 G1 + GT) |
| Encryption key `ek` | 624 B (1 G1 + 1 GT) | 576 B (1 GT) |
| Pre-decryption key `sbk` | 48 B (1 G1) | 48 B (1 G1) |


### Decryption key `dk`

| $\ell$ | BE | BE_short |
|----:|---:|---:|
| 4   | 488 B    | 880 B |
| 16  | 1,640 B  | 3,184 B |
| 64  | 6,248 B  | 12,400 B |
| 128 | 12,392 B | 24,688 B |
| 256 | 24,680 B | 49,264 B |
| 512 | 49,256 B | 98,416 B |


## Environment

- Curve: BLS12-381 (ark-bls12-381 v0.5).
- Hash: SHA-512 (64-byte output, ≤2⁻²⁵⁶ bias for 255-bit scalar field).
- Criterion: 10 samples per benchmark, 3-second warm-up.
- Platform: macOS (Darwin), Apple Silicon. 2024 MacBook Pro with M4, 24 GB of unified memory in single-threaded mode.
  loop, and setup loops.
