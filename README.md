# Composite Masked AES S-Box

A hardware implementation of a **first-order masked AES S-Box** using **Canright's composite field inversion**, with an integrated **True Random Number Generator (TRNG)** for side-channel resistance.

---

## Project Implementations

### S-Box

The AES SubBytes operation requires computing the multiplicative inverse `b⁻¹` in GF(2⁸). Rather than a lookup table, this design computes it structurally using **composite field arithmetic** over GF((2⁴)²), following Canright's basis decomposition.

To guard against power analysis attacks, the S-Box uses **first-order Boolean masking** — every intermediate value is split into two shares before any nonlinear (multiplication) operation occurs. Fresh randomness R is consumed at each GF(2⁴) multiplication; linear steps (squarings, basis transforms, affine transform) are free and handled per-share with no additional randomness.

### TRNG

A hardware TRNG generates the fresh mask values the S-Box requires. It draws physical entropy from a **32-oscillator ring oscillator array** (13 inverters each), mixes outputs via an XOR tree, and samples with a D flip-flop. The raw bitstream passes through **RCT and APT health tests**, is collected into 256-bit entropy blocks, and conditioned through **Keccak-f[1600]** (24 rounds) before being formatted as 4-bit mask values R₁ … R₇.

---

## Documentation

Full implementation details are in the AsciiDoc files:

| Document | Contents |
|---|---|
| [`sbox_implementation.adoc`](sbox_implementation.adoc) | Field definitions, basis matrices, composite inversion, masking strategy, all masked gadgets, squarer derivation, affine transform |
| [`trng_implementation.adoc`](trng_implementation.adoc) | Ring oscillator design, XOR mixing, health tests (RCT/APT), entropy collection, Keccak conditioning, output formatting |
| [`master.adoc`](master.adoc) | Master document that includes both of the above |

---

## Verification

- **S-Box:** All 256 inputs verified against the FIPS-197 AES S-Box table. Test vector: `0x53 → 0xED`.
- **TRNG:** Cocotb-based simulation covering entropy injection, bias detection, stuck-bit faults, health tests, and Keccak permutation correctness.

---

## References

- **FIPS 197** — AES Standard, NIST, 2001 (updated 2023). https://doi.org/10.6028/NIST.FIPS.197-upd1
- **Canright, D.** — A Very Compact Rijndael S-box. Naval Postgraduate School, 2005.
- **Ring Oscillator TRNG with Keccak Conditioning** — Sensors (MDPI), 2025. https://www.mdpi.com/1424-8220/25/5/1678