# AES Encryption Engine

A hardware AES engine supporting **AES-128/192/256 encryption and decryption** across the five **NIST SP 800-38A modes of operation** — ECB, CBC, CFB, OFB and CTR — built around a **first-order masked S-Box** using **Canright's composite field inversion**, with an on-chip **TRNG** supplying masking randomness and an **SP 800-90A IV generator** producing unpredictable initialization vectors.

---

## Project Overview

The engine accepts 128-bit blocks over a VALID/READY handshake, applies the configured mode and direction, and returns result blocks over a second VALID/READY handshake. Chaining state — IVs, feedback registers, counters — is held internally for the duration of a message, so an integrating manager streams blocks in and collects results without feeding anything back between them.

Every block is derived directly from FIPS 197 and SP 800-38A, with a masked, side-channel-resistant datapath where it matters most: the S-Box, the only non-linear element of AES.

**Status:** RTL complete and verified. The top-level regression suite passes 54 of 54.

### Components

| Block | Description |
|---|---|
| **AES top (`aes`)** | Interface, per-mode FSMs and chaining state for ECB/CBC/CFB/OFB/CTR in both directions. Owns the shared S-Box and key-expansion instances and arbitrates them between the cipher and inverse cipher. |
| **Cipher** | Datapath that sequences the forward blocks into the full FIPS 197 `Cipher()` round structure — encryption. |
| **InvCipher** | Datapath that sequences the inverse blocks into the full FIPS 197 `InvCipher()` round structure — decryption. |
| **S-Box** | Computes the AES `SubBytes` multiplicative inverse structurally over the composite field GF((2⁴)²), using Canright's basis decomposition. Every nonlinear step is first-order Boolean masked using randomness from the TRNG. |
| **Inverse S-Box (InvSBox)** | Computes `InvSubBytes` for decryption. Reuses the forward S-Box's composite-field inversion hardware unchanged (GF(2⁸) inversion is an involution); only the surrounding affine transformation differs. |
| **AddRoundKey / KeyExpansion** | Implements FIPS 197 `KeyExpansion()` and `AddRoundKey()` for all three key sizes using a rolling register bank, reusing the masked S-Box for the `SubWord()` step. |
| **InvAddRoundKey / INVCIPHER key schedule** | Reconciles `InvCipher()`'s reverse-order round-key consumption with AddRoundKey's forward-only expansion, by driving AddRoundKey through a full forward pass and buffering every round key for backward traversal. |
| **ShiftRows / MixColumns** | Combinational datapath blocks implementing the FIPS 197 `ShiftRows()` and `MixColumns()` transforms. |
| **InvShiftRows / InvMixColumns** | Combinational datapath blocks implementing the FIPS 197 `InvShiftRows()` and `InvMixColumns()` transforms. |
| **TRNG** | Generates the fresh randomness consumed by the masked S-Box and InvSBox. Draws physical entropy from a 32-oscillator ring oscillator array, passes it through RCT/APT health tests, and conditions it via Keccak-f[1600] into mask values. |
| **IV Generator** | Produces unpredictable IVs for CBC, CFB and OFB encryption. Conditions raw noise through a CBC-MAC and drives an SP 800-90A CTR_DRBG, both built on an unmasked AES-256 core. |
| **ICG** | Glitch-free integrated clock gating cell. Gates the whole block on `enb_n`, and is reused inside every sub-block. |

### Modes of Operation

| Mode | Chaining | IV / counter source (encrypt) | Decryption uses |
|---|---|---|---|
| **ECB** | none | not required | InvCipher |
| **CBC** | previous ciphertext block | generated internally, reported on `encCntxtOut` | InvCipher |
| **CFB** | `s`-bit ciphertext feedback, `s` ∈ {8, 16, 32, 64, 128} | generated internally, reported on `encCntxtOut` | Cipher |
| **OFB** | cipher output feedback | generated internally, reported on `encCntxtOut` | Cipher |
| **CTR** | counter block, SP 800-38A B.1 successor | internal counter, reported on `encCntxtOut` | Cipher |

On the decryption side, CBC, CFB, OFB and CTR take the IV or starting counter from `encCntxtIn`. OFB and CTR additionally support a partial final block through the `partial` and `valid_bits` sidebands.

### Interface Notes

Three points that catch integrators; the specification covers them in full.

- **Handshake discipline.** Input-channel signals must be held from the assertion of `inVALID` until `inREADY` is observed, and may be released on the transfer edge. Every sideband the engine needs afterwards is latched internally at the handshake.
- **`enb_n` is a freeze, not a reset.** Raising it gates the clock off and every register holds, including `inREADY` and `outVALID`. A pending result survives and is delivered on re-enable. A disabled engine cannot observe a handshake, so outstanding transfers must be completed or abandoned before disabling.
- **Port byte order.** All 128-bit ports carry blocks in the internal `state_matrix_t` packing rather than FIPS 197 byte order. The mapping is `b[r + 4c] -> bit ((3 - r) * 4 + c) * 8`, and it applies uniformly to data, IVs and counters.

---

## Verification

Each block carries its own cocotb testbench under [`tb/`](tb/), run against Verilator through [`sim/Makefile`](sim/Makefile). The top level is verified by `aes_sequence.py`, a 54-test suite covering reset and enable behaviour, configuration handling, every mode against the NIST vectors, handshake and protocol conformance, and randomised stress.

```sh
# full top-level regression
make -C sim run_test_suite block=aes_top

# a single test
make -C sim run_test block=aes_top test='cbc_roundtrip'

# block-level suites
make -C sim run_test_suite block=cipher_top
```

Scoring is against `aes_ref_model.py`, a mode-layer reference model self-checked at import against the SP 800-38A Appendix F vectors at all three key sizes. A continuous protocol checker runs alongside every test, asserting that `outVALID` is never withdrawn without `outREADY`, that the output payload is stable across a VALID window, and that no output carries X or Z once reset is released.

`aes_probes.py` holds cycle-level diagnostic probes that print internal traces rather than asserting a golden value. They are not collected by the regression, and are the tool to reach for when a mode produces an unexpected result and the question is whether the formula, the routing, or the cipher's own output is at fault.

Linting and synthesis run from the same Makefile. `synth` takes the target frequency and
produces the timing, area and power reports alongside the netlist:

```sh
make -C sim lint  block=aes_top
make -C sim synth block=cipher freq=200
```

---

## Documentation

This README is intentionally brief. The full technical documentation — design derivations, masking strategy, gadget-level detail, FSMs, mode algorithms and known limitations — lives in the [`docs/`](docs/) directory.

[`docs/aes.adoc`](docs/aes.adoc) is the design specification and pulls in every individual document as a chapter. Generate it from the `docs/` directory:

```sh
asciidoctor aes.adoc          # HTML
asciidoctor-pdf aes.adoc      # PDF
```

---

## Research Background

- **FIPS 197** — *Advanced Encryption Standard (AES)*, NIST, 2001 (updated 2023). https://doi.org/10.6028/NIST.FIPS.197-upd1
- **NIST SP 800-38A** — *Recommendation for Block Cipher Modes of Operation: Methods and Techniques*, 2001. Mode definitions, the Appendix F test vectors used by the reference model, and the Appendix B.1 standard incrementing function used by CTR. https://doi.org/10.6028/NIST.SP.800-38A
- **NIST SP 800-90A Rev. 1** — *Recommendation for Random Number Generation Using Deterministic Random Bit Generators*, 2015. CTR_DRBG construction used by the IV generator. https://doi.org/10.6028/NIST.SP.800-90Ar1
- **NIST SP 800-90B** — *Recommendation for the Entropy Sources Used for Random Bit Generation*, 2018. RCT/APT health tests used by the TRNG and the IV generator's conditioner. https://doi.org/10.6028/NIST.SP.800-90B
- **Canright, D.** — *A Very Compact S-box for AES*, CHES 2005, LNCS 3659, pp. 441–455. Composite field GF((2⁴)²) inversion structure used by the S-Box.
- **Piscopo, V.; Dolmeta, A.; Mirigaldi, M.; Martina, M.; Masera, G.** — *A High-Entropy True Random Number Generator with Keccak Conditioning for FPGA*, Sensors, 25(6), 1678, 2025. https://doi.org/10.3390/s25061678 (Ring-oscillator TRNG architecture and Keccak conditioning approach adapted for the TRNG block.)

---

## Tools & Simulation Environment

| Purpose | Tool |
|---|---|
| **Compiler / Simulator** | [Verilator](https://www.veripool.org/verilator/) — compiles the SystemVerilog RTL into a cycle-accurate C++ simulation model. |
| **Verification Framework** | [cocotb](https://www.cocotb.org/) (Python) — drives the Verilator model and implements all testbenches, checkers and reference models. |
| **Style / Syntax Linting** | [Verible](https://github.com/chipsalliance/verible) and [slang](https://github.com/MikePopoloski/slang) — style and elaboration checks ahead of synthesis. |
| **Synthesis & Timing** | [Xilinx Vivado](https://www.xilinx.com/products/design-tools/vivado.html) — RTL linting, FPGA synthesis and static timing analysis. |
| **Documentation** | [Asciidoctor](https://asciidoctor.org/) — renders the specification to HTML and PDF. |
