# Composite Masked AES

A hardware implementation of the **AES block cipher** built around a **first-order masked S-Box** using **Canright's composite field inversion**, with an integrated **True Random Number Generator (TRNG)** supplying the fresh randomness needed for side-channel resistance.

---

## Project Overview

This project implements AES-128/192/256 encryption as a pipeline of RTL blocks, each derived directly from FIPS 197 with a masked, side-channel-resistant datapath where it matters most — the S-Box.

### Components

| Block | Description |
|---|---|
| **TRNG** | Generates the fresh randomness consumed by the masked S-Box. Draws physical entropy from a 32-oscillator ring oscillator array, passes it through RCT/APT health tests, and conditions it via Keccak-f[1600] into mask values. |
| **S-Box** | Computes the AES `SubBytes` multiplicative inverse structurally over the composite field GF((2⁴)²), using Canright's basis decomposition. Every nonlinear step is first-order Boolean masked using randomness from the TRNG. |
| **AddRoundKey / KeyExpansion** | Implements FIPS 197 `KeyExpansion()` and `AddRoundKey()` for all three standard key sizes (AES-128/192/256) using a rolling register bank, reusing the masked S-Box for the `SubWord()` step. |
| **ShiftRows / MixColumns** | Combinational datapath blocks implementing the FIPS 197 `ShiftRows()` and `MixColumns()` transforms. |
| **Cipher** | Top-level datapath that sequences the blocks above into the full FIPS 197 `Cipher()` round structure. |

---

## Documentation

This README is intentionally brief. For the full technical documentation — design derivations, masking strategy, gadget-level detail, FSMs, and verification results for every block — go to the [`docs/`](docs/) directory.

---

## Research Background

This project's design and verification approach is grounded in the following references:

- **FIPS 197** — *Advanced Encryption Standard (AES)*, NIST, 2001 (updated 2023). https://doi.org/10.6028/NIST.FIPS.197-upd1
- **Canright, D.** — *A Very Compact Rijndael S-box*, Naval Postgraduate School, 2005. (Composite field GF((2⁴)²) inversion structure used by the S-Box.). https://www.mdpi.com/1424-8220/25/6/1678
- **Piscopo, V.; Dolmeta, A.; Mirigaldi, M.; Martina, M.; Masera, G.** — *A High-Entropy True Random Number Generator with Keccak Conditioning for FPGA*, Sensors, 25(6), 1678, 2025. https://doi.org/10.3390/s25061678 (Ring-oscillator TRNG architecture and Keccak conditioning approach adapted for the TRNG block.)


---

## Tools & Simulation Environment

| Purpose | Tool |
|---|---|
| **Compiler / Simulator** | [Verilator](https://www.veripool.org/verilator/) — compiles the SystemVerilog RTL into a cycle-accurate C++ simulation model. |
| **Verification Framework** | [cocotb](https://www.cocotb.org/) (Python) — drives the Verilator model and implements all testbenches, checkers, and coverage. |
| **Linting & Synthesis** | [Xilinx Vivado](https://www.xilinx.com/products/design-tools/vivado.html) — RTL linting and FPGA synthesis. |
