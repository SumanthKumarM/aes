# Composite Masked AES S-Box
## Based on Canright Composite Field Inversion

This project implements a **first-order masked AES S-Box** using  
**Canright’s composite field inversion method**.

The AES SubBytes transformation is defined as:

b′ = A · b⁻¹ ⊕ c

Where:

- `b` is a byte in GF(2⁸)
- `b⁻¹` is the multiplicative inverse in GF(2⁸)
- `A` is the affine transformation matrix
- `c` is the affine constant vector

The most computationally expensive step is computing `b⁻¹`.  
This design computes the inverse using composite field arithmetic:

GF(2⁸) ≅ GF((2⁴)²)

---

# Field Definitions

AES operates in GF(2⁸) defined by the polynomial: x⁸ + x⁴ + x³ + x + 1

For composite inversion we decompose the field as GF((2⁴)²)  

Inner field GF(2⁴) defined by (y⁴ + y + 1)

Extension polynomial: (x² + x + λ)

For Canright’s basis choice:

λ = 0x8

This value arises from the **basis transformation between GF(2⁸) and the tower field representation**.

---

# Basis Transformation

To perform composite inversion, the AES byte must first be converted into the **tower field representation**.

This is achieved using a fixed **8×8 linear transformation matrix**.

The transformation is performed over **GF(2)**, meaning:

- addition = XOR
- multiplication = AND

---

# Forward Basis Matrix (T)

This matrix converts the AES byte into the tower representation:  

Transforms AES byte → tower field representation  

AES byte → GF((2⁴)²)

After transformation:

A(x) = a₁x + a₀

where:

- a₁ ∈ GF(2⁴)
- a₀ ∈ GF(2⁴)  

a₁ and a₀ are obtained using forward basis matrix:  

{a₁, a₀} = T · b

where T is the **forward basis matrix**:  

$$
T = \begin{bmatrix}
1 & 0 & 1 & 0 & 0 & 0 & 0 & 0 \\
1 & 0 & 1 & 0 & 1 & 1 & 0 & 0 \\
1 & 1 & 0 & 1 & 0 & 0 & 1 & 0 \\
0 & 1 & 1 & 1 & 0 & 0 & 0 & 0 \\
0 & 0 & 0 & 1 & 1 & 0 & 0 & 0 \\
1 & 1 & 1 & 1 & 1 & 1 & 0 & 0 \\
0 & 0 & 0 & 0 & 0 & 1 & 0 & 0 \\
1 & 0 & 1 & 0 & 0 & 0 & 0 & 1
\end{bmatrix}
$$  


This operation is implemented purely using **XOR networks** in hardware.

---  

# Inverse Basis Matrix (T⁻¹)

After composite inversion is completed, the tower field representation must be converted back to the AES polynomial basis.

This is done using the inverse transformation matrix:

GF((2⁴)²) → AES byte

The inverse transformation matrix is gives as:  

$$
T^{-1} = \begin{bmatrix}
1 & 1 & 0 & 1 & 0 & 1 & 0 & 0 \\
1 & 0 & 0 & 0 & 1 & 1 & 1 & 0 \\
0 & 1 & 0 & 1 & 0 & 1 & 0 & 0 \\
1 & 1 & 0 & 0 & 1 & 0 & 1 & 0 \\
1 & 1 & 0 & 0 & 0 & 0 & 1 & 0 \\
0 & 0 & 0 & 0 & 0 & 0 & 1 & 0 \\
1 & 0 & 1 & 1 & 0 & 0 & 0 & 0 \\
1 & 0 & 0 & 0 & 0 & 0 & 0 & 1
\end{bmatrix}
$$


This transformation is also linear and implemented entirely using **XOR logic**.

---

# Composite Field Inversion

After applying the forward basis transform:

A(x) = a₁x + a₀

The multiplicative inverse A(x) in GF((2⁴)²) is:

A⁻¹ = D⁻¹ · Ā

Where:  

Ā is the conjugate of A. The conjugate is obtained by evaluating A at the other root (α+1 instead of α):

Ā = a₁(x + 1) + a₀ = a₁x + (a₁ ⊕ a₀)

D = a₁²λ ⊕ a₀a₁ ⊕ a₀²

All arithmetic is performed in **GF(2⁴)**.

---

# Masking Strategy

To protect against **power analysis attacks**, the design uses **first-order Boolean masking**.  
The mask is introduced **at the input**, before any nonlinear operation ever occurs.  
Linear operations (basis transforms, squarings, affine transform) are applied independently per share.  
Only genuine GF(2⁴) multiplications require fresh randomness from the TRNG.

The reason why masking is applied at the input itself is the basis transform T is a purely linear XOR network.  
If a₁ and a₀ were masked after T, the multiplication a₁·a₀ would still occur unmasked, leaking information at that exact moment.  
Therefore masking must be introduced **before the first multiplication**, so that D is never computed in the clear on any wire at any point.  

## Input Splitting

Before any multiplication, a₁ and a₀ are split into two shares using TRNG outputs R₁ and R₂:

```
a₁ᵣ = R₁                  ← random mask from TRNG
a₁ₘ = a₁ ⊕ a₁ᵣ           ← masked share (XOR only, no new R needed)

a₀ᵣ = R₂                  ← random mask from TRNG
a₀ₘ = a₀ ⊕ a₀ᵣ           ← masked share (XOR only, no new R needed)
```

At this point: a₁ₘ ⊕ a₁ᵣ = a₁  and  a₀ₘ ⊕ a₀ᵣ = a₀

---

# Masked Multiplication Gadget

For any two masked operands A = A₁ ⊕ A₂ and B = B₁ ⊕ B₂, the product C = A·B is computed using fresh randomness R from TRNG:

```
C₁ = A₁·B₁ ⊕ R
C₂ = A₁·B₂ ⊕ A₂·B₁ ⊕ A₂·B₂ ⊕ R
```

Verification: C₁ ⊕ C₂ = A₁B₁ ⊕ A₁B₂ ⊕ A₂B₁ ⊕ A₂B₂ = (A₁ ⊕ A₂)(B₁ ⊕ B₂) = A·B 

Neither C₁ nor C₂ individually reveals A·B. R cancels upon recombination.  

This is where the **True Random Number Generator (TRNG)** circuit comes into play to provide these random value.

---

# Computing D in Masked Form

Recall: D = a₁²λ ⊕ a₁a₀ ⊕ a₀²

## Squaring Terms — Linear, Split for Free

In GF(2⁴), squaring is a **linear map**, so it distributes across XOR:

```
a₁² = (a₁ₘ ⊕ a₁ᵣ)² = a₁ₘ² ⊕ a₁ᵣ²     ← no R needed
a₀² = (a₀ₘ ⊕ a₀ᵣ)² = a₀ₘ² ⊕ a₀ᵣ²     ← no R needed
```

## Multiplication Term — Apply Masked Multiplication Gadget with R₃

```
P₁ = a₁ₘ·a₀ₘ ⊕ R₃
P₂ = a₁ₘ·a₀ᵣ ⊕ a₁ᵣ·a₀ₘ ⊕ a₁ᵣ·a₀ᵣ ⊕ R₃
```

Verification: P₁ ⊕ P₂ = (a₁ₘ ⊕ a₁ᵣ)(a₀ₘ ⊕ a₀ᵣ) = a₁·a₀ 

## Assembling D₁ and D₂

```
D₁ = a₁ₘ²·λ ⊕ P₁ ⊕ a₀ₘ²
D₂ = a₁ᵣ²·λ ⊕ P₂ ⊕ a₀ᵣ²
```

Verification:  
D₁ ⊕ D₂ = (a₁ₘ² ⊕ a₁ᵣ²)λ ⊕ (P₁ ⊕ P₂) ⊕ (a₀ₘ² ⊕ a₀ᵣ²)  
         = a₁²λ ⊕ a₁a₀ ⊕ a₀² = D 

**D is born already in masked form. It is never computed in the clear.**

---

# Computing D⁻¹ in Masked Form

Since GF(2⁴) has 16 elements: D⁻¹ = D¹⁴ = D⁸ · D⁴ · D²

## Squarings — Purely Linear, Zero Cost

Squaring each share independently:

```
D₁² , D₂²     →  shares of D²    (no R needed)
D₁⁴ , D₂⁴     →  shares of D⁴    (no R needed)
D₁⁸ , D₂⁸     →  shares of D⁸    (no R needed)
```

Verification for D²:  
D₁² ⊕ D₂² = (D₁ ⊕ D₂)² = D²   (linearity of squaring in GF(2⁴))

## First Masked Multiply — D⁸ · D⁴ using R₄

```
Q₁ = D₁⁸·D₁⁴ ⊕ R₄
Q₂ = D₁⁸·D₂⁴ ⊕ D₂⁸·D₁⁴ ⊕ D₂⁸·D₂⁴ ⊕ R₄
```

Verification: Q₁ ⊕ Q₂ = (D₁⁸ ⊕ D₂⁸)(D₁⁴ ⊕ D₂⁴) = D⁸·D⁴ 

## Second Masked Multiply — (D⁸·D⁴) · D² using R₅

```
E₁ = Q₁·D₁² ⊕ R₅
E₂ = Q₁·D₂² ⊕ Q₂·D₁² ⊕ Q₂·D₂² ⊕ R₅
```

Verification: E₁ ⊕ E₂ = (Q₁ ⊕ Q₂)(D₁² ⊕ D₂²) = D⁸·D⁴·D² = D¹⁴ = D⁻¹ 

---

# Computing A⁻¹ in Masked Form

Need: new_a₁ = D⁻¹·a₁  and  new_a₀ = D⁻¹·(a₁ ⊕ a₀)

## Masked Multiply D⁻¹ · a₁ using R₆

```
F₁ = E₁·a₁ₘ ⊕ R₆
F₂ = E₁·a₁ᵣ ⊕ E₂·a₁ₘ ⊕ E₂·a₁ᵣ ⊕ R₆
```

Verification: F₁ ⊕ F₂ = (E₁ ⊕ E₂)(a₁ₘ ⊕ a₁ᵣ) = D⁻¹·a₁ = new_a₁ 

## Masked Multiply D⁻¹ · (a₁ ⊕ a₀) using R₇

```
G₁ = E₁·(a₁ₘ ⊕ a₀ₘ) ⊕ R₇
G₂ = E₁·(a₁ᵣ ⊕ a₀ᵣ) ⊕ E₂·(a₁ₘ ⊕ a₀ₘ) ⊕ E₂·(a₁ᵣ ⊕ a₀ᵣ) ⊕ R₇
```

Verification: G₁ ⊕ G₂ = (E₁ ⊕ E₂)((a₁ₘ ⊕ a₁ᵣ) ⊕ (a₀ₘ ⊕ a₀ᵣ)) = D⁻¹·(a₁ ⊕ a₀) = new_a₀ 

---

# Optimized GF(2⁴) Squarer

## Why a Dedicated Squarer Is Better

A general GF(2⁴) multiplier applied to inp×inp requires an xTimes chain with conditional XOR logic. But squaring in GF(2⁴) is a **linear operation** — the output bits are fixed XOR combinations of input bits. This collapses to a pure wiring network with only 2 XOR gates.

## Derivation for GF(2⁴) with Reduction Polynomial x⁴ + x + 1

Let inp = {a3, a2, a1, a0}. Expand inp²:

```
inp² = (a3x³ + a2x² + a1x + a0)²
     = a3²x⁶ + a2²x⁴ + a1²x² + a0²
```

In GF(2), squaring coefficients is identity (0²=0, 1²=1), so:

```
inp² = a3·x⁶ + a2·x⁴ + a1·x² + a0
```

Reduce mod (x⁴ + x + 1):

```
x⁴ ≡ x + 1       → {0011}
x⁵ ≡ x² + x      → {0110}
x⁶ ≡ x³ + x²     → {1100}
```

Substituting:

```
inp² = a3·(x³+x²) + a2·(x+1) + a1·x² + a0
     = a3x³ + (a3⊕a1)x² + a2x + (a2⊕a0)
```

Collecting coefficients:

```
out[3] = a3
out[2] = a3 ⊕ a1
out[1] = a2
out[0] = a2 ⊕ a0
```
---

# Converting Back to AES Field

After A⁻¹ is computed in masked share form:

```
{new_a1_share1, new_a0_share1}  →  T⁻¹  →  b_inv_share1
{new_a1_share2, new_a0_share2}  →  T⁻¹  →  b_inv_share2
```

Since T⁻¹ is linear, it is applied independently to each share:

b⁻¹ = b_inv_share1 ⊕ b_inv_share2

---

# Final Affine Transformation

The AES S-Box output is computed as:

b′ = A · b⁻¹ ⊕ c

Where:

- A = fixed AES affine matrix
- c = affine constant vector {01100011}

This step is linear and applied independently per share:

```
b_prime_share1 = A * b_inv_share1 ^ c    ← applied to share 1 only
b_prime_share2 = A * b_inv_share2        ← c added once only to share 1
```

b′ = b_prime_share1 ⊕ b_prime_share2

---

# True Random Number Generator (TRNG) for Masked AES  

**Purpose:**

This project includes a hardware **True Random Number Generator (TRNG)** used to generate **fresh randomness `R`** required for masked arithmetic in the masked AES S-Box implementation.

The generated random values are used as the **fresh mask input `R`** in masked multiplication operations.  

# TRNG Architecture Overview

The TRNG follows a classical entropy-conditioning architecture:

```
Physical Noise (CMOS thermal/flicker jitter)
            │
            ▼
  32 Ring Oscillators (13 inverters each)
            │
            ▼
       XOR Mixing Tree
            │
            ▼
    Sampling (D flip-flop)
            │
            ▼
       Health Tests
       ┌────┴────┐
      RCT       APT
       └────┬────┘
            │
            ▼
  Entropy Collector (256-bit SIPO)
            │
            ▼
  Keccak-f[1600] Conditioning (24 rounds)
            │
            ▼
   Output Formatter (4-bit words)
            │
            ▼
       R₁ … R₇ per S-box
```

The final output is used as **random mask input `R`** for masked AES operations.  

## Entropy Source – Ring Oscillator Array

Randomness originates from **physical noise sources in CMOS circuits**.

Examples include:

- thermal noise
- flicker noise
- supply voltage variation
- temperature fluctuation
- transistor delay variation

These physical phenomena introduce **timing jitter** in logic gate propagation delays.

---

## Ring Oscillator Structure

Each oscillator consists of an **odd number of inverters**:

```
INV → INV → INV → ... → INV
```

An odd number of inverters ensures continuous oscillation.

Configuration used in this design:

32 Ring Oscillators  
13 Inverters per Oscillator

---

# Entropy Amplification via XOR Mixing

Each ring oscillator produces a waveform containing jitter.

To improve entropy quality, oscillator outputs are combined using an XOR tree:

```
RO₀  ─────┐
RO₁  ─────┤
RO₂  ─────┤
 :        ⊕ ───▶ Output
 :        │
RO₃₁ ─────┘
```

XOR mixing combines multiple independent noise sources, increasing entropy.

---

# Sampling the Entropy Signal

The XOR output is sampled using a **D flip-flop driven by an independent clock**.

RO XOR output → DFF → raw_bit_stream

Sampling converts **timing jitter** into **digital random bits**.

Each clock cycle produces one raw entropy bit.

---

# Health Tests

The raw entropy stream is continuously monitored using runtime health tests. These tests ensure that the entropy source has not failed or become biased.

### Core Implementation

* **Repetition Count Test (RCT)**
    * **Purpose:** Detects if the entropy source becomes "stuck."
    * **Mechanism:** The test monitors and counts consecutive identical bits in the stream.
    * **Failure Condition:** If the repetition count exceeds a predefined threshold, an error is raised.
    * **Example Failure:** `111111111111111111...`

* **Adaptive Proportion Test (APT)**
    * **Purpose:** Detects bias in the bitstream within a specific data window.
    * **Window Size:** **1024 bits** (as per **NIST** standard).
    * **Mechanism:** Operates within a sliding window to check the statistical distribution of bits.
    * **Failure Condition:** If the number of `1` bits exceeds a calculated statistical threshold, the entropy source is considered faulty.

---

# Entropy Collector

The entropy source produces **one random bit per clock cycle**.

To form usable entropy blocks, bits are collected using a **Serial-In Parallel-Out (SIPO) shift register**.

Example:

```
raw bits: 1 0 1 1 0 0 1 0

shift register output:

1011
0010
```

For cryptographic conditioning, larger entropy blocks are typically used.

Example configuration:

```
entropy_pool_size = 256 bits
```

These bits are injected into the Keccak conditioning block.

---

# Keccak Conditioning

The TRNG uses the **Keccak permutation** as a cryptographic conditioning function.

Keccak is the algorithm used in **SHA-3**.

Conditioning performs:

- bias removal
- correlation destruction
- entropy diffusion

---

## Keccak State

The permutation operates on a **1600-bit internal state**.

The state is arranged as: 5 × 5 matrix of lanes

Each lane contains: 64 bits

Total state size: 5 × 5 × 64 = 1600 bits

---

## Absorb Phase

Entropy bits are injected into the state using XOR:

```
state = state XOR entropy_block
```

Incoming entropy mixes with the existing state rather than overwriting it.

---

## Keccak Permutation

The permutation **Keccak-f[1600]** executes **24 rounds**.

Each round applies the following transformations:

```
θ → ρ → π → χ → ι
```

---

### Theta (θ)

Column parity is computed:

```
C[x] = A[x,0] ⊕ A[x,1] ⊕ A[x,2] ⊕ A[x,3] ⊕ A[x,4]
```

Columns are mixed:

```
D[x] = C[x−1] ⊕ ROT(C[x+1],1)
```

Then applied:

```
A[x,y] = A[x,y] ⊕ D[x]
```

---

### Rho (ρ)

Each lane undergoes a fixed rotation:

```
A[x,y] = ROT(A[x,y], offset[x,y])
```

Rotation offsets are fixed constants defined in the Keccak specification.

---

### Pi (π)

Lanes are permuted across the matrix:

```
A'[x,y] = A[(x + 3y) mod 5][x]
```

This spreads information throughout the state.

---

### Chi (χ)

This step introduces nonlinearity:

```
A[x,y] = A[x,y] ⊕ ((¬A[x+1,y]) ∧ A[x+2,y])
```

---

### Iota (ι)

A round constant is injected:

```
A[0,0] = A[0,0] ⊕ RC
```

Each round uses a different constant.

---

# Squeeze Phase

After the permutation completes, the Keccak state contains **high-quality pseudorandom bits**.

These bits are extracted sequentially:

```
state → random bit stream
```

---

# Random Output Formatting

The conditioned output stream is formatted into **4-bit random values**.

Example:

```
random stream: 101001110010...

4-bit outputs:

1010
0111
0010
...
```

These values serve as the **fresh randomness `R` used in masked multiplication**.

---

# Integration with Masked AES

The TRNG supplies randomness to masked arithmetic units.

Example masked multiplication:

```
C₁ = A₁B₁ ⊕ R
C₂ = A₁B₂ ⊕ A₂B₁ ⊕ A₂B₂ ⊕ R
```

Where:

```
R = TRNG output
```

Each multiplication must use **fresh randomness**.

---

# Security Properties

The TRNG design provides:

- physical entropy source (ring oscillator jitter)
- entropy amplification via XOR mixing
- runtime health monitoring
- cryptographic conditioning using Keccak
- continuous generation of fresh randomness

These properties ensure strong resistance against **first-order side-channel attacks**.

---

# Verification

The TRNG is verified using **Cocotb-based simulation**.

Verification includes:

- entropy injection models
- bias detection tests
- stuck-bit fault tests
- health test validation
- Keccak permutation verification

---

# Summary

The TRNG converts **physical hardware noise** into **cryptographically strong random numbers**.

Pipeline:

```
Physical noise
      ↓
Ring oscillators
      ↓
XOR mixing
      ↓
Sampling
      ↓
Health tests
      ↓
Entropy collection
      ↓
Keccak conditioning
      ↓
Random mask values (R)
```

These random values protect masked AES operations against side-channel attacks.  

---

# Verification

The S-Box output must match the official AES S-Box table defined in **FIPS-197**.

Example test vector:

Input:  0x53  
Output: 0xED

All **256 possible inputs** must produce identical outputs to the standard AES S-Box.

---

# References

**FIPS 197** — Advanced Encryption Standard (AES), NIST, 2001 (updated 2023).  
https://doi.org/10.6028/NIST.FIPS.197-upd1

**Canright, D.** — A Very Compact Rijndael S-box. Naval Postgraduate School Technical Report, 2005.

**Ring Oscillator Based True Random Number Generator with Keccak Conditioning**  
Sensors Journal (MDPI), 2025.  
https://www.mdpi.com/1424-8220/25/5/1678