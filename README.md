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

# Computing D⁻¹

Since GF(2⁴) contains 16 elements:

D⁻¹ = D¹⁴

Exponentiation is implemented as:

D¹⁴ = D⁸ · D⁴ · D²

This requires:

- squaring operations
- multiplication operations

---

# Masking Strategy

To protect against **power analysis attacks**, the design uses **first-order Boolean masking**.

A value is split into two shares:

D = D₁ ⊕ D₂

Where:

- D₁ = masked share
- D₂ = random mask

Neither share individually reveals the secret value.

---

# Masked Multiplication

For masked operands:

A = A₁ ⊕ A₂  
B = B₁ ⊕ B₂  

The masked product is computed as:

C₁ = A₁B₁ ⊕ R  
C₂ = A₁B₂ ⊕ A₂B₁ ⊕ A₂B₂ ⊕ R  

Where:

- R is fresh randomness
- Final value:

C = C₁ ⊕ C₂

The randomness cancels during recombination.

This is where the **True Random Number Generator (TRNG)** circuit comes into play to provide these random value.

---
# True Random Number Generator (TRNG) for Masked AES

**Purpose:**

This project includes a hardware **True Random Number Generator (TRNG)** used to generate **fresh randomness `R`** required for masked arithmetic in the masked AES S-Box implementation.

The generated random values are used as the **fresh mask input `R`** in masked multiplication operations.

---

# TRNG Architecture Overview

The TRNG follows a classical entropy-conditioning architecture:

```
Entropy Source
      │
      ▼
XOR Mixing
      │
      ▼
Sampling
      │
      ▼
Health Tests
      │
      ▼
Entropy Collector
      │
      ▼
Keccak Conditioning
      │
      ▼
Random Output Formatter
```

The final output is used as **random mask input `R`** for masked AES operations.

---

# Entropy Source – Ring Oscillator Array

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

# References

The TRNG architecture implemented in this project is based on the following research paper:

**Ring Oscillator Based True Random Number Generator with Keccak Conditioning**

Sensors Journal (MDPI)

Paper Link:  
https://www.mdpi.com/1424-8220/25/5/1678

---

# Completing the Inversion

After computing D⁻¹:

new_a₁ = D⁻¹ · a₁  
new_a₀ = D⁻¹ · (a₁ ⊕ a₀)  

This produces the inverse tower element:

A⁻¹ = new_a₁ x + new_a₀

---

# Converting Back to AES Field

The inverted tower element is mapped back to the AES polynomial basis:

b⁻¹ = T⁻¹ · {new_a₁, new_a₀}

This yields the multiplicative inverse in **GF(2⁸)**.

---

# Final Affine Transformation

The AES S-Box output is computed as:

b′ = A · b⁻¹ ⊕ c

Where:

- A = fixed AES affine matrix
- c = affine constant vector

This step is linear and safe under masking.

---

# Security Characteristics

This implementation provides:

- Composite field inversion
- First-order Boolean masking
- No lookup tables
- XOR + AND arithmetic only
- Fresh randomness for nonlinear operations

Linear transformations (basis change and affine transform) are applied **independently per masked share**.

---

# Verification

The S-Box output must match the official AES S-Box table defined in **FIPS-197**.

Example test vector:

Input:  0x53  
Output: 0xED

All **256 possible inputs** must produce identical outputs to the standard AES S-Box.

---
