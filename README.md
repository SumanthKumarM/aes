# Composite Masked AES S-Box Implementation
## Based on Canright Composite Field Inversion

This project implements a first-order masked AES S-Box using Canright's composite field inversion method.

AES SubBytes transformation is defined as:

b′ = A · b⁻¹ ⊕ c

Where:
- b⁻¹ is multiplicative inverse in GF(2⁸)
- A is affine transformation matrix
- c is affine constant vector

The most complex part of this computation is finding b⁻¹ securely.  
This implementation uses composite field arithmetic:

GF(2⁸) ≅ GF((2⁴)²)

---

## Mathematical Foundations

### Field Definitions

- AES field polynomial:
  x⁸ + x⁴ + x³ + x + 1

- GF(2⁴) polynomial:
  y⁴ + y + 1

- Tower field polynomial:
  x² + x + λ
  where λ = 0x8 (as per Canright)

---

## Implementation Steps

### 1. Forward Basis Transformation

Input byte $b \in GF(2^8)$ is mapped into tower representation:

A(x) = a₁x + a₀

Using fixed 8×8 matrix T:

AES basis → Tower basis

This is a linear transformation implemented using XOR networks.

---

### 2. Compute Tower Field Denominator

D = a₁²λ ⊕ a₀a₁ ⊕ a₀²

All operations performed in GF(2⁴).

---

### 3. Compute D⁻¹ Using Exponentiation

Since GF(2⁴) has 16 elements:

D⁻¹ = D¹⁴

Exponentiation is implemented as:

D¹⁴ = D⁸ · D⁴ · D²

Where:
- Squaring operations are linear
- Multiplications are nonlinear

---

## Masking Strategy (First-Order Boolean Masking)

To protect against power analysis attacks:

D is split into two shares:

D = D₁ ⊕ D₂

All nonlinear multiplications use masked multiplication:

C₁ = A₁B₁ ⊕ R  
C₂ = A₁B₂ ⊕ A₂B₁ ⊕ A₂B₂ ⊕ R  

Where:
- R is fresh randomness
- C = C₁ ⊕ C₂ gives correct result
- Randomness cancels upon recombination

Squaring is linear:

(a ⊕ b)² = a² ⊕ b²

So squaring is performed independently per share.

---

### 4. Compute A⁻¹

After obtaining D⁻¹:

A⁻¹ = D⁻¹ · (a₁x + a₀)

Which yields:

new_a₁ = D⁻¹ · a₁  
new_a₀ = D⁻¹ · a₀  

All operations in GF(2⁴).

Masked multipliers are used here as well.

---

### 5. Inverse Basis Transformation

The inverted tower element:

(new_a₁, new_a₀)

is converted back to AES polynomial basis using fixed matrix T⁻¹.

This is again a linear XOR network.

---

### 6. Affine Transformation

Final SubBytes output is computed as:

b′ = A · b⁻¹ ⊕ c

Where:
- A is fixed 8×8 affine matrix
- c is constant vector
- Linear operation (safe for masking)

---

## Security Notes

- All nonlinear GF(2⁴) multiplications are masked.
- Fresh randomness is injected per multiplication.
- Linear transformations (basis + affine) are applied per share independently.
- Shares must never be recombined internally before final output.

---

## Verification Requirement

The final S-Box must match the official AES S-Box table exactly.

Example test vector:

S(0x53) = 0xED

All 256 values must match FIPS-197 specification.

---

## Design Characteristics

- Composite field inversion (area efficient)
- First-order Boolean masking
- No lookup tables
- XOR + AND based arithmetic
- Suitable for ASIC side-channel resistant implementations

---