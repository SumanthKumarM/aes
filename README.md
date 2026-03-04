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

T · b = {a₁, a₀}

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