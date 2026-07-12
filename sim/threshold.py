"""
NIST SP 800-90B Compliant Health Test Threshold Calculator
===========================================================
Computes thresholds for:
  - Repetition Count Test (RCT)
  - Adaptive Proportion Test (APT)

Reference: NIST SP 800-90B Section 4.4
https://doi.org/10.6028/NIST.SP.800-90B

Parameters used:
  alpha  = 0.01    (false positive probability, NIST standard)
  H_min  = 0.9982  (measured min-entropy for 13 INV, 32 RO configuration)
"""

from scipy.stats import binom
import math

# ─── Parameters ───────────────────────────────────────────────────────────────
ALPHA  = 0.01     # false positive probability (NIST standard)
H_MIN  = 0.9982   # measured min-entropy per bit (your design's measured value)
W      = 1024     # APT window size (fixed by NIST SP 800-90B for binary sources)
# ──────────────────────────────────────────────────────────────────────────────

# p = most likely symbol probability, derived from min-entropy
# From NIST SP 800-90B Section 6.3.1:
#   p = 2^(-H_min)
# This is the probability of the MOST LIKELY symbol.
# For a nearly balanced source (H_min close to 1), p is close to 0.5.
p = 2 ** (-H_MIN)

print("=" * 60)
print("NIST SP 800-90B Health Test Threshold Calculator")
print("=" * 60)
print(f"\nInput Parameters:")
print(f"  alpha  = {ALPHA}   (false positive probability)")
print(f"  H_min  = {H_MIN}  (measured min-entropy per bit)")
print(f"  p      = 2^(-{H_MIN}) = {p:.6f}  (most likely symbol probability)")
print(f"  W      = {W}     (APT window size, fixed by NIST for binary sources)")

# ─── RCT Threshold ────────────────────────────────────────────────────────────
# NIST SP 800-90B Section 4.4.1, Formula:
#
#   C = ceil(-log2(alpha) / H_min) + 1
#
# Interpretation: how many consecutive identical bits must appear before
# the probability of that run occurring by chance drops below alpha.
print("\n" + "=" * 60)
print("Repetition Count Test (RCT)")
print("=" * 60)
print("Formula (NIST SP 800-90B Section 4.4.1):")
print("  C = ceil( -log2(alpha) / H_min ) + 1\n")

rct_inner  = -math.log2(ALPHA) / H_MIN
rct_C      = math.ceil(rct_inner) + 1

print(f"  -log2({ALPHA})        = {-math.log2(ALPHA):.6f}")
print(f"  ceil(...)          = {math.ceil(rct_inner)}")
print(f"  + 1                = {rct_C}")
print(f"\n  RCT Threshold C = {rct_C}")
print(f"\n  Interpretation: flag error if {rct_C} or more consecutive")
print(f"  identical bits are observed in the raw bitstream.")

# ─── APT Threshold ────────────────────────────────────────────────────────────
# NIST SP 800-90B Section 4.4.2, Formula:
#
#   C = 1 + iCDF_Binomial(W, p, 1 - alpha)
#
# where iCDF_Binomial(n, p, q) is the smallest integer C such that:
#   P(X <= C) >= q     i.e. the quantile function
#
# Equivalently, find smallest C such that:
#   P(X >= C) <= alpha
# where X ~ Binomial(W, p)
#
# The +1 shift is explicit in the NIST spec to ensure the inequality
# P(X >= C) <= alpha is strictly satisfied.
print("\n" + "=" * 60)
print("Adaptive Proportion Test (APT)")
print("=" * 60)
print("Formula (NIST SP 800-90B Section 4.4.2):")
print("  C = 1 + iCDF_Binomial(W, p, 1 - alpha)\n")
print("Equivalent condition: find smallest C such that P(X >= C) <= alpha")
print(f"where X ~ Binomial(W={W}, p={p:.6f})\n")

# binom.ppf(q, n, p) = quantile function = iCDF
# gives largest k such that P(X <= k) <= q
apt_icdf = binom.ppf(1 - ALPHA, W, p)
apt_C    = int(apt_icdf) + 1

# Verify the result
prob_geq_C   = binom.sf(apt_C - 1, W, p)    # P(X >= C)   = 1 - P(X <= C-1)
prob_geq_Cm1 = binom.sf(apt_C - 2, W, p)    # P(X >= C-1) — should exceed alpha

print(f"  iCDF_Binomial({W}, {p:.6f}, {1-ALPHA}) = {apt_icdf}")
print(f"  C = {apt_icdf} + 1 = {apt_C}")
print(f"\nVerification:")
print(f"  P(X >= {apt_C})   = {prob_geq_C:.6f}  (must be <= alpha={ALPHA}) {'✅' if prob_geq_C <= ALPHA else '❌'}")
print(f"  P(X >= {apt_C-1}) = {prob_geq_Cm1:.6f}  (must be >  alpha={ALPHA}) {'✅' if prob_geq_Cm1 > ALPHA else '❌'}")
print(f"\n  APT Threshold C = {apt_C}")
print(f"\n  Interpretation: within any {W}-bit window, count occurrences")
print(f"  of the most frequent bit. Flag error if count >= {apt_C}.")

# ─── Summary ──────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("Summary — Localparam values for SystemVerilog")
print("=" * 60)
print(f"""
  localparam int RCT_THRESHOLD = {rct_C};   // C for Repetition Count Test
  localparam int APT_WINDOW    = {W};  // W for Adaptive Proportion Test
  localparam int APT_THRESHOLD = {apt_C};  // C for Adaptive Proportion Test
""")
print("=" * 60)