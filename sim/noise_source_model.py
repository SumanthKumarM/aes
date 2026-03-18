"""
ro_noise_model.py
=================
Physics-grounded Ring Oscillator (RO) TRNG Noise Source Model
==============================================================

Models the TRNG noise source described in:
  "A High-Entropy True Random Number Generator with Keccak Conditioning for FPGA"
  Piscopo et al., Sensors 2025, 25, 1678.

The noise model is based on the Valtchanov et al. jitter model [1], which is also
cited and used in the paper's own simulation methodology (Section 4.1.2).

Physics modeled
---------------
1.  **Thermal noise (Johnson-Nyquist)** — White Gaussian phase noise accumulated
    per inverter stage, proportional to kT/P.  This is the dominant true-entropy
    source in CMOS ring oscillators.

2.  **Flicker (1/f) noise** — Low-frequency phase noise that accumulates as a
    correlated random walk (Wiener process integrated with 1/f PSD weighting via
    an IIR approximation).  Modeled as a sum of AR(1) processes with geometrically
    spaced poles (Kasdin-Walter approximation) [2].

3.  **Supply voltage fluctuation** — White noise on VDD drives both a deterministic
    frequency shift (through the Vchar model) and an additional Gaussian jitter
    component added to each stage.

4.  **Thermal drift** — Slow deterministic frequency drift with temperature,
    captured by the empirical CMOS delay vs T relation (linear model around
    nominal T).

5.  **Correlated inter-stage jitter accumulation** — Jitter does not reset each
    period; it accumulates across inverter stages as a random walk (Brownian
    motion on the phase), matching the Valtchanov model [1].

6.  **XOR combination of N_RO parallel ring oscillators** — Each RO has an
    independently drawn mean delay (process variation, ~0.5% sigma Gaussian),
    so their frequencies differ slightly, contributing to de-correlation.

7.  **Sampler (DFF) metastability** — When the RO output edge lands within a
    metastability window τ_meta of the sampling clock edge, the DFF output is
    resolved probabilistically using the standard exponential resolution model.

References
----------
[1] Valtchanov et al., "Modeling and observing the jitter in ring oscillators
    implemented in FPGAs," DDECS 2008.
[2] Kasdin, N.J., "Discrete simulation of colored noise and stochastic processes,"
    Proc. IEEE 1995.

Configuration matches the paper's chosen optimum:
  N_RO  = 32 parallel ring oscillators
  N_INV = 13 inverters per RO
  fs    = 150 MHz  (sampling clock — the clk fed to the DFF sampler)
  The RO free-running frequency is ~270 MHz for 13-stage CMOS at 1 V / 25 °C.
"""

import numpy as np
from dataclasses import dataclass, field
from typing import Optional
import time

K_BOLTZMANN   = 1.380649e-23   # J/K
Q_ELECTRON    = 1.602176634e-19 # C

# ---------------------------------------------------------------------------
# Default process/technology parameters  (Artix-7 / 28 nm planar CMOS)
# These are representative values from published CMOS characterisation data
# and match the mean inverter delay range [275, 282] ps stated in the paper.
# ---------------------------------------------------------------------------

@dataclass
class ProcessParams:
    """Technology and operating-point parameters."""

    # ---- Inverter delay model  (Elmore / FO4 based) ----------------------
    tau0_mean_ps: float = 278.5    # nominal mean gate delay [ps]
    tau0_sigma_ps: float = 1.4     # inter-die process variation sigma [ps]
                                   #  (~0.5% of tau0, typical for FPGA LUT)

    # ---- Thermal noise parameters ----------------------------------------
    # Jitter variance per stage: (sigma)²_stage = (8/3η) · (kT/P) · (VDD/Vchar)
    # We use the Valtchanov parameterisation: (sigma)_stage = c_th · sqrt(tau0)
    # c_th derived from kT/P ratio for a minimum-sized CMOS inverter at 1 V.
    eta: float = 1.0               # technology-dependent noise constant (≈1)
    vchar_V: float = 0.2           # characteristic CMOS voltage [V]
    P_inv_W: float = 50e-6         # dynamic power per inverter [W]
    VDD_V: float = 1.0             # nominal supply voltage [V]
    T_K: float = 298.15            # nominal temperature [K]  (25 °C)

    # ---- Flicker (1/f) noise model (Kasdin–Walter AR approximation) ------
    n_flicker_poles: int = 4       # number of AR(1) poles for 1/f approximation
    flicker_alpha: float = 1.0     # 1/f^alpha; alpha=1 is true flicker noise
    flicker_scale: float = 5e-5    # relative magnitude of 1/f vs thermal jitter

    # ---- Supply noise model ----------------------------------------------
    vdd_noise_sigma_frac: float = 0.005   # VDD noise as fraction of VDD (0.5%)
    vdd_noise_bw_hz: float = 10e6         # bandwidth of supply noise [Hz]

    # ---- Temperature model -----------------------------------------------
    # CMOS delay increases ~0.3%/°C (empirical for Artix-7 at 1 V)
    dTau_dT_frac: float = 0.003    # fractional delay change per K

    # ---- Metastability model (DFF) ----------------------------------------
    tau_meta_s: float = 10e-12     # metastability resolution time constant [s]
    t_meta_window_s: float = 5e-12 # setup+hold window around clk edge [s]

    # ---- XOR tree + final DFF --------------------------------------------
    # No additional parameters needed; the final DFF uses the same metastability model.


@dataclass
class RingOscillatorConfig:
    """Ring oscillator array configuration."""
    n_ro: int = 32          # number of parallel ROs
    n_inv: int = 13         # inverters per RO (must be odd)
    fs_Hz: float = 150e6    # sampling clock frequency [Hz]


# ---------------------------------------------------------------------------
# Helper: Kasdin–Walter 1/f noise generator state
# ---------------------------------------------------------------------------

class FlickerNoiseState:
    """
    Approximate 1/f^alpha noise via a bank of AR(1) processes with
    geometrically spaced poles (Kasdin–Walter method, Proc. IEEE 1995).

    The sum of N AR(1) processes h[k] = a_i * h_{k-1} + w_i approximates
    1/f^alpha noise when the pole radii a_i are chosen appropriately.
    """

    def __init__(self, n_poles: int, alpha: float, scale: float, rng: np.random.Generator):
        self.n_poles = n_poles
        self.alpha   = alpha
        self.scale   = scale
        self.rng     = rng
        # Distribute pole radii logarithmically between 0.01 and 0.999
        log_a = np.linspace(np.log(0.01), np.log(0.999), n_poles)
        self.a = np.exp(log_a)                        # pole radii
        # Variance of white driving noise for each pole:
        # Weight so that higher-frequency poles contribute less (1/f shaping)
        weights = (1.0 - self.a**2) ** (alpha / 2.0)
        self.sigma_w = scale * weights / weights.sum()
        self.state   = np.zeros(n_poles)

    def next_sample(self) -> float:
        """Generate one sample of 1/f noise [ps]."""
        w = self.rng.normal(0.0, 1.0, self.n_poles) * self.sigma_w
        self.state = self.a * self.state + w
        return float(self.state.sum())


# ---------------------------------------------------------------------------
# Single Ring Oscillator model
# ---------------------------------------------------------------------------

class RingOscillator:
    """
    Models one ring oscillator with physics-grounded jitter accumulation.

    The phase of the RO is tracked as accumulated delay [ps].  Each half-period
    (one pass through all N_INV inverters) the phase advances by:

        Δt = N_INV * τ_stage + (sigma) δ_i

    where δ_i are per-stage random jitter contributions (thermal + flicker +
    supply noise), accumulated as a random walk — exactly the Valtchanov model.

    The RO output is a square wave; we track rising-edge times in ps.
    """

    def __init__(
        self,
        cfg: RingOscillatorConfig,
        proc: ProcessParams,
        rng: np.random.Generator,
        ro_index: int = 0,
    ):
        self.cfg  = cfg
        self.proc = proc
        self.rng  = rng
        self.idx  = ro_index

        # Draw this RO's mean inverter delay from process variation distribution
        self.tau0_ps = rng.normal(proc.tau0_mean_ps, proc.tau0_sigma_ps)

        # Compute nominal half-period [ps]: N_INV inverter delays
        self.T_half_nom_ps = cfg.n_inv * self.tau0_ps

        # ---- Thermal jitter sigma per stage [ps] --------------------------
        # (sigma)²_stage = (8 / 3η) · (kT / P) · (VDD / Vchar) · tau0
        # (Valtchanov model, equation from the paper's referenced jitter model)
        kT_over_P = (K_BOLTZMANN * proc.T_K) / proc.P_inv_W
        sigma2_stage_norm = (8.0 / (3.0 * proc.eta)) * kT_over_P * (proc.VDD_V / proc.vchar_V)
        # Scale by tau0 to get physical units [ps²]
        self.sigma_thermal_ps = np.sqrt(sigma2_stage_norm * self.tau0_ps * 1e-12) * 1e12
        # Clamp to a physically reasonable range
        self.sigma_thermal_ps = float(np.clip(self.sigma_thermal_ps, 0.01, 5.0))

        # ---- Supply noise contribution per stage --------------------------
        # ΔV_DD causes Δτ ≈ tau0 · (ΔV/V) · (dτ/dV / τ)
        # We model as additional Gaussian jitter ∝ VDD noise sigma
        self.sigma_supply_ps = (
            proc.tau0_mean_ps
            * proc.vdd_noise_sigma_frac
            * 0.4   # empirical sensitivity factor for CMOS delay vs VDD
        )

        # ---- 1/f flicker noise state per RO --------------------------------
        self.flicker = FlickerNoiseState(
            proc.n_flicker_poles,
            proc.flicker_alpha,
            proc.flicker_scale * self.tau0_ps,
            rng,
        )

        # ---- Supply noise low-pass filter state ---------------------------
        # AR(1) with pole chosen to match bandwidth vdd_noise_bw_hz
        # a = exp(-2π · BW · T_half)  where T_half ≈ T_half_nom_ps
        T_half_s    = self.T_half_nom_ps * 1e-12
        bw          = proc.vdd_noise_bw_hz
        self.a_vdd  = np.exp(-2.0 * np.pi * bw * T_half_s)
        self.vdd_state = 0.0   # filtered supply noise [V]

        # ---- Temperature-induced frequency shift --------------------------
        # Δτ = τ0 · dTau_dT_frac · (T - T_nom)  [ps]
        self.dTau_dT = proc.tau0_mean_ps * proc.dTau_dT_frac  # [ps/K]

        # ---- Phase accumulator -------------------------------------------
        # current_time_ps: absolute time of the most recent RO rising edge [ps]
        self.current_time_ps: float = rng.uniform(0.0, 2.0 * self.T_half_nom_ps)
        self.output_bit: int = 0   # current logic level of this RO

    def advance_to_next_edge(self, temperature_K: float) -> float:
        """
        Advance to the next output edge and return its absolute time [ps].

        Jitter accumulation (random walk on phase):
          Each half-period, all N_INV stage jitters are summed.
          Thermal jitter: each stage contributes i.i.d. N(0, (sigma)_th²) [ps]
          Flicker jitter: one correlated sample per half-period [ps]
          Supply jitter:  filtered VDD noise → additional stage jitter [ps]
          Temp shift:     deterministic shift from current temperature [ps]
        """
        n = self.cfg.n_inv
        proc = self.proc

        # --- Thermal jitter: sum of N_INV i.i.d. Gaussian stage jitters ---
        # Var(sum) = N_INV * sigma²_stage  →  sigma_total = sigma_stage * sqrt(N)
        jitter_thermal_ps = self.rng.normal(0.0, self.sigma_thermal_ps * np.sqrt(n))

        # --- Supply noise: low-pass filtered white noise on VDD -----------
        w_vdd = self.rng.normal(0.0, proc.vdd_noise_sigma_frac * proc.VDD_V)
        self.vdd_state = self.a_vdd * self.vdd_state + (1.0 - self.a_vdd) * w_vdd
        # Convert VDD perturbation to delay perturbation [ps] for all stages
        jitter_supply_ps = (
            n * self.tau0_ps * (self.vdd_state / proc.VDD_V) * 0.4
            + self.rng.normal(0.0, self.sigma_supply_ps * np.sqrt(n))
        )

        # --- Flicker noise: one correlated sample per half-period ----------
        jitter_flicker_ps = self.flicker.next_sample()

        # --- Temperature-induced deterministic delay shift ----------------
        delta_T = temperature_K - proc.T_K
        temp_shift_ps = n * self.dTau_dT * delta_T

        # --- Total half-period --------------------------------------------
        T_half_ps = (
            self.T_half_nom_ps
            + jitter_thermal_ps
            + jitter_supply_ps
            + jitter_flicker_ps
            + temp_shift_ps
        )

        # Advance time and toggle output
        self.current_time_ps += max(T_half_ps, 1.0)   # prevent negative periods
        self.output_bit ^= 1
        return self.current_time_ps


# ---------------------------------------------------------------------------
# DFF Sampler with metastability model
# ---------------------------------------------------------------------------

def sample_with_metastability(
    data_bit: int,
    edge_offset_ps: float,
    proc: ProcessParams,
    rng: np.random.Generator,
) -> int:
    """
    Model a DFF sampling 'data_bit' when the data edge is 'edge_offset_ps'
    from the clock edge.

    If |edge_offset_ps| < t_meta_window/2, the DFF enters metastability and
    resolves to 0 or 1 with probability given by the exponential resolution
    model:  P(resolve correctly) = 1 - exp(-|Δt| / τ_meta)
    Otherwise the DFF captures the current data value deterministically.
    """
    t_meta_half_ps = (proc.t_meta_window_s * 1e12) / 2.0
    tau_meta_ps    = proc.tau_meta_s * 1e12

    if abs(edge_offset_ps) < t_meta_half_ps:
        # Metastable region: resolve probabilistically
        p_correct = 1.0 - np.exp(-abs(edge_offset_ps) / tau_meta_ps)
        if rng.random() < p_correct:
            return data_bit
        else:
            return 1 - data_bit   # bit flip due to metastability resolution
    else:
        return data_bit


# ---------------------------------------------------------------------------
# Noise Source Array: N_RO parallel ROs + XOR + DFF sampler
# ---------------------------------------------------------------------------

class NoiseSourceArray:
    """
    Models the complete noise source block described in the paper (Figure 2):
      - N_RO parallel ring oscillators, each with N_INV inverters
      - DFF sampler on each RO output
      - XOR tree combining all sampled outputs
      - Final DFF on the XOR output (sampled at fs_Hz)

    This matches the Sunar/Wold architecture used in the paper.
    """

    def __init__(
        self,
        cfg: RingOscillatorConfig,
        proc: ProcessParams,
        seed: Optional[int] = None,
        temperature_C: float = 25.0,
    ):
        self.cfg   = cfg
        self.proc  = proc
        self.rng   = np.random.default_rng(seed)
        self.T_K   = temperature_C + 273.15

        # Sampling period [ps]
        self.Ts_ps = 1e12 / cfg.fs_Hz

        # Instantiate all ring oscillators
        self.ros = [
            RingOscillator(cfg, proc, self.rng, i)
            for i in range(cfg.n_ro)
        ]

        # Current absolute simulation time [ps]
        self.sim_time_ps: float = 0.0

        # Pre-compute next edge times for all ROs
        self._next_edge_ps = np.array([
            ro.current_time_ps for ro in self.ros
        ], dtype=np.float64)

    def _advance_ro_to_time(self, ro: RingOscillator, target_ps: float) -> int:
        """
        Advance RO past all edges up to target_ps.
        Returns the RO output bit at target_ps.
        """
        while ro.current_time_ps <= target_ps:
            ro.advance_to_next_edge(self.T_K)
        return ro.output_bit

    def next_sample_bit(self) -> int:
        """
        Advance simulation by one sampling period and return the random bit.

        Process:
          1. Advance simulation time by Ts_ps
          2. For each RO, advance all edges that occurred in this interval
          3. Sample each RO output (with metastability check)
          4. XOR all sampled bits
          5. Final DFF samples XOR output (with metastability)
        """
        self.sim_time_ps += self.Ts_ps

        # Determine offset of each RO's last edge from the sampling clock edge
        xor_val = 0
        for ro in self.ros:
            # Advance all RO edges up to current sampling time
            bit = self._advance_ro_to_time(ro, self.sim_time_ps)

            # Edge offset: time since last RO edge vs sampling edge
            # (used for metastability check)
            last_edge_ps = ro.current_time_ps - ro.T_half_nom_ps  # approx last edge
            edge_offset  = (self.sim_time_ps - last_edge_ps) % ro.T_half_nom_ps
            # Centre around zero: [-T_half/2, T_half/2]
            if edge_offset > ro.T_half_nom_ps / 2.0:
                edge_offset -= ro.T_half_nom_ps

            # DFF sampler with metastability
            sampled = sample_with_metastability(bit, edge_offset, self.proc, self.rng)
            xor_val ^= sampled

        # Final DFF (after XOR tree) — metastability modeled with zero edge offset
        # since the XOR output is a combinational function; its transition time
        # is the maximum of all input transition times, which is not tracked
        # explicitly here. We apply a small random offset to model this.
        final_offset = self.rng.normal(0.0, 2.0)   # ~2 ps uncertainty
        raw_rand_bit = sample_with_metastability(xor_val, final_offset, self.proc, self.rng)

        return raw_rand_bit

    def generate_bits(self, n_bits: int, verbose: bool = False) -> np.ndarray:
        """
        Generate n_bits random bits at the sampling clock rate.

        Returns
        -------
        np.ndarray of dtype uint8, shape (n_bits,), values in {0, 1}.
        """
        bits = np.empty(n_bits, dtype=np.uint8)
        t0 = time.perf_counter()
        for i in range(n_bits):
            bits[i] = self.next_sample_bit()
            if verbose and (i + 1) % 10000 == 0:
                elapsed = time.perf_counter() - t0
                rate    = (i + 1) / elapsed
                sim_us  = self.sim_time_ps / 1e6
                print(f"  [{i+1:,} / {n_bits:,}]  "
                      f"sim_time={sim_us:.1f} µs  "
                      f"rate={rate:.0f} bits/s")
        return bits

    def set_temperature(self, temperature_C: float):
        """Update operating temperature."""
        self.T_K = temperature_C + 273.15

    def set_voltage(self, vdd_V: float):
        """Update supply voltage (recalculates all RO noise parameters)."""
        self.proc.VDD_V = vdd_V
        for ro in self.ros:
            # Recompute thermal sigma with new VDD
            kT_over_P = (K_BOLTZMANN * self.T_K) / self.proc.P_inv_W
            sigma2_stage_norm = (
                (8.0 / (3.0 * self.proc.eta))
                * kT_over_P
                * (vdd_V / self.proc.vchar_V)
            )
            ro.sigma_thermal_ps = float(
                np.clip(np.sqrt(sigma2_stage_norm * ro.tau0_ps * 1e-12) * 1e12, 0.01, 5.0)
            )


# ---------------------------------------------------------------------------
# Convenience wrapper: bit-stream generator matching RTL interface
# ---------------------------------------------------------------------------

class TRNGNoiseSource:
    """
    Drop-in replacement for the RTL's noise source behavioural model.
    Provides:
      - next_bit()           → one raw random bit (at sampling_clk rate)
      - generate_word(n)     → n-bit integer
      - generate_bytes(n)    → bytes object of n random bytes
    """

    def __init__(
        self,
        n_ro: int = 32,
        n_inv: int = 13,
        fs_MHz: float = 150.0,
        temperature_C: float = 25.0,
        vdd_V: float = 1.0,
        seed: Optional[int] = None,
    ):
        proc = ProcessParams(VDD_V=vdd_V, T_K=temperature_C + 273.15)
        cfg  = RingOscillatorConfig(n_ro=n_ro, n_inv=n_inv, fs_Hz=fs_MHz * 1e6)
        self.array = NoiseSourceArray(cfg, proc, seed=seed, temperature_C=temperature_C)
        self._fs_MHz = fs_MHz

    def next_bit(self) -> int:
        return self.array.next_sample_bit()

    def generate_bits(self, n: int, verbose: bool = False) -> np.ndarray:
        return self.array.generate_bits(n, verbose=verbose)

    def generate_word(self, n_bits: int) -> int:
        """Generate an n_bits-wide integer."""
        bits = self.generate_bits(n_bits)
        val  = 0
        for b in bits:
            val = (val << 1) | int(b)
        return val

    def generate_bytes(self, n_bytes: int) -> bytes:
        """Generate n_bytes of random data."""
        bits = self.generate_bits(n_bytes * 8)
        result = bytearray(n_bytes)
        for i in range(n_bytes):
            byte_val = 0
            for j in range(8):
                byte_val = (byte_val << 1) | int(bits[i * 8 + j])
            result[i] = byte_val
        return bytes(result)

    def set_temperature(self, t_C: float):
        self.array.set_temperature(t_C)

    def set_voltage(self, vdd_V: float):
        self.array.set_voltage(vdd_V)

    @property
    def sampling_freq_MHz(self) -> float:
        return self._fs_MHz


# ---------------------------------------------------------------------------
# Basic statistical validation
# ---------------------------------------------------------------------------

def run_basic_validation(n_bits: int = 100_000, seed: Optional[int] = None):
    """
    Run a quick sanity check on the generated bitstream:
      - Bias (mean)
      - Run-length distribution
      - Autocorrelation at lag 1
    These are precursors to formal NIST SP 800-22 tests.
    """

    # If seed is still None here, we can generate one from the clock 
    # or just let the TRNGNoiseSource handle the None value
    if seed is None:
        seed = int(time.time() * 1000) % 2**32
    print(f"Simulation Seed: {seed}")

    print("=" * 60)
    print("RO TRNG Noise Source — Physics Model Validation")
    print("=" * 60)
    print(f"Config: 32 ROs x 13 INV, fs=150 MHz, T=25°C, VDD=1V")
    print(f"Generating {n_bits:,} bits...\n")

    src  = TRNGNoiseSource(seed=seed)
    bits = src.generate_bits(n_bits, verbose=True)

    # Bias
    mean = bits.mean()
    print(f"\n--- Basic Statistics ---")
    print(f"  Bit mean (ideal=0.5):        {mean:.6f}")
    print(f"  Bias from 0.5:               {abs(mean - 0.5):.6f}")

    # Autocorrelation at lag 1
    b = bits.astype(np.float32) - mean
    ac1 = float(np.correlate(b[:-1], b[1:])[0]) / (b.std()**2 * (len(b) - 1))
    print(f"  Autocorrelation lag-1:       {ac1:.6f}  (ideal≈0)")

    # Run-length test (simplified)
    transitions = int(np.sum(np.diff(bits.astype(int)) != 0))
    expected_trans = n_bits // 2
    print(f"  Transitions:                 {transitions:,}  (expected≈{expected_trans:,})")

    # Jitter statistics from one RO
    ro = src.array.ros[0]
    print(f"\n--- RO[0] Physical Parameters ---")
    print(f"  Mean inverter delay τ0:      {ro.tau0_ps:.3f} ps")
    print(f"  Nominal half-period:         {ro.T_half_nom_ps:.2f} ps")
    print(f"  Nominal RO frequency:        {1e12 / (2 * ro.T_half_nom_ps):.1f} MHz")
    print(f"  Thermal jitter (sigma) (per half): {ro.sigma_thermal_ps * np.sqrt(ro.cfg.n_inv):.4f} ps")
    print(f"  Supply jitter (sigma) (per half):  {ro.sigma_supply_ps * np.sqrt(ro.cfg.n_inv):.4f} ps")

    print("\n--- Frequency spread across 32 ROs (process variation) ---")
    freqs = [1e12 / (2 * r.T_half_nom_ps) for r in src.array.ros]
    print(f"  Min RO freq:  {min(freqs):.2f} MHz")
    print(f"  Max RO freq:  {max(freqs):.2f} MHz")
    print(f"  Mean RO freq: {np.mean(freqs):.2f} MHz")
    print(f"  (sigma) RO freq:    {np.std(freqs):.4f} MHz")

    print("\n✓ Validation complete.")
    return bits


# ---------------------------------------------------------------------------
# RTL co-simulation helper
# ---------------------------------------------------------------------------

class RTLBitFeeder:
    """
    Connects this model to an RTL simulation (e.g., cocotb or a custom
    Python-based RTL simulator) by providing bits on demand.

    Usage example (cocotb):
        feeder = RTLBitFeeder(fs_ratio=5)  # sampling_clk = 5x clk
        ...
        @cocotb.coroutine
        async def noise_driver(dut):
            while True:
                await RisingEdge(dut.sampling_clk)
                dut.raw_rand_bit.value = feeder.next_raw_bit()
    """

    def __init__(
        self,
        n_ro: int = 32,
        n_inv: int = 13,
        fs_MHz: float = 150.0,
        temperature_C: float = 25.0,
        vdd_V: float = 1.0,
        seed: Optional[int] = None,
    ):
        self.src = TRNGNoiseSource(n_ro, n_inv, fs_MHz, temperature_C, vdd_V, seed)
        self._bit_count = 0

    def next_raw_bit(self) -> int:
        """Call this once per rising edge of sampling_clk."""
        self._bit_count += 1
        return self.src.next_bit()

    @property
    def bits_generated(self) -> int:
        return self._bit_count


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    n_bits = int(sys.argv[1]) if len(sys.argv) > 1 else 100_000
    bits   = run_basic_validation(n_bits=n_bits)

    # Optionally write raw bits to a file for NIST SP 800-22 / SP 800-90B testing
    out_file = "ro_raw_bits.bin"
    # Pack bits into bytes and save
    n_pad    = (8 - len(bits) % 8) % 8
    padded   = np.concatenate([bits, np.zeros(n_pad, dtype=np.uint8)])
    packed   = np.packbits(padded)
    packed.tofile(out_file)
    print(f"\nRaw bitstream written to '{out_file}' ({len(packed)} bytes).")
    print("Feed this file to NIST SP 800-22 / SP 800-90B test tools for formal validation.")