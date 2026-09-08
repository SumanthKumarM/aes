"""
Verification environment for the AES top block -- bus layer, stimulus, checkers.

`aes_sequence.py` holds the tests; this module holds everything they stand on, so a
test body reads as a sequence of intentions rather than a pile of signal pokes.

WHAT THE DUT IS
---------------
`aes.sv` cannot be a Verilator simulation top: its only port is a SystemVerilog
interface. `rtl/aes_top.sv` -- generated on demand by `rtl/gen_top.py`, like every
other `*_top.sv` in this project -- is a flat-port wrapper that instantiates
`aes_interface` internally and re-exposes every member as an ordinary port; it
contains no logic, so the DUT under test is exactly `aes.sv`. Run it with
`make run_test_suite block=aes_top`, which regenerates the wrapper first.

THE HANDSHAKE, AND WHY THE DRIVER HAS A "HOLD STYLE"
----------------------------------------------------
aes.sv:81-88 documents a Case-1 / AXI-Stream discipline: the sender holds
`inVALID` / `input_block` / `first` stable only until it observes `inREADY`, and
is free to advance immediately after. `HoldStyle.CASE1` implements exactly that
and is the default, because it is the contract the design says it honours.

But several sideband signals are read by the RTL in the SHOOT state, i.e. long
after `inREADY` has been seen and a Case-1 sender has dropped them:
`first` on the CBC decrypt path (aes.sv:460-461), and `partial` / `valid_bits`
in OFB and CTR (aes.sv:636-637, 685-686). `HoldStyle.THROUGH_OUTPUT` keeps them
asserted until `outVALID`, which is the Case-2 discipline the interface
explicitly rejected. Having both lets a test *demonstrate* that a signal needs
the discipline the interface does not promise, instead of quietly adopting
whichever one happens to make the DUT pass.

SAMPLING CONVENTION
-------------------
Two rules, applied consistently:

  * Active driving/handshaking samples on `RisingEdge`. After
    `await RisingEdge(clk)` a registered DUT output holds the value it took at
    that edge, so `inREADY == 1` there means the transfer happened at that edge.
  * Passive checkers sample on `FallingEdge`, so they read the settled value of
    the cycle in flight and can never race a driver assignment (which always
    lands just after a rising edge). This is the rule cbc_mac_tb.py adopted for
    the same reason.

`wait_signal()` has ONE signature here. Across the existing block TBs it has
three mutually incompatible ones (`(signal, value, timeout, clk)` in four files,
`(dut, signal, value, timeout)` in iv_gen_tb), which is a live trap as soon as
helpers get imported across modules.

ENTROPY
-------
Two noise sources in two different clock domains, which no existing TB has had
to do at once:
  * `raw_rand_bit_trng`  -> `trng` -> masked S-box. Sampled in the `sampling_clk`
    domain (aes.sv:191-199), so it is driven on `sampling_clk`.
  * `raw_rand_bit_cbc_mac` -> `iv_gen` -> `cbc_mac`. Sampled on the *gated main
    clock* (aes.sv:274-281), so it is driven on `clk`.
Both default to the physics RO model from sim/noise_source_model.py, with a
seeded-PRNG fallback and deterministic fault patterns for health-test tests.
"""

import logging
import os
import random
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, FallingEdge, RisingEdge

from aes_ref_model import (
    AesModeModel, CFB_SEG_CODE, KEY_SIZE_CODE, MASK128, MODE_CODE, rtl_hex,
)

# ---------------------------------------------------------------------------
# Simulation constants
# ---------------------------------------------------------------------------
CLK_PERIOD_NS = 10          # main clock, 100 MHz
SCLK_PERIOD_NS = 2          # noise-source sampling clock, 500 MHz
RESET_CYCLES = 8

# Measured on this DUT, not guessed:
#   197 clk  steady-state AES-128 block (413 for the first after reset, while
#            the Keccak conditioner fills), ~270 for AES-256
#   1078 clk from reset to the first IV (cbc_mac seed + DRBG instantiate +
#            first generate), measured by TC47
#   ~3200 clk for a CFB8 block -- 16 segments, one cipher run each
# Worst legitimate single wait is therefore a first CFB8-256 block behind a
# cold IV pipeline: ~1400 + 16*270 ~= 5700 clk. 20k leaves 3.5x margin while
# still catching a hang in a fifth of the time an 80k budget would.
BLOCK_TIMEOUT = 20_000      # per 128-bit block, any mode/segment size
IV_TIMEOUT = 20_000         # first IV after reset (seed + instantiate + generate)
HANDSHAKE_TIMEOUT = 20_000  # inREADY / outVALID
CONFIG_SETTLE = 25_000      # how long an inert-configuration test watches for

NOISE_POOL_BITS = int(os.environ.get("AES_TB_NOISE_BITS", "40000"))

_mon_log = logging.getLogger("cocotb.monitor")
_chk_log = logging.getLogger("cocotb.checker")
# Module-level messages (import-time fallbacks, noise-pool generation) go
# through a plain logger, not cocotb.log: this module is importable outside a
# running simulation and `cocotb.log` does not exist until cocotb initialises.
_tb_log = logging.getLogger("cocotb.tb")

# aes_modes_internal_states (rtl/type_defs_pkg.sv)
ST_ARM, ST_SHOOT = 0, 1
ST_NAMES = {ST_ARM: "ARM", ST_SHOOT: "SHOOT"}

# Mode values that select no mode case in aes.sv (the `default` branch).
INVALID_MODES = (0b000, 0b110, 0b111)
INVALID_CFB_SEGS = (0b000, 0b110, 0b111)


class HoldStyle(Enum):
    """How long the driver holds input-channel sideband signals.

    CASE1            -- drop as soon as inREADY is observed. The discipline
                        aes.sv:81-88 mandates.
    THROUGH_OUTPUT   -- hold until outVALID. The Case-2 discipline the interface
                        doc explicitly declined to require.
    """
    CASE1 = "case1"
    THROUGH_OUTPUT = "through_output"


@dataclass
class AesConfig:
    """One (mode, direction, key) configuration of the DUT."""
    mode: str                       # "ECB" / "CBC" / "CFB" / "OFB" / "CTR"
    key: bytes
    decrypt: bool = False
    cfb_seg_bits: int = 128         # only meaningful in CFB
    hold: HoldStyle = HoldStyle.CASE1

    @property
    def mode_value(self):
        """The 4-bit `mode` port value: mode[2:0] = mode, mode[3] = direction."""
        return MODE_CODE[self.mode] | (0b1000 if self.decrypt else 0)

    @property
    def key_size_code(self):
        return KEY_SIZE_CODE[len(self.key) * 8]

    @property
    def cfb_seg_code(self):
        return CFB_SEG_CODE[self.cfb_seg_bits] if self.mode == "CFB" else 0

    @property
    def segments_per_block(self):
        return 128 // self.cfb_seg_bits if self.mode == "CFB" else 1

    @property
    def needs_generated_iv(self):
        """True when the DUT must obtain an IV from iv_gen before it can start.
        CBC/CFB/OFB encryption generate internally; their decrypt paths and both
        CTR directions take the context from encCntxtIn instead."""
        return self.mode in ("CBC", "CFB", "OFB") and not self.decrypt

    def model(self):
        return AesModeModel(self.key)

    def __str__(self):
        seg = f"/s={self.cfb_seg_bits}" if self.mode == "CFB" else ""
        return (f"{self.mode}{seg}-{len(self.key)*8}"
                f"-{'dec' if self.decrypt else 'enc'}")


@dataclass
class BlockResult:
    """One completed output-channel transfer."""
    data: int
    enc_cntxt_out: int
    cycles: int


@dataclass
class MessageResult:
    """Everything a test needs after pushing a message through the DUT."""
    outputs: list = field(default_factory=list)
    enc_cntxt_out: int = 0          # sampled with the FIRST output block
    cycles: int = 0

    @property
    def hexes(self):
        return [rtl_hex(o) for o in self.outputs]


# ---------------------------------------------------------------------------
# Noise stimulus
# ---------------------------------------------------------------------------
try:
    from noise_source_model import TRNGNoiseSource
    _HAVE_PHYSICS = True
except ImportError:                                          # pragma: no cover
    _HAVE_PHYSICS = False
    _tb_log.warning("noise_source_model.py not importable -- PRNG noise only")

try:
    import numpy as np
    _HAVE_NUMPY = True
except ImportError:                                          # pragma: no cover
    _HAVE_NUMPY = False

_POOL_CACHE = {}


def _physics_pool(n_bits, seed):
    """Physics RO bits, generated once per (n_bits, seed) and reused.

    The model costs ~0.3 ms/bit, so regenerating per test would dominate
    runtime and regenerating per `make` invocation would still cost ten-odd
    seconds of dead time before the first test. Cached in-process first, then on
    disk next to the simulation directory -- the same two-tier scheme
    iv_gen_tb.py uses, for the same reason.
    """
    key = (n_bits, seed)
    if key in _POOL_CACHE:
        return _POOL_CACHE[key]

    cache_file = Path(__file__).resolve().parent.parent / "sim" / \
        f".cache_aes_noise_{n_bits}_{seed:x}.npy"
    if _HAVE_NUMPY and cache_file.exists():
        try:
            pool = [int(b) for b in np.load(cache_file)]
            if len(pool) >= n_bits:
                _POOL_CACHE[key] = pool[:n_bits]
                _tb_log.info(f"[noise] loaded {n_bits:,} cached physics bits "
                                f"from {cache_file.name}")
                return _POOL_CACHE[key]
        except (OSError, ValueError):
            pass

    if not _HAVE_PHYSICS:
        rng = random.Random(seed)
        pool = [rng.getrandbits(1) for _ in range(n_bits)]
    else:
        _tb_log.info(f"[noise] generating {n_bits:,} physics bits "
                        f"(32 RO x 13 INV @ 150 MHz, seed=0x{seed:X}) -- "
                        f"one-off, ~{n_bits * 0.31e-3:.0f}s, then cached")
        pool = [int(b) for b in TRNGNoiseSource(
            n_ro=32, n_inv=13, fs_MHz=150.0, seed=seed).generate_bits(n_bits)]
        _tb_log.info(f"[noise] done (mean={sum(pool)/len(pool):.4f}), caching")
        if _HAVE_NUMPY:
            try:
                np.save(cache_file, np.array(pool, dtype=np.uint8))
            except OSError:                                  # pragma: no cover
                _tb_log.warning(f"[noise] could not write {cache_file}")
    _POOL_CACHE[key] = pool
    return pool


class NoiseBits:
    """A raw-entropy bit stream for one noise input.

    Modes
    -----
    physics     RO physics model -- thermal + flicker + supply jitter and DFF
                metastability. The default for every normal-operation test.
    random      seeded uniform bits. Fallback when the model is unavailable.
    stuck_0     constant 0  -- trips the Repetition Count Test.
    stuck_1     constant 1  -- trips the Repetition Count Test.
    apt_trigger 3 ones then a zero -- 75% ones, well over the Adaptive
                Proportion threshold, but a maximum run of 3 so RCT cannot fire
                first. Lets a test aim at APT specifically.

    `offset` rotates the shared physics pool so two drivers (or two tests) get
    de-correlated streams without paying to generate the pool twice.
    """

    def __init__(self, mode="physics", offset=0, n_bits=NOISE_POOL_BITS, seed=0xAE5):
        self.mode = mode
        self._idx = 0
        if mode == "stuck_0":
            self._buf = [0]
        elif mode == "stuck_1":
            self._buf = [1]
        elif mode == "apt_trigger":
            self._buf = [1, 1, 1, 0]
        elif mode == "random":
            rng = random.Random(seed + offset)
            self._buf = [rng.getrandbits(1) for _ in range(n_bits)]
        else:
            pool = _physics_pool(n_bits, seed)
            off = offset % len(pool)
            self._buf = pool[off:] + pool[:off]

    def next_bit(self):
        b = self._buf[self._idx]
        self._idx = (self._idx + 1) % len(self._buf)
        return b


async def trng_noise_driver(dut, bits):
    """`raw_rand_bit_trng` lives in the sampling_clk domain (trng.sv 2-flop CDC)."""
    while True:
        await RisingEdge(dut.sampling_clk)
        dut.raw_rand_bit_trng.value = bits.next_bit()


async def cbcmac_noise_driver(dut, bits):
    """`raw_rand_bit_cbc_mac` is consumed one bit per gated main clock by
    cbc_mac's 128-bit SIPO collector."""
    while True:
        await RisingEdge(dut.clk)
        dut.raw_rand_bit_cbc_mac.value = bits.next_bit()


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------
def has_sig(handle, name):
    """True when `name` exists under `handle` (cocotb raises AttributeError)."""
    try:
        getattr(handle, name)
        return True
    except AttributeError:
        return False


def probe(dut, dotted):
    """Resolve a dotted hierarchical path, or None when it does not exist.
    Internal probes are a debugging aid, never a pass/fail dependency for the
    functional checks, so a missing one must degrade rather than crash."""
    obj = dut
    for part in dotted.split("."):
        if not has_sig(obj, part):
            return None
        obj = getattr(obj, part)
    return obj


def is_x(handle):
    """True when the handle currently holds any X/Z bit.

    No existing TB in this repo checks for X at all -- with `--x-assign 0` an
    uninitialised signal reads as 0 and a 'must be zero after reset' assertion
    passes for the wrong reason. These checks make that distinction visible.
    """
    try:
        return not handle.value.is_resolvable
    except AttributeError:                                   # pragma: no cover
        return False


async def wait_signal(dut, signal, value=1, timeout=HANDSHAKE_TIMEOUT, what=""):
    """Wait until `signal` reads `value`, sampling on the falling edge.

    Falling-edge sampling reads the settled value of the cycle in flight -- the
    same value the next rising edge will act on -- so a one-cycle pulse such as
    `inREADY` cannot be missed the way rising-edge polling can.

    Returns the number of cycles waited; raises with DUT context on timeout.
    """
    for i in range(timeout):
        await FallingEdge(dut.clk)
        if int(signal.value) == value:
            return i + 1
    raise AssertionError(
        f"TIMEOUT ({timeout} cycles): {what or signal._path} never reached "
        f"{value}. {dut_state(dut)}")


def dut_state(dut):
    """One-line snapshot of the DUT for use in failure messages."""
    parts = [
        f"mode=0x{int(dut.mode.value):x}",
        f"inVALID={int(dut.inVALID.value)}",
        f"inREADY={int(dut.inREADY.value)}",
        f"outVALID={int(dut.outVALID.value)}",
        f"outREADY={int(dut.outREADY.value)}",
    ]
    for name, path in (("fsm", "AES.fsm_state"), ("seg_cntr", "AES.seg_cntr"),
                       ("cipher_enb_n", "AES.cipher_enb_n"),
                       ("cipher_done", "AES.cipher_done"),
                       ("invCipher_enb_n", "AES.invCipher_enb_n"),
                       ("invCipher_done", "AES.invCipher_done"),
                       ("iv_valid", "AES.iv_valid"),
                       ("aes_iv_ready", "AES.aes_iv_ready"),
                       ("trng_dead", "AES.trng_dead_flag")):
        h = probe(dut, path)
        if h is not None:
            v = int(h.value)
            parts.append(f"{name}={ST_NAMES[v] if name == 'fsm' else v}")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Bring-up
# ---------------------------------------------------------------------------
def start_clocks(dut):
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, unit="ns").start())
    cocotb.start_soon(Clock(dut.sampling_clk, SCLK_PERIOD_NS, unit="ns").start())


def park_inputs(dut):
    """Drive every DUT input to its idle value."""
    dut.input_block.value = 0
    dut.encCntxtIn.value = 0
    dut.inVALID.value = 0
    dut.outREADY.value = 0
    dut.first.value = 0
    dut.mode.value = 0
    dut.key_size.value = 0
    dut.master_key.value = 0
    dut.cfb_seg_bits.value = 0
    dut.partial.value = 0
    dut.valid_bits.value = 0
    dut.raw_rand_bit_trng.value = 0
    dut.raw_rand_bit_cbc_mac.value = 0


async def reset_dut(dut, enable_during_reset=True):
    """Assert rst_n low for RESET_CYCLES, then release.

    `enb_n` is driven low during the pulse. aes.sv's ICG enable is
    `~enb_n | ~rst_n` (aes.sv:186-189), so the gated clock does run while reset
    is asserted regardless -- but a previous test can leave the DUT parked
    mid-transaction, and enabling during the pulse guarantees the clear is
    actually applied without depending on that ICG detail. This mirrors
    cipher_tb.reset_dut()'s reasoning for the identical gate.
    """
    park_inputs(dut)
    dut.rst_n.value = 0
    dut.enb_n.value = 0 if enable_during_reset else 1
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.rst_n.value = 1
    dut.enb_n.value = 0
    await RisingEdge(dut.clk)


async def bringup(dut, noise="physics", offset=0, monitor=False, checker=True):
    """Standard per-test bring-up.

    Returns an `Env` holding the started tasks so a test can stop the protocol
    checker (for a test that deliberately violates a rule) or swap the noise
    source mid-test (for health-test fault injection).
    """
    start_clocks(dut)
    await reset_dut(dut)
    env = Env(dut)
    env.trng_bits = NoiseBits(noise, offset=offset)
    env.cbcmac_bits = NoiseBits(noise, offset=offset + 7919)   # coprime stride
    env.trng_task = cocotb.start_soon(trng_noise_driver(dut, env.trng_bits))
    env.cbcmac_task = cocotb.start_soon(cbcmac_noise_driver(dut, env.cbcmac_bits))
    if checker:
        env.checker = ProtocolChecker(dut).start()
    if monitor:
        env.monitor_task = cocotb.start_soon(signal_monitor(dut))
    return env


class Env:
    """Handles to everything bringup() started, so tests can steer them."""

    def __init__(self, dut):
        self.dut = dut
        self.trng_bits = None
        self.cbcmac_bits = None
        self.trng_task = None
        self.cbcmac_task = None
        self.checker = None
        self.monitor_task = None

    def set_trng_noise(self, mode, offset=0):
        """Swap the masking TRNG's entropy mid-test (health-test injection)."""
        if self.trng_task:
            self.trng_task.cancel()
        self.trng_bits = NoiseBits(mode, offset=offset)
        self.trng_task = cocotb.start_soon(trng_noise_driver(self.dut, self.trng_bits))

    def set_cbcmac_noise(self, mode, offset=0):
        """Swap the IV generator's entropy mid-test."""
        if self.cbcmac_task:
            self.cbcmac_task.cancel()
        self.cbcmac_bits = NoiseBits(mode, offset=offset)
        self.cbcmac_task = cocotb.start_soon(
            cbcmac_noise_driver(self.dut, self.cbcmac_bits))

    def stop_checker(self):
        if self.checker:
            self.checker.stop()
            self.checker = None


# ---------------------------------------------------------------------------
# Continuous protocol checker
# ---------------------------------------------------------------------------
class ProtocolChecker:
    """Background assertions on the output channel, running every cycle.

    These are the invariants a VALID/READY producer owes its consumer, and they
    are checked continuously rather than at transfer points, because the
    interesting violations happen between transfers:

      C1  outVALID, once asserted, stays asserted until a cycle where outREADY
          is also high. Dropping VALID unilaterally loses a block.
      C2  output_block does not change while outVALID is high. A consumer is
          entitled to sample it on any cycle of the VALID window.
      C3  encCntxtOut does not change while outVALID is high, for the same
          reason -- it is part of the same output transfer.
      C4  no output carries X/Z once rst_n is high.

    Violations are recorded and re-raised by `check()` so one failure does not
    abort the run before the rest of the picture is collected.
    """

    def __init__(self, dut):
        self.dut = dut
        self.errors = []
        self._task = None
        self.enabled = True

    def start(self):
        self._task = cocotb.start_soon(self._run())
        return self

    def stop(self):
        if self._task:
            self._task.cancel()
            self._task = None

    def check(self):
        """Raise if anything was recorded. Call at the end of a test."""
        if self.errors:
            raise AssertionError(
                f"{len(self.errors)} output-channel protocol violation(s):\n  "
                + "\n  ".join(self.errors[:20])
                + ("\n  ..." if len(self.errors) > 20 else ""))

    def _record(self, msg):
        if len(self.errors) < 200:
            self.errors.append(msg)
        _chk_log.error(msg)

    async def _run(self):
        dut = self.dut
        prev_valid = 0
        prev_data = None
        prev_ctx = None
        prev_ready = 0
        cyc = 0
        while True:
            await FallingEdge(dut.clk)
            cyc += 1
            if not int(dut.rst_n.value):
                prev_valid, prev_data, prev_ctx = 0, None, None
                continue
            if not self.enabled:
                continue

            valid = int(dut.outVALID.value)
            ready = int(dut.outREADY.value)

            # C4 -- resolvable outputs
            for name in ("output_block", "encCntxtOut", "inREADY", "outVALID"):
                if is_x(getattr(dut, name)):
                    self._record(f"cyc {cyc}: {name} contains X/Z after reset")

            data = int(dut.output_block.value)
            ctx = int(dut.encCntxtOut.value)

            if prev_valid:
                # C1 -- VALID may only drop on a cycle that had READY high
                if not valid and not prev_ready:
                    self._record(
                        f"cyc {cyc}: outVALID dropped while outREADY was low -- "
                        f"the output block was withdrawn before the consumer "
                        f"accepted it, so that block is lost")
                # C2/C3 -- payload stability across the VALID window
                if valid:
                    if prev_data is not None and data != prev_data:
                        self._record(
                            f"cyc {cyc}: output_block changed while outVALID held "
                            f"({prev_data:032x} -> {data:032x}); a consumer "
                            f"sampling on any cycle of the window would see a "
                            f"different block from the one finally accepted")
                    if prev_ctx is not None and ctx != prev_ctx:
                        self._record(
                            f"cyc {cyc}: encCntxtOut changed while outVALID held "
                            f"({prev_ctx:032x} -> {ctx:032x})")

            prev_valid, prev_ready = valid, ready
            prev_data = data if valid else None
            prev_ctx = ctx if valid else None


async def signal_monitor(dut, label=""):
    """$monitor-style logger: one line per change of the watched signal set."""
    pfx = f"[MON {label}]" if label else "[MON]"
    watched = {
        "fsm": probe(dut, "AES.fsm_state"),
        "seg": probe(dut, "AES.seg_cntr"),
        "cip_enb_n": probe(dut, "AES.cipher_enb_n"),
        "cip_done": probe(dut, "AES.cipher_done"),
        "inv_enb_n": probe(dut, "AES.invCipher_enb_n"),
        "inv_done": probe(dut, "AES.invCipher_done"),
        "iv_valid": probe(dut, "AES.iv_valid"),
        "iv_ready": probe(dut, "AES.aes_iv_ready"),
    }
    watched = {k: v for k, v in watched.items() if v is not None}
    watched.update({"inREADY": dut.inREADY, "outVALID": dut.outVALID})

    def snap():
        return {k: int(h.value) for k, h in watched.items()}

    def fmt(k, v):
        return ST_NAMES.get(v, str(v)) if k == "fsm" else str(v)

    await RisingEdge(dut.clk)
    prev = snap()
    _mon_log.info(f"{pfx} INIT  " + "  ".join(f"{k}={fmt(k,v)}" for k, v in prev.items()))
    cyc = 0
    while True:
        await RisingEdge(dut.clk)
        cyc += 1
        cur = snap()
        diff = [(k, prev[k], cur[k]) for k in cur if prev[k] != cur[k]]
        if diff:
            _mon_log.info(f"{pfx} cyc={cyc:6d}  " + "  ".join(
                f"{k}: {fmt(k,o)}->{fmt(k,n)}" for k, o, n in diff))
        prev = cur


# ---------------------------------------------------------------------------
# Bus transactions
# ---------------------------------------------------------------------------
def apply_config(dut, cfg):
    """Drive the static configuration ports for `cfg`."""
    dut.mode.value = cfg.mode_value
    dut.key_size.value = cfg.key_size_code
    dut.master_key.value = cfg.model().master_key_rtl
    dut.cfb_seg_bits.value = cfg.cfb_seg_code


async def send_block(dut, data, *, first=False, enc_cntxt_in=0, partial=False,
                     valid_bits=0, hold=HoldStyle.CASE1, timeout=HANDSHAKE_TIMEOUT):
    """Input-channel transfer: present a block and wait for `inREADY`.

    Returns the number of cycles the DUT took to accept it. Under
    HoldStyle.CASE1 every input-side signal is released as soon as inREADY is
    observed, which is precisely what aes.sv:81-88 promises is safe.
    """
    dut.input_block.value = data & MASK128
    dut.encCntxtIn.value = enc_cntxt_in & MASK128
    dut.first.value = 1 if first else 0
    dut.partial.value = 1 if partial else 0
    dut.valid_bits.value = valid_bits & 0x7F
    dut.inVALID.value = 1

    # A strict VALID/READY master: the transfer is the rising edge at which BOTH
    # VALID and READY are high *entering* that edge. Sampling on the falling edge
    # gives the settled values of the cycle in flight -- i.e. exactly what the
    # upcoming rising edge will act on -- so the RisingEdge below IS the transfer.
    #
    # This must not be simplified to "await RisingEdge; if inREADY: done". That
    # reads inREADY's value *after* the edge, i.e. one cycle early, and releases
    # VALID before a DUT that requires READY-before-edge has taken the data. It
    # happens to work against a DUT that consumes on VALID alone -- which is
    # precisely the defect these tests are meant to catch -- so getting it wrong
    # makes the correct RTL look broken and the broken RTL look correct.
    for i in range(timeout):
        await FallingEdge(dut.clk)
        if int(dut.inREADY.value):
            await RisingEdge(dut.clk)      # this edge is the transfer
            break
    else:
        raise AssertionError(
            f"TIMEOUT ({timeout} cycles): inREADY never asserted for an input "
            f"block. {dut_state(dut)}")

    dut.inVALID.value = 0
    if hold is HoldStyle.CASE1:
        # Release everything the moment the transfer completes -- the documented
        # contract. Anything the RTL still needs after this point is a bug the
        # tests are meant to surface, not something to paper over.
        dut.input_block.value = 0
        dut.first.value = 0
        dut.partial.value = 0
        dut.valid_bits.value = 0
        dut.encCntxtIn.value = 0
    return i + 1


async def recv_block(dut, *, ready_delay=0, timeout=HANDSHAKE_TIMEOUT):
    """Output-channel transfer: wait for `outVALID`, sample, then accept.

    `ready_delay` holds outREADY low for that many cycles after outVALID rises,
    which is the backpressure the ProtocolChecker's stability rules are written
    to police.
    """
    cycles = 0
    for i in range(timeout):
        await RisingEdge(dut.clk)
        cycles += 1
        if int(dut.outVALID.value):
            break
    else:
        raise AssertionError(
            f"TIMEOUT ({timeout} cycles): outVALID never asserted. {dut_state(dut)}")

    if ready_delay:
        await ClockCycles(dut.clk, ready_delay)
        cycles += ready_delay

    data = int(dut.output_block.value)
    ctx = int(dut.encCntxtOut.value)
    dut.outREADY.value = 1
    await RisingEdge(dut.clk)      # this edge completes the transfer
    dut.outREADY.value = 0
    cycles += 1
    return BlockResult(data=data, enc_cntxt_out=ctx, cycles=cycles)


async def run_message(dut, cfg, blocks, *, enc_cntxt_in=0, partial_bits=None,
                      ready_delay=0, send_gap=0, mark_first=True):
    """Push one whole message through the DUT and collect its outputs.

    `blocks`        128-bit ints in RTL packing.
    `enc_cntxt_in`  IV / initial counter for the paths that take one externally.
    `partial_bits`  when set, the FINAL block is flagged `partial` with this
                    `valid_bits` count (OFB/CTR only).
    `mark_first`    assert `first` on block 0. Turning it off is how the ECB
                    tests show `first` is genuinely ignored there.

    The DUT is strictly one-block-in / one-block-out (ARM -> SHOOT -> ARM), so
    the transfer is sequential by construction; the pipelined-stress case is
    driven by `stream_message()` instead.
    """
    res = MessageResult()
    for idx, blk in enumerate(blocks):
        last = idx == len(blocks) - 1
        is_partial = partial_bits is not None and last
        if send_gap and idx:
            await ClockCycles(dut.clk, send_gap)
        res.cycles += await send_block(
            dut, blk,
            first=(idx == 0 and mark_first),
            enc_cntxt_in=enc_cntxt_in,
            partial=is_partial,
            valid_bits=(partial_bits if is_partial else 0),
            hold=cfg.hold)
        out = await recv_block(dut, ready_delay=ready_delay)
        res.cycles += out.cycles
        res.outputs.append(out.data)
        if idx == 0:
            res.enc_cntxt_out = out.enc_cntxt_out
    return res


# ---------------------------------------------------------------------------
# Scoreboarding
# ---------------------------------------------------------------------------
def expected_outputs(cfg, blocks, context, partial_bits=None, ctr_increment="nist"):
    """Golden outputs for `blocks` under `cfg`, given the IV/counter actually used."""
    m = cfg.model()
    if cfg.mode == "ECB":
        return m.ecb_decrypt(blocks) if cfg.decrypt else m.ecb_encrypt(blocks)
    if cfg.mode == "CBC":
        return (m.cbc_decrypt(blocks, context) if cfg.decrypt
                else m.cbc_encrypt(blocks, context))
    if cfg.mode == "CFB":
        return (m.cfb_decrypt(blocks, context, cfg.cfb_seg_bits) if cfg.decrypt
                else m.cfb_encrypt(blocks, context, cfg.cfb_seg_bits))
    if cfg.mode == "OFB":
        return m.ofb(blocks, context, partial_bits=partial_bits)
    if cfg.mode == "CTR":
        return m.ctr(blocks, context, partial_bits=partial_bits,
                     increment=ctr_increment)
    raise ValueError(f"unmodelled mode {cfg.mode}")


def compare(dut, cfg, got, want, *, context=None, label=""):
    """Assert `got == want`, reporting the first divergent block in NIST hex.

    The message names the block index and both values in the byte order a user
    of the chip would recognise, plus the IV/counter in play, because a mode
    failure is almost always a chaining-value failure and the raw 128-bit
    integers are unreadable.
    """
    assert len(got) == len(want), (
        f"{label or cfg}: DUT produced {len(got)} blocks, expected {len(want)}")
    bad = [i for i, (g, w) in enumerate(zip(got, want)) if g != w]
    if not bad:
        return
    lines = [f"{label or cfg}: {len(bad)}/{len(got)} block(s) mismatched"]
    if context is not None:
        lines.append(f"  chaining context (IV / counter) = {rtl_hex(context)}")
    for i in bad[:8]:
        lines.append(f"  block[{i}] got  {rtl_hex(got[i])}")
        lines.append(f"           want {rtl_hex(want[i])}")
    if len(bad) > 8:
        lines.append(f"  ... and {len(bad) - 8} more")
    lines.append(f"  {dut_state(dut)}")
    raise AssertionError("\n".join(lines))


# ---------------------------------------------------------------------------
# Stimulus generation
# ---------------------------------------------------------------------------
def rand_block(rng):
    return rng.getrandbits(128)


def rand_blocks(rng, n):
    return [rng.getrandbits(128) for _ in range(n)]


# Deliberately awkward 128-bit patterns: all-zero and all-one exercise the XOR
# and masking paths degenerately, the alternating words stress bit-level
# independence, and the single-bit patterns catch a datapath that drops or
# duplicates a lane.
EDGE_BLOCKS = [
    0x0000_0000_0000_0000_0000_0000_0000_0000,
    0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
    0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA,
    0x5555_5555_5555_5555_5555_5555_5555_5555,
    0x0000_0000_0000_0000_0000_0000_0000_0001,
    0x8000_0000_0000_0000_0000_0000_0000_0000,
    0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF,
    0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000,
]

# Keys chosen to be as unhelpful as possible to a buggy key schedule.
EDGE_KEYS_128 = [
    bytes(16),
    bytes([0xFF] * 16),
    bytes(range(16)),
    bytes([0xAA, 0x55] * 8),
]
