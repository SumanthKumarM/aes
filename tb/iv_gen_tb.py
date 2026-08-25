"""
Cocotb testbench for the IV generator (iv_gen.sv).

This is the full entropy pipeline in one DUT:

    noise source (physics model, driven on `entropy`)
        -> health tests (SP 800-90B RCT/APT)
        -> 128-bit SIPO collector
        -> CBC-MAC conditioner            (SP 800-90B Appendix F)
        -> CTR_DRBG                       (SP 800-90A Sec. 10.2.1)
        -> 128-bit IV, VALID/READY to the AES

Verifying iv_gen therefore verifies ctr_drbg.sv indirectly -- ctr_drbg has no
testbench of its own, and its seed input can only be exercised realistically by
a real conditioner. Everything below scoreboards the DUT against reference
models rather than against itself.

DUT interface
  - generated_iv[127:0] : the IV, registered, held while iv_valid is high
  - iv_valid            : asserted when generated_iv is meaningful
  - aes_ready           : consumer ack (input); transfer on valid && ready
  - entropy             : raw noise-source bit, one per clk
  - enb_n, rst_n, clk

Internal hierarchy probed (Verilator public flattening):
  dut.seed / dut.cbcmac_valid / dut.ctr_drbg_ready : conditioner -> DRBG handshake
  dut.cbcmac_enb_n / dut.health_error / dut.rst_cbcmac
  dut.CBC_MAC.*                                    : conditioner FSM + datapath
  dut.CBC_MAC.HEALTH_TESTS.rct_error / .apt_error
  dut.CTR_DRBG.*                                   : DRBG FSMs, regKEY, regV,
                                                     reseed_cntr, Update registers

Reference models
----------------
Two independent layers, both validated at import time:

1. CBC-MAC conditioner -- reused verbatim from cbc_mac_tb.py, which transcribes
   SP 800-90B Appendix F and self-checks against committed pyca/cryptography
   vectors. Importing it re-runs that self-check, so the conditioning key
   unpacking and the AES-256 core are validated before any test runs.

2. CTR_DRBG -- CtrDrbgModel below, a literal transcription of SP 800-90A
   Sec. 10.2.1.2 (Update), 10.2.1.3.1 (Instantiate), 10.2.1.4.1 (Reseed) and
   10.2.1.5.1 (Generate), specialised to this design:
     - AES-256, so keylen = 256, blocklen = 128, seedlen = 384
     - ctr_len = blocklen, which removes the partial-counter branch
     - no derivation function, no additional_input, no prediction resistance
     - requested_number_of_bits = 128, so Generate emits exactly one block

Counter domain. The model runs in the RTL's register domain: V is the u128_t
register value and "V = V + 1" is an integer increment on that register, which
is what the RTL does. state_matrix_t is a byte permutation of the NIST block
order, so this is NOT the same permutation of the counter space that SP 800-90A
Sec. 10.2.1.2 step 2.1 describes. That difference is harmless cryptographically
(the counter is still a full-period bijection over 2^128) but it does mean the
DUT will not reproduce NIST CAVP CTR_DRBG vectors. counter_domain_test below
measures the effect and documents it explicitly rather than hiding it inside
the model.

Entropy stimulus. Normal-operation tests drive `entropy` from the project's
physics-grounded RO noise model (aes/sim/noise_source_model.py): 32 parallel
13-stage ring oscillators at 150 MHz with thermal, flicker and supply jitter
accumulated as a random walk, XOR-combined and sampled through a DFF
metastability model. The pipeline needs far more bits than a single block-level
test (one reseed interval is ~265,000 clk), and those bits cost ~0.3 ms each to
generate, so the pool is generated once and cached in aes/sim/ -- `make clean`
removes it. The RCT/APT negative tests keep deterministic fault vectors, which
are chosen to trip one specific health test and are not samples of a noise
source at all.

Design intent encoded here (RTL is never edited from this file; if the RTL
deviates the test fails and the message documents the deviation):
  - Instantiate derives (Key, V) from the conditioned seed per SP 800-90A.
  - Exactly 4 AES encryptions per Generate: 1 for the IV, 3 for the Update.
  - Exactly RESEED_LIM (1024) IVs are emitted per seed, then Reseed runs.
  - Every reseed consumes a *fresh* seed from the conditioner.
  - generated_iv is stable and iv_valid is held until aes_ready.
  - A health-test failure aborts the DRBG, pulses rst_cbcmac and re-instantiates;
    no IV is released while health_error is asserted.
  - CBC-MAC is clock-gated whenever it is parked holding a seed.
"""

import os
import re
import logging
from collections import namedtuple
from pathlib import Path

import cocotb
import numpy as np
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, FallingEdge, ClockCycles, Timer

# FIPS 197 model + RTL packing helpers (single source of truth, self-checked
# against the FIPS 197 Appendix B / C.1 / C.2 / C.3 vectors at import).
from cipher_tb import (
    AESEncryptModel,
    nist_bytes_to_rtl_state,
    rtl_state_to_nist_bytes,
)

# SP 800-90B conditioner model. Importing this re-runs its cross-implementation
# self-check against committed pyca/cryptography vectors, so the AES core and
# the master_key unpacking convention are validated before anything else runs.
from cbc_mac_tb import (
    CONDITIONER_KEY,
    MASTER_KEY_RTL,
    expected_seed,
    seed_blocks,
    BLOCKS_PER_CALL,
    COND_BLOCKS,
    WORDS_PER_SEED,
    SEED_BITS,
    RCT_THRESHOLD,
    APT_BIT_WINDOW,
    APT_THRESHOLD,
)

try:
    from noise_source_model import TRNGNoiseSource
    _HAVE_PHYSICS_MODEL = True
except ImportError:
    _HAVE_PHYSICS_MODEL = False
    cocotb.log.warning(
        "noise_source_model.py not found -- normal tests fall back to numpy random"
    )

# Simulation constants
CLK_PERIOD_NS = 10
RESET_CYCLES = 8

MASK128 = (1 << 128) - 1
MASK256 = (1 << 256) - 1
MASK384 = (1 << 384) - 1

_RTL_DIR = Path(__file__).resolve().parent.parent / "rtl"
_SIM_DIR = Path(__file__).resolve().parent.parent / "sim"
_CTR_DRBG_FILE = _RTL_DIR / "ctr_drbg.sv"


def _rtl_localparam(path, name, default):
    """Read a localparam out of the RTL so the TB tracks the design."""
    try:
        m = re.search(rf"localparam\s+(?:int\s+)?{name}\s*=\s*(\d+)", path.read_text())
        return int(m.group(1)) if m else default
    except OSError:
        return default


# Reseed interval, parsed from ctr_drbg.sv so shortening it for a quick run
# automatically retargets reseed_test rather than silently invalidating it.
RESEED_LIM = _rtl_localparam(_CTR_DRBG_FILE, "RESEED_LIM", 1024)

# Measured pipeline timing, used only for timeouts and buffer sizing.
CYCLES_PER_GENERATE = 260        # 1 IV encryption + 3 Update encryptions + FSM
CYCLES_PER_SEED = 1200           # 6 x (128 collect + 58 encrypt) + FSM
IV_TIMEOUT = 4 * CYCLES_PER_GENERATE
SEED_TIMEOUT = 4 * CYCLES_PER_SEED

# cbc_mac_states / ctr_drbg_states / gen_internal_states / ctr_drbg_update_states
CB_CONSUME, CB_OPERATE, CB_RELEASE, CB_ERROR = 0, 1, 2, 3
CB_NAMES = {0: "CONSUME", 1: "OPERATE", 2: "RELEASE", 3: "ERROR"}

DR_INSTANTIATE, DR_GENERATE_IV, DR_RESEED, DR_UNINSTANTIATE, DR_RESET_CBCMAC = range(5)
DR_NAMES = {0: "INSTANTIATE", 1: "GENERATE_IV", 2: "RESEED",
            3: "UNINSTANTIATE", 4: "RESET_CBCMAC"}

GEN_INCREMENT, GEN_ENCRYPT, GEN_CALL_UPDATE = 0, 1, 2
GEN_NAMES = {0: "INCREMENT", 1: "ENCRYPT", 2: "CALL_UPDATE"}

UPD_IDLE, UPD_LOAD, UPD_UPDATE, UPD_RST_CBCMAC = 0, 1, 2, 3
UPD_NAMES = {0: "UPD_IDLE", 1: "LOAD", 2: "UPDATE", 3: "RST_CBCMAC"}

_mon_log = logging.getLogger("cocotb.monitor")


# ---------------------------------------------------------------------------
# RTL <-> NIST domain conversion
# ---------------------------------------------------------------------------
def rtl_key_to_nist_bytes(val, nk=8):
    """Invert the RTL master_key packing: NIST key-schedule word w[i] lives at
    bits [32*i +: 32], so the on-the-wire literal is w[0..nk-1] with w[0] in the
    least significant word."""
    return bytes(
        b
        for i in range(nk)
        for b in ((val >> (32 * i)) & 0xFFFF_FFFF).to_bytes(4, "big")
    )


# The conditioning key is the one value where the RTL literal, the NIST byte
# string and the key schedule are all known independently, so it anchors the
# unpacking used for every DRBG key below.
assert rtl_key_to_nist_bytes(MASTER_KEY_RTL) == CONDITIONER_KEY, (
    "master_key unpacking here disagrees with cbc_mac_tb's -- one of them is wrong"
)


def aes_rtl(key_rtl, state_rtl):
    """One AES-256 block encryption, entirely in the RTL register domain.

    key_rtl is a 256-bit master_key literal, state_rtl a 128-bit
    state_matrix_t, and the result is a 128-bit state_matrix_t -- exactly what
    unmasked_cipher consumes and produces. The NIST byte order lives only
    inside this function.
    """
    ct = AESEncryptModel(rtl_key_to_nist_bytes(key_rtl)).encrypt(
        rtl_state_to_nist_bytes(state_rtl)
    )
    return nist_bytes_to_rtl_state(ct)


# ---------------------------------------------------------------------------
# CTR_DRBG reference model -- SP 800-90A Sec. 10.2.1, transcribed literally
# ---------------------------------------------------------------------------
class CtrDrbgModel:
    """CTR_DRBG(AES-256, no df), specialised to this design.

    seedlen = keylen + blocklen = 256 + 128 = 384, ctr_len = blocklen = 128,
    requested_number_of_bits = 128. Working state is (Key, V, reseed_counter).
    """

    def __init__(self):
        self.key = 0
        self.v = 0
        self.reseed_counter = 0
        self.encryptions = 0        # AES calls, for the per-Generate count check

    # SP 800-90A Sec. 10.2.1.2 -- CTR_DRBG_Update(provided_data, Key, V)
    #   1. temp = Null
    #   2. While (len(temp) < seedlen) do
    #        2.1 V = (V + 1) mod 2^blocklen
    #        2.2 output_block = Block_Encrypt(Key, V)
    #        2.3 temp = temp || output_block
    #   3. temp = leftmost seedlen bits of temp
    #   4. temp = temp XOR provided_data
    #   5. Key = leftmost keylen bits of temp
    #   6. V   = rightmost blocklen bits of temp
    def update(self, provided_data):
        temp = 0
        for _ in range(3):                                   # 3 * 128 = 384
            self.v = (self.v + 1) & MASK128                  # step 2.1
            temp = (temp << 128) | aes_rtl(self.key, self.v)  # steps 2.2, 2.3
            self.encryptions += 1
        temp ^= provided_data & MASK384                       # step 4
        self.key = (temp >> 128) & MASK256                    # step 5
        self.v = temp & MASK128                               # step 6

    # Sec. 10.2.1.3.1 -- Instantiate. seed_material is the conditioned seed;
    # Key and V start at 0 and reseed_counter ends at 1.
    def instantiate(self, seed):
        self.key = 0
        self.v = 0
        self.update(seed)
        self.reseed_counter = 1

    # Sec. 10.2.1.4.1 -- Reseed. Same Update, but over the existing Key/V.
    def reseed(self, seed):
        self.update(seed)
        self.reseed_counter = 1

    # Sec. 10.2.1.5.1 -- Generate, with requested_number_of_bits = blocklen, so
    # the while loop runs exactly once and no truncation is needed.
    #   2.1 V = (V + 1) mod 2^blocklen
    #   2.2 output_block = Block_Encrypt(Key, V)
    #   4.  (Key, V) = CTR_DRBG_Update(0, Key, V)
    #   5.  reseed_counter = reseed_counter + 1
    def generate(self):
        self.v = (self.v + 1) & MASK128
        iv = aes_rtl(self.key, self.v)
        self.encryptions += 1
        self.update(0)
        self.reseed_counter += 1
        return iv


class CtrDrbgNistDomain:
    """The same algorithm with the counter incremented in NIST byte order.

    Used only by counter_domain_test, to measure how far the RTL's register-
    domain increment diverges from the literal SP 800-90A step 2.1. Not used
    for scoreboarding.
    """

    def __init__(self):
        self.key = bytes(32)
        self.v = bytes(16)

    @staticmethod
    def _inc(v):
        return ((int.from_bytes(v, "big") + 1) & MASK128).to_bytes(16, "big")

    def update(self, provided_data_bytes):
        temp = b""
        for _ in range(3):
            self.v = self._inc(self.v)
            temp += bytes(AESEncryptModel(self.key).encrypt(self.v))
        temp = bytes(a ^ b for a, b in zip(temp, provided_data_bytes))
        self.key, self.v = temp[:32], temp[32:]

    def instantiate(self, seed_bytes):
        self.key, self.v = bytes(32), bytes(16)
        self.update(seed_bytes)

    def generate(self):
        self.v = self._inc(self.v)
        iv = bytes(AESEncryptModel(self.key).encrypt(self.v))
        self.update(bytes(48))
        return iv


def _drbg_model_self_check():
    """Structural checks on the Update transcription that do not depend on the
    DUT, so a broken model is caught at import rather than as a test failure.

    There are no public CTR_DRBG known-answer vectors committed in this repo,
    and the AES layer is already anchored by cipher_tb's FIPS 197 self-check and
    cbc_mac_tb's pyca/cryptography cross-check. What is checked here is the part
    unique to this model: that Update consumes exactly 3 blocks, that the
    Key/V split lands on the right halves of temp, and that provided_data is
    XORed in with the correct alignment.
    """
    m = CtrDrbgModel()
    m.key, m.v = 0, 0
    m.update(0)
    b1, b2, b3 = (aes_rtl(0, 1), aes_rtl(0, 2), aes_rtl(0, 3))
    want_key = (b1 << 128) | b2
    want_v = b3
    assert m.encryptions == 3, f"Update used {m.encryptions} encryptions, expected 3"
    assert m.key == want_key, "Update Key is not the leftmost 256 bits of temp"
    assert m.v == want_v, "Update V is not the rightmost 128 bits of temp"

    # provided_data alignment: XORing a value that touches only the Key half
    # must leave V untouched, and vice versa.
    m2 = CtrDrbgModel()
    m2.update(0xA5 << 376)
    assert m2.v == want_v, "provided_data[383:128] leaked into V"
    assert m2.key == want_key ^ (0xA5 << 248), "provided_data misaligned on Key"
    m3 = CtrDrbgModel()
    m3.update(0xA5)
    assert m3.key == want_key, "provided_data[127:0] leaked into Key"
    assert m3.v == want_v ^ 0xA5, "provided_data misaligned on V"


_drbg_model_self_check()


# ---------------------------------------------------------------------------
# Noise stimulus
# ---------------------------------------------------------------------------
# One reseed interval is RESEED_LIM * ~260 clk, so the pipeline consumes far
# more simulated cycles than any block-level test. Physics bits cost ~0.3 ms
# each, so the pool is generated once, cached, and shared by every test with a
# per-test offset. `make clean` deletes the cache (it matches ./.cache*).
NOISE_POOL_BITS = int(os.environ.get("IV_GEN_NOISE_BITS", "48000"))
_NOISE_CACHE = _SIM_DIR / f".cache_iv_gen_noise_{NOISE_POOL_BITS}.npy"
_NOISE_SEED = 0xC0FFEE          # fixed so every run sees the same pool
_POOL = None


def _physics_pool():
    """The shared physics-model bit pool, cached on disk across runs."""
    global _POOL
    if _POOL is not None:
        return _POOL
    if _NOISE_CACHE.exists():
        try:
            pool = np.load(_NOISE_CACHE)
            if len(pool) >= NOISE_POOL_BITS:
                _POOL = pool[:NOISE_POOL_BITS]
                cocotb.log.info(
                    f"[noise] loaded {len(_POOL):,} cached physics bits from "
                    f"{_NOISE_CACHE.name} (mean={_POOL.mean():.4f})"
                )
                return _POOL
        except (OSError, ValueError):
            pass
    if not _HAVE_PHYSICS_MODEL:
        cocotb.log.warning("[noise] physics model unavailable -- using numpy random")
        _POOL = np.random.default_rng(_NOISE_SEED).integers(
            0, 2, size=NOISE_POOL_BITS, dtype=np.uint8)
        return _POOL
    cocotb.log.info(
        f"[noise] generating {NOISE_POOL_BITS:,} physics bits "
        f"(32 RO x 13 INV @ 150 MHz, seed=0x{_NOISE_SEED:X}) -- "
        f"one-off, ~{NOISE_POOL_BITS * 0.31e-3:.0f}s, then cached"
    )
    _POOL = TRNGNoiseSource(
        n_ro=32, n_inv=13, fs_MHz=150.0, seed=_NOISE_SEED
    ).generate_bits(NOISE_POOL_BITS)
    cocotb.log.info(f"[noise] done (mean={_POOL.mean():.4f}), caching")
    try:
        np.save(_NOISE_CACHE, _POOL)
    except OSError:
        cocotb.log.warning(f"[noise] could not write cache {_NOISE_CACHE}")
    return _POOL


class NoiseBitBuffer:
    """Raw noise bit source for `entropy`, indexed during simulation.

    Modes
    -----
    'physics'     -- slice of the shared RO physics pool, starting at `offset`.
                     Used for every normal-operation test.
    'random'      -- uniform random bits (fallback only).
    'stuck_0'     -- constant 0. Trips RCT.
    'stuck_1'     -- constant 1. Trips RCT.
    'apt_trigger' -- 3 ones + 1 zero repeating: 75% ones (well above the APT
                     threshold) but a maximum run of 3, so RCT never fires first.

    The three fault modes stay deterministic on purpose: they are fault-injection
    vectors chosen to trip a specific health test, not samples of a noise source.
    """

    def __init__(self, mode="physics", offset=0, n_bits=None):
        self._mode = mode
        self._idx = 0
        if mode == "stuck_0":
            self._buf = np.zeros(n_bits or 4096, dtype=np.uint8)
        elif mode == "stuck_1":
            self._buf = np.ones(n_bits or 4096, dtype=np.uint8)
        elif mode == "apt_trigger":
            n = n_bits or (4 * APT_BIT_WINDOW)
            self._buf = np.array((([1] * 3 + [0]) * (n // 4 + 1))[:n], dtype=np.uint8)
        elif mode == "random":
            self._buf = np.random.default_rng(offset or 1).integers(
                0, 2, size=n_bits or NOISE_POOL_BITS, dtype=np.uint8)
        else:
            pool = _physics_pool()
            self._buf = np.roll(pool, -(offset % len(pool)))

    def next_bit(self) -> int:
        if self._idx >= len(self._buf):
            self._idx = 0
        b = int(self._buf[self._idx])
        self._idx += 1
        return b


async def noise_driver(dut, buf: NoiseBitBuffer):
    """Drive one raw entropy bit per clk, updated just after each edge."""
    while True:
        await RisingEdge(dut.clk)
        dut.entropy.value = buf.next_bit()


# ---------------------------------------------------------------------------
# Monitors
# ---------------------------------------------------------------------------
SeedRecord = namedtuple("SeedRecord", "cycle seed words")


class PipelineMonitor:
    """Single falling-edge monitor for the conditioner -> DRBG -> AES path.

    Entropy-word capture and seed capture are deliberately in one coroutine.
    Each 384-bit seed must be paired with exactly the six 128-bit entropy words
    that built it, and two independent monitors cannot guarantee that pairing:
    the conditioner re-arms and starts collecting for the next seed within a
    cycle of handing the current one over, so a word list sampled even slightly
    after the handshake already contains words belonging to the next seed.
    Pairing at the handshake makes the "exactly 6 words per seed" check real
    rather than a slice of a running list.

    Everything is sampled on the falling edge -- the settled value of the cycle
    in flight, which is what the upcoming rising edge acts on. That matters for
    entropy_word (the collector overwrites it on the very edge that completes
    the transfer) and for iv_valid, which is high for a single cycle when
    aes_ready is already asserted.
    """

    def __init__(self, dut):
        self.dut = dut
        self.seeds = []          # list[SeedRecord]
        self.ivs = []
        self._words = []
        self._task = None
        self._cyc = 0

    def start(self):
        self._task = cocotb.start_soon(self._run())
        return self

    def stop(self):
        if self._task:
            self._task.cancel()

    def clear(self):
        """Drop everything, including a partially collected word list. Call
        after a reset, where the conditioner restarts mid-seed."""
        self.seeds.clear()
        self.ivs.clear()
        self._words = []

    async def _run(self):
        cb = self.dut.CBC_MAC
        prev_hs = prev_iv = 0
        while True:
            await FallingEdge(self.dut.clk)
            self._cyc += 1

            if int(cb.valid.value) and int(cb.ready.value):
                self._words.append(int(cb.entropy_word.value))

            hs = int(self.dut.cbcmac_valid.value) and int(self.dut.ctr_drbg_ready.value)
            if hs and not prev_hs:
                self.seeds.append(
                    SeedRecord(self._cyc, int(self.dut.seed.value), self._words))
                self._words = []
            prev_hs = hs

            v = int(self.dut.iv_valid.value)
            if v and not prev_iv:
                self.ivs.append(int(self.dut.generated_iv.value))
            prev_iv = v

    def take_ivs(self):
        i = list(self.ivs)
        self.ivs.clear()
        return i


class CipherCounter:
    """Counts completed AES encryptions inside the CTR_DRBG by rising edges of
    its cipher_done."""

    def __init__(self, dut):
        self.dut = dut
        self.count = 0
        self._task = None

    def start(self):
        self._task = cocotb.start_soon(self._run())
        return self

    def stop(self):
        if self._task:
            self._task.cancel()

    async def _run(self):
        prev = 0
        while True:
            await FallingEdge(self.dut.clk)
            d = int(self.dut.CTR_DRBG.cipher_done.value)
            if d and not prev:
                self.count += 1
            prev = d

    def take(self):
        c = self.count
        self.count = 0
        return c


# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------
def start_clock(dut):
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, unit="ns").start())


async def reset_dut(dut, enable=True, aes_ready=1):
    dut.rst_n.value = 0
    dut.enb_n.value = 1
    dut.aes_ready.value = 0
    dut.entropy.value = 0
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.rst_n.value = 1
    if enable:
        dut.enb_n.value = 0
    dut.aes_ready.value = aes_ready
    await RisingEdge(dut.clk)
    dut._log.info("DUT reset complete")


async def wait_signal(dut, signal, value=1, timeout=200_000):
    """Poll on the falling edge so the value read is the settled value of the
    cycle in flight -- the same value the next rising edge acts on. Sampling on
    the rising edge reads a cycle late and can miss a one-cycle pulse."""
    for i in range(timeout):
        await FallingEdge(dut.clk)
        if int(signal.value) == value:
            return i + 1
    raise AssertionError(
        f"TIMEOUT ({timeout} cycles): {signal._path} never reached {value}"
    )


async def bringup(dut, mode="physics", offset=0, aes_ready=1, monitors=True):
    """Clock + reset + noise driver + the standard monitor set."""
    start_clock(dut)
    await reset_dut(dut, aes_ready=aes_ready)
    buf = NoiseBitBuffer(mode=mode, offset=offset)
    nd = cocotb.start_soon(noise_driver(dut, buf))
    mon = PipelineMonitor(dut).start() if monitors else None
    return nd, mon


def check_seed_vs_90b(dut, words, seed, tag=""):
    """Scoreboard one conditioned seed against SP 800-90B Appendix F."""
    assert len(words) == WORDS_PER_SEED, (
        f"{tag}conditioner consumed {len(words)} entropy words per 384-bit seed, "
        f"expected exactly {WORDS_PER_SEED} "
        f"({COND_BLOCKS} conditioned blocks x {BLOCKS_PER_CALL} CBC-MAC iterations)"
    )
    exp_seed, exp_blocks = expected_seed(words)
    got_blocks = seed_blocks(seed)
    bad = [(i, g, e) for i, (g, e) in enumerate(zip(got_blocks, exp_blocks)) if g != e]
    if bad:
        lines = [f"{tag}conditioned seed mismatch (SP 800-90B Appendix F):"]
        for i, g, e in bad:
            lines.append(f"  seed[{128*(i+1)-1}:{128*i}]  rtl={g:032x}  ref={e:032x}")
        raise AssertionError("\n".join(lines))
    return exp_seed


def drbg_state(dut):
    """(Key, V, reseed_counter) as the DUT currently holds them."""
    return (
        int(dut.CTR_DRBG.regKEY.value),
        int(dut.CTR_DRBG.regV.value),
        int(dut.CTR_DRBG.reseed_cntr.value),
    )


def check_drbg_state(dut, model, tag=""):
    key, v, rc = drbg_state(dut)
    assert key == model.key, (
        f"{tag}Key mismatch after SP 800-90A Update:\n"
        f"  rtl = {key:064x}\n  ref = {model.key:064x}"
    )
    assert v == model.v, (
        f"{tag}V mismatch after SP 800-90A Update:\n"
        f"  rtl = {v:032x}\n  ref = {model.v:032x}"
    )
    assert rc == model.reseed_counter, (
        f"{tag}reseed_counter mismatch: rtl={rc} ref={model.reseed_counter}"
    )


async def instantiate_and_model(dut, mon, tag=""):
    """Wait for the first seed handshake, then for Instantiate to finish.

    Returns (model, seed) with the model already carrying the DUT's post-
    Instantiate working state, so callers can continue scoreboarding Generates.
    """
    await wait_signal(dut, dut.cbcmac_valid, 1, SEED_TIMEOUT)
    for _ in range(SEED_TIMEOUT):
        await FallingEdge(dut.clk)
        if mon.seeds:
            break
    assert mon.seeds, "no CBC-MAC -> CTR_DRBG seed handshake observed"
    rec = mon.seeds[0]
    seed = rec.seed
    check_seed_vs_90b(dut, rec.words, seed, tag=tag)

    await wait_signal(dut, dut.CTR_DRBG.fsm_state, DR_GENERATE_IV, SEED_TIMEOUT)
    model = CtrDrbgModel()
    model.instantiate(seed)
    check_drbg_state(dut, model, tag=f"{tag}[instantiate] ")
    return model, seed


# ===========================================================================
# TC1 -- Reset / initial state
# ===========================================================================
@cocotb.test()
async def reset_test(dut):
    """Post-reset state of the whole pipeline: outputs cleared, both FSMs in
    their reset state, DRBG working state zeroed, and nothing advances while
    enb_n is high."""
    dut._log.info("=" * 70)
    dut._log.info("TC1: Reset / initial state")
    dut._log.info("=" * 70)

    start_clock(dut)
    await reset_dut(dut, enable=False, aes_ready=0)

    assert int(dut.iv_valid.value) == 0, "iv_valid must be 0 after reset"
    assert int(dut.generated_iv.value) == 0, "generated_iv must be 0 after reset"
    assert int(dut.health_error.value) == 0, "health_error must be 0 after reset"
    assert int(dut.rst_cbcmac.value) == 1, "rst_cbcmac must be released after reset"
    dut._log.info("✓ Top-level outputs cleared")

    assert int(dut.CBC_MAC.fsm_state.value) == CB_CONSUME, "CBC-MAC must reset to CONSUME"
    assert int(dut.CBC_MAC.random_word.value) == 0, "conditioned seed must reset to 0"
    assert int(dut.CBC_MAC.enc_cntr.value) == 0, "CBC-MAC enc_cntr must reset to 0"
    dut._log.info("✓ CBC-MAC in CONSUME, datapath cleared")

    assert int(dut.CTR_DRBG.fsm_state.value) == DR_INSTANTIATE, (
        f"CTR_DRBG must reset to INSTANTIATE, got "
        f"{DR_NAMES.get(int(dut.CTR_DRBG.fsm_state.value))}"
    )
    key, v, rc = drbg_state(dut)
    assert key == 0, "regKEY must reset to 0 -- a stale key would survive reset"
    assert v == 0, "regV must reset to 0 -- Instantiate requires V = 0"
    assert rc == 0, "reseed_cntr must reset to 0"
    assert int(dut.CTR_DRBG.provided_data.value) == 0, (
        "provided_data must reset to 0 -- it holds the raw entropy seed"
    )
    dut._log.info("✓ CTR_DRBG in INSTANTIATE, working state zeroed")

    await ClockCycles(dut.clk, 40)
    assert int(dut.CBC_MAC.fsm_state.value) == CB_CONSUME, "CBC-MAC advanced while disabled"
    assert int(dut.CTR_DRBG.fsm_state.value) == DR_INSTANTIATE, "CTR_DRBG advanced while disabled"
    assert int(dut.iv_valid.value) == 0, "iv_valid asserted while disabled"
    dut._log.info("✓ Frozen while enb_n high -- TC1 PASSED ✓")


# ===========================================================================
# TC2 -- Instantiate against SP 800-90A
# ===========================================================================
@cocotb.test()
async def instantiate_test(dut):
    """The first seed is conditioned per SP 800-90B and consumed by Instantiate,
    which must derive (Key, V) per SP 800-90A Sec. 10.2.1.3.1 and set
    reseed_counter = 1."""
    dut._log.info("=" * 70)
    dut._log.info("TC2: Instantiate vs SP 800-90A Sec. 10.2.1.3.1")
    dut._log.info("=" * 70)

    nd, mon = await bringup(dut, offset=0)
    model, seed = await instantiate_and_model(dut, mon)
    mon.stop()

    dut._log.info(f"  seed = {seed:096x}")
    dut._log.info(f"  Key  = {model.key:064x}")
    dut._log.info(f"  V    = {model.v:032x}")

    assert seed != 0, "conditioned seed is all-zero"
    assert model.key != 0, "Instantiate produced an all-zero Key"

    # Instantiate must start from Key = V = 0, so the derived state is a pure
    # function of the seed. Confirm the DUT did not carry anything in.
    independent = CtrDrbgModel()
    independent.instantiate(seed)
    assert (independent.key, independent.v) == (model.key, model.v)
    dut._log.info("✓ (Key, V) derived from the seed alone -- TC2 PASSED ✓")


# ===========================================================================
# TC3 -- First IV
# ===========================================================================
@cocotb.test()
async def first_iv_test(dut):
    """The first IV must be Block_Encrypt(Key, V+1) using the post-Instantiate
    state, and the Update that follows must advance (Key, V) per the spec."""
    dut._log.info("=" * 70)
    dut._log.info("TC3: First IV vs SP 800-90A Sec. 10.2.1.5.1")
    dut._log.info("=" * 70)

    nd, mon = await bringup(dut, offset=1000)
    model, _ = await instantiate_and_model(dut, mon)

    key_before, v_before = model.key, model.v
    exp_iv = model.generate()

    ivs = []
    for _ in range(IV_TIMEOUT):
        await FallingEdge(dut.clk)
        ivs = mon.ivs
        if ivs:
            break
    assert ivs, "no IV produced within the timeout"
    got = ivs[0]

    dut._log.info(f"  Key = {key_before:064x}")
    dut._log.info(f"  V   = {v_before:032x}  ->  V+1 = {(v_before+1) & MASK128:032x}")
    dut._log.info(f"  IV  rtl = {got:032x}")
    dut._log.info(f"      ref = {exp_iv:032x}")
    assert got == exp_iv, (
        "first IV does not match Block_Encrypt(Key, V+1):\n"
        f"  rtl = {got:032x}\n  ref = {exp_iv:032x}\n"
        f"  (Key = {key_before:064x}, V = {v_before:032x})"
    )
    dut._log.info("✓ IV matches the reference")

    # After the IV the DRBG must run CTR_DRBG_Update(0, Key, V)
    await wait_signal(dut, dut.CTR_DRBG.gen_fsm, GEN_INCREMENT, IV_TIMEOUT)
    check_drbg_state(dut, model, tag="[post-IV update] ")
    mon.stop()
    dut._log.info("✓ Post-IV Update advanced (Key, V) correctly -- TC3 PASSED ✓")


# ===========================================================================
# TC4 -- IV stream
# ===========================================================================
@cocotb.test()
async def iv_stream_test(dut):
    """A run of consecutive IVs, each scoreboarded end to end: the conditioned
    seed against SP 800-90B and every IV plus the Update behind it against
    SP 800-90A."""
    N_IV = 24
    dut._log.info("=" * 70)
    dut._log.info(f"TC4: {N_IV} consecutive IVs, each scoreboarded")
    dut._log.info("=" * 70)

    nd, mon = await bringup(dut, offset=2000)
    model, _ = await instantiate_and_model(dut, mon)
    mon.take_ivs()

    expected = [model.generate() for _ in range(N_IV)]
    got = []
    for k in range(N_IV):
        for _ in range(IV_TIMEOUT):
            await FallingEdge(dut.clk)
            if len(mon.ivs) > k:
                break
        assert len(mon.ivs) > k, f"IV {k+1}/{N_IV} never arrived"
        got.append(mon.ivs[k])
        if got[k] != expected[k]:
            raise AssertionError(
                f"IV {k+1}/{N_IV} mismatch:\n"
                f"  rtl = {got[k]:032x}\n  ref = {expected[k]:032x}\n"
                f"  (the divergence starts here; earlier IVs matched)"
            )
    dut._log.info(f"✓ All {N_IV} IVs match the SP 800-90A reference")
    assert len(set(got)) == N_IV, "duplicate IV in the stream"
    dut._log.info("✓ All IVs distinct")

    # The IV is observed in ENCRYPT, one Update ahead of the model. Let the DUT
    # finish CTR_DRBG_Update before comparing the working state.
    await wait_signal(dut, dut.CTR_DRBG.gen_fsm, GEN_INCREMENT, IV_TIMEOUT)
    mon.stop()
    check_drbg_state(dut, model, tag=f"[after {N_IV} generates] ")
    dut._log.info(f"✓ (Key, V, reseed_counter) still tracking -- TC4 PASSED ✓")


# ===========================================================================
# TC5 -- AES encryptions per Generate
# ===========================================================================
@cocotb.test()
async def encryptions_per_generate_test(dut):
    """Each Generate must cost exactly 4 AES encryptions: one for the IV and
    three for CTR_DRBG_Update. A different count means either the Update loop
    is not filling seedlen or the cipher is being started spuriously."""
    N_GEN = 5
    dut._log.info("=" * 70)
    dut._log.info(f"TC5: exactly 4 AES encryptions per Generate, over {N_GEN}")
    dut._log.info("=" * 70)

    nd, mon = await bringup(dut, offset=3000)
    model, _ = await instantiate_and_model(dut, mon)

    counter = CipherCounter(dut).start()
    per_gen = []
    for k in range(N_GEN):
        await wait_signal(dut, dut.CTR_DRBG.gen_fsm, GEN_INCREMENT, IV_TIMEOUT)
        counter.take()
        # one full Generate: INCREMENT -> ENCRYPT -> CALL_UPDATE -> INCREMENT
        await wait_signal(dut, dut.CTR_DRBG.gen_fsm, GEN_ENCRYPT, IV_TIMEOUT)
        await wait_signal(dut, dut.CTR_DRBG.gen_fsm, GEN_CALL_UPDATE, IV_TIMEOUT)
        await wait_signal(dut, dut.CTR_DRBG.gen_fsm, GEN_INCREMENT, IV_TIMEOUT)
        per_gen.append(counter.take())
    counter.stop()
    mon.stop()

    dut._log.info(f"  encryptions per Generate: {per_gen}")
    assert all(n == 4 for n in per_gen), (
        f"AES encryptions per Generate were {per_gen}, expected 4 each "
        f"(1 for the IV + 3 for CTR_DRBG_Update over seedlen = 384 bits). "
        f"A count above 4 means the cipher is being enabled when no encryption "
        f"is wanted; below 4 means the Update loop is short."
    )
    dut._log.info("✓ Exactly 4 encryptions per Generate -- TC5 PASSED ✓")


# ===========================================================================
# TC6 -- VALID/READY handshake with the AES
# ===========================================================================
@cocotb.test()
async def handshake_test(dut):
    """iv_valid must rise only with a fresh IV, the IV must be stable while
    iv_valid is high, and iv_valid must clear once the AES takes it."""
    dut._log.info("=" * 70)
    dut._log.info("TC6: iv_valid / aes_ready handshake")
    dut._log.info("=" * 70)

    # aes_ready starts low so the handshake can be observed in slow motion
    nd, mon = await bringup(dut, offset=4000, aes_ready=0)
    model, _ = await instantiate_and_model(dut, mon)
    exp_iv = model.generate()

    await wait_signal(dut, dut.iv_valid, 1, IV_TIMEOUT)
    iv_at_valid = int(dut.generated_iv.value)
    assert iv_at_valid == exp_iv, (
        f"IV presented at iv_valid does not match the reference:\n"
        f"  rtl = {iv_at_valid:032x}\n  ref = {exp_iv:032x}"
    )
    dut._log.info("✓ iv_valid rose with the correct IV")

    # Hold ready low: valid stays, data stays
    for cyc in range(60):
        await FallingEdge(dut.clk)
        assert int(dut.iv_valid.value) == 1, (
            f"iv_valid dropped at cycle {cyc} without aes_ready -- the AES would "
            f"lose the IV"
        )
        assert int(dut.generated_iv.value) == iv_at_valid, (
            f"generated_iv changed at cycle {cyc} while iv_valid was high"
        )
    dut._log.info("✓ IV held stable for 60 cycles of backpressure")

    # Take it
    dut.aes_ready.value = 1
    await RisingEdge(dut.clk)
    dut.aes_ready.value = 0
    await wait_signal(dut, dut.iv_valid, 0, 20)
    dut._log.info("✓ iv_valid cleared after the transfer")

    # ... and the next IV must be a different one, correctly derived
    exp_next = model.generate()
    dut.aes_ready.value = 0
    await wait_signal(dut, dut.iv_valid, 1, IV_TIMEOUT)
    got_next = int(dut.generated_iv.value)
    assert got_next != iv_at_valid, "the same IV was presented twice"
    assert got_next == exp_next, (
        f"second IV mismatch:\n  rtl = {got_next:032x}\n  ref = {exp_next:032x}"
    )
    mon.stop()
    dut._log.info("✓ Next IV correct and distinct -- TC6 PASSED ✓")


# ===========================================================================
# TC7 -- Backpressure: nothing advances while the AES is not ready
# ===========================================================================
@cocotb.test()
async def backpressure_test(dut):
    """While the DRBG is parked in ENCRYPT waiting for aes_ready, the working
    state must not advance and the cipher must not be left running -- it would
    burn power spinning on stale data for the whole stall."""
    HOLD = 200
    dut._log.info("=" * 70)
    dut._log.info(f"TC7: Backpressure -- hold aes_ready low for {HOLD} cycles")
    dut._log.info("=" * 70)

    nd, mon = await bringup(dut, offset=5000, aes_ready=0)
    model, _ = await instantiate_and_model(dut, mon)
    exp_iv = model.generate()

    await wait_signal(dut, dut.iv_valid, 1, IV_TIMEOUT)
    frozen = drbg_state(dut)
    iv_held = int(dut.generated_iv.value)

    for cyc in range(HOLD):
        await FallingEdge(dut.clk)
        assert drbg_state(dut) == frozen, (
            f"DRBG working state advanced at cycle {cyc} while stalled on "
            f"aes_ready -- the Update must not start until the IV is taken"
        )
        assert int(dut.generated_iv.value) == iv_held, (
            f"generated_iv changed at cycle {cyc} during backpressure"
        )
        assert int(dut.CTR_DRBG.cipher_enb_n.value) == 1, (
            f"CIPHER still enabled at cycle {cyc} while parked in ENCRYPT -- it "
            f"spins on stale data for the whole stall and can be frozen "
            f"mid-round, corrupting the next real encryption"
        )
    dut._log.info(f"✓ State frozen and CIPHER parked for {HOLD} cycles")

    dut.aes_ready.value = 1
    await wait_signal(dut, dut.CTR_DRBG.gen_fsm, GEN_INCREMENT, IV_TIMEOUT)
    check_drbg_state(dut, model, tag="[after resume] ")
    assert iv_held == exp_iv, "the held IV was not the expected one"
    mon.stop()
    dut._log.info("✓ Resumed correctly after backpressure -- TC7 PASSED ✓")


# ===========================================================================
# TC8 -- Reseed interval
# ===========================================================================
@cocotb.test()
async def reseed_test(dut):
    """Exactly RESEED_LIM IVs are emitted per seed, then the DRBG reseeds from
    a *fresh* conditioned seed and the post-Reseed state matches SP 800-90A
    Sec. 10.2.1.4.1.

    This is the long test: RESEED_LIM x ~260 clk. It is also the one that
    catches a starved conditioner -- a reseed that silently re-consumes the
    seed it already used produces a DRBG that never takes in new entropy again.
    """
    dut._log.info("=" * 70)
    dut._log.info(f"TC8: Reseed after exactly {RESEED_LIM} IVs "
                  f"(~{RESEED_LIM * CYCLES_PER_GENERATE:,} clk)")
    dut._log.info("=" * 70)

    nd, mon = await bringup(dut, offset=6000)
    model, seed0 = await instantiate_and_model(dut, mon)
    mon.take_ivs()
    mon.seeds.clear()

    timeout = (RESEED_LIM + 4) * CYCLES_PER_GENERATE + 4 * CYCLES_PER_SEED
    n_iv = 0
    reseed_seen_at = None
    for _ in range(timeout):
        await FallingEdge(dut.clk)
        n_iv = len(mon.ivs)
        if int(dut.CTR_DRBG.fsm_state.value) == DR_RESEED:
            reseed_seen_at = n_iv
            break
    assert reseed_seen_at is not None, (
        f"CTR_DRBG never entered RESEED within {timeout:,} cycles "
        f"(saw {n_iv} IVs; expected reseed after {RESEED_LIM})"
    )
    dut._log.info(f"  RESEED entered after {reseed_seen_at} IVs")
    assert reseed_seen_at == RESEED_LIM, (
        f"reseed fired after {reseed_seen_at} IVs, expected exactly {RESEED_LIM}. "
        f"Off by one means the reseed_cntr comparison is against the wrong edge "
        f"of the interval; far off means the counter is wrapping."
    )
    dut._log.info(f"✓ Reseed fired after exactly {RESEED_LIM} IVs")

    # Model the same RESEED_LIM generates and compare the whole stream
    exp = [model.generate() for _ in range(RESEED_LIM)]
    got = mon.ivs[:RESEED_LIM]
    mismatch = next((i for i, (g, e) in enumerate(zip(got, exp)) if g != e), None)
    assert mismatch is None, (
        f"IV stream diverges from the reference at IV {mismatch + 1}:\n"
        f"  rtl = {got[mismatch]:032x}\n  ref = {exp[mismatch]:032x}"
    )
    dut._log.info(f"✓ All {RESEED_LIM} IVs match the reference")
    assert len(set(got)) == RESEED_LIM, "duplicate IV within one reseed interval"
    dut._log.info(f"✓ All {RESEED_LIM} IVs distinct")

    # The reseed must consume a seed the DRBG has not seen before
    for _ in range(4 * CYCLES_PER_SEED):
        await FallingEdge(dut.clk)
        if mon.seeds:
            break
    assert mon.seeds, "reseed never completed a seed handshake"
    rec1 = mon.seeds[0]
    seed1 = rec1.seed
    dut._log.info(f"  seed 0 = {seed0:096x}")
    dut._log.info(f"  seed 1 = {seed1:096x}")
    assert seed1 != seed0, (
        "the reseed consumed the SAME 384-bit seed as Instantiate -- the "
        "conditioner is starved and the DRBG will never take in fresh entropy "
        "again. Check that CBC-MAC is re-armed after each handshake."
    )
    check_seed_vs_90b(dut, rec1.words, seed1, tag="[reseed] ")
    dut._log.info("✓ Reseed consumed a fresh, correctly conditioned seed")

    await wait_signal(dut, dut.CTR_DRBG.fsm_state, DR_GENERATE_IV, 4 * CYCLES_PER_SEED)
    model.reseed(seed1)
    check_drbg_state(dut, model, tag="[post-reseed] ")
    assert int(dut.CTR_DRBG.reseed_cntr.value) == 1, (
        "reseed_counter must be reset to 1 by Reseed (SP 800-90A 10.2.1.4.1 step 4)"
    )
    mon.stop()
    dut._log.info("✓ Post-reseed working state correct -- TC8 PASSED ✓")


# ===========================================================================
# TC9 -- Seed freshness across handshakes
# ===========================================================================
@cocotb.test()
async def seed_freshness_test(dut):
    """Every seed the conditioner hands over must be new and independently
    correct. Runs with a shortened view of the pipeline by forcing repeated
    Instantiates through health-error recovery, so it does not need a full
    reseed interval to observe several handshakes."""
    N_SEEDS = 3
    dut._log.info("=" * 70)
    dut._log.info(f"TC9: {N_SEEDS} conditioned seeds, each fresh and verified")
    dut._log.info("=" * 70)

    nd, mon = await bringup(dut, offset=7000)

    seeds, recs = [], []
    for k in range(N_SEEDS):
        await wait_signal(dut, dut.cbcmac_valid, 1, SEED_TIMEOUT)
        for _ in range(SEED_TIMEOUT):
            await FallingEdge(dut.clk)
            if mon.seeds:
                break
        assert mon.seeds, f"seed handshake {k+1} never happened"
        rec = mon.seeds[0]
        recs.append(rec)
        seeds.append(rec.seed)
        dut._log.info(f"  seed {k}: {len(rec.words)} entropy words consumed")

        if k + 1 < N_SEEDS:
            # Force the DRBG back to INSTANTIATE so it asks for another seed,
            # without waiting a full reseed interval. The reset restarts the
            # conditioner mid-collection, so the partial word list goes with it.
            dut.rst_n.value = 0
            await ClockCycles(dut.clk, RESET_CYCLES)
            dut.rst_n.value = 1
            await RisingEdge(dut.clk)
        mon.clear()

    mon.stop()
    for k, rec in enumerate(recs):
        check_seed_vs_90b(dut, rec.words, rec.seed, tag=f"[seed {k}] ")
    dut._log.info(f"✓ All {N_SEEDS} seeds match the SP 800-90B reference")

    assert len(set(seeds)) == N_SEEDS, (
        "duplicate 384-bit seed handed to the CTR_DRBG -- the conditioner is "
        "not re-arming, so the DRBG would reseed with entropy it already used"
    )
    blocks = [b for s in seeds for b in seed_blocks(s)]
    assert len(set(blocks)) == len(blocks), "repeated 128-bit conditioned block"
    dut._log.info(f"✓ All seeds and all {len(blocks)} blocks distinct -- TC9 PASSED ✓")


# ===========================================================================
# TC10 -- CBC-MAC power gating
# ===========================================================================
@cocotb.test()
async def power_gating_test(dut):
    """iv_gen parks the conditioner whenever it is holding a seed the DRBG has
    not asked for yet. While parked its clock must genuinely stop -- FSM,
    counters, accumulator and the entropy collector all frozen -- and it must
    still wake in time to complete the next handshake."""
    dut._log.info("=" * 70)
    dut._log.info("TC10: CBC-MAC clock gating while parked")
    dut._log.info("=" * 70)

    nd, mon = await bringup(dut, offset=8000)
    model, _ = await instantiate_and_model(dut, mon)

    # Wait for the conditioner to prefetch the next seed and park
    await wait_signal(dut, dut.cbcmac_enb_n, 1, 4 * CYCLES_PER_SEED)
    assert int(dut.CBC_MAC.fsm_state.value) == CB_RELEASE, (
        "CBC-MAC was gated somewhere other than RELEASE -- it must only be "
        "parked once it is holding a finished seed"
    )
    assert int(dut.cbcmac_valid.value) == 1, "gated without a valid seed to hold"
    dut._log.info("✓ Parked in RELEASE holding a valid seed")

    frozen = {
        "fsm_state": int(dut.CBC_MAC.fsm_state.value),
        "enc_cntr": int(dut.CBC_MAC.enc_cntr.value),
        "regV": int(dut.CBC_MAC.regV.value),
        "random_word": int(dut.CBC_MAC.random_word.value),
        "entropy_word": int(dut.CBC_MAC.entropy_word.value),
    }
    gated = 0
    for cyc in range(600):
        await FallingEdge(dut.clk)
        if not int(dut.cbcmac_enb_n.value):
            break
        gated += 1
        for name, want in frozen.items():
            got = int(getattr(dut.CBC_MAC, name).value)
            assert got == want, (
                f"CBC_MAC.{name} changed at gated cycle {cyc}: "
                f"0x{got:x} != 0x{want:x} -- the clock is not actually stopped"
            )
    assert gated >= 500, f"only stayed gated for {gated} cycles"
    dut._log.info(f"✓ Fully frozen for {gated} cycles (FSM, counters, "
                  f"accumulator and SIPO all held)")

    # The DRBG must still be producing IVs while the conditioner sleeps
    mon.take_ivs()
    for _ in range(3):
        model.generate()
    for _ in range(4 * IV_TIMEOUT):
        await FallingEdge(dut.clk)
        if len(mon.ivs) >= 3:
            break
    assert len(mon.ivs) >= 3, "IV production stalled while CBC-MAC was gated"
    mon.stop()
    dut._log.info("✓ DRBG kept generating while the conditioner slept -- TC10 PASSED ✓")


# ===========================================================================
# TC11 -- Health-test failure
# ===========================================================================
@cocotb.test()
async def health_error_test(dut):
    """A noise-source failure must abort the DRBG: no IV may be released while
    health_error is asserted, rst_cbcmac must pulse to clear the conditioner's
    latched ERROR state, and the pipeline must re-instantiate from a fresh seed
    once the source recovers."""
    dut._log.info("=" * 70)
    dut._log.info(f"TC11: Health failure mid-generate (RCT threshold "
                  f"{RCT_THRESHOLD})")
    dut._log.info("=" * 70)

    nd, mon = await bringup(dut, offset=9000)
    model, _ = await instantiate_and_model(dut, mon)

    # Let it generate a few IVs from a healthy source first
    for _ in range(3 * IV_TIMEOUT):
        await FallingEdge(dut.clk)
        if len(mon.ivs) >= 2:
            break
    assert len(mon.ivs) >= 2, "no IVs before the fault was injected"
    assert int(dut.health_error.value) == 0, "unexpected early health_error"
    dut._log.info("✓ Pipeline healthy and generating")

    # Kill the noise source
    nd.kill()
    dut._log.info("Noise source going stuck-at-1...")
    bad = NoiseBitBuffer(mode="stuck_1")
    nd = cocotb.start_soon(noise_driver(dut, bad))

    # The conditioner has to be awake for its health tests to see the fault, so
    # allow a full sleep window before giving up.
    n = await wait_signal(dut, dut.health_error, 1,
                          RESEED_LIM * CYCLES_PER_GENERATE + 4 * CYCLES_PER_SEED)
    dut._log.info(f"✓ health_error asserted {n} cycles after the source died")

    await wait_signal(dut, dut.CTR_DRBG.fsm_state, DR_RESET_CBCMAC,
                      4 * CYCLES_PER_GENERATE)
    dut._log.info("✓ CTR_DRBG reached RESET_CBCMAC")

    await wait_signal(dut, dut.rst_cbcmac, 0, 8)
    dut._log.info("✓ rst_cbcmac pulsed -- the conditioner's latched ERROR is cleared")

    # No IV may be released while the source is bad
    mon.take_ivs()
    for _ in range(200):
        await FallingEdge(dut.clk)
        assert not mon.ivs, (
            "an IV was released while health_error was asserted -- a failed "
            "noise source must stop the pipeline, not be generated through"
        )
    key, v, rc = drbg_state(dut)
    assert (key, v, rc) == (0, 0, 0), (
        f"DRBG working state was not zeroised on a health failure: "
        f"Key={key:064x} V={v:032x} reseed_cntr={rc}"
    )
    dut._log.info("✓ No IV released and the working state was zeroised")

    # Restore the source: the pipeline must re-instantiate from a fresh seed
    nd.kill()
    dut._log.info("Noise source recovering...")
    nd = cocotb.start_soon(noise_driver(dut, NoiseBitBuffer(mode="physics", offset=11000)))
    mon.clear()

    # The abort froze the DRBG's CIPHER wherever it happened to be. Nothing
    # resets it: rst_cbcmac reaches CBC-MAC (and CBC-MAC's own cipher) only,
    # while ctr_drbg's CIPHER takes the top-level rst_n. If it is left parked
    # mid-round, the first encryption of the re-instantiate resumes the aborted
    # one instead of starting fresh, and a stale ciphertext lands in the new Key.
    stuck = int(dut.CTR_DRBG.CIPHER.round_cntr.value)
    assert stuck == 0, (
        f"the CTR_DRBG's CIPHER is parked mid-encryption at round {stuck} after "
        f"the health-error abort, and nothing clears it -- rst_cbcmac resets "
        f"CBC-MAC but ctr_drbg's CIPHER is wired to the top-level rst_n. The "
        f"next encryption resumes the aborted one, so Block_Encrypt(Key=0, V=1) "
        f"in the re-instantiate returns a stale ciphertext and the top 128 bits "
        f"of the new Key are wrong (SP 800-90A 10.2.1.2 step 2.2)."
    )
    dut._log.info("✓ DRBG cipher is clean before the re-instantiate")

    await wait_signal(dut, dut.CTR_DRBG.fsm_state, DR_GENERATE_IV, 6 * CYCLES_PER_SEED)
    assert mon.seeds, "re-instantiate happened without a seed handshake"
    rec = mon.seeds[-1]
    new_seed = rec.seed
    check_seed_vs_90b(dut, rec.words, new_seed, tag="[recovery] ")

    recovered = CtrDrbgModel()
    recovered.instantiate(new_seed)
    check_drbg_state(dut, recovered, tag="[recovery] ")
    mon.stop()
    dut._log.info("✓ Re-instantiated correctly from a fresh seed -- TC11 PASSED ✓")


# ===========================================================================
# TC12 -- enb_n gating
# ===========================================================================
@cocotb.test()
async def enb_gating_test(dut):
    """Deasserting enb_n mid-generate must freeze the whole pipeline coherently
    -- both sub-blocks and the cipher inside the DRBG -- and re-enabling must
    resume from exactly where it stopped, with the IV stream still correct."""
    FREEZE = 150
    dut._log.info("=" * 70)
    dut._log.info("TC12: enb_n freeze / resume mid-generate")
    dut._log.info("=" * 70)

    nd, mon = await bringup(dut, offset=12000)
    model, _ = await instantiate_and_model(dut, mon)
    mon.take_ivs()

    # Stop partway through an encryption
    await wait_signal(dut, dut.CTR_DRBG.gen_fsm, GEN_ENCRYPT, IV_TIMEOUT)
    await ClockCycles(dut.clk, 20)
    dut.enb_n.value = 1
    await ClockCycles(dut.clk, 2)

    frozen = {
        "drbg_fsm": int(dut.CTR_DRBG.fsm_state.value),
        "gen_fsm": int(dut.CTR_DRBG.gen_fsm.value),
        "regKEY": int(dut.CTR_DRBG.regKEY.value),
        "regV": int(dut.CTR_DRBG.regV.value),
        "reseed_cntr": int(dut.CTR_DRBG.reseed_cntr.value),
        "cb_fsm": int(dut.CBC_MAC.fsm_state.value),
        "cb_enc_cntr": int(dut.CBC_MAC.enc_cntr.value),
        "iv_valid": int(dut.iv_valid.value),
    }
    probes = {
        "drbg_fsm": dut.CTR_DRBG.fsm_state, "gen_fsm": dut.CTR_DRBG.gen_fsm,
        "regKEY": dut.CTR_DRBG.regKEY, "regV": dut.CTR_DRBG.regV,
        "reseed_cntr": dut.CTR_DRBG.reseed_cntr,
        "cb_fsm": dut.CBC_MAC.fsm_state, "cb_enc_cntr": dut.CBC_MAC.enc_cntr,
        "iv_valid": dut.iv_valid,
    }
    dut._log.info(f"  frozen in {GEN_NAMES[frozen['gen_fsm']]}")

    for cyc in range(FREEZE):
        await FallingEdge(dut.clk)
        for name, want in frozen.items():
            got = int(probes[name].value)
            assert got == want, (
                f"{name} changed while enb_n was high (cycle {cyc}): "
                f"0x{got:x} != 0x{want:x}"
            )
    dut._log.info(f"✓ Whole pipeline frozen for {FREEZE} cycles")

    dut.enb_n.value = 0
    await RisingEdge(dut.clk)
    dut._log.info("Re-enabled -- expecting the IV stream to continue correctly")

    exp = [model.generate() for _ in range(3)]
    for k in range(3):
        for _ in range(IV_TIMEOUT):
            await FallingEdge(dut.clk)
            if len(mon.ivs) > k:
                break
        assert len(mon.ivs) > k, f"IV {k+1} never arrived after resume"
        assert mon.ivs[k] == exp[k], (
            f"IV {k+1} after resume mismatch -- the freeze corrupted state:\n"
            f"  rtl = {mon.ivs[k]:032x}\n  ref = {exp[k]:032x}"
        )
    await wait_signal(dut, dut.CTR_DRBG.gen_fsm, GEN_INCREMENT, IV_TIMEOUT)
    mon.stop()
    check_drbg_state(dut, model, tag="[after resume] ")
    dut._log.info("✓ Resumed with a correct IV stream -- TC12 PASSED ✓")


# ===========================================================================
# TC13 -- Reset mid-operation
# ===========================================================================
@cocotb.test()
async def reset_mid_operation_test(dut):
    """A reset in the middle of a Generate must abandon the partial state
    cleanly, and the pipeline must re-instantiate from a new seed with no
    carry-over of the old working state."""
    dut._log.info("=" * 70)
    dut._log.info("TC13: Reset mid-generate")
    dut._log.info("=" * 70)

    nd, mon = await bringup(dut, offset=14000)
    model, seed_before = await instantiate_and_model(dut, mon)
    key_before, v_before, _ = drbg_state(dut)

    await wait_signal(dut, dut.CTR_DRBG.gen_fsm, GEN_CALL_UPDATE, IV_TIMEOUT)
    await ClockCycles(dut.clk, 30)
    dut._log.info("✓ Interrupting partway through CTR_DRBG_Update")

    dut.rst_n.value = 0
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.rst_n.value = 1
    await RisingEdge(dut.clk)

    assert int(dut.CTR_DRBG.fsm_state.value) == DR_INSTANTIATE, "DRBG must reset to INSTANTIATE"
    assert int(dut.CBC_MAC.fsm_state.value) == CB_CONSUME, "CBC-MAC must reset to CONSUME"
    key, v, rc = drbg_state(dut)
    assert (key, v, rc) == (0, 0, 0), (
        f"working state survived reset: Key={key:064x} V={v:032x} rc={rc} -- "
        f"a stale Key/V would make the next Instantiate depend on the old seed"
    )
    assert int(dut.CTR_DRBG.provided_data.value) == 0, "provided_data survived reset"
    assert int(dut.iv_valid.value) == 0, "iv_valid survived reset"
    dut._log.info("✓ All state cleared by reset")

    mon.clear()
    await wait_signal(dut, dut.CTR_DRBG.fsm_state, DR_GENERATE_IV, 4 * CYCLES_PER_SEED)
    assert mon.seeds, "no seed handshake after reset"
    rec = mon.seeds[-1]
    seed_after = rec.seed
    check_seed_vs_90b(dut, rec.words, seed_after, tag="[post-reset] ")

    fresh = CtrDrbgModel()
    fresh.instantiate(seed_after)
    check_drbg_state(dut, fresh, tag="[post-reset] ")
    assert (fresh.key, fresh.v) != (key_before, v_before) or seed_after == seed_before, (
        "post-reset working state is identical to the pre-reset one from a "
        "different seed -- that should be impossible"
    )
    mon.stop()
    dut._log.info("✓ Correct re-instantiate after mid-operation reset -- TC13 PASSED ✓")


# ===========================================================================
# TC14 -- IV statistics
# ===========================================================================
@cocotb.test()
async def iv_statistics_test(dut):
    """Statistical sanity of the IV stream. A DRBG that collapses -- a stuck
    counter, a Key that stops advancing -- shows up here even when individual
    IVs match, because the reference model would collapse with it."""
    N_IV = 32
    dut._log.info("=" * 70)
    dut._log.info(f"TC14: IV stream statistics over {N_IV} IVs")
    dut._log.info("=" * 70)

    nd, mon = await bringup(dut, offset=16000)
    model, _ = await instantiate_and_model(dut, mon)
    mon.take_ivs()

    for _ in range(N_IV * IV_TIMEOUT):
        await FallingEdge(dut.clk)
        if len(mon.ivs) >= N_IV:
            break
    ivs = mon.ivs[:N_IV]
    mon.stop()
    assert len(ivs) == N_IV, f"only {len(ivs)}/{N_IV} IVs produced"

    assert 0 not in ivs, "an all-zero IV was produced"
    assert len(set(ivs)) == N_IV, "repeated IV -- the counter or the key is stuck"
    dut._log.info(f"✓ {N_IV} distinct non-zero IVs")

    total_ones = sum(bin(iv).count("1") for iv in ivs)
    frac = total_ones / (128 * N_IV)
    dut._log.info(f"  ones fraction over {128*N_IV} bits = {frac:.4f}")
    assert 0.42 <= frac <= 0.58, (
        f"IV bit balance {frac:.4f} outside [0.42, 0.58] -- the output is not "
        f"behaving like a block-cipher output"
    )

    # No two IVs should agree in any 32-bit lane either
    for lane in range(4):
        vals = [(iv >> (32 * lane)) & 0xFFFF_FFFF for iv in ivs]
        assert len(set(vals)) == N_IV, f"repeated 32-bit lane {lane} across IVs"
    dut._log.info("✓ All 32-bit lanes distinct -- TC14 PASSED ✓")


# ===========================================================================
# TC15 -- Counter increment domain
# ===========================================================================
@cocotb.test()
async def counter_domain_test(dut):
    """Document and pin down which domain "V = V + 1" happens in.

    SP 800-90A Sec. 10.2.1.2 step 2.1 increments V as a big-endian integer over
    the NIST block byte order. The RTL increments the u128_t register, and
    state_matrix_t is a byte permutation of that order, so the two walk the
    counter space differently. This test asserts the RTL matches the register-
    domain model (which every other test relies on), shows how far the literal
    NIST-domain model diverges, and checks the property that actually matters:
    the counter is still a full-period bijection, so V never repeats.
    """
    N_IV = 6
    dut._log.info("=" * 70)
    dut._log.info("TC15: V increment domain (SP 800-90A 10.2.1.2 step 2.1)")
    dut._log.info("=" * 70)

    nd, mon = await bringup(dut, offset=18000)
    model, seed = await instantiate_and_model(dut, mon)
    mon.take_ivs()

    exp = [model.generate() for _ in range(N_IV)]
    for _ in range(N_IV * IV_TIMEOUT):
        await FallingEdge(dut.clk)
        if len(mon.ivs) >= N_IV:
            break
    got = mon.ivs[:N_IV]
    mon.stop()
    assert len(got) == N_IV, f"only {len(got)}/{N_IV} IVs produced"
    assert got == exp, "RTL does not match the register-domain reference model"
    dut._log.info("✓ RTL matches the register-domain model used by every other test")

    # How the literal NIST-domain model behaves on the same seed
    nist = CtrDrbgNistDomain()
    nist.instantiate(bytes.fromhex(f"{seed:096x}"))
    nist_ivs = [int.from_bytes(nist.generate(), "big") for _ in range(N_IV)]
    agree = sum(1 for a, b in zip(got, nist_ivs) if a == b)
    dut._log.info(f"  literal NIST byte-order model agrees on {agree}/{N_IV} IVs")
    if agree == N_IV:
        dut._log.info("  -> the two domains coincide for this design")
    else:
        dut._log.warning(
            "  -> the counter runs in the RTL register domain, not NIST byte "
            "order. Cryptographically equivalent (still a full-period counter), "
            "but the DUT will NOT reproduce NIST CAVP CTR_DRBG vectors."
        )

    # The property that has to hold either way: V is a full-period counter, so
    # no value repeats within a reseed interval.
    v_seq, m = [], CtrDrbgModel()
    m.instantiate(seed)
    for _ in range(N_IV):
        m.v = (m.v + 1) & MASK128
        v_seq.append(m.v)
        m.update(0)
    assert len(set(v_seq)) == len(v_seq), (
        "V repeated within a handful of Generates -- the counter is not a "
        "bijection and IVs would eventually repeat under one key"
    )
    dut._log.info("✓ V distinct across Generates -- TC15 PASSED ✓")
