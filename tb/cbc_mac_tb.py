"""
Cocotb testbench for the CBC-MAC entropy conditioner (cbc_mac.sv).

DUT interface (current cbc_mac.sv):
  - random_word[383:0] : 384-bit conditioned seed for CTR_DRBG (seedlen =
                         blocklen + keylen = 128 + 256). Driven only while
                         cbcmac_valid && ctr_drbg_ready, so it is sampled on
                         the handshake cycle.
  - cbcmac_valid       : level, held in RELEASE until ctr_drbg_ready
  - health_error       : SP 800-90B RCT/APT failure (level, from health_tests)
  - ctr_drbg_ready     : consumer ack (input)
  - entropy            : raw noise-source bit, one per clk
  - enb_n              : active-low module enable

Internal hierarchy probed (Verilator public flattening):
  dut.fsm_state / dut.enc_cntr / dut.regV / dut.acc  : conditioner FSM + datapath
  dut.valid / dut.ready / dut.entropy_word           : collector handshake (SIPO)
  dut.cipher_done / dut.cipher_state                 : unmasked AES-256 core
  dut.HEALTH_TESTS.rct_error / .apt_error / .error   : health tests

Algorithm under test — SP 800-90B Appendix F, as required by SP 800-90C
Sec. 3.2.1.3 for an external conditioning function:

    V = 0
    for i = 0 .. w-1:  V = E(Key, V xor s_i)
    output V

The conditioner runs that over TWO 128-bit entropy words to produce ONE
128-bit full-entropy block, and does so THREE times to fill the 384-bit
CTR_DRBG seed. V is re-zeroed at the start of each of the three calls, so
the three blocks are independent CBC-MACs, NOT one chained MAC over six
blocks. Six entropy words (768 raw bits) are therefore consumed per seed;
consuming any other number is a deviation and is flagged as such.

Key: the conditioning key is a fixed public constant (SP 800-90C Sec. 3.2.1.1
explicitly permits hard-coded / fixed / all-zero keys here). It is parsed out
of cbc_mac.sv so the TB always models whatever the RTL was built with, and is
unpacked using the project's master_key convention (NIST key-schedule word
w[i] at bits [32*i +: 32]).

Reference model. cbc_mac_nist() transcribes Appendix F literally and works in
NIST byte order, so it reads directly against the spec text; the RTL's
state_matrix_t bit order is applied only at the DUT boundary in cbc_mac_rtl().
It is validated in two independent layers at import time:
  1. The underlying AES-256 comes from cipher_tb.AESEncryptModel, which
     self-checks against the FIPS 197 Appendix B / C.1 / C.2 / C.3 vectors.
  2. _cbcmac_model_self_check() checks the chaining itself against committed
     vectors generated with pyca/cryptography — a completely separate AES
     implementation — so the two must agree, rather than the model merely
     confirming itself. One vector degenerates to single-block (V = 0) and its
     answer is exactly the published FIPS 197 C.3 ciphertext; two more use the
     real conditioning key, which also anchors the master_key unpacking.

Design intent encoded here (RTL is never edited from this file; if the RTL
deviates the test fails and the message documents the deviation):
  - Exactly 6 entropy words are consumed per 384-bit seed.
  - Each 128-bit slice is an independent 2-block CBC-MAC starting from V = 0.
  - cbcmac_valid is held and random_word is stable until ctr_drbg_ready.
  - A single RCT or APT failure is fatal: the FSM latches in ERROR until
    an external reset, matching trng.sv's fail-fast DEAD behaviour.
"""

import re
import random
import logging
from pathlib import Path

import cocotb
import numpy as np
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, FallingEdge, ClockCycles, Timer

# FIPS 197 model + RTL packing helpers (single source of truth, self-checked)
from cipher_tb import (
    AESEncryptModel,
    nist_bytes_to_rtl_state,
    rtl_state_to_nist_bytes,
)

# Simulation constants
CLK_PERIOD_NS = 10
RESET_CYCLES  = 8

ENTROPY_WORD_BITS = 128          # entropy_clctr #(128) SIPO width
BLOCKS_PER_CALL   = 2            # CBC-MAC iterations per conditioned block
COND_BLOCKS       = 3            # 3 x 128 = 384-bit CTR_DRBG seed
WORDS_PER_SEED    = BLOCKS_PER_CALL * COND_BLOCKS      # 6
SEED_BITS         = 384
ENC_PER_SEED      = WORDS_PER_SEED                     # one AES call per word

# ~128 clk to refill the SIPO + ~58 clk per AES-256 encryption, x6, plus slack
SEED_TIMEOUT = 6000

# cbc_mac_states enum (type_defs_pkg.sv)
ST_CONSUME = 0
ST_OPERATE = 1
ST_RELEASE = 2
ST_ERROR   = 3
_ST_NAMES  = {0: "CONSUME", 1: "OPERATE", 2: "RELEASE", 3: "ERROR"}

_RTL_DIR   = Path(__file__).resolve().parent.parent / "rtl"
_PKG_FILE  = _RTL_DIR / "trng_param_pkg.sv"
_DUT_FILE  = _RTL_DIR / "cbc_mac.sv"

_mon_log = logging.getLogger("cocotb.monitor")


def _pkg_param(name, default):
    try:
        m = re.search(rf"localparam int {name}\s*=\s*(\d+)", _PKG_FILE.read_text())
        return int(m.group(1)) if m else default
    except OSError:
        return default


RCT_THRESHOLD  = _pkg_param("RCT_THRESHOLD", 22)
APT_BIT_WINDOW = _pkg_param("APT_BIT_WINDOW", 1024)
APT_THRESHOLD  = _pkg_param("APT_THRESHOLD", 590)


# Conditioning key — parsed from the RTL so the model can never drift from it
def _parse_master_key():
    m = re.search(r"MASTER_KEY\s*=\s*256'h([0-9A-Fa-f_]+)", _DUT_FILE.read_text())
    if not m:
        raise RuntimeError(f"Could not find MASTER_KEY localparam in {_DUT_FILE}")
    return int(m.group(1).replace("_", ""), 16)


MASTER_KEY_RTL = _parse_master_key()


def _rtl_master_key_to_nist_bytes(val, nk=8):
    """Invert the RTL master_key packing: NIST word w[i] lives at [32*i +: 32],
    so the on-the-wire literal is the key-schedule words in reverse order."""
    return bytes(
        b
        for i in range(nk)
        for b in ((val >> (32 * i)) & 0xFFFF_FFFF).to_bytes(4, "big")
    )


CONDITIONER_KEY = _rtl_master_key_to_nist_bytes(MASTER_KEY_RTL)
_AES = AESEncryptModel(CONDITIONER_KEY)

# Round-trip check: re-packing the modelled key must reproduce the RTL literal
assert _AES.master_key_rtl_int() == MASTER_KEY_RTL, (
    "Conditioning-key unpacking disagrees with the RTL master_key convention"
)


# Reference model — SP 800-90B Appendix F, transcribed literally
#
#   Process:
#     1. Let s0, s1, ... s(w-1) be the sequence of n-bit blocks of input_string
#     2. V = 0
#     3. For i = 0 to w-1:  V = E(Key, V xor si)
#     4. Output V
#
# The model is written in NIST byte order — the standard's own domain — so it
# can be read straight against the spec text and checked against third-party
# AES implementations. Conversion to the RTL's state_matrix_t bit order happens
# only at the DUT boundary, in cbc_mac_rtl().
def cbc_mac_nist(key_bytes, blocks):
    """CBC-MAC of a list of 16-byte NIST-order blocks under key_bytes."""
    aes = AESEncryptModel(key_bytes)
    v = bytes(16)                                        # step 2: V = 0
    for s in blocks:                                     # step 3
        v = bytes(aes.encrypt([a ^ b for a, b in zip(v, s)]))
    return v                                             # step 4


# Known-answer vectors generated with pyca/cryptography — an AES implementation
# with no shared code path with AESEncryptModel — so the check below is a real
# cross-implementation agreement test, not the model confirming itself. They are
# committed rather than computed at import so the check runs with no extra
# dependency. Note the single-block case degenerates to plain AES-256 ECB (V=0),
# and its expected value is exactly the FIPS 197 Appendix C.3 ciphertext.
_KAT_NIST_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

_CBCMAC_KAT = [
    # (key, [input blocks], expected MAC)
    (_KAT_NIST_KEY, ["00112233445566778899aabbccddeeff"],
     "8ea2b7ca516745bfeafc49904b496089"),          # == FIPS 197 C.3 ciphertext
    (_KAT_NIST_KEY, ["00112233445566778899aabbccddeeff",
                     "ffeeddccbbaa99887766554433221100"],
     "f1bcea379c3fc23221bd5cfe41d37533"),
    (CONDITIONER_KEY, ["00000000000000000000000000000000",
                       "00000000000000000000000000000000"],
     "098a8201699013a88f59ae7ca4f4503b"),          # anchors the key unpacking
    (CONDITIONER_KEY, ["379bc7d6a0dd7c711c3d4db7e1b9759a",
                       "dde413e70a3964bfe4e2143de62e595c"],
     "b14d8d61573b44a2e457ae52aca7d32c"),
]


def _cbcmac_model_self_check():
    for key, blocks_hex, want in _CBCMAC_KAT:
        got = cbc_mac_nist(key, [bytes.fromhex(b) for b in blocks_hex])
        assert got.hex() == want, (
            f"CBC-MAC reference model self-check FAILED\n"
            f"  key      = {key.hex()}\n"
            f"  blocks   = {blocks_hex}\n"
            f"  got      = {got.hex()}\n"
            f"  expected = {want}"
        )


_cbcmac_model_self_check()


def cbc_mac_rtl(words):
    """CBC-MAC over RTL-domain 128-bit words, returning an RTL-domain value.

    Only the domain conversion lives here; the algorithm itself is
    cbc_mac_nist(). XOR commutes with the flat-vector <-> state_matrix_t bit
    permutation, so converting per block and chaining in NIST order is exactly
    what the DUT computes.
    """
    mac = cbc_mac_nist(
        CONDITIONER_KEY, [rtl_state_to_nist_bytes(w) for w in words]
    )
    return nist_bytes_to_rtl_state(mac)


def expected_seed(words):
    """Six consumed words -> the 384-bit seed, as three independent 2-block
    CBC-MACs. Slice 0 occupies random_word[127:0]."""
    if len(words) != WORDS_PER_SEED:
        raise ValueError(f"need {WORDS_PER_SEED} words, got {len(words)}")
    blocks = [
        cbc_mac_rtl(words[i * BLOCKS_PER_CALL:(i + 1) * BLOCKS_PER_CALL])
        for i in range(COND_BLOCKS)
    ]
    seed = 0
    for i, b in enumerate(blocks):
        seed |= b << (128 * i)
    return seed, blocks


def seed_blocks(seed):
    """Split a 384-bit seed into its three 128-bit slices, LSB slice first."""
    return [(seed >> (128 * i)) & ((1 << 128) - 1) for i in range(COND_BLOCKS)]


# Noise bit buffer
class NoiseBitBuffer:
    """Pre-generated raw noise, indexed during simulation (zero scheduler cost).

    Modes
    -----
    'random'      — uniform random bits (healthy source).
    'stuck_0'     — constant 0. Trips RCT.
    'stuck_1'     — constant 1. Trips RCT.
    'apt_trigger' — 3 ones + 1 zero repeating: 75% ones (well above the APT
                    threshold) but a maximum run of 3, so RCT never fires first.
    """

    def __init__(self, mode="random", n_bits=200_000, seed=None):
        self._mode = mode
        self._seed = seed if seed is not None else random.randint(0, 0xFFFF_FFFF)
        self._idx = 0
        self._buf = self._generate(n_bits)

    def _generate(self, n):
        rng = np.random.default_rng(self._seed)
        if self._mode == "stuck_0":
            return np.zeros(n, dtype=np.uint8)
        if self._mode == "stuck_1":
            return np.ones(n, dtype=np.uint8)
        if self._mode == "apt_trigger":
            pattern = ([1] * 3 + [0]) * (n // 4 + 1)
            return np.array(pattern[:n], dtype=np.uint8)
        return rng.integers(0, 2, size=n, dtype=np.uint8)

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


# Entropy-word monitor
class WordMonitor:
    """Records every 128-bit word that crosses the collector -> conditioner
    handshake.

    Sampled on the falling edge so the recorded value is the one the DUT sees
    at the upcoming rising edge: the collector overwrites entropy_word on the
    very edge that completes the transfer, so a post-edge read would return
    an already-shifted word.
    """

    def __init__(self, dut):
        self.dut = dut
        self.words = []
        self._task = None

    def start(self):
        self._task = cocotb.start_soon(self._run())
        return self

    def stop(self):
        if self._task:
            self._task.cancel()

    async def _run(self):
        while True:
            await FallingEdge(self.dut.clk)
            if int(self.dut.valid.value) and int(self.dut.ready.value):
                self.words.append(int(self.dut.entropy_word.value))

    def take(self):
        w = list(self.words)
        self.words.clear()
        return w


async def signal_monitor(dut, label=""):
    """$monitor-style logger: prints only when a watched signal changes."""
    pfx = f"[MON {label}]" if label else "[MON]"

    def snap():
        return {
            "fsm": int(dut.fsm_state.value),
            "enc_cntr": int(dut.enc_cntr.value),
            "valid": int(dut.valid.value),
            "ready": int(dut.ready.value),
            "cipher_enb_n": int(dut.cipher_enb_n.value),
            "cipher_done": int(dut.cipher_done.value),
            "cbcmac_valid": int(dut.cbcmac_valid.value),
            "drbg_ready": int(dut.ctr_drbg_ready.value),
            "health_err": int(dut.health_error.value),
        }

    def fmt(k, v):
        return _ST_NAMES.get(v, str(v)) if k == "fsm" else str(v)

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
            _mon_log.info(
                f"{pfx} cyc={cyc:6d}  "
                + "  ".join(f"{k}: {fmt(k,o)}->{fmt(k,n)}" for k, o, n in diff)
            )
        prev = cur


# Common helpers
def start_clock(dut):
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, unit="ns").start())


async def reset_dut(dut, enable=True):
    dut.rst_n.value = 0
    dut.enb_n.value = 1
    dut.ctr_drbg_ready.value = 0
    dut.entropy.value = 0
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.rst_n.value = 1
    if enable:
        dut.enb_n.value = 0
    await RisingEdge(dut.clk)
    dut._log.info("DUT reset complete")


async def wait_signal(signal, value=1, timeout=50_000, clk=None):
    """Poll on the falling edge so the value read is the settled value of the
    cycle currently in flight — the same value the next rising edge will act
    on. Sampling on the rising edge instead would read a cycle late and can
    miss a one-cycle pulse such as cbcmac_valid when ctr_drbg_ready is already
    asserted."""
    for i in range(timeout):
        await FallingEdge(clk)
        if int(signal.value) == value:
            return i + 1
    raise AssertionError(
        f"TIMEOUT ({timeout} cycles): {signal._path} never reached {value}"
    )


async def collect_seed(dut, timeout=SEED_TIMEOUT):
    """Wait for cbcmac_valid, complete the ctr_drbg_ready handshake, return the
    384-bit seed.

    random_word is combinational on (cbcmac_valid && ctr_drbg_ready), so ready
    is raised mid-cycle and the data read after a settling delta, still ahead
    of the rising edge that completes the transfer.
    """
    await wait_signal(dut.cbcmac_valid, 1, timeout, dut.clk)
    dut.ctr_drbg_ready.value = 1
    await Timer(1, unit="ns")          # settle the combinational output path
    seed = int(dut.random_word.value)
    await RisingEdge(dut.clk)          # this edge completes the transfer
    dut.ctr_drbg_ready.value = 0

    # Ride out any stale assertion of cbcmac_valid after the handshake so a
    # later collect_seed() cannot re-consume the seed just taken. Whether the
    # deassert is prompt is a protocol requirement in its own right and is
    # owned by backpressure_test; swallowing it here keeps every other test
    # failing on its own cause instead of on this one.
    for _ in range(4):
        await FallingEdge(dut.clk)
        if int(dut.cbcmac_valid.value) == 0:
            break
    return seed


def check_seed(dut, words, seed, tag=""):
    """Scoreboard one seed against the SP 800-90B reference."""
    assert len(words) == WORDS_PER_SEED, (
        f"{tag}conditioner consumed {len(words)} entropy words per 384-bit seed, "
        f"expected exactly {WORDS_PER_SEED} "
        f"({COND_BLOCKS} conditioned blocks x {BLOCKS_PER_CALL} CBC-MAC iterations). "
        f"A word consumed but never encrypted is discarded entropy and "
        f"{ENTROPY_WORD_BITS} wasted collection cycles."
    )

    exp_seed, exp_blocks = expected_seed(words)
    got_blocks = seed_blocks(seed)

    mismatches = [
        (i, g, e) for i, (g, e) in enumerate(zip(got_blocks, exp_blocks)) if g != e
    ]
    if mismatches:
        lines = [f"{tag}CBC-MAC output mismatch (SP 800-90B Appendix F):"]
        for i, g, e in mismatches:
            lo, hi = 128 * i, 128 * (i + 1) - 1
            lines.append(f"  random_word[{hi}:{lo}]  rtl={g:032x}  ref={e:032x}")
            lines.append(
                f"    from s0={words[2*i]:032x}"
            )
            lines.append(
                f"         s1={words[2*i+1]:032x}"
            )
        raise AssertionError("\n".join(lines))

    dut._log.info(f"{tag}✓ all {COND_BLOCKS} conditioned blocks match the reference")
    return exp_seed


# TC1 — Reset / initial state
@cocotb.test()
async def reset_test(dut):
    """Post-reset state: FSM in CONSUME, counters and accumulator cleared,
    no output asserted."""
    dut._log.info("=" * 64)
    dut._log.info("TC1: Reset / initial state")
    dut._log.info("=" * 64)

    start_clock(dut)
    await reset_dut(dut, enable=False)

    assert int(dut.cbcmac_valid.value) == 0, "cbcmac_valid must be 0 after reset"
    assert int(dut.random_word.value) == 0, "random_word must be 0 after reset"
    assert int(dut.health_error.value) == 0, "health_error must be 0 after reset"
    dut._log.info("✓ All outputs cleared")

    assert int(dut.fsm_state.value) == ST_CONSUME, (
        f"FSM must reset to CONSUME, got {_ST_NAMES.get(int(dut.fsm_state.value))}"
    )
    assert int(dut.enc_cntr.value) == 0, "enc_cntr must reset to 0"
    assert int(dut.regV.value) == 0, "regV must reset to 0"
    assert int(dut.acc.value) == 0, "acc must reset to 0"
    assert int(dut.cipher_enb_n.value) == 1, "CIPHER must be disabled after reset"
    dut._log.info("✓ FSM in CONSUME, datapath cleared, CIPHER disabled")

    # With enb_n still high the module must not advance
    await ClockCycles(dut.clk, 20)
    assert int(dut.fsm_state.value) == ST_CONSUME, "FSM advanced while disabled"
    assert int(dut.cbcmac_valid.value) == 0, "cbcmac_valid asserted while disabled"
    dut._log.info("✓ Held in reset state while enb_n high — TC1 PASSED ✓")


# TC2 — Entropy collector SIPO + handshake
@cocotb.test()
async def sipo_collector_test(dut):
    """128-bit SIPO fills in exactly ENTROPY_WORD_BITS cycles, raises valid,
    and the conditioner acknowledges it."""
    dut._log.info("=" * 64)
    dut._log.info("TC2: Entropy collector SIPO + valid/ready handshake")
    dut._log.info("=" * 64)

    start_clock(dut)
    buf = NoiseBitBuffer(mode="random", seed=0xABCD)
    await reset_dut(dut)
    cocotb.start_soon(noise_driver(dut, buf))
    mon = WordMonitor(dut).start()

    n = await wait_signal(dut.valid, 1, ENTROPY_WORD_BITS + 20, dut.clk)
    word = int(dut.entropy_word.value)
    dut._log.info(f"✓ valid asserted after {n} cycles, entropy_word=0x{word:032X}")
    assert word != 0, "entropy_word all-zero — no bits shifted in"

    ones = bin(word).count("1")
    dut._log.info(f"  bit balance = {ones}/{ENTROPY_WORD_BITS} ones")
    assert 40 <= ones <= 88, f"entropy_word bit balance suspicious: {ones}/128"
    dut._log.info("✓ entropy_word bit balance OK")

    # The conditioner must take the word and start encrypting it
    await wait_signal(dut.fsm_state, ST_OPERATE, 20, dut.clk)
    dut._log.info("✓ Conditioner accepted the word and entered OPERATE")

    assert len(mon.words) >= 1, "no word recorded crossing the handshake"
    assert mon.words[0] == word, (
        f"handshaked word 0x{mon.words[0]:032x} != word presented by the "
        f"collector 0x{word:032x} — the SIPO is overwritten before it is latched"
    )
    dut._log.info("✓ Word latched by the conditioner matches the collector")

    # A second word must follow one full SIPO period later
    prev = len(mon.words)
    await wait_signal(dut.valid, 1, 2 * ENTROPY_WORD_BITS + 50, dut.clk)
    dut._log.info("✓ Collector refilled for the next block")
    mon.stop()
    dut._log.info("TC2 PASSED ✓")


# TC3 — Functional correctness of one 384-bit seed
@cocotb.test()
async def cbcmac_seed_test(dut):
    """One full 384-bit seed checked against the SP 800-90B Appendix F
    reference, using the entropy words the DUT actually consumed."""
    dut._log.info("=" * 64)
    dut._log.info("TC3: 384-bit seed vs SP 800-90B CBC-MAC reference")
    dut._log.info("=" * 64)
    dut._log.info(f"  conditioning key = {CONDITIONER_KEY.hex()}")

    start_clock(dut)
    buf = NoiseBitBuffer(mode="random", seed=0x1234)
    await reset_dut(dut)
    cocotb.start_soon(noise_driver(dut, buf))
    cocotb.start_soon(signal_monitor(dut, label="TC3"))
    mon = WordMonitor(dut).start()

    seed = await collect_seed(dut)
    words = mon.take()
    mon.stop()

    dut._log.info(f"  consumed {len(words)} entropy words")
    for i, w in enumerate(words):
        dut._log.info(f"    s{i} = {w:032x}")
    dut._log.info(f"  seed = {seed:096x}")

    assert seed != 0, "384-bit seed is all-zero"
    check_seed(dut, words, seed)
    dut._log.info("TC3 PASSED ✓")


# TC4 — Multiple back-to-back seeds
@cocotb.test()
async def multi_seed_test(dut):
    """Three consecutive seeds, each independently verified. Also proves the
    conditioner re-arms cleanly and never repeats a seed."""
    N_SEEDS = 3
    dut._log.info("=" * 64)
    dut._log.info(f"TC4: {N_SEEDS} back-to-back seeds, each scoreboarded")
    dut._log.info("=" * 64)

    start_clock(dut)
    buf = NoiseBitBuffer(mode="random", seed=0x5A5A)
    await reset_dut(dut)
    cocotb.start_soon(noise_driver(dut, buf))
    mon = WordMonitor(dut).start()

    seeds = []
    for k in range(N_SEEDS):
        seed = await collect_seed(dut)
        words = mon.take()
        dut._log.info(f"  seed {k+1}/{N_SEEDS}: {len(words)} words consumed")
        check_seed(dut, words, seed, tag=f"[seed {k}] ")
        seeds.append(seed)
    mon.stop()

    assert len(set(seeds)) == N_SEEDS, "duplicate 384-bit seeds produced"
    dut._log.info("✓ All seeds distinct")

    all_blocks = [b for s in seeds for b in seed_blocks(s)]
    assert len(set(all_blocks)) == len(all_blocks), (
        "duplicate 128-bit conditioned block across seeds — V is probably not "
        "being re-zeroed between CBC-MAC calls"
    )
    dut._log.info(f"✓ All {len(all_blocks)} conditioned blocks distinct — TC4 PASSED ✓")


# TC5 — Backpressure: valid held, data stable until ready
@cocotb.test()
async def backpressure_test(dut):
    """cbcmac_valid must stay asserted and the seed must not change while
    ctr_drbg_ready is held low."""
    HOLD = 300
    dut._log.info("=" * 64)
    dut._log.info(f"TC5: Backpressure — hold ctr_drbg_ready low for {HOLD} cycles")
    dut._log.info("=" * 64)

    start_clock(dut)
    buf = NoiseBitBuffer(mode="random", seed=0x7777)
    await reset_dut(dut)
    cocotb.start_soon(noise_driver(dut, buf))
    mon = WordMonitor(dut).start()

    await wait_signal(dut.cbcmac_valid, 1, SEED_TIMEOUT, dut.clk)
    dut._log.info("✓ cbcmac_valid asserted")

    acc_at_valid = int(dut.acc.value)
    for cyc in range(HOLD):
        await FallingEdge(dut.clk)
        assert int(dut.cbcmac_valid.value) == 1, (
            f"cbcmac_valid dropped at cycle {cyc} without ctr_drbg_ready — "
            f"the consumer would lose the seed"
        )
        assert int(dut.acc.value) == acc_at_valid, (
            f"accumulator changed at cycle {cyc} while waiting for ready — "
            f"held data must be stable across backpressure"
        )
        assert int(dut.fsm_state.value) == ST_RELEASE, (
            f"FSM left RELEASE at cycle {cyc} without ctr_drbg_ready"
        )
    dut._log.info(f"✓ valid held and data stable for {HOLD} cycles")

    # CIPHER must not be left running while parked in RELEASE
    assert int(dut.cipher_enb_n.value) == 1, (
        "CIPHER is still enabled in RELEASE — it burns power spinning on stale "
        "data for the whole backpressure window"
    )
    dut._log.info("✓ CIPHER disabled in RELEASE")

    # Now accept it and confirm the handshake completes
    words = mon.take()
    dut.ctr_drbg_ready.value = 1
    await Timer(1, unit="ns")
    seed = int(dut.random_word.value)
    await RisingEdge(dut.clk)
    dut.ctr_drbg_ready.value = 0
    mon.stop()

    assert seed == acc_at_valid, (
        f"seed delivered on the handshake (0x{seed:096x}) differs from the value "
        f"held during backpressure (0x{acc_at_valid:096x})"
    )
    dut._log.info("✓ Delivered seed equals the held value")

    await RisingEdge(dut.clk)
    assert int(dut.cbcmac_valid.value) == 0, "cbcmac_valid must clear after transfer"
    dut._log.info("✓ cbcmac_valid deasserted after transfer")

    check_seed(dut, words, seed)
    dut._log.info("TC5 PASSED ✓")


# TC6 — ctr_drbg_ready tied high (consumer always ready)
@cocotb.test()
async def always_ready_test(dut):
    """Corner case: ready asserted before valid and held high forever. The
    conditioner must still deliver a correct seed and re-arm."""
    dut._log.info("=" * 64)
    dut._log.info("TC6: ctr_drbg_ready tied high from reset")
    dut._log.info("=" * 64)

    start_clock(dut)
    buf = NoiseBitBuffer(mode="random", seed=0x2468)
    await reset_dut(dut)
    dut.ctr_drbg_ready.value = 1          # ready long before valid
    cocotb.start_soon(noise_driver(dut, buf))
    mon = WordMonitor(dut).start()

    await wait_signal(dut.cbcmac_valid, 1, SEED_TIMEOUT, dut.clk)
    await Timer(1, unit="ns")
    seed = int(dut.random_word.value)
    words = mon.take()

    assert seed != 0, "seed all-zero with ready tied high"
    check_seed(dut, words, seed, tag="[always-ready] ")

    # It must re-arm and produce a second, different seed without intervention
    await RisingEdge(dut.clk)
    await wait_signal(dut.cbcmac_valid, 0, 50, dut.clk)
    await wait_signal(dut.cbcmac_valid, 1, SEED_TIMEOUT, dut.clk)
    await Timer(1, unit="ns")
    seed2 = int(dut.random_word.value)
    words2 = mon.take()
    mon.stop()

    assert seed2 != seed, "second seed identical to the first"
    check_seed(dut, words2, seed2, tag="[always-ready #2] ")
    dut._log.info("✓ Re-armed and produced a second correct seed — TC6 PASSED ✓")


# TC7 — RCT negative test (stuck-at-0)
@cocotb.test()
async def rct_neg_test(dut):
    """Repetition Count Test: a stuck noise source must raise health_error and
    drive the conditioner into ERROR."""
    dut._log.info("=" * 64)
    dut._log.info(f"TC7: RCT — stuck-at-0 (threshold={RCT_THRESHOLD})")
    dut._log.info("=" * 64)

    start_clock(dut)
    buf = NoiseBitBuffer(mode="stuck_0")
    await reset_dut(dut)
    cocotb.start_soon(noise_driver(dut, buf))

    await wait_signal(dut.HEALTH_TESTS.rct_error, 1, RCT_THRESHOLD + 20, dut.clk)
    dut._log.info("✓ rct_error asserted")
    assert int(dut.health_error.value) == 1, "health_error output must follow rct_error"
    dut._log.info("✓ health_error output asserted")

    await wait_signal(dut.fsm_state, ST_ERROR, 10, dut.clk)
    dut._log.info("✓ Conditioner entered ERROR")

    assert int(dut.cbcmac_valid.value) == 0, "cbcmac_valid must not be set in ERROR"
    assert int(dut.cipher_enb_n.value) == 1, "CIPHER must be disabled in ERROR"
    dut._log.info("✓ Output withheld and CIPHER disabled — TC7 PASSED ✓")


# TC8 — APT negative test (75% ones, RCT-safe)
@cocotb.test()
async def apt_neg_test(dut):
    """Adaptive Proportion Test: a heavily biased but run-limited source must
    trip APT (and not RCT first) and drive the conditioner into ERROR."""
    dut._log.info("=" * 64)
    dut._log.info(f"TC8: APT — 75% ones (window={APT_BIT_WINDOW}, thr={APT_THRESHOLD})")
    dut._log.info("=" * 64)

    start_clock(dut)
    buf = NoiseBitBuffer(mode="apt_trigger", n_bits=4 * APT_BIT_WINDOW)
    await reset_dut(dut)
    cocotb.start_soon(noise_driver(dut, buf))

    await wait_signal(dut.HEALTH_TESTS.apt_error, 1, APT_BIT_WINDOW + 300, dut.clk)
    dut._log.info("✓ apt_error asserted")
    assert int(dut.HEALTH_TESTS.rct_error.value) == 0, (
        "rct_error also fired — the stimulus is not RCT-safe, so this test is "
        "not isolating the APT path"
    )
    dut._log.info("✓ rct_error clear — APT isolated")
    assert int(dut.health_error.value) == 1, "health_error output must follow apt_error"

    await wait_signal(dut.fsm_state, ST_ERROR, 10, dut.clk)
    dut._log.info("✓ Conditioner entered ERROR — TC8 PASSED ✓")


# TC9 — ERROR latches until external reset, then recovers
@cocotb.test()
async def error_latch_recovery_test(dut):
    """ERROR is fatal: it must latch with no self-exit, and only rst_n may
    recover the block. After recovery a healthy source must produce a correct
    seed again."""
    dut._log.info("=" * 64)
    dut._log.info("TC9: ERROR latch + reset recovery")
    dut._log.info("=" * 64)

    start_clock(dut)
    bad = NoiseBitBuffer(mode="stuck_1", n_bits=400)
    await reset_dut(dut)
    nd = cocotb.start_soon(noise_driver(dut, bad))

    await wait_signal(dut.fsm_state, ST_ERROR, RCT_THRESHOLD + 40, dut.clk)
    dut._log.info("✓ ERROR entered")

    # No self-exit: even once the (dead) source stops driving errors
    nd.cancel()
    dut.entropy.value = 0
    violations = []
    for cyc in range(50):
        await FallingEdge(dut.clk)
        st = int(dut.fsm_state.value)
        if st != ST_ERROR or int(dut.cbcmac_valid.value) != 0:
            violations.append((cyc, _ST_NAMES.get(st, st), int(dut.cbcmac_valid.value)))
    assert not violations, (
        "ERROR did not latch until rst_n — FSM left ERROR or asserted valid "
        f"without an external reset (first 5: {violations[:5]})"
    )
    dut._log.info("✓ ERROR latched for 50 cycles")

    assert int(dut.regV.value) == 0, "regV must be cleared in ERROR"
    assert int(dut.enc_cntr.value) == 0, "enc_cntr must be cleared in ERROR"
    dut._log.info("✓ Datapath cleared in ERROR")

    dut._log.info("Applying rst_n to recover...")
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.rst_n.value = 1
    await RisingEdge(dut.clk)

    assert int(dut.fsm_state.value) == ST_CONSUME, "FSM must return to CONSUME"
    assert int(dut.health_error.value) == 0, "health_error must clear after reset"
    dut._log.info("✓ Recovered to CONSUME, health_error cleared")

    good = NoiseBitBuffer(mode="random", seed=0xBEEF)
    cocotb.start_soon(noise_driver(dut, good))
    mon = WordMonitor(dut).start()
    seed = await collect_seed(dut)
    words = mon.take()
    mon.stop()

    assert seed != 0, "post-recovery seed is all-zero"
    check_seed(dut, words, seed, tag="[post-recovery] ")
    dut._log.info("✓ Correct seed produced after recovery — TC9 PASSED ✓")


# TC10 — enb_n gating mid-operation
@cocotb.test()
async def enb_gating_test(dut):
    """Deasserting enb_n mid-conditioning must freeze the FSM and datapath,
    and re-enabling must resume from exactly where it stopped."""
    FREEZE = 100
    dut._log.info("=" * 64)
    dut._log.info("TC10: enb_n freeze / resume mid-conditioning")
    dut._log.info("=" * 64)

    start_clock(dut)
    buf = NoiseBitBuffer(mode="random", seed=0x0F0F)
    await reset_dut(dut)
    nd = cocotb.start_soon(noise_driver(dut, buf))
    mon = WordMonitor(dut).start()

    # Let it get partway through a seed
    await wait_signal(dut.enc_cntr, 2, SEED_TIMEOUT, dut.clk)
    dut._log.info("✓ Reached enc_cntr=2 (first conditioned block done)")

    dut.enb_n.value = 1
    await ClockCycles(dut.clk, 2)
    frozen = {
        "fsm_state": int(dut.fsm_state.value),
        "enc_cntr": int(dut.enc_cntr.value),
        "regV": int(dut.regV.value),
        "acc": int(dut.acc.value),
    }
    dut._log.info(f"  frozen at fsm={_ST_NAMES[frozen['fsm_state']]} "
                  f"enc_cntr={frozen['enc_cntr']}")

    for cyc in range(FREEZE):
        await FallingEdge(dut.clk)
        for name, want in frozen.items():
            got = int(getattr(dut, name).value)
            assert got == want, (
                f"{name} changed while enb_n was high (cycle {cyc}): "
                f"0x{got:x} != 0x{want:x}"
            )
    dut._log.info(f"✓ FSM and datapath frozen for {FREEZE} cycles")
    assert int(dut.cbcmac_valid.value) == 0, "cbcmac_valid asserted while disabled"

    dut.enb_n.value = 0
    await RisingEdge(dut.clk)
    dut._log.info("Re-enabled — expecting the seed to complete")

    seed = await collect_seed(dut)
    words = mon.take()
    mon.stop()
    check_seed(dut, words, seed, tag="[resume] ")
    dut._log.info("✓ Seed completed correctly after resume — TC10 PASSED ✓")


# TC11 — enc_cntr / accumulator sequencing
@cocotb.test()
async def enc_cntr_sequence_test(dut):
    """enc_cntr must advance 0..6 with exactly one step per completed AES
    encryption, and each 128-bit accumulator slice must be written exactly
    once, at the end of its own CBC-MAC call."""
    dut._log.info("=" * 64)
    dut._log.info("TC11: enc_cntr sequencing + accumulator slice capture")
    dut._log.info("=" * 64)

    start_clock(dut)
    buf = NoiseBitBuffer(mode="random", seed=0x3141)
    await reset_dut(dut)
    cocotb.start_soon(noise_driver(dut, buf))

    seq = []
    done_count = 0
    slice_writes = [0, 0, 0]
    prev_slices = [0, 0, 0]
    prev_cntr = 0

    for _ in range(SEED_TIMEOUT):
        await FallingEdge(dut.clk)
        if int(dut.fsm_state.value) == ST_OPERATE and int(dut.cipher_done.value):
            done_count += 1
            seq.append(int(dut.enc_cntr.value))

        cur_slices = seed_blocks(int(dut.acc.value))
        for i in range(COND_BLOCKS):
            if cur_slices[i] != prev_slices[i]:
                slice_writes[i] += 1
        prev_slices = cur_slices
        prev_cntr = int(dut.enc_cntr.value)

        if int(dut.cbcmac_valid.value):
            break

    assert done_count == ENC_PER_SEED, (
        f"{done_count} AES encryptions per seed, expected {ENC_PER_SEED} "
        f"({COND_BLOCKS} blocks x {BLOCKS_PER_CALL})"
    )
    dut._log.info(f"✓ Exactly {ENC_PER_SEED} AES encryptions per seed")

    assert seq == list(range(ENC_PER_SEED)), (
        f"enc_cntr at each cipher_done was {seq}, expected {list(range(ENC_PER_SEED))} "
        f"— the counter must advance once per completed encryption"
    )
    dut._log.info(f"✓ enc_cntr sequence at cipher_done: {seq}")

    for i, n in enumerate(slice_writes):
        assert n == 1, (
            f"acc slice {i} (random_word[{128*(i+1)-1}:{128*i}]) was written {n} "
            f"times during one seed, expected exactly 1 — a slice written more "
            f"than once is being overwritten after its CBC-MAC call completed"
        )
    dut._log.info("✓ Each accumulator slice written exactly once — TC11 PASSED ✓")


# TC12 — Output statistics
@cocotb.test()
async def statistics_test(dut):
    """Statistical sanity of the conditioned output: balanced bits and no
    repeated 128-bit blocks. A conditioning function that collapses entropy
    shows up here even when the per-seed KAT passes."""
    N_SEEDS = 3
    dut._log.info("=" * 64)
    dut._log.info(f"TC12: Output statistics over {N_SEEDS} seeds")
    dut._log.info("=" * 64)

    start_clock(dut)
    buf = NoiseBitBuffer(mode="random", seed=0xC0FFEE)
    await reset_dut(dut)
    cocotb.start_soon(noise_driver(dut, buf))

    seeds = []
    for k in range(N_SEEDS):
        seeds.append(await collect_seed(dut))
        frac = bin(seeds[-1]).count("1") / SEED_BITS
        dut._log.info(f"  seed {k}: ones fraction = {frac:.3f}")
        assert 0.35 <= frac <= 0.65, (
            f"seed {k} bit balance {frac:.3f} outside [0.35, 0.65] — the "
            f"conditioned output is not behaving like a PRF output"
        )
    dut._log.info("✓ All seeds pass bit-balance")

    blocks = [b for s in seeds for b in seed_blocks(s)]
    assert 0 not in blocks, "an all-zero conditioned block was produced"
    assert len(set(blocks)) == len(blocks), "repeated 128-bit conditioned block"
    dut._log.info(f"✓ {len(blocks)} distinct non-zero blocks — TC12 PASSED ✓")


# TC13 — Reset asserted mid-conditioning
@cocotb.test()
async def reset_mid_operation_test(dut):
    """An asynchronous-looking reset in the middle of a CBC-MAC call must
    abandon the partial state cleanly and the next seed must still be correct
    (no carry-over of a stale chaining value into the new first block)."""
    dut._log.info("=" * 64)
    dut._log.info("TC13: Reset mid-conditioning")
    dut._log.info("=" * 64)

    start_clock(dut)
    buf = NoiseBitBuffer(mode="random", seed=0xDEAD)
    await reset_dut(dut)
    cocotb.start_soon(noise_driver(dut, buf))

    await wait_signal(dut.enc_cntr, 3, SEED_TIMEOUT, dut.clk)
    dut._log.info("✓ Interrupting partway through the second conditioned block")

    dut.rst_n.value = 0
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.rst_n.value = 1
    await RisingEdge(dut.clk)

    assert int(dut.fsm_state.value) == ST_CONSUME, "FSM must reset to CONSUME"
    assert int(dut.enc_cntr.value) == 0, "enc_cntr must clear"
    assert int(dut.regV.value) == 0, "regV must clear — a stale V would chain into "\
                                     "the first block of the next seed"
    assert int(dut.acc.value) == 0, "acc must clear — stale blocks would leak into "\
                                    "the next seed"
    dut._log.info("✓ All state cleared by reset")

    mon = WordMonitor(dut).start()
    seed = await collect_seed(dut)
    words = mon.take()
    mon.stop()

    check_seed(dut, words, seed, tag="[post-reset] ")
    dut._log.info("✓ Next seed correct after mid-operation reset — TC13 PASSED ✓")


# TC14 — Health failure during conditioning
@cocotb.test()
async def health_error_mid_operation_test(dut):
    """A health failure that appears *after* conditioning has started must
    still abort into ERROR and must not release a partially conditioned seed."""
    dut._log.info("=" * 64)
    dut._log.info("TC14: Health failure mid-conditioning")
    dut._log.info("=" * 64)

    start_clock(dut)
    good = NoiseBitBuffer(mode="random", seed=0x9999)
    await reset_dut(dut)
    nd = cocotb.start_soon(noise_driver(dut, good))

    await wait_signal(dut.enc_cntr, 2, SEED_TIMEOUT, dut.clk)
    dut._log.info("✓ Conditioning under way (enc_cntr=2)")
    assert int(dut.fsm_state.value) != ST_ERROR, "unexpected early ERROR"

    # Kill the noise source mid-flight
    nd.cancel()
    dut._log.info("Noise source going stuck-at-1...")
    bad = NoiseBitBuffer(mode="stuck_1", n_bits=400)
    cocotb.start_soon(noise_driver(dut, bad))

    await wait_signal(dut.health_error, 1, RCT_THRESHOLD + 40, dut.clk)
    dut._log.info("✓ health_error asserted mid-conditioning")

    await wait_signal(dut.fsm_state, ST_ERROR, 200, dut.clk)
    dut._log.info("✓ Conditioner aborted into ERROR")

    for _ in range(50):
        await FallingEdge(dut.clk)
        assert int(dut.cbcmac_valid.value) == 0, (
            "cbcmac_valid asserted after a health failure — a partially "
            "conditioned seed must never be released to the CTR_DRBG"
        )
    dut._log.info("✓ No seed released after the failure — TC14 PASSED ✓")
