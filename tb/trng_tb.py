"""
Cocotb testbench for the TRNG block (trng.sv).

DUT interface (current trng.sv):
  - rand_word[1679:0] : one-shot 1680-bit random packet
  - trng_key_valid    : key ready (level, held until acknowledged)
  - sbox_ready        : consumer ack (input). One-cycle pulse completes the
                        handshake: rand_word is registered ON the ack edge,
                        so the fresh value is readable one cycle AFTER the
                        pulse; trng_key_valid deasserts one cycle later still.
  - dead_flag         : TRNG total failure indicator
  - raw_rand_bit      : noise source input (sampling_clk domain)

Internal hierarchy probed (Verilator --public-flat-rw):
  dut.rand_bit_sync1 / dut.rand_bit         : 2-flop CDC synchronizer
  dut.valid / dut.entropy_word              : entropy collector SIPO
  dut.CONTROL_UNIT.*                        : control unit FSM + controls
  dut.KECCAK_COND.fsm_state/rx_cntr/round_cntr : Keccak conditioning FSM
  dut.HEALTH_TESTS.rct_error/apt_error/error   : health tests

Health-test / DRBG parameters are parsed from the generated
rtl/trng_param_pkg.sv so the TB always matches what the RTL was built with.

Raw-entropy absorb note: keccak absorbs 3 x 64-bit SIPO words (rx_cntr 0..2
fill temp_entropy[191:0]; when rx_cntr==3 the state is seeded and PERMUTE
starts), so the first key appears ~200 clk after reset with live noise.

Design intent (current RTL): fail-fast, no recovery. There is no
ERROR_RECOVERY state and no total_failure/consecutive-error counting — a
SINGLE health-test error (RCT or APT) is treated as fatal and the CU
transitions directly BIST/WAIT_FOR_XFER -> DEAD. DEAD latches (dead_flag
stays 1, fsm_state stays DEAD) until ext_rst_n is asserted; that is the
only way back to IDLE. Negative tests (TC2/TC3/TC4/TC6) encode this
fail-fast behavior. If the RTL deviates, the test fails and the failure
message documents the deviation — RTL is never edited from here.
"""

import cocotb
import random
import re
import logging
import numpy as np
from pathlib import Path
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles

# Simulation constants
CLK_PERIOD_NS  = 10
SCLK_PERIOD_NS = 2
RESET_CYCLES   = 8
NOISE_BUF_SIZE = 5000

ENTROPY_WORD_BITS   = 64
KECCAK_PERMUTE_RNDS = 24
RAND_WORD_BITS      = 1680

# Parameters parsed from the generated package (single source of truth)
_PKG_FILE = Path(__file__).resolve().parent.parent / "rtl" / "trng_param_pkg.sv"

def _pkg_param(name, default):
    try:
        m = re.search(rf"localparam int {name}\s*=\s*(\d+)", _PKG_FILE.read_text())
        return int(m.group(1)) if m else default
    except OSError:
        return default

RCT_THRESHOLD      = _pkg_param("RCT_THRESHOLD", 22)
APT_BIT_WINDOW     = _pkg_param("APT_BIT_WINDOW", 1024)
APT_THRESHOLD      = _pkg_param("APT_THRESHOLD", 551)
DRBG_CYCLES        = _pkg_param("DRBG_CYCLES", 1024)

# cu_states enum (type_defs_pkg.sv): IDLE, BIST, WAIT_FOR_XFER, DEAD
# ERROR_RECOVERY was removed from the enum itself (not just made unreachable),
# so the encoding is now 2 bits wide with DEAD=3.
CU_IDLE           = 0
CU_BIST           = 1
CU_WAIT_FOR_XFER  = 2
CU_DEAD           = 3

KEC_ABSORB  = 0
KEC_PERMUTE = 1
KEC_SQUEEZ  = 2

# ~28 clk per DRBG key (1 absorb + 24 permute + 2 squeeze + handshake)
DRBG_KEY_CYCLES   = 32
FIRST_KEY_TIMEOUT = 2000    # covers 3 SIPO fills (~200 clk) + margin

_mon_log = logging.getLogger("cocotb.monitor")

try:
    from noise_source_model import TRNGNoiseSource
    _HAVE_PHYSICS_MODEL = True
except ImportError:
    _HAVE_PHYSICS_MODEL = False
    cocotb.log.warning(
        "noise_source_model.py not found — normal tests fall back to numpy random"
    )


# Noise bit buffer
class NoiseBitBuffer:
    """
    Pre-generates noise bits before simulation starts.
    All generation cost is paid once upfront; during simulation next_bit()
    is a pure array index lookup — zero scheduler impact. The buffer wraps,
    so long runs (e.g. a full DRBG wrap of ~30k clk) reuse the same bits.

    Modes
    -----
    'physics'  — RO physics model (TRNGNoiseSource, 32 ROs x 13 INV, 150 MHz).
                 Use for all normal-operation tests.
    'random'   — numpy uniform random. Automatic fallback if model unavailable.
    'stuck_0'  — constant 0. Triggers RCT (TC2) -> fatal, DEAD.
    'stuck_1'  — constant 1. Triggers RCT (TC4/TC6) -> fatal, DEAD.
    'biased'   — P(1)=bias. Triggers APT.
    'apt_trigger' — 3 ones + 1 zero repeating: 75% ones (>> APT threshold
                 53.8%) but max run of 3 at any sampling stride, so RCT
                 never fires first (TC3).
    """

    def __init__(self, mode='random', n_bits=NOISE_BUF_SIZE, bias=0.9, seed=None):
        self._mode = mode
        self._seed = seed if seed is not None else random.randint(0, 0xFFFF_FFFF)
        self._bias = bias
        self._idx  = 0
        self._buf  = self._generate(n_bits)

    def _generate(self, n):
        rng = np.random.default_rng(self._seed)

        if self._mode == 'physics':
            if not _HAVE_PHYSICS_MODEL:
                cocotb.log.warning("Physics model not available — using numpy random")
                return rng.integers(0, 2, size=n, dtype=np.uint8)
            cocotb.log.info(
                f"[NoiseBitBuffer] Generating {n:,} physics bits "
                f"(32 RO x 13 INV @ 150 MHz)..."
            )
            src  = TRNGNoiseSource(n_ro=32, n_inv=13, fs_MHz=150.0, seed=self._seed)
            bits = src.generate_bits(n)
            cocotb.log.info("[NoiseBitBuffer] Done.")
            return bits

        elif self._mode == 'stuck_0':
            return np.zeros(n, dtype=np.uint8)

        elif self._mode == 'stuck_1':
            return np.ones(n, dtype=np.uint8)

        elif self._mode == 'biased':
            return (rng.random(n) < self._bias).astype(np.uint8)

        elif self._mode == 'apt_trigger':
            pattern = ([1]*3 + [0]*1) * (n // 4 + 1)
            return np.array(pattern[:n], dtype=np.uint8)

        else:   # 'random'
            return rng.integers(0, 2, size=n, dtype=np.uint8)

    def next_bit(self) -> int:
        if self._idx >= len(self._buf):
            self._idx = 0
        b = int(self._buf[self._idx])
        self._idx += 1
        return b


# Noise driver
async def noise_driver(dut, buf: NoiseBitBuffer):
    """Drive raw_rand_bit from pre-generated buffer on every sampling_clk edge."""
    while True:
        await RisingEdge(dut.sampling_clk)
        dut.raw_rand_bit.value = buf.next_bit()


# Signal monitor  (cocotb equivalent of $monitor)
_CU_NAMES  = {0:"IDLE", 1:"BIST", 2:"WAIT_FOR_XFER", 3:"DEAD"}
_KEC_NAMES = {0:"ABSORB", 1:"PERMUTE", 2:"SQUEEZ"}


async def signal_monitor(dut, label=""):
    """
    Background coroutine that watches all key signals on every rising clk
    edge and logs only when something changes — identical to $monitor.
    Uses the "cocotb.monitor" logger so test checkpoints ("cocotb.trng")
    and signal transitions stay grep-separable in the same log.
    """
    pfx = f"[MON {label}]" if label else "[MON]"

    def snap():
        return {
            "ext_rst_n"   : int(dut.ext_rst_n.value),
            "raw_bit"     : int(dut.raw_rand_bit.value),
            "sbox_ready"  : int(dut.sbox_ready.value),
            "key_valid"   : int(dut.trng_key_valid.value),
            "dead_flag"   : int(dut.dead_flag.value),
            "cu_state"    : int(dut.CONTROL_UNIT.fsm_state.value),
            "ns_enb_n"    : int(dut.CONTROL_UNIT.noise_src_enb_n.value),
            "enb_hlth_n"  : int(dut.CONTROL_UNIT.enb_health_tests_n.value),
            "get_raw"     : int(dut.CONTROL_UNIT.get_raw_entropy.value),
            "local_rst_n" : int(dut.CONTROL_UNIT.local_rst_n.value),
            "drbg_cntr"   : int(dut.CONTROL_UNIT.drbg_cntr.value),
            "kec_state"   : int(dut.KECCAK_COND.fsm_state.value),
            "rx_cntr"     : int(dut.KECCAK_COND.rx_cntr.value),
            "round_cntr"  : int(dut.KECCAK_COND.round_cntr.value),
            "rct_err"     : int(dut.HEALTH_TESTS.rct_error.value),
            "apt_err"     : int(dut.HEALTH_TESTS.apt_error.value),
            "hlth_err"    : int(dut.HEALTH_TESTS.error.value),
            "valid"       : int(dut.valid.value),
        }

    def fmt(k, v):
        if k == "cu_state":  return _CU_NAMES.get(v, str(v))
        if k == "kec_state": return _KEC_NAMES.get(v, str(v))
        return str(v)

    await RisingEdge(dut.clk)
    prev = snap()
    _mon_log.info(
        f"{pfx} INIT  "
        + "  ".join(f"{k}={fmt(k,v)}" for k, v in prev.items())
    )

    cyc = 0
    while True:
        await RisingEdge(dut.clk)
        cyc += 1
        cur  = snap()
        diff = [(k, prev[k], cur[k]) for k in cur if prev[k] != cur[k]]
        if diff:
            changes = "  ".join(f"{k}: {fmt(k,ov)}->{fmt(k,nv)}" for k, ov, nv in diff)
            _mon_log.info(f"{pfx} cyc={cyc:5d}  {changes}")
        prev = cur


# Common helpers
def start_clocks(dut):
    cocotb.start_soon(Clock(dut.clk,          CLK_PERIOD_NS,  unit="ns").start())
    cocotb.start_soon(Clock(dut.sampling_clk, SCLK_PERIOD_NS, unit="ns").start())


async def reset_dut(dut):
    dut.ext_rst_n.value    = 0
    dut.sbox_ready.value   = 0
    dut.raw_rand_bit.value = 0
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.ext_rst_n.value = 1
    await RisingEdge(dut.clk)
    dut._log.info("DUT reset complete")


async def wait_signal(signal, value=1, timeout=50_000, clk=None):
    for i in range(timeout):
        await RisingEdge(clk)
        if int(signal.value) == value:
            return i + 1
    raise AssertionError(f"TIMEOUT ({timeout} cycles): {signal._path} never reached {value}")


async def collect_key(dut, timeout=FIRST_KEY_TIMEOUT):
    """
    Wait for trng_key_valid, complete the sbox_ready handshake and return the
    1680-bit rand_word.

    Timing: rand_word is registered on the same edge that samples
    sbox_ready=1, so the fresh key is readable one cycle after the ack pulse;
    trng_key_valid clears one further cycle later (keccak back in ABSORB).
    """
    await wait_signal(dut.trng_key_valid, value=1, timeout=timeout, clk=dut.clk)
    dut.sbox_ready.value = 1
    await RisingEdge(dut.clk)      # ack sampled: rand_word registered now
    dut.sbox_ready.value = 0
    await RisingEdge(dut.clk)      # rand_word readable; key_valid clearing
    key = int(dut.rand_word.value)
    await RisingEdge(dut.clk)      # trng_key_valid now 0 — safe to re-poll
    return key


def key_words(key, width=64):
    """Split a 1680-bit key into width-bit chunks (LSB first)."""
    n = RAND_WORD_BITS // width
    return [(key >> (width * i)) & ((1 << width) - 1) for i in range(n)]


# TC1 — Normal end-to-end operation (physics noise)
@cocotb.test()
async def e2e_op_test(dut):
    """Full end-to-end TRNG operation with physics noise."""
    dut._log.info("=" * 60)
    dut._log.info("TC1: Normal operation")
    dut._log.info("=" * 60)

    start_clocks(dut)
    buf = NoiseBitBuffer(
        mode='physics' if _HAVE_PHYSICS_MODEL else 'random',
        seed=random.randint(0, 0xFFFF_FFFF)
    )
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC1"))
    cocotb.start_soon(noise_driver(dut, buf))

    await ClockCycles(dut.clk, 3)
    cu = int(dut.CONTROL_UNIT.fsm_state.value)
    assert cu == CU_BIST, f"Expected CU_BIST({CU_BIST}), got {cu}"
    dut._log.info("✓ CU in BIST state")

    await wait_signal(dut.CONTROL_UNIT.get_raw_entropy, value=1, timeout=50, clk=dut.clk)
    dut._log.info("✓ get_raw_entropy = 1 (raw entropy path active)")

    # The FIRST key must be seeded from raw noise: keccak has to sit in
    # ABSORB handshaking SIPO words (rx_cntr advancing) before its first
    # PERMUTE. If it already left ABSORB it sampled get_raw_entropy=0 on the
    # cycle after reset and DRBG-absorbed an all-zero state — a
    # deterministic, zero-entropy first key.
    assert int(dut.KECCAK_COND.fsm_state.value) == KEC_ABSORB, (
        "Keccak left ABSORB before raw entropy was available — first key is "
        "DRBG-generated from the all-zero reset state (deterministic, zero "
        "entropy); raw noise is not absorbed until drbg_cntr wraps "
        f"({DRBG_CYCLES} keys)")
    await wait_signal(dut.KECCAK_COND.rx_cntr, value=1,
                      timeout=2 * ENTROPY_WORD_BITS, clk=dut.clk)
    dut._log.info("✓ Keccak accepted first raw SIPO word (rx_cntr=1)")

    # 3 x 64-bit SIPO words feed the absorb, ~64 clk each
    await wait_signal(dut.KECCAK_COND.fsm_state, value=KEC_PERMUTE, timeout=500, clk=dut.clk)
    dut._log.info("✓ Keccak entered PERMUTE (entropy absorbed)")

    await wait_signal(dut.KECCAK_COND.fsm_state, value=KEC_SQUEEZ, timeout=50, clk=dut.clk)
    dut._log.info("✓ Keccak in SQUEEZ")

    key = await collect_key(dut, timeout=200)
    assert key != 0, "rand_word is all-zero — suspicious"
    words = key_words(key)
    assert len(set(words)) == len(words), "Duplicate 64-bit words within key"
    dut._log.info(f"✓ 1680-bit key collected, {len(words)} unique 64-bit words "
                  f"(rand_word[63:0]=0x{words[0]:016X})")

    await ClockCycles(dut.clk, 2)
    assert int(dut.trng_key_valid.value) == 0, "trng_key_valid should be 0 after transfer"
    dut._log.info("✓ trng_key_valid deasserted")

    # DRBG phase: keys keep coming with get_raw_entropy low until drbg_cntr
    # wraps at DRBG_CYCLES-1, then the raw-entropy path is re-enabled.
    dut._log.info(f"Monitoring DRBG phase (expect {DRBG_CYCLES - 1} keys before raw re-assert)...")
    drbg_keys = 0
    raw_seen  = False
    for _ in range(DRBG_CYCLES * DRBG_KEY_CYCLES + 10_000):
        await RisingEdge(dut.clk)
        if int(dut.CONTROL_UNIT.get_raw_entropy.value) == 1:
            raw_seen = True
            dut._log.info(f"  Raw entropy re-asserted after {drbg_keys} DRBG keys")
            break
        if int(dut.trng_key_valid.value) == 1:
            drbg_keys += 1
            if drbg_keys % 100 == 0 or drbg_keys <= 3:
                dut._log.info(f"  DRBG key #{drbg_keys}  drbg_cntr={int(dut.CONTROL_UNIT.drbg_cntr.value)}")
            dut.sbox_ready.value = 1
            await RisingEdge(dut.clk)
            dut.sbox_ready.value = 0
            await ClockCycles(dut.clk, 2)   # let trng_key_valid clear

    assert raw_seen, "get_raw_entropy never re-asserted after DRBG phase"
    dut._log.info(f"✓ DRBG ran for {drbg_keys} keys, raw entropy restored")
    assert int(dut.dead_flag.value) == 0,             "dead_flag set"
    assert int(dut.HEALTH_TESTS.error.value) == 0,    "health_error set"
    dut._log.info("✓ No health errors — TC1 PASSED ✓")


# TC2 — RCT negative test (stuck_0): single error is fatal -> DEAD
@cocotb.test()
async def rct_neg_test(dut):
    """RCT negative test — stuck-at-0 noise. Design intent is fail-fast:
    there is no ERROR_RECOVERY state, so a single rct_error must send the
    CU directly from BIST to DEAD, latching dead_flag."""
    dut._log.info("=" * 60)
    dut._log.info("TC2: RCT — stuck-at-0 (fail-fast to DEAD)")
    dut._log.info("=" * 60)

    start_clocks(dut)
    buf = NoiseBitBuffer(mode='stuck_0')
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC2"))
    cocotb.start_soon(noise_driver(dut, buf))

    await wait_signal(dut.CONTROL_UNIT.enb_health_tests_n, value=0, timeout=20, clk=dut.clk)
    dut._log.info("✓ Health tests enabled")

    await wait_signal(dut.HEALTH_TESTS.rct_error, value=1, timeout=RCT_THRESHOLD + 15, clk=dut.clk)
    dut._log.info("✓ rct_error asserted")

    await wait_signal(dut.CONTROL_UNIT.fsm_state, value=CU_DEAD, timeout=5, clk=dut.clk)
    dut._log.info("✓ CU transitioned directly to DEAD (fail-fast, no recovery state)")

    await wait_signal(dut.dead_flag, value=1, timeout=5, clk=dut.clk)
    dut._log.info("✓ dead_flag asserted — TC2 PASSED ✓")


# TC3 — APT negative test (75% ones, RCT-safe pattern): single error is fatal -> DEAD
@cocotb.test()
async def apt_neg_test(dut):
    """APT negative test — 75%-ones pattern that cannot trip RCT. A single
    apt_error is fatal by design and must send the CU directly to DEAD."""
    dut._log.info("=" * 60)
    dut._log.info("TC3: APT — 75% ones (RCT-safe, fail-fast to DEAD)")
    dut._log.info("=" * 60)

    start_clocks(dut)
    buf = NoiseBitBuffer(mode='apt_trigger', n_bits=APT_BIT_WINDOW + 500)
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC3"))
    cocotb.start_soon(noise_driver(dut, buf))

    await wait_signal(dut.CONTROL_UNIT.enb_health_tests_n, value=0, timeout=20, clk=dut.clk)
    dut._log.info("✓ Health tests enabled")

    await wait_signal(dut.HEALTH_TESTS.apt_error, value=1, timeout=APT_BIT_WINDOW + 200, clk=dut.clk)
    dut._log.info("✓ apt_error asserted")

    assert int(dut.HEALTH_TESTS.error.value) == 1, "health_error should be high"
    dut._log.info("✓ health_error asserted")

    await wait_signal(dut.CONTROL_UNIT.fsm_state, value=CU_DEAD, timeout=5, clk=dut.clk)
    dut._log.info("✓ CU transitioned directly to DEAD — TC3 PASSED ✓")


# TC4 — Fatal health error -> DEAD (stuck_1): DEAD must latch until ext reset
@cocotb.test()
async def dead_neg_test(dut):
    """Fatal health-test error -> DEAD state. DEAD (and dead_flag) must
    persist until ext_rst_n; recovery via external reset is then verified.
    A single error event is sufficient — there is no consecutive-error
    counting or ERROR_RECOVERY state in the current design."""
    dut._log.info("=" * 60)
    dut._log.info("TC4: Fatal health error -> DEAD state")
    dut._log.info("=" * 60)

    start_clocks(dut)
    buf = NoiseBitBuffer(mode='stuck_1')
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC4"))
    cocotb.start_soon(noise_driver(dut, buf))

    total_fail_timeout = RCT_THRESHOLD + 30
    await wait_signal(dut.HEALTH_TESTS.error, value=1, timeout=total_fail_timeout, clk=dut.clk)
    dut._log.info("✓ health_error asserted")

    await wait_signal(dut.CONTROL_UNIT.fsm_state, value=CU_DEAD, timeout=5, clk=dut.clk)
    dut._log.info("✓ CU in DEAD state")

    await wait_signal(dut.dead_flag, value=1, timeout=5, clk=dut.clk)
    dut._log.info("✓ dead_flag asserted")

    assert int(dut.CONTROL_UNIT.noise_src_enb_n.value) == 1, "noise must be disabled in DEAD"
    assert int(dut.CONTROL_UNIT.enb_health_tests_n.value) == 1, "health tests must be off in DEAD"
    dut._log.info("✓ Noise + health tests disabled in DEAD")

    # DEAD must latch: no self-exit, dead_flag stays high with no ext reset
    violations = []
    for cyc in range(20):
        await RisingEdge(dut.clk)
        st, df = int(dut.CONTROL_UNIT.fsm_state.value), int(dut.dead_flag.value)
        if st != CU_DEAD or df != 1:
            violations.append((cyc, _CU_NAMES.get(st, st), df))
    assert not violations, (
        f"DEAD did not latch until ext_rst_n — CU left DEAD / dead_flag dropped "
        f"without external reset (first 5 violations (cyc, cu_state, dead_flag): "
        f"{violations[:5]})")
    dut._log.info("✓ DEAD latched for 20 cycles")

    dut._log.info("Applying ext_rst_n to recover...")
    dut.ext_rst_n.value = 0
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.ext_rst_n.value = 1
    await ClockCycles(dut.clk, 3)

    cu = int(dut.CONTROL_UNIT.fsm_state.value)
    assert cu in (CU_IDLE, CU_BIST), f"Expected IDLE/BIST after reset, got {cu}"
    dut._log.info(f"✓ CU state = {cu} after reset")

    assert int(dut.dead_flag.value) == 0, "dead_flag must clear after ext_rst_n"
    dut._log.info("✓ dead_flag cleared — TC4 PASSED ✓")


# TC5 — DRBG counter sequence (physics noise)
@cocotb.test()
async def drbg_cntr_test(dut):
    """drbg_cntr increment sequence: 1..DRBG_CYCLES-1 then wrap to raw entropy."""
    dut._log.info("=" * 60)
    dut._log.info(f"TC5: DRBG counter sequence (DRBG_CYCLES={DRBG_CYCLES})")
    dut._log.info("=" * 60)

    start_clocks(dut)
    buf = NoiseBitBuffer(
        mode='physics' if _HAVE_PHYSICS_MODEL else 'random',
        seed=7
    )
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC5"))
    cocotb.start_soon(noise_driver(dut, buf))

    dut._log.info("Waiting for first key (raw entropy)...")
    _ = await collect_key(dut, timeout=FIRST_KEY_TIMEOUT)
    dut._log.info("✓ First key collected")

    observed = []
    raw_seen = False
    for _ in range(DRBG_CYCLES * DRBG_KEY_CYCLES + 10_000):
        await RisingEdge(dut.clk)
        if int(dut.CONTROL_UNIT.get_raw_entropy.value) == 1:
            raw_seen = True
            dut._log.info(f"  get_raw_entropy=1 after {len(observed)} DRBG keys")
            break
        if int(dut.trng_key_valid.value) == 1:
            cnt = int(dut.CONTROL_UNIT.drbg_cntr.value)
            if not observed or cnt != observed[-1]:
                observed.append(cnt)
                if len(observed) % 100 == 0 or len(observed) <= 3:
                    dut._log.info(f"  DRBG key #{len(observed)}: drbg_cntr={cnt}")
            dut.sbox_ready.value = 1
            await RisingEdge(dut.clk)
            dut.sbox_ready.value = 0
            await ClockCycles(dut.clk, 2)
            if int(dut.CONTROL_UNIT.get_raw_entropy.value) == 1:
                raw_seen = True
                dut._log.info(f"  get_raw_entropy=1 after {len(observed)} DRBG keys")
                break

    assert raw_seen, "get_raw_entropy never re-asserted"
    expected = list(range(1, DRBG_CYCLES))
    assert observed == expected, (
        f"drbg_cntr sequence wrong.\n"
        f"  Expected: 1..{DRBG_CYCLES - 1} ({len(expected)} keys)\n"
        f"  Got:      {len(observed)} keys, "
        f"first/last 5: {observed[:5]} ... {observed[-5:] if observed else []}")
    dut._log.info(f"✓ drbg_cntr sequence 1..{DRBG_CYCLES - 1} correct — TC5 PASSED ✓")


# TC6 — Full DEAD -> ext_rst_n -> normal-operation recovery cycle
@cocotb.test()
async def dead_recovery_test(dut):
    """Full DEAD -> ext_rst_n -> normal-operation recovery cycle. The
    current design has no ERROR_RECOVERY path: once DEAD, the ONLY way back
    is an external reset. This test drives a fatal RCT error, confirms DEAD
    latches and dead_flag clears after ext_rst_n, then collects a live key
    to prove the TRNG is fully operational again post-reset."""
    dut._log.info("=" * 60)
    dut._log.info("TC6: DEAD -> ext_rst_n -> normal resumption")
    dut._log.info("=" * 60)

    start_clocks(dut)
    buf_bad = NoiseBitBuffer(mode='stuck_0', n_bits=200)
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC6"))

    nd_task = cocotb.start_soon(noise_driver(dut, buf_bad))
    await wait_signal(dut.CONTROL_UNIT.fsm_state, value=CU_DEAD,
                      timeout=RCT_THRESHOLD + 30, clk=dut.clk)
    dut._log.info("✓ CU in DEAD (fatal RCT error)")
    nd_task.kill()

    dut._log.info("Applying ext_rst_n to recover...")
    dut.ext_rst_n.value = 0
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.ext_rst_n.value = 1
    await RisingEdge(dut.clk)
    assert int(dut.dead_flag.value) == 0, "dead_flag must clear after ext_rst_n"
    dut._log.info("✓ dead_flag cleared after reset")

    buf_good = NoiseBitBuffer(
        mode='physics' if _HAVE_PHYSICS_MODEL else 'random',
        seed=0xBEEF
    )
    cocotb.start_soon(noise_driver(dut, buf_good))

    key = await collect_key(dut, timeout=FIRST_KEY_TIMEOUT)
    assert key != 0, "Post-recovery key is all-zero"
    dut._log.info("✓ Valid key produced after recovery")
    assert int(dut.dead_flag.value) == 0, "dead_flag set after successful recovery"
    dut._log.info("✓ dead_flag = 0 — TC6 PASSED ✓")


# TC7 — CDC synchronizer (raw_rand_bit, sampling_clk -> clk)
@cocotb.test()
async def cdc_lat_test(dut):
    """2-flop CDC synchronizer latency check for raw_rand_bit."""
    dut._log.info("=" * 60)
    dut._log.info("TC7: CDC synchronizer latency")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC7"))

    dut.ext_rst_n.value    = 0
    dut.raw_rand_bit.value = 1
    dut.sbox_ready.value   = 0
    await ClockCycles(dut.clk, RESET_CYCLES)

    assert int(dut.rand_bit_sync1.value) == 0, "sync1 must be 0 during reset"
    assert int(dut.rand_bit.value)       == 0, "rand_bit must be 0 during reset"
    dut._log.info("✓ Synchronizer zeroed during reset")

    dut.ext_rst_n.value    = 1
    dut.raw_rand_bit.value = 0
    await ClockCycles(dut.clk, 4)
    assert int(dut.rand_bit.value) == 0

    dut.raw_rand_bit.value = 1
    await RisingEdge(dut.clk)   # edge 1: sync1 register captures raw_rand_bit=1
    await RisingEdge(dut.clk)   # edge 2: sync1 readable; rand_bit captures sync1
    s1 = int(dut.rand_bit_sync1.value)
    await RisingEdge(dut.clk)   # edge 3: rand_bit readable
    s2 = int(dut.rand_bit.value)

    assert s1 == 1, f"sync1 must be 1 after 1 clk of input=1, got {s1}"
    assert s2 == 1, f"rand_bit must be 1 after 2 clk of input=1, got {s2}"
    dut._log.info("✓ CDC 2-cycle latency confirmed")

    # noise_src_enb_n is generated in the CU (clk domain); the old
    # sampling_clk-domain synchronizer for it was removed from trng.sv,
    # so only the clk-domain assertion remains.
    buf = NoiseBitBuffer(mode='random')
    cocotb.start_soon(noise_driver(dut, buf))
    await wait_signal(dut.CONTROL_UNIT.noise_src_enb_n, value=0, timeout=20, clk=dut.clk)
    dut._log.info("✓ noise_src_enb_n asserted (low) in BIST — TC7 PASSED ✓")


# TC8 — Entropy collector SIPO
@cocotb.test()
async def sipo_test(dut):
    """Entropy collector SIPO 64-bit shift register and absorb handshake."""
    dut._log.info("=" * 60)
    dut._log.info("TC8: Entropy collector SIPO")
    dut._log.info("=" * 60)

    start_clocks(dut)
    buf = NoiseBitBuffer(mode='random', seed=0xABCD)
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC8"))
    cocotb.start_soon(noise_driver(dut, buf))

    # Check 1: noise enabled
    await wait_signal(dut.CONTROL_UNIT.noise_src_enb_n, value=0, timeout=20, clk=dut.clk)
    dut._log.info("✓ Noise enabled (BIST)")

    # Check 2: SIPO fills and valid asserts within 64+10 cycles
    await wait_signal(dut.valid, value=1, timeout=ENTROPY_WORD_BITS + 10, clk=dut.clk)
    ew = int(dut.entropy_word.value)
    dut._log.info(f"✓ valid asserted — entropy_word = 0x{ew:016X}")
    assert ew != 0, "entropy_word is all-zero — no bits shifted in"

    # Check 3: entropy word bit balance
    bit_count = bin(ew).count('1')
    dut._log.info(f"  bit count = {bit_count}/64")
    assert 10 <= bit_count <= 54, \
        f"entropy_word bit balance suspicious: {bit_count}/64 ones"
    dut._log.info("✓ entropy_word bit balance OK")

    # Check 4: keccak handshakes the word away (ready held during raw absorb,
    # rx_cntr increments per accepted word; after 3 words -> PERMUTE)
    assert int(dut.KECCAK_COND.fsm_state.value) == KEC_ABSORB, \
        "Keccak should still be in ABSORB while collecting SIPO words"
    await wait_signal(dut.KECCAK_COND.rx_cntr, value=1, timeout=10, clk=dut.clk)
    dut._log.info("✓ Keccak accepted SIPO word 1 (rx_cntr=1)")

    await wait_signal(dut.KECCAK_COND.fsm_state, value=KEC_PERMUTE,
                      timeout=3 * ENTROPY_WORD_BITS + 50, clk=dut.clk)
    dut._log.info("✓ Keccak entered PERMUTE after absorbing raw entropy")

    # Check 5: full key emerges and system stays healthy
    key = await collect_key(dut, timeout=200)
    assert key != 0, "key all-zero"
    await ClockCycles(dut.clk, 3)
    assert int(dut.dead_flag.value) == 0, "dead_flag set — unexpected failure"
    dut._log.info("✓ Key produced, no dead_flag — TC8 PASSED ✓")


# TC9 — Output word statistics (physics noise)
@cocotb.test()
async def sanity_test(dut):
    """Statistical sanity of Keccak output (3 keys x 1680 bits)."""
    N_KEYS = 3
    dut._log.info("=" * 60)
    dut._log.info(f"TC9: Output statistics ({N_KEYS} keys)")
    dut._log.info("=" * 60)

    start_clocks(dut)
    buf = NoiseBitBuffer(
        mode='physics' if _HAVE_PHYSICS_MODEL else 'random',
        seed=99
    )
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC9"))
    cocotb.start_soon(noise_driver(dut, buf))

    keys = []
    for k in range(N_KEYS):
        dut._log.info(f"  Collecting key {k+1}/{N_KEYS}...")
        keys.append(await collect_key(dut, timeout=FIRST_KEY_TIMEOUT))

    assert len(set(keys)) == len(keys), "Identical 1680-bit keys collected"

    all_words = [w for key in keys for w in key_words(key)]
    assert len(set(all_words)) == len(all_words), \
        f"64-bit word collision across {N_KEYS} keys"
    dut._log.info(f"✓ No collisions across {len(all_words)} words")

    for i, key in enumerate(keys):
        frac = bin(key).count('1') / RAND_WORD_BITS
        dut._log.info(f"  key {i}: ones fraction = {frac:.3f}")
        assert 0.40 <= frac <= 0.60, \
            f"Key {i}: bit balance {frac:.3f} outside [0.40, 0.60]"
    dut._log.info(f"✓ All {N_KEYS} keys pass bit-balance check — TC9 PASSED ✓")


# TC10 — Keccak FSM sequencing (physics noise)
@cocotb.test()
async def fsm_test(dut):
    """Keccak FSM ABSORB->PERMUTE(x24)->SQUEEZ->ABSORB sequencing."""
    dut._log.info("=" * 60)
    dut._log.info("TC10: Keccak FSM sequencing")
    dut._log.info("=" * 60)

    start_clocks(dut)
    buf = NoiseBitBuffer(
        mode='physics' if _HAVE_PHYSICS_MODEL else 'random',
        seed=77
    )
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC10"))
    cocotb.start_soon(noise_driver(dut, buf))

    await wait_signal(dut.KECCAK_COND.fsm_state, value=KEC_PERMUTE,
                      timeout=FIRST_KEY_TIMEOUT, clk=dut.clk)
    dut._log.info("✓ Keccak entered PERMUTE")

    # Count cycles spent in PERMUTE and collect round_cntr sequence.
    # Sample BEFORE advancing so the round_cntr==23 cycle is counted before
    # fsm_state transitions to SQUEEZ on the next edge.
    permute_cycles = 0
    round_seq = []

    for _ in range(KECCAK_PERMUTE_RNDS + 5):
        if int(dut.KECCAK_COND.fsm_state.value) != KEC_PERMUTE:
            break
        round_seq.append(int(dut.KECCAK_COND.round_cntr.value))
        permute_cycles += 1
        await RisingEdge(dut.clk)

    assert permute_cycles == KECCAK_PERMUTE_RNDS, \
        f"PERMUTE: {permute_cycles} cycles, expected {KECCAK_PERMUTE_RNDS}"
    dut._log.info(f"✓ PERMUTE: exactly {permute_cycles} cycles")

    assert round_seq == list(range(KECCAK_PERMUTE_RNDS)), \
        f"round_cntr sequence wrong: {round_seq}"
    dut._log.info(f"✓ round_cntr: 0 -> {KECCAK_PERMUTE_RNDS - 1}")

    ks = int(dut.KECCAK_COND.fsm_state.value)
    assert ks == KEC_SQUEEZ, f"Expected SQUEEZ after PERMUTE, got {ks}"
    dut._log.info("✓ SQUEEZ entered after round 23")

    # Complete the handshake inline. In DRBG mode ABSORB lasts exactly one
    # cycle before the next PERMUTE, so poll every edge with a tight timeout
    # (collect_key() would consume edges and miss the 1-cycle window).
    await wait_signal(dut.trng_key_valid, value=1, timeout=50, clk=dut.clk)
    dut.sbox_ready.value = 1
    await RisingEdge(dut.clk)
    dut.sbox_ready.value = 0
    await wait_signal(dut.KECCAK_COND.fsm_state, value=KEC_ABSORB, timeout=5, clk=dut.clk)
    dut._log.info("✓ ABSORB re-entered after SQUEEZ — TC10 PASSED ✓")
