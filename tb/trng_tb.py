import cocotb
import random
import logging
import sys
import numpy as np
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles

# Simulation constants 
CLK_PERIOD_NS       = 10
SCLK_PERIOD_NS      = 2
RESET_CYCLES        = 8
NOISE_BUF_SIZE      = 5000

ENTROPY_WORD_BITS   = 64
KECCAK_PERMUTE_RNDS = 24
KECCAK_OUTPUT_WORDS = 3

RCT_THRESHOLD       = 8
APT_BIT_WINDOW      = 1024
APT_THRESHOLD       = 551
CONSECUTIVE_ERRORS  = 3
DRBG_CYCLES         = 24

CU_IDLE             = 0
CU_BIST             = 1
CU_WAIT_FOR_XFER    = 2
CU_ERROR_RECOVERY   = 3
CU_DEAD             = 4

KEC_ABSORB          = 0
KEC_PERMUTE         = 1
KEC_SQUEEZ          = 2

try:
    from noise_source_model import TRNGNoiseSource
    _HAVE_PHYSICS_MODEL = True
except ImportError:
    _HAVE_PHYSICS_MODEL = False
    cocotb.log.warning(
        "noise_source_model.py not found — normal tests fall back to numpy random"
    )

# monitor logger 
# "cocotb.monitor" is a child of the "cocotb" logger in Python's hierarchy,
# so it flows through the same cocotb log handler and appears in the same
# output file/stream — but with the source label "cocotb.monitor" instead of
# "cocotb.trng".  You will see BOTH in the log, clearly distinguished:
#
#   INFO  cocotb.trng     ✓ CU in BIST state          <- test checkpoint
#   INFO  cocotb.monitor  [MON TC1] cyc=2  cu_state: IDLE->BIST  <- monitor
#
# Neither suppresses the other.
_mon_log = logging.getLogger("cocotb.monitor")


# Noise bit buffer
class NoiseBitBuffer:
    """
    Pre-generates noise bits before simulation starts.
    All generation cost is paid once upfront; during simulation next_bit()
    is a pure array index lookup — zero scheduler impact.

    Modes
    -----
    'physics'  — RO physics model (TRNGNoiseSource, 32 ROs x 13 INV, 150 MHz).
                 Use for all normal-operation tests.
    'random'   — numpy uniform random. Automatic fallback if model unavailable.
    'stuck_0'  — constant 0. Triggers RCT (TC2).
    'stuck_1'  — constant 1. Triggers RCT -> total_failure (TC4).
    'biased'   — P(1)=bias. Triggers APT (TC3).
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
            # 3 ones + 1 zero repeating
            # Density = 75% >> APT threshold 53.8%
            # Zero every 4 bits — even at 5:1 sampling, zeros appear regularly
            # preventing any run of 8+ same bits at the health test input
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
_CU_NAMES  = {0:"IDLE", 1:"BIST", 2:"WAIT_FOR_XFER", 3:"ERROR_RECOVERY", 4:"DEAD"}
_KEC_NAMES = {0:"ABSORB", 1:"PERMUTE", 2:"SQUEEZ"}


async def signal_monitor(dut, label=""):
    """
    Background coroutine that watches all key signals on every rising clk
    edge and logs only when something changes — identical to $monitor.

    WHY A SEPARATE LOGGER
    ---------------------
    This function uses _mon_log = logging.getLogger("cocotb.monitor").
    Test checkpoint messages use dut._log which resolves to "cocotb.trng".
    Both loggers feed the same cocotb output handler, so both appear in the
    log simultaneously.  In the output you can grep "cocotb.trng" for test
    checkpoints only, or "cocotb.monitor" for signal transitions only, or
    leave both visible for the full picture.

    Signal coverage
    ---------------
    Top ports : ext_rst_n, raw_rand_bit, sbox_ack, key_ready_req,
                dead_flag, rand_word
    CU        : fsm_state, noise_src_enb_n, enb_health_tests,
                get_raw_entropy, local_rst_n, drbg_cntr
    Keccak    : fsm_state, rx_cntr, round_cntr, word_tx_cntr
    Health    : rct_error, apt_error, error, total_failure
    Entropy   : valid, entropy_word
    """
    pfx = f"[MON {label}]" if label else "[MON]"

    def snap():
        return {
            "ext_rst_n"   : int(dut.ext_rst_n.value),
            "raw_bit"     : int(dut.raw_rand_bit.value),
            "sbox_ack"   : int(dut.sbox_ack.value),
            "key_rdy_req" : int(dut.key_ready_req.value),
            "dead_flag"   : int(dut.dead_flag.value),
            "rand_word"   : int(dut.rand_word.value),
            "cu_state"    : int(dut.cu.fsm_state.value),
            "ns_enb_n"    : int(dut.cu.noise_src_enb_n.value),
            "enb_hlth"    : int(dut.cu.enb_health_tests.value),
            "get_raw"     : int(dut.cu.get_raw_entropy.value),
            "local_rst_n" : int(dut.cu.local_rst_n.value),
            "drbg_cntr"   : int(dut.cu.drbg_cntr.value),
            "kec_state"   : int(dut.keccak.fsm_state.value),
            "rx_cntr"     : int(dut.keccak.rx_cntr.value),
            "round_cntr"  : int(dut.keccak.round_cntr.value),
            "word_tx"     : int(dut.keccak.word_tx_cntr.value),
            "rct_err"     : int(dut.hlth_tst.rct_error.value),
            "apt_err"     : int(dut.hlth_tst.apt_error.value),
            "hlth_err"    : int(dut.hlth_tst.error.value),
            "tot_fail"    : int(dut.hlth_tst.total_failure.value),
            "valid"       : int(dut.valid.value),
            "ent_word"    : int(dut.entropy_word.value),
        }

    def fmt(k, v):
        if k == "cu_state":  return _CU_NAMES.get(v, str(v))
        if k == "kec_state": return _KEC_NAMES.get(v, str(v))
        if k == "rand_word": return f"0x{v:064X}"
        if k == "ent_word":  return f"0x{v:016X}"
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
    dut.sbox_ack.value    = 0
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


async def ack_all_words(dut, n=KECCAK_OUTPUT_WORDS):
    """Send n ACK pulses to drain SQUEEZ without reading word values."""
    for _ in range(n):
        dut.sbox_ack.value = 1
        await RisingEdge(dut.clk)
        dut.sbox_ack.value = 0
        await RisingEdge(dut.clk)


async def wait_and_collect_words(dut, n=KECCAK_OUTPUT_WORDS, timeout=30_000):
    """
    Wait for key_ready_req then read n x 256-bit words with correct timing.

    Timing: rand_word and word_tx_cntr are both registered. rand_word takes
    2 cycles to stabilise after an ACK: 1 cycle for word_tx_cntr to register,
    1 more for rand_word to register the new slice. A final ACK after the last
    word drives word_tx_cntr=n which clears key_ready_req and returns to ABSORB.
    """
    await wait_signal(dut.key_ready_req, value=1, timeout=timeout, clk=dut.clk)
    dut._log.info("key_ready_req asserted — collecting words")
    words = []

    # Word[0]: valid immediately when key_ready_req asserts
    wtx = int(dut.keccak.word_tx_cntr.value)
    rw  = int(dut.rand_word.value)
    dut._log.info(f"  Word[0]  word_tx_cntr={wtx}  0x{rw:064X}")
    words.append(rw)

    # Words[1..n-1]: ACK -> 2 cycles settle -> read
    for i in range(1, n):
        dut.sbox_ack.value = 1
        await RisingEdge(dut.clk)   # word_tx_cntr -> i
        dut.sbox_ack.value = 0
        await RisingEdge(dut.clk)   # word_tx_cntr registered
        await RisingEdge(dut.clk)   # rand_word updated to slice[i]
        wtx = int(dut.keccak.word_tx_cntr.value)
        rw  = int(dut.rand_word.value)
        dut._log.info(f"  Word[{i}]  word_tx_cntr={wtx}  0x{rw:064X}")
        words.append(rw)

    # Final ACK: word_tx_cntr -> n, clears key_ready_req, FSM -> ABSORB
    dut.sbox_ack.value = 1
    await RisingEdge(dut.clk)
    dut.sbox_ack.value = 0
    await RisingEdge(dut.clk)

    return words


# Normal end-to-end test (physics noise)
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
    cu = int(dut.cu.fsm_state.value)
    assert cu == CU_BIST, f"Expected CU_BIST({CU_BIST}), got {cu}"
    dut._log.info("✓ CU in BIST state")

    await wait_signal(dut.cu.get_raw_entropy, value=1, timeout=50, clk=dut.clk)
    dut._log.info("✓ get_raw_entropy = 1 (raw entropy path active)")

    await wait_signal(dut.keccak.fsm_state, value=KEC_PERMUTE, timeout=500, clk=dut.clk)
    dut._log.info("✓ Keccak entered PERMUTE (entropy absorbed)")

    await wait_signal(dut.keccak.fsm_state, value=KEC_SQUEEZ, timeout=50, clk=dut.clk)
    dut._log.info("✓ Keccak in SQUEEZ")
    words = await wait_and_collect_words(dut, timeout=200)
    assert all(w != 0 for w in words),    "A word is all-zero — suspicious"
    assert len(set(words)) == len(words), "Duplicate words in key"
    dut._log.info(f"✓ {len(words)} unique non-zero words collected")

    await ClockCycles(dut.clk, 4)
    assert int(dut.key_ready_req.value) == 0, "key_ready_req should be 0 after transfer"
    dut._log.info("✓ key_ready_req deasserted")

    dut._log.info(f"Monitoring DRBG phase (expect {DRBG_CYCLES} keys)...")
    drbg_keys = 0
    raw_seen  = False
    for _ in range(DRBG_CYCLES * 100):
        await RisingEdge(dut.clk)
        if int(dut.cu.get_raw_entropy.value) == 1:
            raw_seen = True
            dut._log.info(f"  Raw entropy re-asserted after {drbg_keys} DRBG keys")
            break
        if int(dut.key_ready_req.value) == 1:
            drbg_keys += 1
            dut._log.info(f"  DRBG key #{drbg_keys}  drbg_cntr={int(dut.cu.drbg_cntr.value)}")
            await ack_all_words(dut)

    assert raw_seen, "get_raw_entropy never re-asserted after DRBG phase"
    dut._log.info(f"✓ DRBG ran for {drbg_keys} keys, raw entropy restored")
    assert int(dut.dead_flag.value) == 0,              "dead_flag set"
    assert int(dut.hlth_tst.total_failure.value) == 0, "total_failure set"
    dut._log.info("✓ No health errors — TC1 PASSED ✓")


# RCT negative test  (stuck_0)
@cocotb.test()
async def rct_neg_test(dut):
    """RCT negative test — stuck-at-0 noise."""
    dut._log.info("=" * 60)
    dut._log.info("TC2: RCT — stuck-at-0")
    dut._log.info("=" * 60)

    start_clocks(dut)
    buf = NoiseBitBuffer(mode='stuck_0')
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC2"))
    nd_task = cocotb.start_soon(noise_driver(dut, buf))

    await wait_signal(dut.cu.enb_health_tests, value=1, timeout=20, clk=dut.clk)
    dut._log.info("✓ Health tests enabled")

    await wait_signal(dut.hlth_tst.rct_error, value=1, timeout=RCT_THRESHOLD + 15, clk=dut.clk)
    dut._log.info("✓ rct_error asserted")

    await wait_signal(dut.cu.fsm_state, value=CU_ERROR_RECOVERY, timeout=10, clk=dut.clk)
    dut._log.info("✓ CU in ERROR_RECOVERY")
    nd_task.kill()
    cocotb.start_soon(noise_driver(dut, NoiseBitBuffer(mode='random')))

    await RisingEdge(dut.clk)
    assert int(dut.cu.local_rst_n.value) == 0, "local_rst_n must be 0 in ERROR_RECOVERY"
    dut._log.info("✓ local_rst_n deasserted")

    # Wait enough cycles for ERROR_RECOVERY to complete and verify no total failure
    await ClockCycles(dut.clk, 20)
    assert int(dut.dead_flag.value) == 0, "dead_flag must NOT set on single error"
    dut._log.info("✓ dead_flag = 0 — TC2 PASSED ✓")


# TC3 — APT negative test  (biased)
@cocotb.test()
async def apt_neg_test(dut):
    """APT negative test — biased noise P(1)=0.95."""
    dut._log.info("=" * 60)
    dut._log.info("TC3: APT — biased noise P(1)=0.95")
    dut._log.info("=" * 60)

    start_clocks(dut)
    buf = NoiseBitBuffer(mode='apt_trigger', n_bits=APT_BIT_WINDOW + 500)
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC3"))
    nd_task = cocotb.start_soon(noise_driver(dut, buf))

    await wait_signal(dut.cu.enb_health_tests, value=1, timeout=20, clk=dut.clk)
    dut._log.info("✓ Health tests enabled")

    await wait_signal(dut.hlth_tst.apt_error, value=1, timeout=APT_BIT_WINDOW + 200, clk=dut.clk)
    dut._log.info("✓ apt_error asserted")

    assert int(dut.hlth_tst.error.value) == 1, "health_error should be high"
    dut._log.info("✓ health_error asserted")

    await wait_signal(dut.cu.fsm_state, value=CU_ERROR_RECOVERY, timeout=10, clk=dut.clk)
    dut._log.info("✓ CU in ERROR_RECOVERY — TC3 PASSED ✓")
    nd_task.kill()


# Total failure / DEAD  (stuck_1)
@cocotb.test()
async def dead_neg_test(dut):
    """Total failure -> DEAD state."""
    dut._log.info("=" * 60)
    dut._log.info("TC4: Total failure -> DEAD state")
    dut._log.info("=" * 60)

    start_clocks(dut)
    buf = NoiseBitBuffer(mode='stuck_1')
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC4"))
    cocotb.start_soon(noise_driver(dut, buf))

    total_fail_timeout = CONSECUTIVE_ERRORS * (RCT_THRESHOLD + 20) + 100
    await wait_signal(dut.hlth_tst.total_failure, value=1, timeout=total_fail_timeout, clk=dut.clk)
    dut._log.info("✓ total_failure asserted")

    await wait_signal(dut.cu.fsm_state, value=CU_DEAD, timeout=10, clk=dut.clk)
    dut._log.info("✓ CU in DEAD state")

    await wait_signal(dut.dead_flag, value=1, timeout=10, clk=dut.clk)
    dut._log.info("✓ dead_flag asserted")

    assert int(dut.cu.noise_src_enb_n.value) == 1, "noise must be disabled in DEAD"
    assert int(dut.cu.enb_health_tests.value) == 0, "health tests must be off in DEAD"
    dut._log.info("✓ Noise + health tests disabled in DEAD")

    dut._log.info("Applying ext_rst_n to recover...")
    dut.ext_rst_n.value = 0
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.ext_rst_n.value = 1
    await ClockCycles(dut.clk, 3)

    cu = int(dut.cu.fsm_state.value)
    assert cu in (CU_IDLE, CU_BIST), f"Expected IDLE/BIST after reset, got {cu}"
    dut._log.info(f"✓ CU state = {cu} after reset")

    assert int(dut.dead_flag.value) == 0, "dead_flag must clear after ext_rst_n"
    dut._log.info("✓ dead_flag cleared — TC4 PASSED ✓")


# DRBG counter sequence  (physics noise)
@cocotb.test()
async def drbg_cntr_test(dut):
    """drbg_cntr increment sequence verification."""
    dut._log.info("=" * 60)
    dut._log.info("TC5: DRBG counter sequence")
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
    await wait_signal(dut.key_ready_req, value=1, timeout=10_000, clk=dut.clk)
    dut._log.info("✓ First key ready")
    await ack_all_words(dut)

    observed = []
    raw_seen  = False
    for _ in range(DRBG_CYCLES * 100):
        await RisingEdge(dut.clk)
        if int(dut.cu.get_raw_entropy.value) == 1:
            raw_seen = True
            dut._log.info(f"  get_raw_entropy=1 after {len(observed)} DRBG keys")
            break
        if int(dut.key_ready_req.value) == 1:
            cnt = int(dut.cu.drbg_cntr.value)
            if not observed or cnt != observed[-1]:
                observed.append(cnt)
                dut._log.info(f"  DRBG key #{len(observed)}: drbg_cntr={cnt}")
            await ack_all_words(dut)
            # Check again immediately after acking — raw entropy may have asserted
            if int(dut.cu.get_raw_entropy.value) == 1:
                raw_seen = True
                dut._log.info(f"  get_raw_entropy=1 after {len(observed)} DRBG keys")
                break

    assert raw_seen, "get_raw_entropy never re-asserted"
    expected = list(range(1, DRBG_CYCLES + 1))
    assert observed == expected, \
        f"drbg_cntr sequence wrong.\n  Expected: {expected}\n  Got:      {observed}"
    dut._log.info(f"✓ drbg_cntr sequence correct: {observed} — TC5 PASSED ✓")


# Error recovery  (bad=stuck_0, recovery=physics)
@cocotb.test()
async def err_rec_test(dut):
    """Single RCT error recovery, then normal key generation resumes."""
    dut._log.info("=" * 60)
    dut._log.info("TC6: Error recovery -> normal resumption")
    dut._log.info("=" * 60)

    start_clocks(dut)
    buf_bad  = NoiseBitBuffer(mode='stuck_0', n_bits=200)
    buf_good = NoiseBitBuffer(
        mode='physics' if _HAVE_PHYSICS_MODEL else 'random',
        seed=0xBEEF
    )
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC6"))

    nd_task = cocotb.start_soon(noise_driver(dut, buf_bad))
    await wait_signal(dut.cu.fsm_state, value=CU_ERROR_RECOVERY, timeout=200, clk=dut.clk)
    dut._log.info("✓ CU in ERROR_RECOVERY")

    await RisingEdge(dut.clk)
    drbg_cnt = int(dut.cu.drbg_cntr.value)
    assert drbg_cnt == 0, f"drbg_cntr must be 0 in ERROR_RECOVERY, got {drbg_cnt}"
    dut._log.info("✓ drbg_cntr = 0 in ERROR_RECOVERY")

    nd_task.kill()
    cocotb.start_soon(noise_driver(dut, buf_good))

    await wait_signal(dut.cu.fsm_state, value=CU_BIST, timeout=15, clk=dut.clk)
    dut._log.info("✓ CU back in BIST")

    await wait_signal(dut.cu.get_raw_entropy, value=1, timeout=20, clk=dut.clk)
    dut._log.info("✓ get_raw_entropy=1 (drbg_cntr=0 forces raw path)")

    words = await wait_and_collect_words(dut, timeout=10_000)
    assert all(w != 0 for w in words), "Post-recovery key has all-zero word"
    dut._log.info(f"✓ Valid key produced ({len(words)} words)")
    assert int(dut.dead_flag.value) == 0
    dut._log.info("✓ dead_flag = 0 — TC6 PASSED ✓")


# CDC synchronizer  (random is fine — no key generation)
@cocotb.test()
async def cdc_lat_test(dut):
    """2-flop CDC synchronizer latency check."""
    dut._log.info("=" * 60)
    dut._log.info("TC7: CDC synchronizer latency")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC7"))

    dut.ext_rst_n.value    = 0
    dut.raw_rand_bit.value = 1
    dut.sbox_ack.value    = 0
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
    await RisingEdge(dut.clk)   # edge 2: sync1 value now readable; rand_bit captures sync1
    s1 = int(dut.rand_bit_sync1.value)   # ✓ sync1=1 (captured on edge 1)
    await RisingEdge(dut.clk)   # edge 3: rand_bit value now readable
    s2 = int(dut.rand_bit.value)         # ✓ rand_bit=1 (captured on edge 2)

    assert s1 == 1, f"sync1 must be 1 after 1 clk of input=1, got {s1}"
    assert s2 == 1, f"rand_bit must be 1 after 2 clk of input=1, got {s2}"
    dut._log.info("✓ CDC 2-cycle latency confirmed")

    buf = NoiseBitBuffer(mode='random')
    cocotb.start_soon(noise_driver(dut, buf))
    await wait_signal(dut.cu.noise_src_enb_n, value=0, timeout=20, clk=dut.clk)
    await ClockCycles(dut.clk, 3)
    enb = int(dut.noise_enb_n.value)
    assert enb == 0, f"noise_enb_n (sampling_clk domain) should be 0, got {enb}"
    dut._log.info("✓ noise_enb_n crossed to sampling_clk domain — TC7 PASSED ✓")


# Entropy collector SIPO  (random is fine — tests shift register only)
@cocotb.test()
async def sipo_test(dut):
    """Entropy collector SIPO 64-bit shift register check."""
    dut._log.info("=" * 60)
    dut._log.info("TC8: Entropy collector SIPO")
    dut._log.info("=" * 60)

    start_clocks(dut)
    buf = NoiseBitBuffer(mode='random', seed=0xABCD)
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC8"))
    cocotb.start_soon(noise_driver(dut, buf))

    # Check 1: noise enabled 
    await wait_signal(dut.cu.noise_src_enb_n, value=0, timeout=20, clk=dut.clk)
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

    # Check 4: Keccak already consumed entropy and produced a key 
    # Keccak enters PERMUTE on the very first clock (drbg_cntr=0,
    # get_raw_entropy=1 at reset), so by the time valid fires at cyc~64,
    # Keccak is already in SQUEEZ or has key_ready_req=1.
    # Just confirm key_ready_req — the definitive proof entropy was
    # absorbed and a full Keccak permutation completed successfully.
    kec_state_now = int(dut.keccak.fsm_state.value)
    dut._log.info(f"  keccak fsm_state at valid = {kec_state_now} "
                  f"(ABSORB=0, PERMUTE=1, SQUEEZ=2)")
    assert kec_state_now in (KEC_PERMUTE, KEC_SQUEEZ), \
        f"Unexpected kec_state {kec_state_now} when valid fired — " \
        f"Keccak should be processing entropy"
    dut._log.info("✓ Keccak is processing entropy (PERMUTE or SQUEEZ)")

    await wait_signal(dut.key_ready_req, value=1, timeout=50, clk=dut.clk)
    dut._log.info("✓ key_ready_req asserted — entropy absorbed, key produced")

    # Check 5: drain SQUEEZ and confirm FSM continues 
    await ack_all_words(dut)
    await ClockCycles(dut.clk, 3)
    assert int(dut.dead_flag.value) == 0, "dead_flag set — unexpected failure"
    dut._log.info("✓ No dead_flag — system healthy")
    dut._log.info("TC8 PASSED ✓")
    

# Output word statistics  (physics noise)
@cocotb.test()
async def sanity_test(dut):
    """Statistical sanity of Keccak output (3 key sets, 18 words)."""
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

    all_words = []
    for k in range(N_KEYS):
        dut._log.info(f"  Collecting key {k+1}/{N_KEYS}...")
        words = await wait_and_collect_words(dut, timeout=20_000)
        all_words.extend(words)

    assert len(set(all_words)) == len(all_words), \
        f"Word collision detected across {N_KEYS} keys"
    dut._log.info(f"✓ No collisions across {len(all_words)} words")

    for i, w in enumerate(all_words):
        frac = bin(w).count('1') / 256.0
        assert 0.35 <= frac <= 0.65, \
            f"Word {i}: bit balance {frac:.3f} outside [0.35, 0.65]"
    dut._log.info(f"✓ All {len(all_words)} words pass bit-balance check — TC9 PASSED ✓")


# Keccak FSM sequencing  (physics noise)
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

    await wait_signal(dut.keccak.fsm_state, value=KEC_PERMUTE,
                      timeout=10_000, clk=dut.clk)
    dut._log.info("✓ Keccak entered PERMUTE")

    # Count cycles spent in PERMUTE and collect round_cntr sequence.
    # Strategy: sample BEFORE advancing — check current state first,
    # then clock. This way the cycle where round_cntr==23 is counted
    # before fsm_state transitions to SQUEEZ on the next edge.
    permute_cycles = 0
    round_seq = []

    for _ in range(KECCAK_PERMUTE_RNDS + 5):
        # Read state BEFORE the next edge
        if int(dut.keccak.fsm_state.value) != KEC_PERMUTE:
            break
        round_seq.append(int(dut.keccak.round_cntr.value))
        permute_cycles += 1
        await RisingEdge(dut.clk)   # advance — may cause PERMUTE->SQUEEZ

    assert permute_cycles == KECCAK_PERMUTE_RNDS, \
        f"PERMUTE: {permute_cycles} cycles, expected {KECCAK_PERMUTE_RNDS}"
    dut._log.info(f"✓ PERMUTE: exactly {permute_cycles} cycles")

    assert round_seq == list(range(KECCAK_PERMUTE_RNDS)), \
        f"round_cntr sequence wrong: {round_seq}"
    dut._log.info(f"✓ round_cntr: 0 -> {KECCAK_PERMUTE_RNDS - 1}")

    # After the loop, fsm_state should now be SQUEEZ
    # (the RisingEdge that ended the loop registered SQUEEZ)
    await RisingEdge(dut.clk)   # one more edge so SQUEEZ is readable
    ks = int(dut.keccak.fsm_state.value)
    assert ks == KEC_SQUEEZ, f"Expected SQUEEZ after PERMUTE, got {ks}"
    dut._log.info("✓ SQUEEZ entered after round 23")

    await ack_all_words(dut)
    await wait_signal(dut.keccak.fsm_state, value=KEC_ABSORB,
                      timeout=20, clk=dut.clk)
    dut._log.info("✓ ABSORB re-entered after SQUEEZ — TC10 PASSED ✓")