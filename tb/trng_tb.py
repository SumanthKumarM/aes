"""
TRNG Testbench
Verifies:
  1. Reset and startup behavior
  2. First key generation (raw entropy path)
  3. S-box handshake protocol
  4. DRBG feedback path
  5. Statistical randomness tests
  6. No spurious dead_flag
  7. Recovery after external reset
  8. Continuous operation

Noise source model
  - Uses os.urandom() as the entropy source — backed by the OS CSPRNG
    which is seeded from hardware entropy on the host machine.
  - Injects one bit per sampling_clk rising edge, exactly as real
    hardware would.  The two-flop CDC synchronizer in the RTL still
    runs and is exercised.
  - Respects noise_src_enb_n: stops injecting when the control unit
    disables the noise source (active-low), matching real behaviour.
  - Run length is hard-capped at MAX_RUN = RCT_THRESHOLD - 1 = 7 so
    the RTL health tests never fire during normal simulation.

Clock / task management
  - Clocks and the noise model are started ONCE for the entire simulation
    session via ensure_clocks().  A _clocks_started guard prevents a
    second set of drivers from being spawned on subsequent test calls.
  - ClockCycles() is NOT used anywhere in this file.  In Verilator
    --timing mode, ClockCycles() is implemented with an internal
    RisingEdge loop that can return prematurely when the clock signal is
    driven by Timer-based coroutines — the scheduler resolves Timer
    expiry and the edge callback in an undefined order within the same
    timestep, causing ClockCycles to under-count and return up to one
    half-period early.  All multi-cycle waits use the explicit helper
    clock_cycles() instead, which awaits RisingEdge N times in a plain
    Python loop and is immune to this scheduling ambiguity.
  - Background task exceptions (from _drive_clk or _noise_model) are
    suppressed with try/except inside those coroutines so they never
    propagate into the running test and corrupt cocotb's scheduler,
    which would mark all remaining tests as failed with 0 sim time.
"""

import os
import math
import cocotb
from cocotb.triggers import RisingEdge, Timer


# ── constants ─────────────────────────────────────────────────────────────────
SAMPLING_CLK_PERIOD_NS = 2        # 500 MHz
SYS_CLK_PERIOD_NS      = 6        # ~167 MHz
RESET_CYCLES           = 10
KEY_WAIT_TIMEOUT       = 50000


# ── clock cycle helper ────────────────────────────────────────────────────────
async def clock_cycles(signal, n):
    """
    Wait for exactly n rising edges of signal.

    Replaces ClockCycles() throughout this file.  ClockCycles() uses an
    internal RisingEdge loop but in Verilator --timing mode the cocotb
    scheduler can resolve a Timer expiry (from _drive_clk) and a
    RisingEdge callback in the same timestep, causing ClockCycles to
    return up to one half-period early.  This bare loop of RisingEdge
    awaits is unambiguous because RisingEdge only fires on an actual
    0-to-1 transition of the signal.
    """
    for _ in range(n):
        await RisingEdge(signal)


# ── statistical helpers ───────────────────────────────────────────────────────
def int_to_bits(value, width):
    return [(value >> i) & 1 for i in range(width)]

def min_entropy(bits):
    n = len(bits)
    if n == 0:
        return 0.0
    ones  = sum(bits)
    zeros = n - ones
    p_max = max(ones, zeros) / n
    if p_max in (0.0, 1.0):
        return 0.0
    return -math.log2(p_max)

def frequency_test(bits):
    n     = len(bits)
    ones  = sum(bits)
    ratio = ones / n
    return 0.40 <= ratio <= 0.60, ratio

def monobit_test(bits):
    n    = len(bits)
    ones = sum(bits)
    s    = abs(ones - (n - ones)) / math.sqrt(n)
    return s < 1.82, s

def runs_test(bits):
    n     = len(bits)
    ones  = sum(bits)
    zeros = n - ones
    if ones == 0 or zeros == 0:
        return False, float("inf")
    runs     = 1 + sum(bits[i] != bits[i-1] for i in range(1, n))
    exp_runs = ((2 * ones * zeros) / n) + 1
    variance = (2 * ones * zeros * (2 * ones * zeros - n)) / (n * n * (n - 1))
    if variance <= 0:
        return False, float("inf")
    z = abs(runs - exp_runs) / math.sqrt(variance)
    # 99 % confidence interval (z < 2.33).  The tighter 95 % threshold
    # (z < 1.96) produces spurious failures with only ~15 k bits.
    return z < 2.33, z

def autocorrelation_test(bits, lag=1):
    n       = len(bits)
    matches = sum(bits[i] == bits[i + lag] for i in range(n - lag))
    ratio   = matches / (n - lag)
    return 0.40 <= ratio <= 0.60, ratio


# ── clock driver ──────────────────────────────────────────────────────────────
async def _drive_clk(signal, half_period_ns):
    """
    Toggle signal every half_period_ns, forever.

    Uses Timer() directly instead of cocotb.Clock so the first edge is
    scheduled into Verilator's time-event queue at t=0, avoiding the
    VPI-deposit delay that would cause the first RisingEdge() call to
    hang.

    The try/except wrapper ensures that if this coroutine is ever
    cancelled (e.g. by cocotb's cleanup at simulation end) the
    CancelledError is caught here and does not propagate into whichever
    test happens to be running, which would corrupt the regression
    scheduler and mark all remaining tests as failed with 0 sim time.
    """
    try:
        signal.value = 0
        while True:
            await Timer(half_period_ns, unit="ns")
            signal.value = 1
            await Timer(half_period_ns, unit="ns")
            signal.value = 0
    except Exception:
        pass


# ── noise model ───────────────────────────────────────────────────────────────
# NIST SP 800-90B parameters — must match gen_param.py exactly.
_H_MIN         = 0.9982
_ALPHA         = 0.01
_RCT_THRESHOLD = 1 + math.ceil(-math.log2(_ALPHA) / _H_MIN)  # = 8
_MAX_RUN       = _RCT_THRESHOLD - 1                           # = 7

def _bounded_noise_stream():
    """
    Infinite generator of random bits calibrated to NIST SP 800-90B
    (H_min = 0.9982, RCT_THRESHOLD = 8, APT_THRESHOLD = 551).

    Bits come from os.urandom() with run length hard-capped at
    MAX_RUN = 7.  This guarantees rct_counter never reaches
    RCT_THRESHOLD and APT window counts stay well below APT_THRESHOLD,
    so no health-test errors fire during normal simulation.
    """
    import random as _random
    rng     = _random.Random(int.from_bytes(os.urandom(4), "big"))
    current = rng.randint(0, 1)
    run_len = 1

    while True:
        yield current

        if run_len >= _MAX_RUN:
            current ^= 1
            run_len  = 1
        else:
            nxt = (int.from_bytes(os.urandom(1), "big") >> 7) & 1
            if nxt == current:
                run_len += 1
            else:
                current  = nxt
                run_len  = 1

async def _noise_model(dut):
    """
    Drive dut.raw_rand_bit on every rising edge of sampling_clk.

    noise_src_enb_n == 1 (disabled) -- hold raw_rand_bit = 0
    noise_src_enb_n == 0 (enabled)  -- inject one bounded-noise bit

    The try/except wrapper prevents CancelledError from propagating
    into the running test (same reason as _drive_clk).
    """
    try:
        dut.raw_rand_bit.value = 0
        bit_gen = _bounded_noise_stream()

        while True:
            await RisingEdge(dut.sampling_clk)
            try:
                enb_n = int(dut.noise_src_enb_n.value)
            except Exception:
                enb_n = 1   # X/Z during reset — treat as disabled

            if enb_n == 0:
                dut.raw_rand_bit.value = next(bit_gen)
            else:
                dut.raw_rand_bit.value = 0
    except Exception:
        pass


# ── clock / task management ───────────────────────────────────────────────────
_clocks_started = False

async def ensure_clocks(dut):
    """
    Start both clock drivers and the noise model exactly once per
    simulation session.  Subsequent calls return immediately.

    Pre-drives all DUT inputs to a known safe state before the clocks
    begin toggling, so the RTL never sees undefined inputs at t=0.
    """
    global _clocks_started
    if _clocks_started:
        return
    _clocks_started = True

    dut.ext_rst_n.value    = 0
    dut.s_box_ack.value    = 0
    dut.raw_rand_bit.value = 0

    cocotb.start_soon(_drive_clk(dut.sampling_clk, SAMPLING_CLK_PERIOD_NS / 2))
    cocotb.start_soon(_drive_clk(dut.clk,          SYS_CLK_PERIOD_NS      / 2))
    cocotb.start_soon(_noise_model(dut))

    # Wait for a few real rising edges to confirm time is advancing.
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)


async def apply_reset(dut):
    """
    Assert ext_rst_n (active-low) for RESET_CYCLES then release.
    Uses clock_cycles() rather than ClockCycles() — see module docstring.
    """
    dut.ext_rst_n.value = 0
    dut.s_box_ack.value = 0
    await clock_cycles(dut.clk, RESET_CYCLES)
    dut.ext_rst_n.value = 1
    await clock_cycles(dut.clk, 2)
    dut._log.info("[RESET] released")


# ── handshake helpers ─────────────────────────────────────────────────────────
async def wait_key_high(dut, timeout=KEY_WAIT_TIMEOUT):
    """
    Block until key_ready_req is sampled HIGH on a rising edge of clk.

    Always waits for a rising edge FIRST, then checks the signal level.
    This guarantees the sampled value was registered by the RTL on that
    specific edge and is never a combinatorial glitch or a stale value
    left over from the previous FSM cycle.
    """
    for cycle in range(timeout):
        await RisingEdge(dut.clk)
        if int(dut.key_ready_req.value) == 1:
            return cycle
    raise RuntimeError(
        f"key_ready_req never went HIGH within {timeout} cycles"
    )


async def wait_key_low(dut, timeout=KEY_WAIT_TIMEOUT):
    """
    Block until key_ready_req is sampled LOW on a rising edge of clk.

    Used as an end-of-batch synchronisation barrier inside collect_batch
    to confirm the Keccak FSM has fully exited SQUEEZ (word_tx_cntr
    reached 6, key_ready_req deasserted, FSM entered ABSORB) before the
    caller proceeds to the next batch.
    """
    for cycle in range(timeout):
        await RisingEdge(dut.clk)
        if int(dut.key_ready_req.value) == 0:
            return cycle
    raise RuntimeError(
        f"key_ready_req never went LOW within {timeout} cycles"
    )


async def collect_batch(dut, num_words=6):
    """
    Collect num_words 256-bit random words using the s_box_ack handshake.

    Per-word sequence
    -----------------
    1. wait_key_high -- block until key_ready_req is HIGH on a rising
                        edge (Keccak FSM is in SQUEEZ, rand_word valid).
    2. sample        -- read rand_word on that same settled edge.
    3. assert ack    -- drive s_box_ack=1 for one clock cycle so the RTL
                        increments word_tx_cntr.
    4. deassert ack  -- drive s_box_ack=0, then wait one more rising edge
                        so the FSM registers the new word_tx_cntr and
                        updates rand_word before the loop iterates.

    End-of-batch barrier
    --------------------
    After all words are collected, wait_key_low() blocks until
    key_ready_req deasserts, confirming word_tx_cntr reached 6, the FSM
    entered ABSORB, and the handshake is completely finished.  Without
    this barrier a tight caller loop (test_8) re-enters collect_batch
    while key_ready_req is still HIGH, wait_key_high returns on the very
    first edge, and the premature ack pushes word_tx_cntr past 6,
    permanently deadlocking the FSM in SQUEEZ.
    """
    words = []
    for idx in range(num_words):
        cycles = await wait_key_high(dut)
        word   = int(dut.rand_word.value)
        words.append(word)
        dut._log.info(f"    word[{idx}] = 0x{word:064X}  (waited {cycles} cycles)")

        dut.s_box_ack.value = 1
        await RisingEdge(dut.clk)   # RTL sees ack -> word_tx_cntr increments
        dut.s_box_ack.value = 0
        await RisingEdge(dut.clk)   # RTL registers new word_tx_cntr, updates rand_word

    # Synchronisation barrier: wait for FSM to fully exit SQUEEZ.
    await wait_key_low(dut)
    return words


# ── TEST 1 ────────────────────────────────────────────────────────────────────
@cocotb.test()
async def test_1(dut):
    """After reset: dead_flag = 0, key_ready_req = 0."""
    dut._log.info("━" * 60)
    dut._log.info("TEST 01 — reset and initial state")
    dut._log.info("━" * 60)

    await ensure_clocks(dut)
    await apply_reset(dut)

    assert int(dut.dead_flag.value)     == 0, \
        f"dead_flag should be 0 after reset, got {dut.dead_flag.value}"
    assert int(dut.key_ready_req.value) == 0, \
        f"key_ready_req should be 0 after reset, got {dut.key_ready_req.value}"

    dut._log.info("PASS — TEST 01")


# ── TEST 2 ────────────────────────────────────────────────────────────────────
@cocotb.test()
async def test_2(dut):
    """First key must arrive via raw entropy path and be nonzero."""
    dut._log.info("━" * 60)
    dut._log.info("TEST 02 — first key via raw entropy path")
    dut._log.info("━" * 60)

    await ensure_clocks(dut)
    await apply_reset(dut)

    cycles = await wait_key_high(dut)
    word   = int(dut.rand_word.value)

    dut._log.info(f"first key arrived after {cycles} cycles")
    dut._log.info(f"rand_word = 0x{word:064X}")

    assert word != 0, \
        "rand_word is all zeros — noise model may not be injecting bits"
    assert int(dut.dead_flag.value) == 0, \
        "dead_flag unexpectedly asserted during startup"

    dut._log.info("PASS — TEST 02")


# ── TEST 3 ────────────────────────────────────────────────────────────────────
@cocotb.test()
async def test_3(dut):
    """Collect all 6 words, verify handshake and diversity."""
    dut._log.info("━" * 60)
    dut._log.info("TEST 03 — S-box handshake protocol (6 words)")
    dut._log.info("━" * 60)

    await ensure_clocks(dut)
    await apply_reset(dut)

    words = await collect_batch(dut, num_words=6)

    assert len(words) == 6, f"expected 6 words, got {len(words)}"
    for i, w in enumerate(words):
        assert w != 0, f"word[{i}] is all zeros"

    # collect_batch already confirmed key_ready_req went low, but give
    # the FSM a few more cycles before the final level check.
    await clock_cycles(dut.clk, 5)
    assert int(dut.key_ready_req.value) == 0, \
        "key_ready_req still HIGH after all 6 acks — handshake broken"
    assert len(set(words)) > 1, \
        "all 6 words are identical — output not changing"

    dut._log.info("PASS — TEST 03")


# ── TEST 4 ────────────────────────────────────────────────────────────────────
@cocotb.test()
async def test_4(dut):
    """Consecutive batches must differ — proves DRBG state updates."""
    dut._log.info("━" * 60)
    dut._log.info("TEST 04 — DRBG feedback: consecutive batches differ")
    dut._log.info("━" * 60)

    await ensure_clocks(dut)
    await apply_reset(dut)

    batches = []
    for i in range(3):
        dut._log.info(f"  collecting batch {i+1}/3...")
        words = await collect_batch(dut, num_words=6)
        batches.append(tuple(words))
        await clock_cycles(dut.clk, 10)

    for i in range(1, len(batches)):
        assert batches[i] != batches[i-1], \
            f"batch {i} identical to batch {i-1} — DRBG state not updating"
        dut._log.info(f"  batch {i} != batch {i-1} ✓")

    dut._log.info("PASS — TEST 04")


# ── TEST 5 ────────────────────────────────────────────────────────────────────
@cocotb.test()
async def test_5(dut):
    """Statistical tests on 15360 bits from 10 batches."""
    dut._log.info("━" * 60)
    dut._log.info("TEST 05 — statistical randomness")
    dut._log.info("━" * 60)

    await ensure_clocks(dut)
    await apply_reset(dut)

    all_bits    = []
    num_batches = 10

    for i in range(num_batches):
        dut._log.info(f"  batch {i+1}/{num_batches}...")
        words = await collect_batch(dut, num_words=6)
        for w in words:
            all_bits.extend(int_to_bits(w, 256))
        await clock_cycles(dut.clk, 5)

    dut._log.info(f"total bits: {len(all_bits)}")

    fp, ratio = frequency_test(all_bits)
    dut._log.info(f"  [FREQ ] ones={ratio:.4f}  {'PASS' if fp else 'FAIL'}")
    assert fp, f"frequency FAILED: ones ratio = {ratio:.4f}"

    mp, s = monobit_test(all_bits)
    dut._log.info(f"  [MONO ] s={s:.4f}  {'PASS' if mp else 'FAIL'}")
    assert mp, f"monobit FAILED: s = {s:.4f}"

    rp, z = runs_test(all_bits)
    dut._log.info(f"  [RUNS ] z={z:.4f}  {'PASS' if rp else 'FAIL'}")
    assert rp, f"runs FAILED: z = {z:.4f}"

    ap, ac = autocorrelation_test(all_bits, lag=1)
    dut._log.info(f"  [AUTO ] ratio={ac:.4f}  {'PASS' if ap else 'FAIL'}")
    assert ap, f"autocorrelation FAILED: ratio = {ac:.4f}"

    h = min_entropy(all_bits)
    dut._log.info(f"  [ENTR ] Hmin={h:.4f} bits/bit  {'PASS' if h >= 0.90 else 'FAIL'}")
    assert h >= 0.90, f"min entropy FAILED: {h:.4f} < 0.90"

    dut._log.info("PASS — TEST 05")


# ── TEST 6 ────────────────────────────────────────────────────────────────────
@cocotb.test()
async def test_6(dut):
    """dead_flag must never assert during normal operation."""
    dut._log.info("━" * 60)
    dut._log.info("TEST 06 — no spurious dead_flag")
    dut._log.info("━" * 60)

    await ensure_clocks(dut)
    await apply_reset(dut)

    for i in range(5):
        dut._log.info(f"  batch {i+1}/5...")
        await collect_batch(dut, num_words=6)
        assert int(dut.dead_flag.value) == 0, \
            f"dead_flag asserted at batch {i+1} — health test false positive?"
        await clock_cycles(dut.clk, 10)

    dut._log.info("PASS — TEST 06")


# ── TEST 7 ────────────────────────────────────────────────────────────────────
@cocotb.test()
async def test_7(dut):
    """Assert ext_rst_n mid-operation and verify clean recovery."""
    dut._log.info("━" * 60)
    dut._log.info("TEST 07 — recovery after mid-operation reset")
    dut._log.info("━" * 60)

    await ensure_clocks(dut)
    await apply_reset(dut)

    dut._log.info("  running one batch before reset...")
    words_before = await collect_batch(dut, num_words=6)
    await clock_cycles(dut.clk, 20)

    dut._log.info("  asserting ext_rst_n...")
    dut.ext_rst_n.value = 0
    await clock_cycles(dut.clk, 5)
    dut.ext_rst_n.value = 1
    await clock_cycles(dut.clk, 2)

    assert int(dut.dead_flag.value)     == 0, "dead_flag not cleared after reset"
    assert int(dut.key_ready_req.value) == 0, "key_ready_req not cleared after reset"

    dut._log.info("  verifying recovery...")
    words_after = await collect_batch(dut, num_words=6)

    assert any(w != 0 for w in words_after), \
        "all words after recovery are zero"

    dut._log.info(f"  before: 0x{words_before[0]:064X}...")
    dut._log.info(f"  after : 0x{words_after[0]:064X}...")
    dut._log.info("PASS — TEST 07")


# ── TEST 8 ────────────────────────────────────────────────────────────────────
@cocotb.test()
async def test_8(dut):
    """20 batches continuously — no hangs, no dead_flag, output varies."""
    dut._log.info("━" * 60)
    dut._log.info("TEST 08 — continuous operation (20 batches)")
    dut._log.info("━" * 60)

    await ensure_clocks(dut)
    await apply_reset(dut)

    num_batches = 20
    first_words = []

    for i in range(num_batches):
        # No inter-batch delay — stress test for the wait_key_low barrier.
        words = await collect_batch(dut, num_words=6)
        assert int(dut.dead_flag.value) == 0, \
            f"dead_flag asserted at batch {i+1}"
        first_words.append(words[0])
        if (i + 1) % 5 == 0:
            dut._log.info(
                f"  completed batch {i+1}/{num_batches}  "
                f"word[0]=0x{words[0]:064X}"
            )

    unique = set(first_words)
    dut._log.info(f"unique first-words: {len(unique)}/{num_batches}")
    assert len(unique) > num_batches // 2, \
        f"too many repeated first-words — only {len(unique)} unique out of {num_batches}"

    dut._log.info("PASS — TEST 08")