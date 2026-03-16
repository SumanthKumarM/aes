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
"""

import cocotb
from cocotb.clock    import Clock
from cocotb.triggers import RisingEdge, ClockCycles, Timer
from cocotb.result   import TestFailure
import math

# constants
SAMPLING_CLK_PERIOD_NS = 2      # 500 MHz — high freq for noise source
SYS_CLK_PERIOD_NS      = 6      # ~167 MHz — system clock
RESET_CYCLES           = 10
KEY_WAIT_TIMEOUT       = 50000  # cycles before declaring timeout


# statistical helper functions
def int_to_bits(value, width):
    """convert integer to list of bits LSB first"""
    return [(value >> i) & 1 for i in range(width)]

def min_entropy(bits):
    """
    Hmin = -log2(max symbol probability)
    for a binary source this is -log2(max(p1, p0))
    """
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
    """
    proportion of 1s should be 0.5 ± 0.10
    returns (pass, ratio)
    """
    n     = len(bits)
    ones  = sum(bits)
    ratio = ones / n
    return 0.40 <= ratio <= 0.60, ratio

def monobit_test(bits):
    """
    |ones - zeros| / sqrt(n) should be < 1.82
    returns (pass, s_statistic)
    """
    n    = len(bits)
    ones = sum(bits)
    s    = abs(ones - (n - ones)) / math.sqrt(n)
    return s < 1.82, s

def runs_test(bits):
    """
    z-score of run count vs expected should be < 1.96
    returns (pass, z_score)
    """
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
    return z < 1.96, z

def autocorrelation_test(bits, lag=1):
    """
    ratio of lag-matched bits should be 0.5 ± 0.10
    returns (pass, ratio)
    """
    n       = len(bits)
    matches = sum(bits[i] == bits[i + lag] for i in range(n - lag))
    ratio   = matches / (n - lag)
    return 0.40 <= ratio <= 0.60, ratio


# DUT helpers
async def start_clocks(dut):
    """launch both independent clocks"""
    cocotb.start_soon(
        Clock(dut.sampling_clk, SAMPLING_CLK_PERIOD_NS, units="ns").start()
    )
    cocotb.start_soon(
        Clock(dut.clk, SYS_CLK_PERIOD_NS, units="ns").start()
    )
    await Timer(20, units="ns")   # let clocks settle

async def apply_reset(dut):
    """drive ext_rst_n low then release"""
    dut.ext_rst_n.value = 0
    dut.s_box_ack.value = 0
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.ext_rst_n.value = 1
    await ClockCycles(dut.clk, 2)
    dut.log.info("[RESET] released")

async def wait_key_high(dut, timeout=KEY_WAIT_TIMEOUT):
    """
    poll key_ready_req on rising edges of clk
    return cycle count when asserted
    raises TestFailure on timeout
    """
    for cycle in range(timeout):
        await RisingEdge(dut.clk)
        if int(dut.key_ready_req.value) == 1:
            return cycle
    raise TestFailure(
        f"key_ready_req never went HIGH within {timeout} cycles"
    )

async def wait_key_low(dut, timeout=KEY_WAIT_TIMEOUT):
    """wait for key_ready_req to deassert"""
    for cycle in range(timeout):
        await RisingEdge(dut.clk)
        if int(dut.key_ready_req.value) == 0:
            return cycle
    raise TestFailure(
        f"key_ready_req never went LOW within {timeout} cycles"
    )

async def collect_batch(dut, num_words=6):
    """
    simulate S-box consuming one complete batch:
      - wait for key_ready_req
      - read rand_word
      - pulse s_box_ack
    returns list of num_words integers (256-bit each)
    """
    words = []
    for idx in range(num_words):
        cycles = await wait_key_high(dut)
        word   = int(dut.rand_word.value)
        words.append(word)
        dut.log.info(f"    word[{idx}] = 0x{word:064X}  (waited {cycles} cycles)")

        # one-cycle ack pulse
        dut.s_box_ack.value = 1
        await RisingEdge(dut.clk)
        dut.s_box_ack.value = 0
        await RisingEdge(dut.clk)

    return words


# TEST 1 — reset and initial state
@cocotb.test()
async def test_1(dut):
    """
    after reset:
      dead_flag     should be 0
      key_ready_req should be 0
    """
    dut.log.info("━" * 60)
    dut.log.info("TEST 01 — reset and initial state")
    dut.log.info("━" * 60)

    await start_clocks(dut)
    await apply_reset(dut)

    assert int(dut.dead_flag.value)     == 0, \
        f"dead_flag should be 0 after reset, got {dut.dead_flag.value}"
    assert int(dut.key_ready_req.value) == 0, \
        f"key_ready_req should be 0 after reset, got {dut.key_ready_req.value}"

    dut.log.info("PASS — TEST 01")


# TEST 2 — first key via raw entropy path
@cocotb.test()
async def test_2(dut):
    """
    drbg_cntr starts at 0 so first key must use real entropy
    key_ready_req must go high and rand_word must be nonzero
    """
    dut.log.info("━" * 60)
    dut.log.info("TEST 02 — first key via raw entropy path")
    dut.log.info("━" * 60)

    await start_clocks(dut)
    await apply_reset(dut)

    cycles = await wait_key_high(dut)
    word   = int(dut.rand_word.value)

    dut.log.info(f"first key arrived after {cycles} cycles")
    dut.log.info(f"rand_word = 0x{word:064X}")

    assert word != 0, \
        "rand_word is all zeros — ring oscillators may not be toggling"
    assert int(dut.dead_flag.value) == 0, \
        "dead_flag unexpectedly asserted during startup"

    dut.log.info("PASS — TEST 02")


# TEST 3 — S-box handshake (full batch of 6 words)
@cocotb.test()
async def test_3(dut):
    """
    collect all 6 words of one batch via s_box_ack handshake
    verify:
      - 6 nonzero words received
      - key_ready_req goes low after last ack
      - words are not all identical
    """
    dut.log.info("━" * 60)
    dut.log.info("TEST 03 — S-box handshake protocol (6 words)")
    dut.log.info("━" * 60)

    await start_clocks(dut)
    await apply_reset(dut)

    words = await collect_batch(dut, num_words=6)

    assert len(words) == 6, \
        f"expected 6 words, got {len(words)}"

    for i, w in enumerate(words):
        assert w != 0, f"word[{i}] is all zeros"

    # after all acks key_ready_req must deassert
    await ClockCycles(dut.clk, 5)
    assert int(dut.key_ready_req.value) == 0, \
        "key_ready_req still HIGH after all 6 acks — handshake broken"

    # words must not all be identical
    assert len(set(words)) > 1, \
        "all 6 words are identical — output not changing"

    dut.log.info("PASS — TEST 03")


# TEST 4 — DRBG: consecutive batches differ
@cocotb.test()
async def test_4(dut):
    """
    collect 3 batches and verify each is different
    from the previous one — proves DRBG state updates
    """
    dut.log.info("━" * 60)
    dut.log.info("TEST 04 — DRBG feedback: consecutive batches differ")
    dut.log.info("━" * 60)

    await start_clocks(dut)
    await apply_reset(dut)

    batches = []
    for i in range(3):
        dut.log.info(f"  collecting batch {i+1}/3...")
        words = await collect_batch(dut, num_words=6)
        batches.append(tuple(words))
        await ClockCycles(dut.clk, 10)

    for i in range(1, len(batches)):
        assert batches[i] != batches[i-1], \
            f"batch {i} identical to batch {i-1} — DRBG state not updating"
        dut.log.info(f"  batch {i} ≠ batch {i-1} ✓")

    dut.log.info("PASS — TEST 04")


# TEST 5 — statistical randomness
@cocotb.test()
async def test_5(dut):
    """
    collect 10 batches × 6 words × 256 bits = 15360 bits
    run:
      frequency test    (ones ratio 0.40–0.60)
      monobit test      (s < 1.82)
      runs test         (z < 1.96)
      autocorrelation   (ratio 0.40–0.60 at lag 1)
      min entropy       (>= 0.90 bits/bit)
    """
    dut.log.info("━" * 60)
    dut.log.info("TEST 05 — statistical randomness")
    dut.log.info("━" * 60)

    await start_clocks(dut)
    await apply_reset(dut)

    all_bits    = []
    num_batches = 10

    for i in range(num_batches):
        dut.log.info(f"  batch {i+1}/{num_batches}...")
        words = await collect_batch(dut, num_words=6)
        for w in words:
            all_bits.extend(int_to_bits(w, 256))
        await ClockCycles(dut.clk, 5)

    dut.log.info(f"total bits: {len(all_bits)}")

    # frequency
    fp, ratio = frequency_test(all_bits)
    dut.log.info(f"  [FREQ ] ones={ratio:.4f}  {'PASS' if fp else 'FAIL'}")
    assert fp, f"frequency FAILED: ones ratio = {ratio:.4f}"

    # monobit
    mp, s = monobit_test(all_bits)
    dut.log.info(f"  [MONO ] s={s:.4f}  {'PASS' if mp else 'FAIL'}")
    assert mp, f"monobit FAILED: s = {s:.4f}"

    # runs
    rp, z = runs_test(all_bits)
    dut.log.info(f"  [RUNS ] z={z:.4f}  {'PASS' if rp else 'FAIL'}")
    assert rp, f"runs FAILED: z = {z:.4f}"

    # autocorrelation
    ap, ac = autocorrelation_test(all_bits, lag=1)
    dut.log.info(f"  [AUTO ] ratio={ac:.4f}  {'PASS' if ap else 'FAIL'}")
    assert ap, f"autocorrelation FAILED: ratio = {ac:.4f}"

    # min entropy
    h = min_entropy(all_bits)
    dut.log.info(f"  [ENTR ] Hmin={h:.4f} bits/bit  {'PASS' if h >= 0.90 else 'FAIL'}")
    assert h >= 0.90, f"min entropy FAILED: {h:.4f} < 0.90"

    dut.log.info("PASS — TEST 05")


# TEST 6 — no spurious dead_flag during normal operation
@cocotb.test()
async def test_6(dut):
    """
    run 5 batches and verify dead_flag never asserts
    spurious dead_flag would mean health tests are
    too aggressive or thresholds miscalculated
    """
    dut.log.info("━" * 60)
    dut.log.info("TEST 06 — no spurious dead_flag")
    dut.log.info("━" * 60)

    await start_clocks(dut)
    await apply_reset(dut)

    for i in range(5):
        dut.log.info(f"  batch {i+1}/5...")
        await collect_batch(dut, num_words=6)

        assert int(dut.dead_flag.value) == 0, \
            f"dead_flag asserted at batch {i+1} — health test false positive?"

        await ClockCycles(dut.clk, 10)

    dut.log.info("PASS — TEST 06")


# TEST 7 — recovery after external reset
@cocotb.test()
async def test_7(dut):
    """
    assert ext_rst_n mid-operation and verify:
      - outputs clear immediately
      - TRNG restarts cleanly
      - new keys generated after recovery
    """
    dut.log.info("━" * 60)
    dut.log.info("TEST 07 — recovery after mid-operation reset")
    dut.log.info("━" * 60)

    await start_clocks(dut)
    await apply_reset(dut)

    # run one batch normally
    dut.log.info("  running one batch before reset...")
    words_before = await collect_batch(dut, num_words=6)
    await ClockCycles(dut.clk, 20)

    # assert reset mid-operation
    dut.log.info("  asserting ext_rst_n...")
    dut.ext_rst_n.value = 0
    await ClockCycles(dut.clk, 5)
    dut.ext_rst_n.value = 1
    await ClockCycles(dut.clk, 2)

    # outputs must be cleared
    assert int(dut.dead_flag.value)     == 0, "dead_flag not cleared after reset"
    assert int(dut.key_ready_req.value) == 0, "key_ready_req not cleared after reset"

    # TRNG must recover and produce new keys
    dut.log.info("  verifying recovery...")
    words_after = await collect_batch(dut, num_words=6)

    assert any(w != 0 for w in words_after), \
        "all words after recovery are zero"

    dut.log.info(
        f"  before: 0x{words_before[0]:064X}..."
    )
    dut.log.info(
        f"  after : 0x{words_after[0]:064X}..."
    )

    dut.log.info("PASS — TEST 07")


# TEST 8 — continuous operation (20 batches)
@cocotb.test()
async def test_8(dut):
    """
    run TRNG for 20 batches continuously
    verify:
      - no hangs (all batches complete)
      - dead_flag never asserts
      - output keeps changing across batches
    """
    dut.log.info("━" * 60)
    dut.log.info("TEST 08 — continuous operation (20 batches)")
    dut.log.info("━" * 60)

    await start_clocks(dut)
    await apply_reset(dut)

    num_batches     = 20
    first_words     = []

    for i in range(num_batches):
        words = await collect_batch(dut, num_words=6)

        assert int(dut.dead_flag.value) == 0, \
            f"dead_flag asserted at batch {i+1}"

        first_words.append(words[0])

        if (i + 1) % 5 == 0:
            dut.log.info(
                f"  completed batch {i+1}/{num_batches}  "
                f"word[0]=0x{words[0]:016X}"
            )

    # majority of first words should be unique
    unique = set(first_words)
    dut.log.info(
        f"unique first-words: {len(unique)}/{num_batches}"
    )
    assert len(unique) > num_batches // 2, \
        f"too many repeated first-words — only {len(unique)} unique out of {num_batches}"

    dut.log.info("PASS — TEST 08")
    