"""
Cocotb testbench for the masked inverse AES S-Box (invSbox.sv).

STATUS / ASSUMED DUT INTERFACE
------------------------------
At the time this TB was written, neither the `invSbox_top` verification wrapper
nor the matching `trng.sv` changes exist yet (the user is building them). This
TB therefore targets an ASSUMED top module `invSbox_top` that mirrors
`sbox_top` (see rtl/gen_top.py: SBOX_TOP) but adapted for invSbox's simpler
port list. When you build the wrapper, match these names (or edit the
`DUT SIGNAL NAMES` constants / accessors below to match your wrapper):

    module invSbox_top(
        output logic [127:0] invSubBytes,       // 16-byte InvSubBytes result
        output logic         invSbox_ready,      // wired to TRNG .sbox_ready
        output logic         trng_dead_flag,     // TRNG fatal error
        output logic         invSbox_done_pulse, // 1-cycle done pulse
        output logic         rst_trng,           // invSbox forces TRNG reset
        input  logic         clk,
        input  logic         invSbox_enb_n,      // single active-low enable (0 = enabled)
        input  logic         sampling_clk,       // high-freq noise-source clock
        input  logic         ext_rst_n,          // external reset (active low)
        input  logic         raw_rand_bit,       // raw noise bit (python model)
        input  logic         proceed,            // TB acks invSbox_done_pulse
        input  logic [127:0] invSbox_input);     // 128-bit ciphertext-side input

The internal invSbox instance is named `InvSBox` (per rtl/invSbox_top.sv), so
its FSM is probed at `dut.InvSBox.fsm_state`. FSM probing is wrapped in
try/except, so a different instance name only disables the state monitor --
it does not fail the tests.

NOTE on rand width: invSbox declares `rand_num[1343:0]` (1344 bits = 28*16*3,
i.e. one TRNG batch feeds 3 InvSubBytes computations via invSbox_cntr 0->1->2),
while trng.sv emits rand_word[1679:0]. invSbox_top.sv reconciles this by
slicing `.rand_num(rand_num[1343:0])` at the instantiation -- the upper 336
bits of each TRNG batch go unused. This is internal to the wrapper and does
not affect this TB (the TB never drives rand_num directly -- it feeds entropy
bits through the noise model, identical to sbox_tb.py).

VERIFICATION MODEL
------------------
invSbox is purely byte-wise: invSubBytes[8*i +: 8] = InvSBox(state[8*i +: 8]).
Because the TB loads `invSbox_input` and reads `invSubBytes` through the same
symmetric big-endian packing (bytes_to_int / int_to_bytes), the expected output
is simply [INV_SBOX[b] for b in plaintext] -- no row/column transpose is needed
(that reshuffling only applies to state_matrix_t-typed ports like cipher's).
"""

import cocotb
import numpy as np
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles
import logging

# SIMULATION PARAMETERS
CLK_PERIOD_NS = 10   # Main clock
SCLK_PERIOD_NS = 2   # Sampling clock (noise source)
RESET_CYCLES = 8     # Reset duration

# invSbox has a single active-low enable; 0 => fully enabled.
INVSBOX_ENB_N_ENABLED = 0

# NIST FIPS 197 Table 4 -- forward AES S-box. The inverse table (Table 6) is
# derived from this below, so there is a single source of truth and no risk of
# a transcription error in the inverse table.
NIST_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

# Derive the inverse S-box (FIPS 197 Table 6): INV_SBOX[SBOX[x]] = x.
INV_SBOX = [0] * 256
for _x in range(256):
    INV_SBOX[NIST_SBOX[_x]] = _x

# Sanity spot-checks straight from invSbox.adoc's verification section.
assert INV_SBOX[0x63] == 0x00, "InvSBox(0x63) must be 0x00"
assert INV_SBOX[0xED] == 0x53, "InvSBox(0xED) must be 0x53"
assert INV_SBOX[0x7C] == 0x01, "InvSBox(0x7C) must be 0x01"

# invSbox_states enum (rtl/type_defs_pkg.sv) order -> name, for the FSM monitor.
INVSBOX_STATES = {
    0: "ISB_INIT",
    1: "INV_AFFINE_TOWER_FIELD",
    2: "ISB_MASKED_D",
    3: "ISB_MASKED_D_INV",
    4: "ISB_MASKED_A_INV",
    5: "INV_SUB_BYTES",
    6: "ISB_RESET_TRNG",
}

_mon_log = logging.getLogger("cocotb.monitor")


# noise model integration (identical approach to sbox_tb.py)
class NoiseBitBuffer:
    """Noise bit buffer using noise_source_model.py; falls back to numpy."""

    def __init__(self, mode='physics', n_bits=10000, seed=None):
        self._mode = mode
        self._seed = seed if seed is not None else np.random.randint(0, 2**32)
        self._idx = 0
        self._buf = self._generate(n_bits)
        cocotb.log.info(f"[NoiseBitBuffer] {len(self._buf)} bits (mode={self._mode}, seed={self._seed})")

    def _generate(self, n):
        try:
            if self._mode == 'physics':
                from noise_source_model import TRNGNoiseSource
                src = TRNGNoiseSource(n_ro=32, n_inv=13, fs_MHz=150.0, seed=self._seed)
                return src.generate_bits(n)
            raise ImportError("Not using physics mode")
        except ImportError as e:
            cocotb.log.warning(f"[NoiseBitBuffer] physics model unavailable ({e}); using numpy random")
            rng = np.random.default_rng(self._seed)
            return rng.integers(0, 2, size=n, dtype=np.uint8)

    def next_bit(self) -> int:
        if self._idx >= len(self._buf):
            self._idx = 0
        b = int(self._buf[self._idx])
        self._idx += 1
        return b


async def noise_driver(dut, buf):
    """Drive raw_rand_bit from the noise buffer on every sampling_clk edge."""
    while True:
        await RisingEdge(dut.sampling_clk)
        dut.raw_rand_bit.value = buf.next_bit()


# helper functions
def start_clocks(dut):
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, unit="ns").start())
    cocotb.start_soon(Clock(dut.sampling_clk, SCLK_PERIOD_NS, unit="ns").start())


def bytes_to_int(byte_list):
    """16 bytes -> 128-bit int, big-endian (byte_list[0] -> bits [127:120])."""
    result = 0
    for b in byte_list:
        result = (result << 8) | b
    return result


def int_to_bytes(value, num_bytes=16):
    """128-bit int -> 16 bytes, big-endian (bits [127:120] -> result[0])."""
    return [(value >> (8 * i)) & 0xFF for i in range(num_bytes - 1, -1, -1)]


def apply_inv_sbox(input_bytes):
    """Golden model: byte-wise inverse S-box over the 16 input bytes."""
    return [INV_SBOX[b] for b in input_bytes]


def drive_input(dut, plaintext):
    """Load a 16-byte ciphertext-side vector onto the DUT's 128-bit input."""
    dut.invSbox_input.value = bytes_to_int(plaintext)


def read_output(dut):
    """Read the 128-bit InvSubBytes result back as a 16-byte list."""
    return int_to_bytes(int(dut.invSubBytes.value))


def get_fsm(dut):
    """Best-effort FSM read; returns None if the instance name doesn't match."""
    try:
        return int(dut.InvSBox.fsm_state.value)
    except Exception:
        return None


async def reset_dut(dut):
    """Assert reset, park inputs in a safe/enabled state."""
    dut._log.info("Resetting DUT...")
    dut.ext_rst_n.value = 0
    dut.raw_rand_bit.value = 0
    dut.invSbox_enb_n.value = INVSBOX_ENB_N_ENABLED
    # TB is the sole consumer, so always acknowledge invSbox_done_pulse at once.
    dut.proceed.value = 1
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.ext_rst_n.value = 1
    await RisingEdge(dut.clk)
    dut._log.info("DUT reset complete")


async def wait_signal(signal, value=1, timeout=100000, clk=None):
    """Wait up to `timeout` rising edges for signal == value."""
    for i in range(timeout):
        await RisingEdge(clk)
        if int(signal.value) == value:
            return i + 1
    raise AssertionError(f"TIMEOUT ({timeout} cyc): {signal._path} never reached {value}")


async def wait_trng_ready(dut):
    """Wait for the TRNG to produce its first valid random batch."""
    dut._log.info("Waiting for TRNG to compute random bits...")
    cycles = await wait_signal(dut.trng_key_valid, value=1, timeout=20000, clk=dut.clk)
    dut._log.info(f"TRNG ready after {cycles} cycles")


async def signal_monitor(dut, label=""):
    """Lightweight monitor: logs FSM transitions, done pulses, and key events."""
    pfx = f"[MON {label}]" if label else "[MON]"

    def snap():
        return {
            "ext_rst_n":          int(dut.ext_rst_n.value),
            "invSbox_ready":      int(dut.invSbox_ready.value),
            "invSbox_done_pulse": int(dut.invSbox_done_pulse.value),
            "trng_key_valid":     int(dut.trng_key_valid.value),
            "trng_dead_flag":     int(dut.trng_dead_flag.value),
            "fsm":                get_fsm(dut),
        }

    await RisingEdge(dut.clk)
    prev = snap()
    cyc = 0
    while True:
        await RisingEdge(dut.clk)
        cyc += 1
        cur = snap()

        if cur["fsm"] != prev["fsm"] and cur["fsm"] is not None:
            old = INVSBOX_STATES.get(prev["fsm"], f"?{prev['fsm']}")
            new = INVSBOX_STATES.get(cur["fsm"], f"?{cur['fsm']}")
            _mon_log.info(f"{pfx} cyc={cyc:5d}  [FSM] {old} -> {new}")

        if cur["invSbox_done_pulse"] == 1 and prev["invSbox_done_pulse"] == 0:
            out = " ".join(f"{b:02x}" for b in read_output(dut))
            _mon_log.info(f"{pfx} cyc={cyc:5d}  *** [DONE] *** invSubBytes: {out}")

        if cur["trng_dead_flag"] == 1 and prev["trng_dead_flag"] == 0:
            _mon_log.warning(f"{pfx} cyc={cyc:5d}  *** [TRNG_DEAD] ***")

        prev = cur


async def run_vectors(dut, vectors, label):
    """
    Drive a list of (name, plaintext) vectors through the pipeline, checking
    each InvSubBytes result against the golden inverse S-box. The first vector
    must already be driven before this is called; subsequent vectors are driven
    right after each done pulse so the next FSM pass captures them.
    """
    for idx, (name, plaintext) in enumerate(vectors):
        await wait_signal(dut.invSbox_done_pulse, value=1, timeout=200, clk=dut.clk)

        output = read_output(dut)
        expected = apply_inv_sbox(plaintext)

        # Drive the next vector immediately (2 FSM edges of slack before capture).
        if idx < len(vectors) - 1:
            drive_input(dut, vectors[idx + 1][1])

        if output != expected:
            dut._log.error(f"[{label}] Vector {idx} ({name}) MISMATCH")
            dut._log.error(f"  input:    {' '.join(f'{b:02x}' for b in plaintext)}")
            dut._log.error(f"  expected: {' '.join(f'{b:02x}' for b in expected)}")
            dut._log.error(f"  got:      {' '.join(f'{b:02x}' for b in output)}")
            for i in range(16):
                if output[i] != expected[i]:
                    dut._log.error(f"    byte {i}: exp 0x{expected[i]:02x} got 0x{output[i]:02x}")
            raise AssertionError(f"[{label}] vector {idx} ({name}) failed")

        dut._log.info(f"[{label}] Vector {idx} ({name}): PASS")
        if idx < len(vectors) - 1:
            await RisingEdge(dut.clk)


# test case-1: single vector with intensive monitoring
@cocotb.test()
async def test_invsbox_single_vector(dut):
    """TC1: one vector end-to-end, with FSM/done monitoring."""
    dut._log.info("=" * 80)
    dut._log.info("TC1: Single Inverse S-box Vector")
    dut._log.info("=" * 80)

    start_clocks(dut)
    buf = NoiseBitBuffer(mode='physics', seed=12345)

    plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    expected = apply_inv_sbox(plaintext)
    dut._log.info(f"Input:    {' '.join(f'{b:02x}' for b in plaintext)}")
    dut._log.info(f"Expected: {' '.join(f'{b:02x}' for b in expected)}")

    drive_input(dut, plaintext)          # drive before reset so it's stable
    await reset_dut(dut)

    cocotb.start_soon(signal_monitor(dut, label="TC1"))
    cocotb.start_soon(noise_driver(dut, buf))

    await wait_trng_ready(dut)

    cycles = await wait_signal(dut.invSbox_done_pulse, value=1, timeout=200, clk=dut.clk)
    dut._log.info(f"invSbox_done_pulse after {cycles} cycles")

    output = read_output(dut)
    dut._log.info(f"RTL out:  {' '.join(f'{b:02x}' for b in output)}")

    if output != expected:
        for i in range(16):
            if output[i] != expected[i]:
                dut._log.error(f"  byte {i}: exp 0x{expected[i]:02x} got 0x{output[i]:02x}")
        raise AssertionError("TC1 failed")
    dut._log.info("TC1 PASSED")


# test case-2: FIPS 197 known InvSBox relations (forward round-trip anchors)
@cocotb.test()
async def test_invsbox_known_vectors(dut):
    """
    TC2: bytes chosen so every lane exercises a documented relation, e.g.
    InvSBox(0x63)=0x00, InvSBox(0xED)=0x53, InvSBox(0x7C)=0x01, plus a spread
    of forward-table outputs SBox(k) that must invert back to k.
    """
    dut._log.info("=" * 80)
    dut._log.info("TC2: FIPS 197 Known Inverse Relations")
    dut._log.info("=" * 80)

    start_clocks(dut)
    buf = NoiseBitBuffer(mode='physics', seed=0xBEEF)

    # Lane j feeds SBox(k_j); InvSBox must return k_j. Covers the doc spot-checks
    # (k=0x00 -> 0x63, k=0x53 -> 0xED, k=0x01 -> 0x7C) and a broad sweep.
    keys = [0x00, 0x53, 0x01, 0x10, 0x20, 0x40, 0x80, 0xA5,
            0x5A, 0x0F, 0xF0, 0x3C, 0xC3, 0x7E, 0xE7, 0xFF]
    ciphertext = [NIST_SBOX[k] for k in keys]   # what we feed invSbox
    expected = keys                             # what invSbox must return

    dut._log.info(f"Feed (SBox(k)): {' '.join(f'{b:02x}' for b in ciphertext)}")
    dut._log.info(f"Expect (k):     {' '.join(f'{b:02x}' for b in expected)}")

    drive_input(dut, ciphertext)
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC2"))
    cocotb.start_soon(noise_driver(dut, buf))
    await wait_trng_ready(dut)

    await wait_signal(dut.invSbox_done_pulse, value=1, timeout=200, clk=dut.clk)
    output = read_output(dut)

    if output != expected:
        for i in range(16):
            if output[i] != expected[i]:
                dut._log.error(f"  lane {i}: fed SBox({keys[i]:#04x})={ciphertext[i]:#04x}, "
                               f"exp {expected[i]:#04x} got {output[i]:#04x}")
        raise AssertionError("TC2 failed")
    dut._log.info("TC2 PASSED - all documented inverse relations hold")


# test case-3: pipelined edge-case vectors
@cocotb.test()
async def test_invsbox_edge_cases(dut):
    """TC3: back-to-back edge patterns through the pipeline."""
    dut._log.info("=" * 80)
    dut._log.info("TC3: Edge-Case Vectors")
    dut._log.info("=" * 80)

    start_clocks(dut)
    buf = NoiseBitBuffer(mode='physics', seed=99999)

    edge_cases = [
        ("ALL_ZEROS", [0x00] * 16),
        ("ALL_ONES",  [0xFF] * 16),
        ("ALT_AA",    [0xAA] * 16),
        ("ALT_55",    [0x55] * 16),
        ("INCR",      list(range(16))),
        ("DECR",      list(range(15, -1, -1))),
        ("SBOX_C",    [0x63] * 16),   # every lane must invert to 0x00
    ]

    drive_input(dut, edge_cases[0][1])
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC3"))
    cocotb.start_soon(noise_driver(dut, buf))
    await wait_trng_ready(dut)

    await run_vectors(dut, edge_cases, label="TC3")
    dut._log.info(f"TC3 PASSED - {len(edge_cases)} edge cases verified")


# test case-4: randomized stress
@cocotb.test()
async def test_invsbox_stress(dut):
    """TC4: many random vectors for sustained pipelined operation."""
    dut._log.info("=" * 80)
    dut._log.info("TC4: Randomized Stress")
    dut._log.info("=" * 80)

    start_clocks(dut)
    buf = NoiseBitBuffer(mode='physics', seed=11111)

    import random
    random.seed(2024)
    n_vectors = 12
    vectors = [(f"RAND_{i}", [random.randint(0, 255) for _ in range(16)])
               for i in range(n_vectors)]

    drive_input(dut, vectors[0][1])
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC4"))
    cocotb.start_soon(noise_driver(dut, buf))
    await wait_trng_ready(dut)

    await run_vectors(dut, vectors, label="TC4")
    dut._log.info(f"TC4 PASSED - {n_vectors} random vectors verified")


# test case-5: exhaustive coverage of all 256 byte values
@cocotb.test()
async def test_invsbox_exhaustive(dut):
    """
    TC5: cover every possible input byte 0x00..0xFF across 16 lanes x 16
    vectors, so the full inverse S-box table is exercised end-to-end.
    """
    dut._log.info("=" * 80)
    dut._log.info("TC5: Exhaustive 256-Value Coverage")
    dut._log.info("=" * 80)

    start_clocks(dut)
    buf = NoiseBitBuffer(mode='physics', seed=0xC0FFEE)

    # 16 vectors of 16 bytes = all 256 values exactly once.
    vectors = [(f"BLK_{blk}", [16 * blk + lane for lane in range(16)])
               for blk in range(16)]

    drive_input(dut, vectors[0][1])
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC5"))
    cocotb.start_soon(noise_driver(dut, buf))
    await wait_trng_ready(dut)

    await run_vectors(dut, vectors, label="TC5")
    dut._log.info("TC5 PASSED - all 256 input byte values verified")
