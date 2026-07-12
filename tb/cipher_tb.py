"""
Cocotb testbench for the CIPHER block (cipher.sv), verified through the
auto-generated cipher_top wrapper (cipher + real TRNG instance).

Golden reference: a NIST FIPS 197 software model (key expansion + full
encryption with per-round intermediates). The model self-checks against the
FIPS 197 Appendix B / C.1 / C.2 / C.3 known-answer vectors at import time, so
any TB-side modeling mistake aborts the run before touching the DUT.

DUT (cipher_top) interface notes:
  - The TRNG is a real instance fed by raw_rand_bit (noise driver on
    sampling_clk). The cipher stalls its SubBytes rounds until trng_key_valid,
    so no explicit TRNG warm-up is needed -- just a generous timeout.
  - The cipher free-runs: once rst_n deasserts and key_size is valid, it starts
    an encryption of whatever is on `state`; after cipher_done it wraps
    round_cntr to 0 and starts over. Back-to-back encryption works by swapping
    `state` after a done pulse.
  - key_size=2'b00 parks the DUT: addRoundKey never raises ark_done, so the
    cipher sits in round 0. reset_dut() leaves the DUT parked.

RTL data representation (same convention the addRoundKey TB validated):
  - state_matrix_t = logic [3:0][3:0][7:0]: state[row][col] at bits (row*4+col)*8
  - Row convention: RTL row 3 = NIST row 0 (MSByte of a column word),
                    RTL row 0 = NIST row 3. Columns match NIST.
  - master_key packs NIST key-schedule word w[i] (big-endian bytes) at
    bits [32*i +: 32].

Diagnostics: run_encryption() traces dut.CIPHER.round_cntr and captures
temp_state at every round boundary, so a ciphertext mismatch is reported with
the first cipher round where the DUT diverged from the NIST reference.

Signal access notes (Verilator, --public-flat-rw):
  - dut.cipher_state, dut.cipher_done, dut.trng_key_valid   -- top-level ports
  - dut.CIPHER.round_cntr, dut.CIPHER.temp_state, dut.CIPHER.fsm_state
"""

import cocotb
import random
import logging
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles

# Simulation constants
CLK_PERIOD_NS  = 10    # main clock
SCLK_PERIOD_NS = 2     # sampling clock for the TRNG noise source
RESET_CYCLES   = 8
ENCRYPT_TIMEOUT = 30000  # cycles to wait for cipher_done (covers TRNG start-up)

KEY_SIZE_128 = 0b01
KEY_SIZE_192 = 0b10
KEY_SIZE_256 = 0b11

_mon_log = logging.getLogger("cocotb.monitor")

# NIST AES S-Box
SBOX = [
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

# NIST FIPS 197 Rcon table (Rcon[0] unused padding)
RCON = [0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000]


# NIST FIPS 197 reference model (encryption with per-round trace)
#
# States are kept as 16-byte lists in NIST input order: byte index r + 4*c is
# state element s[r][c] (FIPS 197 Section 3.4).
def _sub_word(word):
    return ((SBOX[(word >> 24) & 0xFF] << 24) |
            (SBOX[(word >> 16) & 0xFF] << 16) |
            (SBOX[(word >>  8) & 0xFF] <<  8) |
             SBOX[ word        & 0xFF])

def _rot_word(word):
    return ((word & 0x00FFFFFF) << 8) | ((word >> 24) & 0xFF)

def _xtime(b):
    b <<= 1
    return (b ^ 0x11B) & 0xFF if b & 0x100 else b

def _sub_bytes(s):
    return [SBOX[b] for b in s]

def _shift_rows(s):
    # s'[r][c] = s[r][(c + r) mod 4]; byte index is r + 4*c
    return [s[(i % 4) + 4 * (((i // 4) + (i % 4)) % 4)] for i in range(16)]

def _mix_columns(s):
    out = [0] * 16
    for c in range(4):
        b0, b1, b2, b3 = s[4*c:4*c+4]
        out[4*c + 0] = _xtime(b0) ^ (_xtime(b1) ^ b1) ^ b2 ^ b3
        out[4*c + 1] = b0 ^ _xtime(b1) ^ (_xtime(b2) ^ b2) ^ b3
        out[4*c + 2] = b0 ^ b1 ^ _xtime(b2) ^ (_xtime(b3) ^ b3)
        out[4*c + 3] = (_xtime(b0) ^ b0) ^ b1 ^ b2 ^ _xtime(b3)
    return out

def _add_round_key(s, rk_words):
    out = list(s)
    for c in range(4):
        for r in range(4):
            out[r + 4*c] ^= (rk_words[c] >> (24 - 8*r)) & 0xFF
    return out


class AESEncryptModel:
    """FIPS 197 encryption model with the full key schedule and a per-round
    intermediate-state trace for DUT debugging."""

    _KEY_PARAMS = {16: (4, 10), 24: (6, 12), 32: (8, 14)}  # key bytes → (Nk, Nr)

    def __init__(self, key_bytes):
        key_bytes = list(key_bytes)
        if len(key_bytes) not in self._KEY_PARAMS:
            raise ValueError(f"Key must be 16, 24, or 32 bytes; got {len(key_bytes)}")
        self.key_bytes = key_bytes
        self.Nk, self.Nr = self._KEY_PARAMS[len(key_bytes)]
        self.w = []
        for i in range(self.Nk):
            b = key_bytes[4*i:4*i+4]
            self.w.append((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3])
        for i in range(self.Nk, 4 * (self.Nr + 1)):
            temp = self.w[i - 1]
            if i % self.Nk == 0:
                temp = _sub_word(_rot_word(temp)) ^ RCON[i // self.Nk]
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = _sub_word(temp)
            self.w.append(self.w[i - self.Nk] ^ temp)

    def round_key(self, rnd):
        return self.w[4*rnd : 4*rnd + 4]

    def encrypt_trace(self, pt_bytes):
        """Encrypt one block. Returns (ct_bytes, trace) where trace[r] is a dict
        of the intermediate 16-byte states of NIST round r (FIPS 197 Sec 5.1)."""
        s = list(pt_bytes)
        trace = []

        s = _add_round_key(s, self.round_key(0))
        trace.append({"round": 0, "after_ark": s})

        for rnd in range(1, self.Nr):
            sub  = _sub_bytes(s)
            shft = _shift_rows(sub)
            mix  = _mix_columns(shft)
            s    = _add_round_key(mix, self.round_key(rnd))
            trace.append({"round": rnd, "after_sub": sub, "after_shift": shft,
                          "after_mix": mix, "after_ark": s})

        sub  = _sub_bytes(s)
        shft = _shift_rows(sub)
        s    = _add_round_key(shft, self.round_key(self.Nr))
        trace.append({"round": self.Nr, "after_sub": sub, "after_shift": shft,
                      "after_ark": s})

        return s, trace

    def encrypt(self, pt_bytes):
        return self.encrypt_trace(pt_bytes)[0]

    def master_key_rtl_int(self):
        """RTL master_key packing: NIST word w[i] at bits [32*i +: 32]."""
        val = 0
        for i in range(self.Nk):
            val |= (self.w[i] & 0xFFFFFFFF) << (32 * i)
        return val


# Model self-check against FIPS 197 known-answer vectors (runs at import)
def _model_self_check():
    vectors = [
        # (key, plaintext, ciphertext) -- FIPS 197 Appendix B, C.1, C.2, C.3
        ("2b7e151628aed2a6abf7158809cf4f3c",
         "3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32"),
        ("000102030405060708090a0b0c0d0e0f",
         "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("000102030405060708090a0b0c0d0e0f1011121314151617",
         "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
    ]
    for key_hex, pt_hex, ct_hex in vectors:
        got = AESEncryptModel(bytes.fromhex(key_hex)).encrypt(list(bytes.fromhex(pt_hex)))
        assert bytes(got).hex() == ct_hex, (
            f"AESEncryptModel self-check FAILED for key={key_hex}: "
            f"got {bytes(got).hex()}, want {ct_hex}")

_model_self_check()


# RTL bit-packing helpers (same convention as addRoundKey_tb, validated there)
def nist_bytes_to_rtl_state(b16):
    """16-byte NIST-order block → 128-bit state_matrix_t integer.
    NIST s[r][c] = b16[r + 4c]; RTL row (3-r) = NIST row r."""
    val = 0
    for r in range(4):
        for c in range(4):
            val |= b16[r + 4*c] << (((3 - r) * 4 + c) * 8)
    return val

def rtl_state_to_nist_bytes(val):
    """128-bit state_matrix_t integer → 16-byte NIST-order block."""
    out = [0] * 16
    for rtl_row in range(4):
        for c in range(4):
            out[(3 - rtl_row) + 4*c] = (val >> ((rtl_row * 4 + c) * 8)) & 0xFF
    return out

def hexs(b16):
    return "".join(f"{b:02x}" for b in b16)


# Noise source for the real TRNG instance
class NoiseBitBuffer:
    """Random bit stream for raw_rand_bit. Prefers the physics-based
    noise_source_model.py (on PYTHONPATH via the sim dir); falls back to a
    seeded PRNG when it isn't available."""

    def __init__(self, n_bits=60000, seed=None):
        self._seed = seed if seed is not None else random.getrandbits(32)
        self._idx = 0
        try:
            from noise_source_model import TRNGNoiseSource
            src = TRNGNoiseSource(n_ro=32, n_inv=13, fs_MHz=150.0, seed=self._seed)
            self._buf = [int(b) for b in src.generate_bits(n_bits)]
            cocotb.log.info(f"[NoiseBitBuffer] physics model, {n_bits} bits, seed={self._seed}")
        except ImportError as e:
            rng = random.Random(self._seed)
            self._buf = [rng.getrandbits(1) for _ in range(n_bits)]
            cocotb.log.warning(f"[NoiseBitBuffer] physics model unavailable ({e}); PRNG fallback")

    def next_bit(self):
        b = self._buf[self._idx]
        self._idx = (self._idx + 1) % len(self._buf)
        return b

async def noise_driver(dut, seed=None):
    """Drive raw_rand_bit with fresh noise on every sampling_clk edge."""
    buf = NoiseBitBuffer(seed=seed)
    while True:
        await RisingEdge(dut.sampling_clk)
        dut.raw_rand_bit.value = buf.next_bit()


# DUT control helpers
def start_clocks(dut):
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, unit="ns").start())
    cocotb.start_soon(Clock(dut.sampling_clk, SCLK_PERIOD_NS, unit="ns").start())

async def reset_dut(dut):
    dut.rst_n.value        = 0
    dut.state.value        = 0
    dut.master_key.value   = 0
    dut.key_size.value     = 0   # parks the cipher in round 0 after reset
    dut.raw_rand_bit.value = 0
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.rst_n.value = 1
    await RisingEdge(dut.clk)
    dut._log.info("DUT reset complete")


async def signal_monitor(dut, label=""):
    """Log cipher FSM / round transitions (low-volume debug aid)."""
    pfx = f"[MON {label}]" if label else "[MON]"

    def snap():
        return {
            "round_cntr"     : int(dut.CIPHER.round_cntr.value),
            "fsm_state"      : int(dut.CIPHER.fsm_state.value),
            "cipher_done"    : int(dut.cipher_done.value),
            "trng_key_valid" : int(dut.trng_key_valid.value),
            "trng_dead_flag" : int(dut.trng_dead_flag.value),
        }

    await RisingEdge(dut.clk)
    prev = snap()
    cyc = 0
    while True:
        await RisingEdge(dut.clk)
        cyc += 1
        cur = snap()
        diff = [(k, prev[k], cur[k]) for k in cur if prev[k] != cur[k]]
        if diff:
            changes = "  ".join(f"{k}: {ov}->{nv}" for k, ov, nv in diff)
            _mon_log.info(f"{pfx} cyc={cyc:6d}  {changes}")
        prev = cur


async def run_encryption(dut, key_bytes, pt_bytes, key_size_code,
                         timeout=ENCRYPT_TIMEOUT, already_running=False,
                         next_pt_bytes=None):
    """Drive one encryption and wait for cipher_done.

    Returns (ct_nist_bytes, model, trace, dut_round_trace) where
    dut_round_trace is a list of (round_cntr, temp_state_int) captured at every
    round boundary -- temp_state holds that round's addRoundKey output.

    If already_running (back-to-back test), only `state` is updated; the DUT
    picks it up when its internal round counter wraps to 0.

    next_pt_bytes: for chaining a second back-to-back block. cipher.sv samples
    `state` into `ark_state` on essentially every cycle round_cntr==0 is
    active, starting the very cycle round_cntr wraps -- reacting to
    cipher_done and only then driving the next plaintext lands one cycle too
    late for that first sample. If given, this drives `state` proactively the
    cycle round_cntr first reaches Nr (the final round), well before
    cipher_done, so it's already settled by the time round_cntr wraps.
    """
    model = AESEncryptModel(key_bytes)
    ct_expect, trace = model.encrypt_trace(list(pt_bytes))

    # Present the plaintext BEFORE key_size becomes valid: the cipher's round-0
    # handshake raises ark_done one cycle after key_size is valid, and the
    # addRoundKey input register (ark_state) needs a cycle to pick up `state`.
    dut.state.value = nist_bytes_to_rtl_state(list(pt_bytes))
    if not already_running:
        await ClockCycles(dut.clk, 2)
        dut.master_key.value = model.master_key_rtl_int()
        dut.key_size.value   = key_size_code

    dut_rounds = []
    prev_round = int(dut.CIPHER.round_cntr.value)
    next_state_driven = next_pt_bytes is None
    for _ in range(timeout):
        await RisingEdge(dut.clk)
        cur_round = int(dut.CIPHER.round_cntr.value)
        if cur_round != prev_round:
            # temp_state just captured round prev_round's addRoundKey output
            dut_rounds.append((prev_round, int(dut.CIPHER.temp_state.value)))
            prev_round = cur_round
        if not next_state_driven and cur_round == model.Nr:
            dut.state.value = nist_bytes_to_rtl_state(list(next_pt_bytes))
            next_state_driven = True
        if int(dut.cipher_done.value) == 1:
            ct_rtl = int(dut.cipher_state.value)
            return rtl_state_to_nist_bytes(ct_rtl), model, trace, dut_rounds
    raise AssertionError(
        f"TIMEOUT ({timeout} cycles): cipher_done never asserted "
        f"(round_cntr={int(dut.CIPHER.round_cntr.value)}, "
        f"trng_key_valid={int(dut.trng_key_valid.value)}, "
        f"trng_dead_flag={int(dut.trng_dead_flag.value)})")


def report_round_divergence(dut, model, trace, dut_rounds):
    """Compare the DUT per-round addRoundKey outputs against the NIST trace and
    log the first divergent round with the reference sub-step states."""
    dut._log.warning("Per-round comparison (DUT temp_state vs NIST reference):")
    ref_by_round = {t["round"]: t for t in trace}
    first_bad = None
    for rnd, temp_int in dut_rounds:
        dut_bytes = rtl_state_to_nist_bytes(temp_int)
        ref = ref_by_round.get(rnd)
        if ref is None:
            dut._log.warning(f"  round {rnd:2d}: DUT={hexs(dut_bytes)}  "
                             f"(no such round in NIST AES-{len(model.key_bytes)*8}: Nr={model.Nr})")
            if first_bad is None:
                first_bad = rnd
            continue
        ok = dut_bytes == ref["after_ark"]
        dut._log.warning(f"  round {rnd:2d}: DUT={hexs(dut_bytes)}  "
                         f"NIST={hexs(ref['after_ark'])}  {'✓' if ok else '✗'}")
        if not ok and first_bad is None:
            first_bad = rnd
    if first_bad is not None and first_bad in ref_by_round:
        ref = ref_by_round[first_bad]
        dut._log.warning(f"First divergence at cipher round {first_bad}. "
                         f"NIST sub-step states for that round:")
        for k in ("after_sub", "after_shift", "after_mix", "after_ark"):
            if k in ref:
                dut._log.warning(f"    {k:12s}: {hexs(ref[k])}")
    return first_bad


# TC1: Reset & TRNG liveness
@cocotb.test()
async def tc1_reset_and_trng_liveness(dut):
    """TC1: outputs are zero after reset; the embedded TRNG produces
    trng_key_valid on its own (noise source → health tests → Keccak)."""
    dut._log.info("=" * 60)
    dut._log.info("TC1: Reset behavior + TRNG liveness")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(noise_driver(dut, seed=1001))
    await reset_dut(dut)

    assert int(dut.cipher_state.value) == 0, \
        f"cipher_state not zero after reset: 0x{int(dut.cipher_state.value):032x}"
    assert int(dut.cipher_done.value) == 0, "cipher_done not zero after reset"
    dut._log.info(" cipher_state = 0 and cipher_done = 0 after reset")

    # key_size=0 parks the cipher: round_cntr must stay 0
    await ClockCycles(dut.clk, 20)
    assert int(dut.CIPHER.round_cntr.value) == 0, \
        "cipher advanced past round 0 with key_size=2'b00"
    dut._log.info(" cipher parked in round 0 while key_size=2'b00")

    # TRNG must come alive by itself
    for i in range(20000):
        await RisingEdge(dut.clk)
        if int(dut.trng_key_valid.value) == 1:
            dut._log.info(f" trng_key_valid asserted after {i+1} cycles")
            break
    else:
        raise AssertionError("TIMEOUT: trng_key_valid never asserted (20000 cycles)")

    assert int(dut.trng_dead_flag.value) == 0, "trng_dead_flag asserted with live noise"
    dut._log.info(" TC1 PASSED")


# TC2: AES-128, FIPS 197 Appendix B vector
@cocotb.test()
async def tc2_aes128_appendix_b(dut):
    """TC2: AES-128 known-answer test, FIPS 197 Appendix B.
    key=2b7e1516... pt=3243f6a8... → ct=3925841d02dc09fbdc118597196a0b32"""
    dut._log.info("=" * 60)
    dut._log.info("TC2: AES-128 FIPS 197 Appendix B")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(noise_driver(dut, seed=2002))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC2"))

    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt  = bytes.fromhex("3243f6a8885a308d313198a2e0370734")

    ct_dut, model, trace, dut_rounds = await run_encryption(dut, key, pt, KEY_SIZE_128)
    ct_ref = trace[-1]["after_ark"]

    dut._log.info(f"  plaintext : {pt.hex()}")
    dut._log.info(f"  key       : {key.hex()}")
    dut._log.info(f"  DUT   ct  : {hexs(ct_dut)}")
    dut._log.info(f"  NIST  ct  : {hexs(ct_ref)}")

    if ct_dut != ct_ref:
        report_round_divergence(dut, model, trace, dut_rounds)
        raise AssertionError(
            f"AES-128 Appendix B ciphertext mismatch: DUT={hexs(ct_dut)} NIST={hexs(ct_ref)}")

    dut._log.info(" TC2 PASSED")


# TC3: AES-128, FIPS 197 Appendix C.1 vector
@cocotb.test()
async def tc3_aes128_c1(dut):
    """TC3: AES-128 known-answer test, FIPS 197 Appendix C.1."""
    dut._log.info("=" * 60)
    dut._log.info("TC3: AES-128 FIPS 197 Appendix C.1")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(noise_driver(dut, seed=3003))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC3"))

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt  = bytes.fromhex("00112233445566778899aabbccddeeff")

    ct_dut, model, trace, dut_rounds = await run_encryption(dut, key, pt, KEY_SIZE_128)
    ct_ref = trace[-1]["after_ark"]

    dut._log.info(f"  DUT  ct: {hexs(ct_dut)}")
    dut._log.info(f"  NIST ct: {hexs(ct_ref)} (expect 69c4e0d86a7b0430d8cdb78070b4c55a)")

    if ct_dut != ct_ref:
        report_round_divergence(dut, model, trace, dut_rounds)
        raise AssertionError(
            f"AES-128 C.1 ciphertext mismatch: DUT={hexs(ct_dut)} NIST={hexs(ct_ref)}")

    dut._log.info(" TC3 PASSED")


# TC4: AES-192, FIPS 197 Appendix C.2 vector
@cocotb.test()
async def tc4_aes192_c2(dut):
    """TC4: AES-192 known-answer test, FIPS 197 Appendix C.2."""
    dut._log.info("=" * 60)
    dut._log.info("TC4: AES-192 FIPS 197 Appendix C.2")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(noise_driver(dut, seed=4004))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC4"))

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
    pt  = bytes.fromhex("00112233445566778899aabbccddeeff")

    ct_dut, model, trace, dut_rounds = await run_encryption(dut, key, pt, KEY_SIZE_192)
    ct_ref = trace[-1]["after_ark"]

    dut._log.info(f"  DUT  ct: {hexs(ct_dut)}")
    dut._log.info(f"  NIST ct: {hexs(ct_ref)} (expect dda97ca4864cdfe06eaf70a0ec0d7191)")

    if ct_dut != ct_ref:
        report_round_divergence(dut, model, trace, dut_rounds)
        raise AssertionError(
            f"AES-192 C.2 ciphertext mismatch: DUT={hexs(ct_dut)} NIST={hexs(ct_ref)}")

    dut._log.info(" TC4 PASSED")


# TC5: AES-256, FIPS 197 Appendix C.3 vector
@cocotb.test()
async def tc5_aes256_c3(dut):
    """TC5: AES-256 known-answer test, FIPS 197 Appendix C.3."""
    dut._log.info("=" * 60)
    dut._log.info("TC5: AES-256 FIPS 197 Appendix C.3")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(noise_driver(dut, seed=5005))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC5"))

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    pt  = bytes.fromhex("00112233445566778899aabbccddeeff")

    ct_dut, model, trace, dut_rounds = await run_encryption(dut, key, pt, KEY_SIZE_256)
    ct_ref = trace[-1]["after_ark"]

    dut._log.info(f"  DUT  ct: {hexs(ct_dut)}")
    dut._log.info(f"  NIST ct: {hexs(ct_ref)} (expect 8ea2b7ca516745bfeafc49904b496089)")

    if ct_dut != ct_ref:
        report_round_divergence(dut, model, trace, dut_rounds)
        raise AssertionError(
            f"AES-256 C.3 ciphertext mismatch: DUT={hexs(ct_dut)} NIST={hexs(ct_ref)}")

    dut._log.info(" TC5 PASSED")


# TC6: back-to-back encryptions (same key)
@cocotb.test()
async def tc6_back_to_back(dut):
    """TC6: two consecutive AES-128 encryptions without reset. After
    cipher_done the round counter wraps and the DUT re-encrypts whatever is on
    `state`; swap in a new plaintext and check the second ciphertext too."""
    dut._log.info("=" * 60)
    dut._log.info("TC6: Back-to-back AES-128 encryptions")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(noise_driver(dut, seed=6006))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC6"))

    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt1 = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    pt2 = bytes.fromhex("00112233445566778899aabbccddeeff")

    ct1, model, trace1, rounds1 = await run_encryption(
        dut, key, pt1, KEY_SIZE_128, next_pt_bytes=pt2)
    ref1 = trace1[-1]["after_ark"]
    dut._log.info(f"  Block 1: DUT={hexs(ct1)}  NIST={hexs(ref1)}")
    if ct1 != ref1:
        report_round_divergence(dut, model, trace1, rounds1)
        raise AssertionError(f"Block 1 mismatch: DUT={hexs(ct1)} NIST={hexs(ref1)}")

    # `state` for block 2 was already driven proactively (see next_pt_bytes
    # above) during block 1's final round -- cipher.sv samples `state` into
    # ark_state starting the very cycle round_cntr wraps, so reacting to
    # cipher_done here and driving state only now would be one cycle too late.
    ct2, model, trace2, rounds2 = await run_encryption(
        dut, key, pt2, KEY_SIZE_128, already_running=True)
    ref2 = trace2[-1]["after_ark"]
    dut._log.info(f"  Block 2: DUT={hexs(ct2)}  NIST={hexs(ref2)}")
    if ct2 != ref2:
        report_round_divergence(dut, model, trace2, rounds2)
        raise AssertionError(f"Block 2 mismatch: DUT={hexs(ct2)} NIST={hexs(ref2)}")

    dut._log.info(" TC6 PASSED")


# TC7: random stimulus vs reference model
@cocotb.test()
async def tc7_random_aes128(dut):
    """TC7: random AES-128 key/plaintext checked against the reference model."""
    dut._log.info("=" * 60)
    dut._log.info("TC7: Random AES-128 vector vs reference model")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(noise_driver(dut, seed=7007))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC7"))

    rng = random.Random(0xAE5)
    key = bytes(rng.getrandbits(8) for _ in range(16))
    pt  = bytes(rng.getrandbits(8) for _ in range(16))
    dut._log.info(f"  key: {key.hex()}  pt: {pt.hex()}")

    ct_dut, model, trace, dut_rounds = await run_encryption(dut, key, pt, KEY_SIZE_128)
    ct_ref = trace[-1]["after_ark"]

    dut._log.info(f"  DUT  ct: {hexs(ct_dut)}")
    dut._log.info(f"  model ct: {hexs(ct_ref)}")

    if ct_dut != ct_ref:
        report_round_divergence(dut, model, trace, dut_rounds)
        raise AssertionError(
            f"Random-vector ciphertext mismatch: DUT={hexs(ct_dut)} model={hexs(ct_ref)}")

    dut._log.info(" TC7 PASSED")
