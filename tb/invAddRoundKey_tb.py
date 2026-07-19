"""
Cocotb testbench for the invAddRoundKey module, verified through the
auto-generated invAddRoundKey_top wrapper (invAddRoundKey + addRoundKey +
word-mode SBox + real TRNG).

invAddRoundKey operation (two phases, per the RTL's design intent):
  1. KEY ACQUISITION: while keys_received=0, invAddRoundKey enables AddRoundKey
     (ark_enb_n=0) in key_only_mode and drives round_cntr as its round_num.
     Each ark_done pulse delivers one NIST round key w[4r..4r+3] on exp_key,
     which is stored into key_mem slot r. When round_cntr reaches Nr and the
     last key lands, keys_received latches 1 and AddRoundKey is disabled.
  2. INVERSE KEY ADDITION: with keys_received=1, every enabled clock cycle
     registers invAddRoundKeyOut = state ^ key_mem[invCipher_round]. The
     caller (inverse CIPHER) supplies invCipher_round already mapped to the
     NIST key index it wants -- backward iteration is the caller's job, so
     this TB exercises rounds in descending order the way invCipher would.

Golden reference: NIST FIPS 197 key schedule (AESReferenceModel, same
conventions as addRoundKey_tb.py, which is regression-proven 19/19). Expected
XOR outputs are computed with the identical row-inversion packing rules.

DUT (invAddRoundKey_top) interface notes:
  - The TRNG is a real instance fed by raw_rand_bit; in word mode (the only
    mode this wrapper uses) the SBox never handshakes with the TRNG, so key
    acquisition needs no TRNG warm-up.
  - enb_n gates invAddRoundKey's own ICG (enable includes ~rst_n, so reset
    lands even while parked). Key acquisition starts as soon as enb_n=0 with
    a valid key_size; keys_received clears only by reset, so each test does a
    fresh reset before loading a different key.
  - round_cntr / ark_enb_n / ark_done are exposed as top-level ports for
    handshake observation.

RTL data representation (same conventions addRoundKey_tb validated):
  - state_matrix_t = logic [3:0][3:0][7:0]: state[row][col] at bits (row*4+col)*8
  - Row convention: RTL row 3 = NIST row 0 (MSByte of a column word),
                    RTL row 0 = NIST row 3. Columns match NIST.
  - master_key packs NIST key word w[i] at bits [32*i +: 32].
  - key_mem = logic [3:0][59:0][7:0]: key_mem[row][word_idx] at bits
    (row*60 + word_idx)*8; slot r occupies word indices 4r..4r+3 and should
    hold NIST w[4r..4r+3] (RTL row 3 = MSByte of the word).

Signal access notes (Verilator, --public-flat-rw):
  - dut.invAddRoundKeyOut, dut.round_cntr, dut.ark_enb_n, dut.ark_done,
    dut.sbox_enb_n -- top-level ports
  - dut.InvAddRoundKey.keys_received, dut.InvAddRoundKey.key_mem -- internal
    (note the instance name casing: InvAddRoundKey). TRNG/SBox-side debug
    signals (rand_num, keys_rx_done, subByte, sbox_state, sbox_ready,
    sbox_done_pulse, trng_key_valid) are internal wires in invAddRoundKey_top,
    not top-level ports -- this testbench doesn't drive/read them directly, so
    reach them via dut.SBox.*/dut.TRNG.* if ever needed.
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
LOAD_TIMEOUT   = 800   # cycles for the full key-acquisition phase (AES-256 worst case)

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


# AES Reference Model -- NIST FIPS 197 key schedule (same as addRoundKey_tb)
class AESReferenceModel:
    """NIST FIPS 197 key expansion with per-round key words and RTL-format
    expected-output helpers. Identical conventions to addRoundKey_tb.py."""

    _KEY_PARAMS = {16: (4, 10), 24: (6, 12), 32: (8, 14)}  # key bytes -> (Nk, Nr)

    def __init__(self, key_bytes):
        if isinstance(key_bytes, (bytes, bytearray)):
            key_bytes = list(key_bytes)
        if len(key_bytes) not in self._KEY_PARAMS:
            raise ValueError(f"Key must be 16, 24, or 32 bytes; got {len(key_bytes)}")
        self.key_bytes = key_bytes
        self.Nk, self.Nr = self._KEY_PARAMS[len(key_bytes)]
        self.w = []
        self._expand_key()

    @staticmethod
    def _sub_word(word):
        return ((SBOX[(word >> 24) & 0xFF] << 24) |
                (SBOX[(word >> 16) & 0xFF] << 16) |
                (SBOX[(word >>  8) & 0xFF] <<  8) |
                 SBOX[ word        & 0xFF])

    @staticmethod
    def _rot_word(word):
        return ((word & 0x00FFFFFF) << 8) | ((word >> 24) & 0xFF)

    def _expand_key(self):
        self.w = []
        for i in range(self.Nk):
            b = self.key_bytes[4*i : 4*i+4]
            self.w.append((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3])
        for i in range(self.Nk, 4 * (self.Nr + 1)):
            temp = self.w[i - 1]
            if i % self.Nk == 0:
                temp = self._sub_word(self._rot_word(temp)) ^ RCON[i // self.Nk]
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = self._sub_word(temp)
            self.w.append(self.w[i - self.Nk] ^ temp)

    def get_round_key_words(self, rnd):
        """[w[4*rnd], w[4*rnd+1], w[4*rnd+2], w[4*rnd+3]]"""
        return self.w[4*rnd : 4*(rnd+1)]

    def master_key_rtl_int(self):
        """RTL master_key packing: NIST word w[i] at bits [32*i +: 32]."""
        val = 0
        for i, word in enumerate(self.w[:self.Nk]):
            val |= (word & 0xFFFFFFFF) << (32 * i)
        return val

    def expected_ark_rtl_int(self, state_rtl_int, rnd):
        """Expected (state XOR round-key) in RTL 128-bit integer format.
        RTL row r = NIST row (3-r); NIST key byte for NIST row n of word w
        is at bit (24 - 8n)."""
        rk = self.get_round_key_words(rnd)
        result = 0
        for rtl_row in range(4):
            nist_row = 3 - rtl_row
            for col in range(4):
                s_byte = (state_rtl_int >> ((rtl_row * 4 + col) * 8)) & 0xFF
                k_byte = (rk[col] >> (24 - nist_row * 8)) & 0xFF
                result |= (s_byte ^ k_byte) << ((rtl_row * 4 + col) * 8)
        return result

    def dump_key_schedule(self, log_fn=None):
        lines = [f"AES-{len(self.key_bytes)*8} Key Schedule (Nk={self.Nk}, Nr={self.Nr}):"]
        for rnd in range(self.Nr + 1):
            ws = self.get_round_key_words(rnd)
            lines.append("  Round {:2d}: ".format(rnd) +
                         "  ".join(f"w[{4*rnd+j}]=0x{w:08x}" for j, w in enumerate(ws)))
        text = "\n".join(lines)
        if log_fn:
            log_fn(text)
        return text


# RTL bit-packing helpers (same conventions as addRoundKey_tb)
def plaintext_to_rtl_state(pt_bytes):
    """16-byte NIST column-major block -> RTL 128-bit state integer.
    NIST state[row][col] = pt_bytes[row + 4*col]; RTL row (3-r) = NIST row r."""
    val = 0
    for row in range(4):
        for col in range(4):
            val |= pt_bytes[row + 4*col] << (((3 - row) * 4 + col) * 8)
    return val

def get_keymem_word(km_int, word_idx):
    """Extract the 32-bit NIST key word at key_mem word index word_idx.

    key_mem = logic [3:0][59:0][7:0]: key_mem[row][word_idx] at bits
    (row*60 + word_idx)*8. RTL row 3 = MSByte of the NIST word (same row
    convention get_expkey_word() uses in addRoundKey_tb, but with the 60-wide
    row stride of key_mem instead of expKey_matrix_t's 8-wide stride).
    """
    result = 0
    for row in range(4):
        byte = (km_int >> ((row * 60 + word_idx) * 8)) & 0xFF
        result |= byte << (row * 8)
    return result


# Noise source for the real TRNG instance
class NoiseBitBuffer:
    """Random bit stream for raw_rand_bit. Prefers the physics-based
    noise_source_model.py (on PYTHONPATH via the sim dir); falls back to a
    seeded PRNG when it isn't available."""

    def __init__(self, n_bits=20000, seed=None):
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
    """Reset and park the DUT (enb_n=1). invAddRoundKey's ICG enable includes
    ~rst_n, so its reset lands even while parked; the same holds for the
    embedded AddRoundKey/SBox after the project-wide ICG reset fix."""
    dut.rst_n.value           = 0
    dut.enb_n.value           = 1
    dut.key_size.value        = 0
    dut.master_key.value      = 0
    dut.state.value           = 0
    dut.invCipher_round.value = 0
    dut.invARK_proceed.value  = 0
    dut.raw_rand_bit.value    = 0
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.rst_n.value = 1
    await RisingEdge(dut.clk)
    dut._log.info("DUT reset complete (parked: enb_n=1)")

async def start_key_load(dut, ref, key_size_code):
    """Drive master_key/key_size and enable the DUT so key acquisition starts."""
    dut.master_key.value = ref.master_key_rtl_int()
    dut.key_size.value   = key_size_code
    dut.enb_n.value      = 0
    await RisingEdge(dut.clk)

async def wait_keys_received(dut, timeout=LOAD_TIMEOUT):
    """Wait for the key-acquisition phase to finish. Returns cycles taken."""
    for i in range(timeout):
        await RisingEdge(dut.clk)
        if int(dut.InvAddRoundKey.keys_received.value) == 1:
            return i + 1
    raise AssertionError(
        f"TIMEOUT ({timeout} cycles): keys_received never asserted "
        f"(round_cntr={int(dut.round_cntr.value)}, "
        f"ark_enb_n={int(dut.ark_enb_n.value)}, "
        f"ark_done={int(dut.ark_done.value)}, "
        f"sbox_enb_n={int(dut.sbox_enb_n.value):#04b})")

def check_key_mem(dut, ref):
    """Compare every key_mem slot against the NIST schedule. Returns a list of
    mismatch strings (empty = fully NIST-correct)."""
    km = int(dut.InvAddRoundKey.key_mem.value)
    mismatches = []
    dut._log.info(f"key_mem vs NIST schedule (slots 0..{ref.Nr}):")
    for rnd in range(ref.Nr + 1):
        nist_rk = ref.get_round_key_words(rnd)
        for i in range(4):
            rtl_word  = get_keymem_word(km, 4*rnd + i)
            nist_word = nist_rk[i]
            ok = rtl_word == nist_word
            dut._log.info(f"  slot {rnd:2d} w[{4*rnd+i:2d}]: RTL=0x{rtl_word:08x}  "
                          f"NIST=0x{nist_word:08x}  {'PASS' if ok else 'FAIL'}")
            if not ok:
                mismatches.append(
                    f"slot {rnd} w[{4*rnd+i}]: RTL=0x{rtl_word:08x} NIST=0x{nist_word:08x}")
    return mismatches

async def check_inverse_rounds(dut, ref, rng, rounds=None):
    """Drive random states through the inverse key-addition phase for the given
    rounds (default: Nr down to 0, the order invCipher consumes keys) and
    compare against the NIST model. Returns a list of mismatch strings."""
    if rounds is None:
        rounds = range(ref.Nr, -1, -1)  # backward, as inverse CIPHER iterates
    mismatches = []
    for rnd in rounds:
        state_int = rng.getrandbits(128)
        dut.state.value           = state_int
        dut.invCipher_round.value = rnd
        await ClockCycles(dut.clk, 2)

        expected = ref.expected_ark_rtl_int(state_int, rnd)
        actual   = int(dut.invAddRoundKeyOut.value)
        ok = actual == expected
        dut._log.info(f"  round {rnd:2d}: {'PASS' if ok else 'FAIL'}"
                      + ("" if ok else f"  RTL=0x{actual:032x} NIST=0x{expected:032x}"))
        if not ok:
            mismatches.append(
                f"round {rnd}: RTL=0x{actual:032x} NIST=0x{expected:032x}")
    return mismatches


# Signal monitor
async def signal_monitor(dut, label=""):
    pfx = f"[MON {label}]" if label else "[MON]"

    def snap():
        return {
            "round_cntr"    : int(dut.round_cntr.value),
            "ark_enb_n"     : int(dut.ark_enb_n.value),
            "ark_done"      : int(dut.ark_done.value),
            "sbox_enb_n"    : int(dut.sbox_enb_n.value),
            "keys_received" : int(dut.InvAddRoundKey.keys_received.value),
        }

    await RisingEdge(dut.clk)
    prev = snap()
    _mon_log.info(pfx + " INIT  " + "  ".join(f"{k}={v}" for k, v in prev.items()))
    cyc = 0
    while True:
        await RisingEdge(dut.clk)
        cyc += 1
        cur = snap()
        diff = [(k, prev[k], cur[k]) for k in cur if prev[k] != cur[k]]
        if diff:
            changes = "  ".join(f"{k}: {ov}->{nv}" for k, ov, nv in diff)
            _mon_log.info(f"{pfx} cyc={cyc:4d}  {changes}")
        prev = cur


# TC1: Reset behavior
@cocotb.test()
async def tc1_reset(dut):
    """TC1: after reset, outputs are zero, AddRoundKey is disabled, and the
    parked DUT (enb_n=1) makes no progress."""
    dut._log.info("=" * 60)
    dut._log.info("TC1: Reset behavior")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(noise_driver(dut, seed=1001))
    await reset_dut(dut)

    assert int(dut.invAddRoundKeyOut.value) == 0, \
        f"invAddRoundKeyOut not zero after reset: 0x{int(dut.invAddRoundKeyOut.value):032x}"
    assert int(dut.round_cntr.value) == 0, "round_cntr not zero after reset"
    assert int(dut.ark_enb_n.value) == 1, "ark_enb_n not 1 (AddRoundKey enabled) after reset"
    assert int(dut.InvAddRoundKey.keys_received.value) == 0, "keys_received set after reset"
    dut._log.info(" outputs zero, AddRoundKey disabled, keys_received=0")

    # parked: no progress may occur
    await ClockCycles(dut.clk, 20)
    assert int(dut.round_cntr.value) == 0, "round_cntr advanced while parked (enb_n=1)"
    assert int(dut.ark_enb_n.value) == 1, "AddRoundKey enabled while parked (enb_n=1)"
    dut._log.info(" no progress while parked")
    dut._log.info(" TC1 PASSED")


# TC2: AES-128 key acquisition
@cocotb.test()
async def tc2_aes128_key_acquisition(dut):
    """TC2: AES-128 key acquisition -- key_mem must end up holding the full
    NIST A.1 schedule w[0..43] in slots 0..10, AddRoundKey must be disabled
    afterwards, and round_cntr must have wrapped to 0."""
    dut._log.info("=" * 60)
    dut._log.info("TC2: AES-128 key acquisition (NIST A.1 schedule)")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(noise_driver(dut, seed=2002))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC2"))

    ref = AESReferenceModel(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
    ref.dump_key_schedule(dut._log.info)

    await start_key_load(dut, ref, KEY_SIZE_128)
    cyc = await wait_keys_received(dut)
    dut._log.info(f" keys_received after {cyc} cycles")

    await ClockCycles(dut.clk, 2)  # let ark_enb_n disable settle
    assert int(dut.ark_enb_n.value) == 1, \
        "AddRoundKey not disabled after key acquisition finished"
    assert int(dut.round_cntr.value) == 0, \
        f"round_cntr did not wrap to 0 after loading (got {int(dut.round_cntr.value)})"
    dut._log.info(" AddRoundKey disabled and round_cntr wrapped after loading")

    mismatches = check_key_mem(dut, ref)
    if mismatches:
        dut._log.warning(f"TC2: {len(mismatches)} key_mem mismatch(es):")
        for m in mismatches:
            dut._log.warning(f"  {m}")
        assert False, f"TC2 FAILED: {len(mismatches)} key_mem mismatches vs NIST A.1"

    dut._log.info(" TC2 PASSED -- key_mem holds the full NIST A.1 schedule")


# TC3: AES-128 inverse round-key addition
@cocotb.test()
async def tc3_aes128_inverse_rounds(dut):
    """TC3: AES-128 -- after key acquisition, every round key applied in
    backward order (Nr..0, as inverse CIPHER consumes them) must satisfy
    invAddRoundKeyOut = state ^ w[4r..4r+3]."""
    dut._log.info("=" * 60)
    dut._log.info("TC3: AES-128 inverse round-key addition (rounds 10..0)")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(noise_driver(dut, seed=3003))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC3"))

    ref = AESReferenceModel(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
    await start_key_load(dut, ref, KEY_SIZE_128)
    cyc = await wait_keys_received(dut)
    dut._log.info(f" keys loaded in {cyc} cycles; starting inverse key addition")

    rng = random.Random(0x1A3)
    mismatches = await check_inverse_rounds(dut, ref, rng)
    if mismatches:
        assert False, "TC3 FAILED:\n" + "\n".join(mismatches)

    dut._log.info(" TC3 PASSED -- all 11 AES-128 round keys applied correctly")


# TC4: AES-192 key acquisition + inverse round-key addition
@cocotb.test()
async def tc4_aes192_full(dut):
    """TC4: AES-192 (NIST A.2 key) -- key acquisition spans 13 round keys
    (with AddRoundKey's bypass rounds 2,5,8,11 in the middle of the schedule),
    then all rounds 12..0 are checked."""
    dut._log.info("=" * 60)
    dut._log.info("TC4: AES-192 key acquisition + inverse rounds (NIST A.2)")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(noise_driver(dut, seed=4004))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC4"))

    ref = AESReferenceModel(bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"))
    ref.dump_key_schedule(dut._log.info)

    await start_key_load(dut, ref, KEY_SIZE_192)
    cyc = await wait_keys_received(dut)
    dut._log.info(f" keys_received after {cyc} cycles")

    mismatches = check_key_mem(dut, ref)
    rng = random.Random(0x1A4)
    mismatches += await check_inverse_rounds(dut, ref, rng)
    if mismatches:
        assert False, f"TC4 FAILED ({len(mismatches)} mismatches):\n" + "\n".join(mismatches)

    dut._log.info(" TC4 PASSED -- AES-192 schedule loaded and applied correctly")


# TC5: AES-256 key acquisition + inverse round-key addition
@cocotb.test()
async def tc5_aes256_full(dut):
    """TC5: AES-256 (NIST A.3 key) -- key acquisition spans 15 round keys
    (including AddRoundKey's round-1 master-key bypass), then all rounds
    14..0 are checked."""
    dut._log.info("=" * 60)
    dut._log.info("TC5: AES-256 key acquisition + inverse rounds (NIST A.3)")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(noise_driver(dut, seed=5005))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC5"))

    ref = AESReferenceModel(bytes.fromhex(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dfe4"))
    ref.dump_key_schedule(dut._log.info)

    await start_key_load(dut, ref, KEY_SIZE_256)
    cyc = await wait_keys_received(dut)
    dut._log.info(f" keys_received after {cyc} cycles")

    mismatches = check_key_mem(dut, ref)
    rng = random.Random(0x1A5)
    mismatches += await check_inverse_rounds(dut, ref, rng)
    if mismatches:
        assert False, f"TC5 FAILED ({len(mismatches)} mismatches):\n" + "\n".join(mismatches)

    dut._log.info(" TC5 PASSED -- AES-256 schedule loaded and applied correctly")


# TC6: enable gating
@cocotb.test()
async def tc6_enable_gating(dut):
    """TC6: enb_n gating -- the output register must freeze while parked and
    resume within a couple of cycles of re-enabling. Checked by change
    detection only (state-XOR difference), so this test isolates the gating
    behavior from key-schedule correctness (TC2-5 cover that)."""
    dut._log.info("=" * 60)
    dut._log.info("TC6: Enable gating during the inverse-round phase")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(noise_driver(dut, seed=6006))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC6"))

    ref = AESReferenceModel(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
    await start_key_load(dut, ref, KEY_SIZE_128)
    await wait_keys_received(dut)

    # settle one XOR result
    dut.state.value           = 0x00112233445566778899AABBCCDDEEFF
    dut.invCipher_round.value = 5
    await ClockCycles(dut.clk, 2)
    out_before = int(dut.invAddRoundKeyOut.value)
    dut._log.info(f"  output before parking: 0x{out_before:032x}")

    # park, then change the inputs -- output must not react
    dut.enb_n.value = 1
    await RisingEdge(dut.clk)
    dut.state.value           = 0xFFEEDDCCBBAA99887766554433221100
    dut.invCipher_round.value = 2
    await ClockCycles(dut.clk, 10)
    out_parked = int(dut.invAddRoundKeyOut.value)
    assert out_parked == out_before, (
        f"output changed while parked: 0x{out_before:032x} -> 0x{out_parked:032x}")
    dut._log.info(" output frozen while parked (enb_n=1)")

    # resume -- output must update within 2 cycles (different state guarantees
    # a different XOR result regardless of key content)
    dut.enb_n.value = 0
    await ClockCycles(dut.clk, 2)
    out_resumed = int(dut.invAddRoundKeyOut.value)
    assert out_resumed != out_parked, "output did not update after re-enabling"
    dut._log.info(f" output resumed after re-enable: 0x{out_resumed:032x}")
    dut._log.info(" TC6 PASSED")


# TC7: random-state stress (AES-128)
@cocotb.test()
async def tc7_random_stress_aes128(dut):
    """TC7: 24 random (state, round) pairs against the NIST model, AES-128."""
    dut._log.info("=" * 60)
    dut._log.info("TC7: Random-state stress, AES-128")
    dut._log.info("=" * 60)

    start_clocks(dut)
    cocotb.start_soon(noise_driver(dut, seed=7007))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC7"))

    rng = random.Random(0xAE5)
    key = bytes(rng.getrandbits(8) for _ in range(16))
    ref = AESReferenceModel(key)
    dut._log.info(f"  random key: {key.hex()}")

    await start_key_load(dut, ref, KEY_SIZE_128)
    await wait_keys_received(dut)

    rounds = [rng.randrange(0, ref.Nr + 1) for _ in range(24)]
    mismatches = await check_inverse_rounds(dut, ref, rng, rounds=rounds)
    if mismatches:
        assert False, f"TC7 FAILED ({len(mismatches)} mismatches):\n" + "\n".join(mismatches)

    dut._log.info(" TC7 PASSED -- 24 random vectors match the NIST model")
