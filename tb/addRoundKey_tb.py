"""
Cocotb testbench for addRoundKey module.

NIST FIPS 197 compliance: AESReferenceModel is the golden reference for all test comparisons.

RTL data representation notes:
  - state_matrix_t = logic [3:0][3:0][7:0]: state[row][col] at bits (row*4+col)*8
  - expKey_matrix_t = logic [3:0][7:0][7:0]: expKey[row][word_idx] at bits (row*8+word_idx)*8
  - Row convention: RTL row 3 = NIST row 0 (MSByte of column word)
                    RTL row 0 = NIST row 3 (LSByte of column word)
  - Testbench applies row inversion in plaintext_to_rtl_state() to match this convention

AES-192 concat_sel pattern (from RTL concatenate_sel function):
  - concat_sel=01: rounds 1,4,7,10  → new key expansion, sbox enabled
  - concat_sel=10: rounds 3,6,9,12  → new key expansion, sbox enabled
  - concat_sel=11: rounds 2,5,8,11  → bypass (sbox_enb_n=1, reuse prev keys)

Signal access notes (Verilator):
  - dut.sbox_done, dut.sbox_enb_n, dut.subByte, dut.sbox_state  -- internal wires
  - dut.prev_expKey                                             -- internal register (256-bit)
  - dut.Sbox.fsm_state                                          -- sbox instance internal
"""

import cocotb
import random
import logging
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles

# Simulation constants
CLK_PERIOD_NS = 10
RESET_CYCLES  = 8
SBOX_LATENCY  = 6     # TOWER_FIELD → MASKED_D → ... → SUB_BYTES (6 edges)
SBOX_TIMEOUT  = 20    # max cycles to wait for sbox_done

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


# AES Reference Model — NIST FIPS 197 golden reference
class AESReferenceModel:
    """
    NIST FIPS 197 compliant reference implementation for AES key expansion and AddRoundKey.

    Supports AES-128 (16-byte key), AES-192 (24-byte key), AES-256 (32-byte key).
    Generates the complete key schedule upfront using the NIST-standard RotWord (left rotation)
    and provides per-round AddRoundKey outputs in RTL integer format for DUT comparison.

    Key schedule notation: w[i] for i in 0..4*(Nr+1)-1 following FIPS 197 Section 5.2.
    get_round_key_words(r) returns [w[4r], w[4r+1], w[4r+2], w[4r+3]].
    """

    _KEY_PARAMS = {16: (4, 10), 24: (6, 12), 32: (8, 14)}  # key_len_bytes → (Nk, Nr)

    def __init__(self, key_bytes):
        """
        Args:
            key_bytes: 16, 24, or 32 byte sequence (AES-128/192/256 key).
        """
        if isinstance(key_bytes, (bytes, bytearray)):
            key_bytes = list(key_bytes)
        if len(key_bytes) not in self._KEY_PARAMS:
            raise ValueError(f"Key must be 16, 24, or 32 bytes; got {len(key_bytes)}")
        self.key_bytes = key_bytes
        self.Nk, self.Nr = self._KEY_PARAMS[len(key_bytes)]
        self.w = []
        self._expand_key()

    # NIST key schedule primitives
    @staticmethod
    def _sub_word(word):
        """Apply NIST SubWord: S-box substitute each byte of a 32-bit word."""
        return ((SBOX[(word >> 24) & 0xFF] << 24) |
                (SBOX[(word >> 16) & 0xFF] << 16) |
                (SBOX[(word >>  8) & 0xFF] <<  8) |
                 SBOX[ word        & 0xFF])

    @staticmethod
    def _rot_word(word):
        """NIST RotWord: left-rotate bytes {a0,a1,a2,a3} → {a1,a2,a3,a0} (a0 is MSByte)."""
        return ((word & 0x00FFFFFF) << 8) | ((word >> 24) & 0xFF)

    def _expand_key(self):
        """Generate full NIST key schedule per FIPS 197 Section 5.2."""
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
 
    # Per-round outputs
    def get_round_key_words(self, rnd):
        """Return list of 4 NIST key schedule words for AES round rnd.

        Returns [w[4*rnd], w[4*rnd+1], w[4*rnd+2], w[4*rnd+3]].
        """
        return self.w[4*rnd : 4*(rnd+1)]

    def master_key_rtl_int(self):
        """Return master key as RTL 256-bit integer.

        RTL master_key signal packs NIST word i at bits [32*i+31 : 32*i].
        For AES-128, only bits [127:0] are used; for AES-192 bits [191:0]; for AES-256 all 256.
        """
        val = 0
        for i, word in enumerate(self.w[:self.Nk]):
            val |= (word & 0xFFFFFFFF) << (32 * i)
        return val

    def expected_ark_rtl_int(self, state_rtl_int, rnd):
        """Compute expected addRoundKeyOut in RTL integer format.

        RTL state[row][col] is at bits [(row*4+col)*8 +: 8] in the packed integer.
        Row inversion: RTL row r corresponds to NIST row (3-r):
          RTL row 3 = NIST row 0 = MSByte of the column word
          RTL row 0 = NIST row 3 = LSByte of the column word
        NIST key word[col] byte at NIST row r is at bit (24 - r*8) of the word.

        Args:
            state_rtl_int: 128-bit RTL state integer (as driven to DUT).
            rnd: AES cipher round number.
        Returns:
            128-bit expected addRoundKeyOut in RTL integer format.
        """
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
        """Format the full key schedule as a string; optionally pass to log_fn."""
        lines = [f"AES-{len(self.key_bytes)*8} Key Schedule (Nk={self.Nk}, Nr={self.Nr}):"]
        for rnd in range(self.Nr + 1):
            ws = self.get_round_key_words(rnd)
            lines.append("  Round {:2d}: ".format(rnd) +
                         "  ".join(f"w[{4*rnd+j}]=0x{w:08x}" for j, w in enumerate(ws)))
        text = "\n".join(lines)
        if log_fn:
            log_fn(text)
        return text


# RTL bit-packing helpers
#
# state_matrix_t = logic [3:0][3:0][7:0]
#   state[row][col] at bits [(row*4 + col)*8 +: 8]
#   state[0][0] at bits [7:0] (LSB), state[3][3] at bits [127:120] (MSB)
#
# expKey_matrix_t = logic [3:0][7:0][7:0]
#   expKey[row][word_idx] at bits [(row*8 + word_idx)*8 +: 8]
#
# master_key[255:0]: NIST word i at bits [32*i+31 : 32*i]
#
# Row convention: RTL row 3 is MSByte (=NIST row 0); RTL row 0 is LSByte (=NIST row 3).
# plaintext_to_rtl_state() applies row inversion to match the RTL's hardware convention.
def state_bytes_to_int(state_4x4):
    """state_4x4[row][col] → 128-bit RTL integer for state_matrix_t."""
    val = 0
    for row in range(4):
        for col in range(4):
            val |= (state_4x4[row][col] & 0xFF) << ((row*4 + col)*8)
    return val

def state_int_to_bytes(val):
    """128-bit RTL integer → state_4x4[row][col]."""
    s = [[0]*4 for _ in range(4)]
    for row in range(4):
        for col in range(4):
            s[row][col] = (val >> ((row*4 + col)*8)) & 0xFF
    return s

def plaintext_to_rtl_state(pt_bytes):
    """16-byte NIST column-major plaintext → RTL 128-bit state integer.

    NIST state[row][col] = pt_bytes[row + 4*col].
    RTL row inversion: RTL row r = NIST row (3-r), so RTL row 3 = NIST row 0 (MSByte).
    """
    val = 0
    for row in range(4):
        for col in range(4):
            nist_row = row
            rtl_row = 3 - row
            val |= pt_bytes[nist_row + 4*col] << ((rtl_row*4 + col)*8)
    return val

def rtl_state_to_nist_bytes(state_int):
    """RTL 128-bit state integer → 16-byte NIST column-major list."""
    out = [0]*16
    for row in range(4):
        for col in range(4):
            rtl_row = row
            nist_row = 3 - rtl_row
            out[nist_row + 4*col] = (state_int >> ((rtl_row*4 + col)*8)) & 0xFF
    return out

def compute_expected_ark(state_int, nist_key_words):
    """Compute expected addRoundKeyOut in RTL format given a list of 4 NIST key words.

    Equivalent to AESReferenceModel.expected_ark_rtl_int() but accepts the key words directly.
    nist_key_words: list of 4 32-bit NIST key schedule words for the round.
    """
    result = 0
    for rtl_row in range(4):
        nist_row = 3 - rtl_row
        for col in range(4):
            s_byte = (state_int >> ((rtl_row*4 + col)*8)) & 0xFF
            k_byte = (nist_key_words[col] >> (24 - nist_row*8)) & 0xFF
            result |= (s_byte ^ k_byte) << ((rtl_row*4 + col)*8)
    return result

def get_expkey_word(expkey_int, word_idx):
    """Extract packed 32-bit key word from expKey_matrix_t flat integer.

    expKey[row][word_idx] at bits (row*8 + word_idx)*8.
    Returns 32-bit word with RTL row 3 as MSByte and RTL row 0 as LSByte,
    which equals the NIST word value directly.
    """
    result = 0
    for row in range(4):
        byte = (expkey_int >> ((row*8 + word_idx)*8)) & 0xFF
        result |= byte << (row*8)
    return result

# DUT control helpers
def start_clock(dut):
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, unit="ns").start())

async def reset_dut(dut):
    dut.rst_n.value          = 0
    dut.round_num.value      = 0
    dut.key_size.value       = 0
    dut.state.value          = 0
    dut.master_key.value     = 0
    dut.rand_num.value       = 0
    dut.trng_key_valid.value = 0
    dut.trng_dead_flag.value = 0
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.rst_n.value = 1
    await RisingEdge(dut.clk)
    dut._log.info("DUT reset complete")

async def trng_model(dut):
    """
    TRNG model driver for masked sbox.

    Critical behavior: rand_num must be stable from TOWER_FIELD through MASKED_A_INV.
    sbox uses rand_num bits in both tower_field() and masked_A_inverse(), so bits
    must not change during the pipeline delay (3+ cycles).

    Protocol:
    1. Monitor sbox_ready pulse (HIGH at posedge when fsm_state = TOWER_FIELD)
    2. On sbox_ready rising edge: latch fresh random bits, assert trng_key_valid
    3. Hold rand_num stable until sbox_ready falls (sbox transitioned past TOWER_FIELD)
    4. De-assert trng_key_valid on sbox_ready falling edge
    """
    await RisingEdge(dut.clk)
    prev_ready = 0
    current_rand = 0

    while True:
        await RisingEdge(dut.clk)
        cur_ready = int(dut.sbox_ready.value)

        if cur_ready and not prev_ready:
            current_rand = random.randint(0, (1 << 112) - 1)
            dut.rand_num.value = current_rand
            dut.trng_key_valid.value = 1
        elif not cur_ready and prev_ready:
            dut.trng_key_valid.value = 0
            dut.rand_num.value = 0
        else:
            dut.rand_num.value = current_rand

        prev_ready = cur_ready

async def wait_sbox_done(dut, timeout=SBOX_TIMEOUT):
    """Wait for sbox_done to pulse high. Returns cycle count when found."""
    for i in range(timeout):
        await RisingEdge(dut.clk)
        if int(dut.sbox_done.value) == 1:
            return i + 1
    raise AssertionError(
        f"TIMEOUT ({timeout} cycles): sbox_done never asserted. "
        f"Check sbox_enb_n={int(dut.sbox_enb_n.value)}"
    )

# Signal monitor
async def signal_monitor(dut, label=""):
    pfx = f"[MON {label}]" if label else "[MON]"

    def snap():
        return {
            "round_num"  : int(dut.round_num.value),
            "key_size"   : int(dut.key_size.value),
            "sbox_enb_n" : int(dut.sbox_enb_n.value),
            "sbox_done"  : int(dut.sbox_done.value),
            "rst_trng"   : int(dut.rst_trng.value),
        }

    await RisingEdge(dut.clk)
    prev = snap()
    _mon_log.info(pfx + " INIT  " + "  ".join(f"{k}={v}" for k, v in prev.items()))

    cyc = 0
    while True:
        await RisingEdge(dut.clk)
        cyc += 1
        cur  = snap()
        diff = [(k, prev[k], cur[k]) for k in cur if prev[k] != cur[k]]
        if diff:
            changes = "  ".join(f"{k}: {ov}->{nv}" for k, ov, nv in diff)
            _mon_log.info(f"{pfx} cyc={cyc:4d}  {changes}")
        prev = cur


# TC1: Reset
@cocotb.test()
async def tc1_reset(dut):
    """TC1: All outputs zero during active reset."""
    dut._log.info("=" * 60)
    dut._log.info("TC1: Reset behavior")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))

    dut.rst_n.value          = 0
    dut.round_num.value      = 0xF
    dut.key_size.value       = KEY_SIZE_128
    dut.state.value          = 0xDEADBEEFCAFEBABE1234567890ABCDEF
    dut.master_key.value     = 0xDEADBEEFCAFEBABE1234567890ABCDEF
    dut.trng_dead_flag.value = 0

    await ClockCycles(dut.clk, RESET_CYCLES)

    ark_out  = int(dut.addRoundKeyOut.value)
    rst_trng = int(dut.rst_trng.value)

    assert ark_out == 0,  f"addRoundKeyOut not zero during reset: 0x{ark_out:032x}"
    assert rst_trng == 0, f"rst_trng not zero during reset: {rst_trng}"

    dut._log.info(" addRoundKeyOut = 0 during reset")
    dut._log.info(" rst_trng       = 0 during reset")
    dut._log.info(" TC1 PASSED")


# TC2: AES-128 round 0
@cocotb.test()
async def tc2_aes128_round0(dut):
    """TC2: AES-128 round 0 — state XOR master key, no Sbox.
    Uses NIST Appendix B test vector. Expected: 193de3be...e9f84808"""
    dut._log.info("=" * 60)
    dut._log.info("TC2: AES-128 round 0")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC2"))

    # NIST Appendix B: key and plaintext
    key_bytes = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt_bytes  = bytes.fromhex("3243f6a8885a308d313198a2e0370734")

    ref = AESReferenceModel(key_bytes)
    ref.dump_key_schedule(dut._log.info)

    state_int      = plaintext_to_rtl_state(list(pt_bytes))
    master_key_int = ref.master_key_rtl_int()

    dut._log.info(f"  state_int      = 0x{state_int:032x}")
    dut._log.info(f"  master_key_int = 0x{master_key_int:032x}")

    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_128
    dut.state.value          = state_int
    dut.master_key.value     = master_key_int
    dut.trng_dead_flag.value = 0

    # Sbox must be disabled for round 0 (combinational check)
    await RisingEdge(dut.clk)
    enb = int(dut.sbox_enb_n.value)
    assert enb == 1, f"sbox_enb_n should be 1 for round 0, got {enb}"
    dut._log.info(" sbox_enb_n = 1 (Sbox disabled for round 0)")

    # One more clock for addRoundKeyOut to register
    await RisingEdge(dut.clk)

    expected = ref.expected_ark_rtl_int(state_int, 0)
    actual   = int(dut.addRoundKeyOut.value)

    dut._log.info(f"  expected = 0x{expected:032x}")
    dut._log.info(f"  actual   = 0x{actual:032x}")

    assert actual == expected, (
        f"Round 0 addRoundKeyOut mismatch:\n"
        f"  Expected (NIST): 0x{expected:032x}\n"
        f"  Got (DUT):       0x{actual:032x}"
    )
    dut._log.info(f" addRoundKeyOut = 0x{actual:032x}")

    # Cross-check: convert to NIST bytes and compare with Appendix B
    nist_expected_hex = "193de3bea0f4e22b9ac68d2ae9f84808"
    nist_out_bytes = rtl_state_to_nist_bytes(actual)
    nist_out_hex = "".join(f"{b:02x}" for b in nist_out_bytes)
    if nist_out_hex == nist_expected_hex:
        dut._log.info(f" Matches NIST Appendix B round-0 output: {nist_expected_hex}")
    else:
        dut._log.warning(f"  NIST Appendix B expected: {nist_expected_hex}")
        dut._log.warning(f"  DUT NIST bytes:           {nist_out_hex}")

    dut._log.info(" TC2 PASSED")


# TC3: AES-128 key expansion diagnostics
@cocotb.test()
async def tc3_aes128_key_expansion(dut):
    """TC3: AES-128 key expansion — 10 rounds vs NIST Appendix A.1.
    Compares prev_expKey words and addRoundKeyOut against the NIST reference model."""
    dut._log.info("=" * 60)
    dut._log.info("TC3: AES-128 key expansion diagnostics (10 rounds)")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC3"))

    key_bytes = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    Nk, Nr    = 4, 10

    ref = AESReferenceModel(key_bytes)
    ref.dump_key_schedule(dut._log.info)

    state_int      = plaintext_to_rtl_state(list(bytes.fromhex("046681e5e0cb199a48f8d37a2806264c")))
    master_key_int = ref.master_key_rtl_int()

    # Round 0: verify master key loads into prev_expKey
    dut._log.info("\n=== ROUND 0: Master Key Loading ===")
    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_128
    dut.state.value          = state_int
    dut.master_key.value     = master_key_int
    dut.trng_dead_flag.value = 0
    await ClockCycles(dut.clk, 2)

    prev_ek_r0 = int(dut.prev_expKey.value)
    dut._log.info("Master key loading check (prev_expKey vs NIST w[0..3]):")
    all_match = True
    for wi in range(Nk):
        rtl_word  = get_expkey_word(prev_ek_r0, wi)
        nist_word = ref.get_round_key_words(0)[wi]
        match_str = "PASS" if rtl_word == nist_word else "FAIL"
        if rtl_word != nist_word:
            all_match = False
        dut._log.info(f"  w[{wi}]: RTL=0x{rtl_word:08x}  NIST=0x{nist_word:08x}  {match_str}")

    assert all_match, "Master key did not load correctly into prev_expKey"
    dut._log.info("Round 0: master key verified\n")

    # Rounds 1-10: trace key expansion
    dut._log.info("=== ROUNDS 1-10: Key Expansion vs NIST Reference ===")
    mismatches = []

    for rnd in range(1, Nr + 1):
        dut._log.info(f"--- Round {rnd} ---")
        dut.round_num.value = rnd

        cyc = await wait_sbox_done(dut)
        dut._log.info(f"  sbox_done after {cyc} cycles")
        await RisingEdge(dut.clk)

        # Compare prev_expKey (now updated) with reference round key words
        prev_ek = int(dut.prev_expKey.value)
        ark_out = int(dut.addRoundKeyOut.value)
        nist_rk = ref.get_round_key_words(rnd)

        for wi in range(Nk):
            rtl_word  = get_expkey_word(prev_ek, wi)
            nist_word = nist_rk[wi]
            match_str = "PASS" if rtl_word == nist_word else "FAIL"
            if rtl_word != nist_word:
                mismatches.append(f"Round {rnd} w[{Nk*rnd+wi}]: RTL=0x{rtl_word:08x}  NIST=0x{nist_word:08x}")
            dut._log.info(f"  w[{Nk*rnd+wi}]: RTL=0x{rtl_word:08x}  NIST=0x{nist_word:08x}  {match_str}")

        # Verify addRoundKeyOut against reference
        expected_ark = ref.expected_ark_rtl_int(state_int, rnd)
        ark_match    = "PASS" if ark_out == expected_ark else "FAIL"
        dut._log.info(f"  addRoundKeyOut: RTL=0x{ark_out:032x}  NIST=0x{expected_ark:032x}  {ark_match}")
        if ark_out != expected_ark:
            mismatches.append(f"Round {rnd} addRoundKeyOut mismatch")

    dut._log.info("\n" + "="*60)
    if mismatches:
        dut._log.warning(f"TC3: {len(mismatches)} mismatch(es) found:")
        for m in mismatches:
            dut._log.warning(f"  {m}")
        assert False, f"TC3 FAILED: {len(mismatches)} NIST reference mismatches"

    dut._log.info("TC3 PASSED — all 10 AES-128 rounds match NIST A.1")
    dut._log.info("="*60)


# TC4: AES-192 round 0
@cocotb.test()
async def tc4_aes192_round0(dut):
    """TC4: AES-192 round 0 — state XOR first 4 of 6 master key words."""
    dut._log.info("=" * 60)
    dut._log.info("TC4: AES-192 round 0")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)

    key_bytes = bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
    ref = AESReferenceModel(key_bytes)

    state_int      = plaintext_to_rtl_state(list(range(16)))
    master_key_int = ref.master_key_rtl_int()

    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_192
    dut.state.value          = state_int
    dut.master_key.value     = master_key_int
    dut.trng_dead_flag.value = 0

    assert int(dut.sbox_enb_n.value) == 1, "sbox_enb_n should be 1 for round 0"
    await ClockCycles(dut.clk, 2)

    # Round 0 for AES-192 uses w[0..3] (first 4 of 6 master key words)
    expected = ref.expected_ark_rtl_int(state_int, 0)
    actual   = int(dut.addRoundKeyOut.value)

    assert actual == expected, (
        f"AES-192 round 0 mismatch:\n"
        f"  Expected: 0x{expected:032x}\n"
        f"  Got:      0x{actual:032x}"
    )
    dut._log.info(f" addRoundKeyOut = 0x{actual:032x}")
    dut._log.info(" TC4 PASSED")


# TC5: AES-192 key expansion
@cocotb.test()
async def tc5_aes192_key_expansion(dut):
    """TC5: AES-192 key expansion — 12 rounds vs NIST A.2.

    AES-192 concat_sel bypass pattern (sbox_enb_n=1): rounds 2, 5, 8, 11 (rnd % 3 == 2).
    All other rounds trigger new key expansion (sbox_enb_n=0).
    """
    dut._log.info("=" * 60)
    dut._log.info("TC5: AES-192 key expansion (12 rounds)")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC5"))

    key_bytes = bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
    Nr = 12

    ref = AESReferenceModel(key_bytes)
    ref.dump_key_schedule(dut._log.info)

    state_int      = plaintext_to_rtl_state(list(range(16)))
    master_key_int = ref.master_key_rtl_int()

    # Round 0
    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_192
    dut.state.value          = state_int
    dut.master_key.value     = master_key_int
    dut.trng_dead_flag.value = 0
    await ClockCycles(dut.clk, 2)
    dut._log.info("Round 0 done")

    mismatches = []

    for rnd in range(1, Nr + 1):
        dut._log.info(f"--- Round {rnd} ---")
        dut.round_num.value = rnd
        await RisingEdge(dut.clk)

        enb = int(dut.sbox_enb_n.value)

        # Bypass rounds: concat_sel=2'b11 → rounds 2, 5, 8, 11 (rnd % 3 == 2)
        is_bypass = (rnd % 3 == 2)

        if is_bypass:
            assert enb == 1, f"Round {rnd}: expected sbox_enb_n=1 (bypass), got {enb}"
            dut._log.info(f"  Bypass round — sbox_enb_n=1")
            # One clock sufficient: addRoundKeyOut updates at next rising edge
            await RisingEdge(dut.clk)
        else:
            assert enb == 0, f"Round {rnd}: expected sbox_enb_n=0 (compute), got {enb}"
            cyc = await wait_sbox_done(dut)
            dut._log.info(f"  Compute round — sbox_done after {cyc} cycles")
            await RisingEdge(dut.clk)

        # Compare addRoundKeyOut against NIST reference
        expected = ref.expected_ark_rtl_int(state_int, rnd)
        actual   = int(dut.addRoundKeyOut.value)

        if actual != expected:
            mismatches.append(
                f"Round {rnd}: RTL=0x{actual:032x}  NIST=0x{expected:032x}"
            )
            dut._log.warning(f"  MISMATCH: RTL=0x{actual:032x}  NIST=0x{expected:032x}")
        else:
            nist_rk = ref.get_round_key_words(rnd)
            dut._log.info(f"  addRoundKeyOut matches NIST (using w[{4*rnd}..{4*rnd+3}])")

    if mismatches:
        dut._log.warning(f"TC5: {len(mismatches)} output mismatch(es):")
        for m in mismatches:
            dut._log.warning(f"  {m}")
        assert False, f"TC5 FAILED: {len(mismatches)} NIST output mismatches"

    dut._log.info(" TC5 PASSED — all 12 AES-192 rounds match NIST A.2")


# TC6: AES-256 round 0
@cocotb.test()
async def tc6_aes256_round0(dut):
    """TC6: AES-256 round 0 — state XOR first 4 of 8 master key words."""
    dut._log.info("=" * 60)
    dut._log.info("TC6: AES-256 round 0")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)

    key_bytes = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dfe4")
    ref = AESReferenceModel(key_bytes)

    state_int      = plaintext_to_rtl_state(list(range(16)))
    master_key_int = ref.master_key_rtl_int()

    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_256
    dut.state.value          = state_int
    dut.master_key.value     = master_key_int
    dut.trng_dead_flag.value = 0

    assert int(dut.sbox_enb_n.value) == 1, "sbox_enb_n should be 1 for round 0"
    await ClockCycles(dut.clk, 2)

    expected = ref.expected_ark_rtl_int(state_int, 0)
    actual   = int(dut.addRoundKeyOut.value)

    assert actual == expected, (
        f"AES-256 round 0 mismatch:\n"
        f"  Expected: 0x{expected:032x}\n"
        f"  Got:      0x{actual:032x}"
    )
    dut._log.info(f" addRoundKeyOut = 0x{actual:032x}")
    dut._log.info(" TC6 PASSED")


# TC7: AES-256 key expansion
@cocotb.test()
async def tc7_aes256_key_expansion(dut):
    """TC7: AES-256 key expansion — 14 rounds vs NIST A.3.
    Even rounds: SubWord(RotWord) + Rcon for first 4 words.
    Odd rounds:  SubWord only for last 4 words. Sbox always active (no bypass)."""
    dut._log.info("=" * 60)
    dut._log.info("TC7: AES-256 key expansion (14 rounds)")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC7"))

    key_bytes = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dfe4")
    Nr = 14

    ref = AESReferenceModel(key_bytes)
    ref.dump_key_schedule(dut._log.info)

    state_int      = plaintext_to_rtl_state(list(range(16)))
    master_key_int = ref.master_key_rtl_int()

    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_256
    dut.state.value          = state_int
    dut.master_key.value     = master_key_int
    dut.trng_dead_flag.value = 0
    await ClockCycles(dut.clk, 2)

    mismatches = []

    for rnd in range(1, Nr + 1):
        parity = "even" if rnd % 2 == 0 else "odd"
        dut._log.info(f"--- Round {rnd} ({parity}) ---")
        dut.round_num.value = rnd

        cyc = await wait_sbox_done(dut)
        dut._log.info(f"  sbox_done after {cyc} cycles")
        await RisingEdge(dut.clk)

        # Compare addRoundKeyOut against NIST reference
        expected = ref.expected_ark_rtl_int(state_int, rnd)
        actual   = int(dut.addRoundKeyOut.value)

        if actual != expected:
            mismatches.append(
                f"Round {rnd} ({parity}): RTL=0x{actual:032x}  NIST=0x{expected:032x}"
            )
            dut._log.warning(f"  MISMATCH: RTL=0x{actual:032x}  NIST=0x{expected:032x}")
        else:
            dut._log.info(f"  Round {rnd} output matches NIST (w[{4*rnd}..{4*rnd+3}])")

    if mismatches:
        assert False, f"TC7 FAILED:\n" + "\n".join(mismatches)

    dut._log.info(" TC7 PASSED — all 14 AES-256 rounds match NIST A.3")


# TC8: Sbox gating — registers stable until sbox_done
@cocotb.test()
async def tc8_sbox_gating(dut):
    """TC8: prev_expKey and addRoundKeyOut must not change before sbox_done asserts."""
    dut._log.info("=" * 60)
    dut._log.info("TC8: Register gating by sbox_done")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)

    key_bytes = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    ref = AESReferenceModel(key_bytes)

    state_int      = plaintext_to_rtl_state(list(range(16)))
    master_key_int = ref.master_key_rtl_int()

    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_128
    dut.state.value          = state_int
    dut.master_key.value     = master_key_int
    dut.trng_dead_flag.value = 0
    await ClockCycles(dut.clk, 2)

    out_r0 = int(dut.addRoundKeyOut.value)
    ek_r0  = int(dut.prev_expKey.value)
    dut._log.info(f"  Round 0 snapshot: addRoundKeyOut=0x{out_r0:032x}")

    # Transition to round 1 — sbox enables, but registers must hold until sbox_done
    dut.round_num.value = 1
    stable_cycles = 0
    for _ in range(SBOX_LATENCY - 1):
        await RisingEdge(dut.clk)
        if int(dut.sbox_done.value) == 1:
            break
        cur_out = int(dut.addRoundKeyOut.value)
        cur_ek  = int(dut.prev_expKey.value)
        if cur_out == out_r0 and cur_ek == ek_r0:
            stable_cycles += 1
        else:
            assert False, (
                f"Register changed before sbox_done at cycle {stable_cycles+1}:\n"
                f"  addRoundKeyOut: was 0x{out_r0:032x} now 0x{cur_out:032x}\n"
                f"  prev_expKey:    was 0x{ek_r0:064x} now 0x{cur_ek:064x}"
            )

    dut._log.info(f" Registers stable for {stable_cycles} pre-sbox_done cycles")

    # After sbox_done + 1 clock, registers must update
    cyc = await wait_sbox_done(dut)
    await RisingEdge(dut.clk)

    out_r1 = int(dut.addRoundKeyOut.value)
    assert out_r1 != out_r0, "addRoundKeyOut did not update after sbox_done"
    dut._log.info(f" addRoundKeyOut updated after sbox_done: 0x{out_r1:032x}")

    # Verify sbox_done was a single-cycle pulse
    sd_now = int(dut.sbox_done.value)
    assert sd_now == 0, f"sbox_done should be 0 one cycle after pulse, got {sd_now}"
    dut._log.info(" sbox_done is a single-cycle pulse")

    dut._log.info(" TC8 PASSED")


# TC9: TRNG dead flag → rst_trng
@cocotb.test()
async def tc9_trng_dead_flag(dut):
    """TC9: Assert trng_dead_flag mid-sbox computation; verify rst_trng asserts."""
    dut._log.info("=" * 60)
    dut._log.info("TC9: TRNG dead flag → rst_trng")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)

    key_bytes = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    ref = AESReferenceModel(key_bytes)

    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_128
    dut.state.value          = 0
    dut.master_key.value     = ref.master_key_rtl_int()
    dut.trng_dead_flag.value = 0
    await ClockCycles(dut.clk, 2)

    # Start round 1 (sbox enabled), inject dead flag after 2 cycles
    dut.round_num.value = 1
    await ClockCycles(dut.clk, 2)

    dut.trng_dead_flag.value = 1
    dut._log.info("trng_dead_flag asserted")

    rst_asserted = False
    for i in range(10):
        await RisingEdge(dut.clk)
        if int(dut.rst_trng.value) == 1:
            dut._log.info(f" rst_trng asserted after {i+1} cycles")
            rst_asserted = True
            break

    assert rst_asserted, "TIMEOUT: rst_trng never asserted after trng_dead_flag"

    dut.trng_dead_flag.value = 0
    await ClockCycles(dut.clk, 2)

    rst_now = int(dut.rst_trng.value)
    dut._log.info(f"  rst_trng after flag clear: {rst_now}")

    dut._log.info(" TC9 PASSED")


# TC10: RCON table values
@cocotb.test()
async def tc10_rcon_check(dut):
    """TC10: Verify RCON[4] = 0x08000000 (NIST correct value).
    Uses all-zero key to isolate RCON effect in AES-128 round-4 expansion."""
    dut._log.info("=" * 60)
    dut._log.info("TC10: RCON table — RCON[4] verification")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)

    # All-zero key: w[4i] = SubWord(RotWord(0)) XOR RCON[i] = 0x63636363 XOR RCON[i]
    key_bytes = bytes(16)
    ref = AESReferenceModel(key_bytes)

    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_128
    dut.state.value          = 0
    dut.master_key.value     = 0
    dut.trng_dead_flag.value = 0
    await ClockCycles(dut.clk, 2)

    # Run through first 4 rounds to reach the RCON[4]-affected word w[16]
    for rnd in range(1, 5):
        dut.round_num.value = rnd
        await wait_sbox_done(dut)
        await RisingEdge(dut.clk)

    prev_ek  = int(dut.prev_expKey.value)
    rtl_w16  = get_expkey_word(prev_ek, 0)
    nist_w16 = ref.get_round_key_words(4)[0]  # w[16]

    dut._log.info(f"  After round 4: RTL w[16]=0x{rtl_w16:08x}  NIST w[16]=0x{nist_w16:08x}")

    if rtl_w16 == nist_w16:
        dut._log.info(f" w[16] matches NIST — RCON[4]=0x{RCON[4]:08x} is correct")
    else:
        assert False, (
            f"TC10 FAILED: RCON[4] value mismatch.\n"
            f"  RTL w[16]=0x{rtl_w16:08x}  NIST w[16]=0x{nist_w16:08x}\n"
            f"  Expected RCON[4] = 0x{RCON[4]:08x}"
        )

    dut._log.info(" TC10 PASSED")


# TC11: All-zero key
@cocotb.test()
async def tc11_all_zero_key(dut):
    """TC11: All-zero key — round 0 output == state, Sbox still fires for round 1."""
    dut._log.info("=" * 60)
    dut._log.info("TC11: All-zero key edge case")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)

    pt_bytes  = [0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
                 0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34]
    state_int = plaintext_to_rtl_state(pt_bytes)

    ref = AESReferenceModel(bytes(16))  # all-zero key

    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_128
    dut.state.value          = state_int
    dut.master_key.value     = 0
    dut.trng_dead_flag.value = 0
    await ClockCycles(dut.clk, 2)

    # Round 0: XOR with all-zero key = state itself
    expected = ref.expected_ark_rtl_int(state_int, 0)
    actual   = int(dut.addRoundKeyOut.value)
    assert actual == expected, (
        f"Zero key round 0: expected=0x{expected:032x} got=0x{actual:032x}"
    )
    assert actual == state_int, "With zero key round 0 output should equal state"
    dut._log.info(" Round 0 with zero key: addRoundKeyOut == state")

    # Round 1: Sbox must still fire (SubWord(0) = 0x63 for all bytes)
    dut.round_num.value = 1
    cyc = await wait_sbox_done(dut)
    dut._log.info(f" sbox_done after {cyc} cycles (Sbox active with zero key)")

    await RisingEdge(dut.clk)
    out_r1 = int(dut.addRoundKeyOut.value)
    dut._log.info(f"  Round 1 output: 0x{out_r1:032x}")

    assert out_r1 != 0, "Round 1 with zero key should produce non-zero output"
    dut._log.info(" Round 1 output non-zero (Sbox active)")

    dut._log.info(" TC11 PASSED")


# TC12: All-ones key
@cocotb.test()
async def tc12_all_ones_key(dut):
    """TC12: All-ones key — verify no stuck-at behavior."""
    dut._log.info("=" * 60)
    dut._log.info("TC12: All-ones key edge case")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)

    key_ff = bytes([0xFF]*16)
    ref    = AESReferenceModel(key_ff)

    state_int = 0  # all-zero state

    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_128
    dut.state.value          = state_int
    dut.master_key.value     = ref.master_key_rtl_int()
    dut.trng_dead_flag.value = 0
    await ClockCycles(dut.clk, 2)

    # Round 0: state=0 XOR 0xff...ff → output should be non-zero
    actual_r0 = int(dut.addRoundKeyOut.value)
    assert actual_r0 != 0, "Round 0 with 0xff key and zero state should not be zero"
    dut._log.info(f" Round 0 output: 0x{actual_r0:032x} (non-zero)")

    # Round 1: Sbox fires; output changes
    dut.round_num.value = 1
    cyc = await wait_sbox_done(dut)
    await RisingEdge(dut.clk)
    actual_r1 = int(dut.addRoundKeyOut.value)
    dut._log.info(f" Round 1 output after sbox_done ({cyc} cycles): 0x{actual_r1:032x}")

    assert actual_r1 != actual_r0, "Round 1 output should differ from round 0"
    dut._log.info(" TC12 PASSED")


# TC13: Sbox pipeline latency
@cocotb.test()
async def tc13_sbox_latency(dut):
    """TC13: Sbox pipeline must take exactly 6 clock cycles (TOWER_FIELD→SUB_BYTES)."""
    dut._log.info("=" * 60)
    dut._log.info("TC13: Sbox latency = exactly 6 cycles")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)

    key_bytes = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    ref = AESReferenceModel(key_bytes)

    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_128
    dut.state.value          = 0
    dut.master_key.value     = ref.master_key_rtl_int()
    dut.trng_dead_flag.value = 0
    await ClockCycles(dut.clk, 2)

    # Enable sbox (round_num = 1). Measure cycles until sbox_done.
    dut.round_num.value = 1
    await RisingEdge(dut.clk)  # cycle where sbox_enb_n → 0

    measured = 0
    for _ in range(SBOX_TIMEOUT):
        await RisingEdge(dut.clk)
        measured += 1
        if int(dut.sbox_done.value) == 1:
            break
    else:
        assert False, f"sbox_done never asserted within {SBOX_TIMEOUT} cycles"

    dut._log.info(f"  Measured sbox latency: {measured} cycles")
    assert measured == SBOX_LATENCY, (
        f"Expected sbox latency = {SBOX_LATENCY}, got {measured}"
    )
    dut._log.info(f" Sbox latency = {measured} cycles (correct)")
    dut._log.info(" TC13 PASSED")


# TC14: Per-round key comparison — same stimulus, both RTL and reference
@cocotb.test()
async def tc14_per_round_key_comparison_aes128(dut):
    """TC14: AES-128 per-round key expansion comparison.

    Drives the DUT and reference model with identical random stimulus (rand_num)
    and compares generated key words (prev_expKey) at each round against NIST reference.
    This validates that RTL key expansion matches NIST across all cipher rounds.
    """
    dut._log.info("=" * 60)
    dut._log.info("TC14: AES-128 per-round key comparison (same stimulus)")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC14"))

    key_bytes = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    Nk, Nr = 4, 10
    ref = AESReferenceModel(key_bytes)

    state_int      = plaintext_to_rtl_state(list(bytes.fromhex("046681e5e0cb199a48f8d37a2806264c")))
    master_key_int = ref.master_key_rtl_int()

    dut._log.info(f"Reference model: AES-{len(key_bytes)*8} (Nk={Nk}, Nr={Nr})")
    ref.dump_key_schedule(dut._log.info)

    # Round 0: load master key
    dut._log.info("\n=== Round 0: Master Key Loading ===")
    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_128
    dut.state.value          = state_int
    dut.master_key.value     = master_key_int
    dut.trng_dead_flag.value = 0
    await ClockCycles(dut.clk, 2)

    prev_ek_r0 = int(dut.prev_expKey.value)
    dut._log.info("Round 0: Verifying master key in prev_expKey")
    for wi in range(Nk):
        rtl_word  = get_expkey_word(prev_ek_r0, wi)
        nist_word = ref.get_round_key_words(0)[wi]
        match = "✓" if rtl_word == nist_word else "✗"
        dut._log.info(f"  w[{wi}]: RTL=0x{rtl_word:08x}  NIST=0x{nist_word:08x}  {match}")
        assert rtl_word == nist_word, f"Round 0 w[{wi}] mismatch"

    # Rounds 1-10: compare key expansion with reference model (same stimulus)
    dut._log.info("\n=== Rounds 1-10: Key Expansion with Controlled Stimulus ===")
    mismatches = []

    for rnd in range(1, Nr + 1):
        dut._log.info(f"\n--- Round {rnd} ---")
        dut.round_num.value = rnd
        await RisingEdge(dut.clk)

        cyc = await wait_sbox_done(dut)
        await RisingEdge(dut.clk)

        prev_ek = int(dut.prev_expKey.value)
        nist_rk = ref.get_round_key_words(rnd)

        dut._log.info(f"  Sbox completed in {cyc} cycles")
        dut._log.info(f"  Comparing prev_expKey words with reference model round {rnd}:")

        for wi in range(Nk):
            rtl_word  = get_expkey_word(prev_ek, wi)
            nist_word = nist_rk[wi]
            match = "✓" if rtl_word == nist_word else "✗"
            dut._log.info(f"    w[{Nk*rnd+wi}]: RTL=0x{rtl_word:08x}  NIST=0x{nist_word:08x}  {match}")

            if rtl_word != nist_word:
                mismatches.append(f"Round {rnd} w[{Nk*rnd+wi}]: RTL=0x{rtl_word:08x} vs NIST=0x{nist_word:08x}")

    dut._log.info("\n" + "=" * 60)
    if mismatches:
        dut._log.warning(f"TC14: {len(mismatches)} key mismatch(es):")
        for m in mismatches:
            dut._log.warning(f"  {m}")
        assert False, f"TC14 FAILED: {len(mismatches)} key mismatches"

    dut._log.info("TC14 PASSED — AES-128 key expansion matches reference model")
    dut._log.info("=" * 60)


@cocotb.test()
async def tc15_per_round_key_comparison_aes192(dut):
    """TC15: AES-192 per-round key expansion comparison (same stimulus).

    Validates AES-192 key expansion against NIST A.2, including bypass rounds.
    Compares both key words and addRoundKeyOut at each cipher round.
    """
    dut._log.info("=" * 60)
    dut._log.info("TC15: AES-192 per-round key comparison (same stimulus)")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC15"))

    key_bytes = bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
    Nk, Nr = 6, 12
    ref = AESReferenceModel(key_bytes)

    state_int      = plaintext_to_rtl_state(list(range(16)))
    master_key_int = ref.master_key_rtl_int()

    dut._log.info(f"Reference model: AES-{len(key_bytes)*8} (Nk={Nk}, Nr={Nr})")
    dut._log.info("Note: AES-192 has bypass rounds (2,5,8,11) where sbox_enb_n=1")

    # Round 0
    dut._log.info("\n=== Round 0: Master Key Loading ===")
    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_192
    dut.state.value          = state_int
    dut.master_key.value     = master_key_int
    dut.trng_dead_flag.value = 0
    await ClockCycles(dut.clk, 2)

    prev_ek_r0 = int(dut.prev_expKey.value)
    dut._log.info("Round 0: Verifying 6 master key words")
    for wi in range(Nk):
        rtl_word  = get_expkey_word(prev_ek_r0, wi)
        nist_word = ref.get_round_key_words(0)[wi]
        match = "✓" if rtl_word == nist_word else "✗"
        dut._log.info(f"  w[{wi}]: RTL=0x{rtl_word:08x}  NIST=0x{nist_word:08x}  {match}")
        assert rtl_word == nist_word, f"Round 0 w[{wi}] mismatch"

    # Rounds 1-12: key expansion with bypass pattern
    dut._log.info("\n=== Rounds 1-12: Key Expansion with Bypass Rounds ===")
    mismatches = []

    for rnd in range(1, Nr + 1):
        is_bypass = (rnd % 3 == 2)
        dut._log.info(f"\n--- Round {rnd} {'(BYPASS)' if is_bypass else '(COMPUTE)'} ---")
        dut.round_num.value = rnd
        await RisingEdge(dut.clk)

        if is_bypass:
            dut._log.info("  Bypass round: sbox disabled, registers hold")
            await RisingEdge(dut.clk)
        else:
            cyc = await wait_sbox_done(dut)
            dut._log.info(f"  Compute round: sbox_done after {cyc} cycles")
            await RisingEdge(dut.clk)

        prev_ek = int(dut.prev_expKey.value)
        ark_out = int(dut.addRoundKeyOut.value)
        nist_rk = ref.get_round_key_words(rnd)
        expected_ark = ref.expected_ark_rtl_int(state_int, rnd)

        dut._log.info(f"  Comparing {Nk} key words:")
        for wi in range(Nk):
            rtl_word  = get_expkey_word(prev_ek, wi)
            nist_word = nist_rk[wi]
            match = "✓" if rtl_word == nist_word else "✗"
            dut._log.info(f"    w[{Nk*rnd+wi:2d}]: RTL=0x{rtl_word:08x}  NIST=0x{nist_word:08x}  {match}")

            if rtl_word != nist_word:
                mismatches.append(f"Round {rnd} w[{Nk*rnd+wi}]: RTL=0x{rtl_word:08x} vs NIST=0x{nist_word:08x}")

        ark_match = "✓" if ark_out == expected_ark else "✗"
        dut._log.info(f"  addRoundKeyOut: RTL=0x{ark_out:032x}  NIST=0x{expected_ark:032x}  {ark_match}")
        if ark_out != expected_ark:
            mismatches.append(f"Round {rnd} addRoundKeyOut: RTL=0x{ark_out:032x} vs NIST=0x{expected_ark:032x}")

    dut._log.info("\n" + "=" * 60)
    if mismatches:
        dut._log.warning(f"TC15: {len(mismatches)} mismatch(es):")
        for m in mismatches:
            dut._log.warning(f"  {m}")
        assert False, f"TC15 FAILED: {len(mismatches)} mismatches"

    dut._log.info("TC15 PASSED — AES-192 key expansion matches reference model")
    dut._log.info("=" * 60)


@cocotb.test()
async def tc16_per_round_key_comparison_aes256(dut):
    """TC16: AES-256 per-round key expansion comparison (same stimulus).

    Validates AES-256 key expansion against NIST A.3. AES-256 has no bypass rounds;
    sbox is active on all cipher rounds. Even and odd rounds use different key patterns.
    """
    dut._log.info("=" * 60)
    dut._log.info("TC16: AES-256 per-round key comparison (same stimulus)")
    dut._log.info("=" * 60)

    start_clock(dut)
    cocotb.start_soon(trng_model(dut))
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC16"))

    key_bytes = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dfe4")
    Nk, Nr = 8, 14
    ref = AESReferenceModel(key_bytes)

    state_int      = plaintext_to_rtl_state(list(range(16)))
    master_key_int = ref.master_key_rtl_int()

    dut._log.info(f"Reference model: AES-{len(key_bytes)*8} (Nk={Nk}, Nr={Nr})")
    dut._log.info("Note: AES-256 has no bypass; sbox active all rounds (even and odd)")

    # Round 0
    dut._log.info("\n=== Round 0: Master Key Loading ===")
    dut.round_num.value      = 0
    dut.key_size.value       = KEY_SIZE_256
    dut.state.value          = state_int
    dut.master_key.value     = master_key_int
    dut.trng_dead_flag.value = 0
    await ClockCycles(dut.clk, 2)

    prev_ek_r0 = int(dut.prev_expKey.value)
    dut._log.info("Round 0: Verifying 8 master key words")
    for wi in range(Nk):
        rtl_word  = get_expkey_word(prev_ek_r0, wi)
        nist_word = ref.get_round_key_words(0)[wi]
        match = "✓" if rtl_word == nist_word else "✗"
        dut._log.info(f"  w[{wi}]: RTL=0x{rtl_word:08x}  NIST=0x{nist_word:08x}  {match}")
        assert rtl_word == nist_word, f"Round 0 w[{wi}] mismatch"

    # Rounds 1-14: key expansion (no bypass)
    dut._log.info("\n=== Rounds 1-14: Key Expansion (Sbox Always Active) ===")
    mismatches = []

    for rnd in range(1, Nr + 1):
        parity = "even" if rnd % 2 == 0 else "odd"
        dut._log.info(f"\n--- Round {rnd} ({parity}) ---")
        dut.round_num.value = rnd

        cyc = await wait_sbox_done(dut)
        dut._log.info(f"  Sbox completed in {cyc} cycles")
        await RisingEdge(dut.clk)

        prev_ek = int(dut.prev_expKey.value)
        ark_out = int(dut.addRoundKeyOut.value)
        nist_rk = ref.get_round_key_words(rnd)
        expected_ark = ref.expected_ark_rtl_int(state_int, rnd)

        if rnd % 2 == 0:
            dut._log.info(f"  Even round: comparing first 4 key words")
            num_words = 4
        else:
            dut._log.info(f"  Odd round: comparing last 4 key words")
            num_words = 4

        dut._log.info(f"  Comparing {num_words} key words:")
        for wi in range(Nk):
            rtl_word  = get_expkey_word(prev_ek, wi)
            nist_word = nist_rk[wi]
            match = "✓" if rtl_word == nist_word else "✗"
            dut._log.info(f"    w[{Nk*rnd+wi:2d}]: RTL=0x{rtl_word:08x}  NIST=0x{nist_word:08x}  {match}")

            if rtl_word != nist_word:
                mismatches.append(f"Round {rnd} w[{Nk*rnd+wi}]: RTL=0x{rtl_word:08x} vs NIST=0x{nist_word:08x}")

        ark_match = "✓" if ark_out == expected_ark else "✗"
        dut._log.info(f"  addRoundKeyOut: RTL=0x{ark_out:032x}  NIST=0x{expected_ark:032x}  {ark_match}")
        if ark_out != expected_ark:
            mismatches.append(f"Round {rnd} addRoundKeyOut: RTL=0x{ark_out:032x} vs NIST=0x{expected_ark:032x}")

    dut._log.info("\n" + "=" * 60)
    if mismatches:
        dut._log.warning(f"TC16: {len(mismatches)} mismatch(es):")
        for m in mismatches:
            dut._log.warning(f"  {m}")
        assert False, f"TC16 FAILED: {len(mismatches)} mismatches"

    dut._log.info("TC16 PASSED — AES-256 key expansion matches reference model")
    dut._log.info("=" * 60)
