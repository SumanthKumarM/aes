"""
Cocotb testbench for the AES forward-CIPHER datapath.

ONE TESTBENCH, TWO DUT FLAVORS
------------------------------
Both forward ciphers in this project implement the identical FIPS 197 CIPHER
procedure and share ShiftRows/MixColumns, so they share this testbench. The
flavor is auto-detected from COCOTB_TOPLEVEL at import time:

    make run_all block=cipher_top       -> "masked"    (cipher.sv via cipher_top.sv)
    make run_all block=unmasked_cipher  -> "unmasked"  (unmasked_cipher.sv)

                    | cipher_top (masked)            | unmasked_cipher
    ----------------+--------------------------------+---------------------------
    SubBytes        | masked composite-field SBox,   | plain 256-entry LUT,
                    | TRNG-fed, multi-cycle          | purely combinational
    AddRoundKey     | shared `addRoundKey` sibling;  | private `addRoundKey_AES256`
                    | borrows the shared SBox for    | with its own LUT SBox for
                    | KeyExpansion subWord           | KeyExpansion subWord
    Key sizes       | 128 / 192 / 256 (`key_size`)   | 256 ONLY (no `key_size` port)
    TRNG            | real `trng` instance driven by | none -- no `raw_rand_bit`,
                    | `raw_rand_bit`/`sampling_clk`  | no `sampling_clk`
    Round-FSM regs  | dut.CIPHER.{round_cntr,...}    | dut.{round_cntr,...} (top)

Everything the two flavors do NOT share is funnelled through the small adapter
layer below (`cipher_core`, `start_clocks`, `start_noise`, `reset_dut`,
`run_encryption`), so the test bodies themselves are flavor-agnostic. Tests that
need a key size the DUT cannot do are skipped rather than silently reinterpreted;
the two generic tests (back-to-back, random stimulus) run at the flavor's
GEN_KEY_BITS so both DUTs get that coverage.

Golden reference: a NIST FIPS 197 software model (key expansion + full
encryption with per-round intermediates). The model self-checks against the
FIPS 197 Appendix B / C.1 / C.2 / C.3 known-answer vectors at import time, so
any TB-side modeling mistake aborts the run before touching the DUT.

DUT interface notes:
  - cipher_top's TRNG is a real instance fed by raw_rand_bit (noise driver on
    sampling_clk). The cipher stalls its SubBytes rounds until trng_key_valid,
    so no explicit TRNG warm-up is needed -- just a generous timeout.
    unmasked_cipher has no TRNG at all: its SBox is a LUT, so it never stalls.
  - Both ciphers have an active-low enb_n: an ICG cell gates the cipher's own
    clock off entirely while enb_n=1, so the FSM makes no progress at all while
    parked (the power-saving pattern also used by invCipher.sv). enb_n=0 must be
    driven to start an encryption of whatever is on `state`/`master_key`
    (/`key_size` on cipher_top); after cipher_done the round counter wraps to 0
    and it starts over. Back-to-back encryption works by keeping enb_n=0 and
    swapping `state` after a done pulse.
  - reset_dut() leaves the DUT parked (enb_n=1, and key_size=2'b00 where that
    port exists); run_encryption() drives enb_n=0 to start.
  - On cipher_top only cipher_state/cipher_done are top-level ports (rand_num/
    sbox_ready/trng_key_valid/trng_dead_flag are internal wires of cipher_top,
    the same convention already used in addRoundKey_top). Verilator's
    --public-flat-rw still exposes internal signals directly by name, so
    dut.trng_key_valid / dut.trng_dead_flag below keep working unchanged.

RTL data representation (same convention the addRoundKey TB validated, and
identical for both flavors):
  - state_matrix_t = logic [3:0][3:0][7:0]: state[row][col] at bits (row*4+col)*8
  - Row convention: RTL row 3 = NIST row 0 (MSByte of a column word),
                    RTL row 0 = NIST row 3. Columns match NIST.
  - master_key packs NIST key-schedule word w[i] (big-endian bytes) at
    bits [32*i +: 32].

Diagnostics: run_encryption() traces the cipher's round_cntr and captures
temp_state at every round boundary, so a ciphertext mismatch is reported with
the first cipher round where the DUT diverged from the NIST reference.

Signal access notes (Verilator, --public-flat-rw):
  - dut.cipher_state, dut.cipher_done                       -- top level, both flavors
  - dut.trng_key_valid, dut.trng_dead_flag                  -- cipher_top only
  - cipher_core(dut).{round_cntr, temp_state, fsm_state}    -- dut.CIPHER.* on
    cipher_top, dut.* on unmasked_cipher
  - dut.ark_done, dut.ark_enb_n                             -- both flavors (wires of
    cipher_top / regs of unmasked_cipher)
  - dut.SBOX, dut.AddRoundKey -- sibling instances of CIPHER inside cipher_top
    (not currently probed by this TB, but available if a future test needs to
    inspect the shared SBox/AddRoundKey directly; note the ALL-CAPS "SBOX"
    instance name, distinct from addRoundKey_top's "SBox"). unmasked_cipher's
    private key-expansion block is dut.AddRoundKey (addRoundKey_AES256).
"""

import cocotb
import os
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

# key length in bytes -> key_size encoding on cipher_top's key_size port
KEY_SIZE_CODE = {16: KEY_SIZE_128, 24: KEY_SIZE_192, 32: KEY_SIZE_256}

_mon_log = logging.getLogger("cocotb.monitor")


# DUT flavor selection
#
# `skip=` on @cocotb.test() is evaluated when this module is imported, before
# any DUT handle exists, so the flavor has to come from the environment rather
# than from port probing. cocotb exports COCOTB_TOPLEVEL (TOPLEVEL in the
# pre-2.0 spelling) for exactly this. check_flavor() re-derives the flavor from
# the real DUT handle at the start of every test and fails loudly on a mismatch,
# so a stale/mis-set variable can never silently mis-configure the run.
MASKED   = "masked"    # cipher_top      : masked SBox + TRNG, AES-128/192/256
UNMASKED = "unmasked"  # unmasked_cipher : LUT SBox, no TRNG, AES-256 only

_UNMASKED_TOPLEVELS = {"unmasked_cipher"}

def _flavor_from_env():
    top = (os.environ.get("COCOTB_TOPLEVEL") or os.environ.get("TOPLEVEL") or "").strip()
    return UNMASKED if top in _UNMASKED_TOPLEVELS else MASKED

DUT_FLAVOR  = _flavor_from_env()
IS_UNMASKED = (DUT_FLAVOR == UNMASKED)

# Key sizes this DUT can actually be asked for. unmasked_cipher hard-wires
# Nr=14 and an AES-256-only key schedule (CBC-MAC / CTR_DRBG only ever need
# 256-bit encryption), so the 128/192 known-answer tests are skipped there.
SUPPORTED_KEY_BITS = (256,) if IS_UNMASKED else (128, 192, 256)

def supports(key_bits):
    return key_bits in SUPPORTED_KEY_BITS

# Key size used by the two flavor-agnostic tests (back-to-back and random
# stimulus). cipher_top keeps running those at AES-128 exactly as before;
# unmasked_cipher runs them at its only supported size.
GEN_KEY_BITS = 256 if IS_UNMASKED else 128
GEN_KEY = (bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
           if IS_UNMASKED else
           bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))

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
        # NIST SP 800-38A F.1.5 (AES-256 ECB) -- covers GEN_KEY on the unmasked flavor
        ("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
         "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8"),
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


# Noise source for the real TRNG instance (cipher_top only)
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


# DUT adapter layer -- everything the two flavors do differently lives here
def has_sig(handle, name):
    """True when `name` exists under `handle`. cocotb raises AttributeError for
    an unknown child, which is how the two port lists are told apart."""
    try:
        getattr(handle, name)
        return True
    except AttributeError:
        return False

def cipher_core(dut):
    """Handle to the module owning round_cntr / temp_state / fsm_state.

    On cipher_top the round FSM lives in the CIPHER child instance (SBox and
    AddRoundKey are its siblings, not its children, because invCipher shares
    them). unmasked_cipher is self-contained, so its FSM registers are on the
    toplevel handle itself."""
    return dut.CIPHER if has_sig(dut, "CIPHER") else dut

def check_flavor(dut):
    """Fail loudly if the import-time flavor disagrees with the real DUT.

    The `skip=` decisions on the key-size known-answer tests were already made
    from COCOTB_TOPLEVEL by the time any test body runs, so a mismatch here
    means the run is mis-configured (wrong TOPLEVEL, or cipher_tb pointed at an
    unexpected block) and every later result would be meaningless."""
    actual = MASKED if has_sig(dut, "key_size") else UNMASKED
    assert actual == DUT_FLAVOR, (
        f"DUT flavor mismatch: this run was configured for '{DUT_FLAVOR}' from "
        f"COCOTB_TOPLEVEL={os.environ.get('COCOTB_TOPLEVEL')!r}, but the DUT handle "
        f"looks like '{actual}' (key_size port {'present' if actual == MASKED else 'absent'}). "
        f"Check TOPLEVEL/block in the Makefile invocation.")
    return actual

def start_clocks(dut):
    """Start clk, plus sampling_clk when the DUT embeds a TRNG."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, unit="ns").start())
    if has_sig(dut, "sampling_clk"):
        cocotb.start_soon(Clock(dut.sampling_clk, SCLK_PERIOD_NS, unit="ns").start())

def start_noise(dut, seed=None):
    """Start the raw_rand_bit noise driver; a no-op on the TRNG-less flavor."""
    if has_sig(dut, "raw_rand_bit"):
        cocotb.start_soon(noise_driver(dut, seed=seed))

async def reset_dut(dut):
    """Reset and park the DUT: enb_n=1 (disabled), and key_size=2'b00 where the
    port exists.

    enb_n=0 is held DURING the reset pulse (not just rst_n=0), then raised to
    1 the same cycle rst_n deasserts. The cipher's own registers -- round_cntr,
    temp_state, fsm_state, ark_enb_n, etc. -- only update on its ICG-gated
    clock. Both ciphers fold ~rst_n into that ICG enable so the clock does run
    during reset regardless, but a previous test can leave the cipher enabled
    mid-computation (TC1 deliberately parks partway through, to test the enable
    gate itself), so enabling during the reset pulse guarantees the clear is
    applied before the DUT is parked, without depending on that ICG detail.
    """
    dut.rst_n.value        = 0
    dut.state.value        = 0
    dut.master_key.value   = 0
    if has_sig(dut, "key_size"):
        dut.key_size.value = 0   # parks the cipher in round 0 after reset
    dut.enb_n.value        = 0   # briefly enabled so the gated clock ticks during reset
    if has_sig(dut, "raw_rand_bit"):
        dut.raw_rand_bit.value = 0
    await ClockCycles(dut.clk, RESET_CYCLES)
    dut.rst_n.value = 1
    dut.enb_n.value = 1  # park the DUT now that the reset has actually applied
    await RisingEdge(dut.clk)
    dut._log.info(f"DUT reset complete ({DUT_FLAVOR} flavor; parked: enb_n=1"
                  f"{', key_size=0' if has_sig(dut, 'key_size') else ''})")


async def signal_monitor(dut, label=""):
    """Log cipher FSM / round transitions (low-volume debug aid)."""
    pfx = f"[MON {label}]" if label else "[MON]"
    core = cipher_core(dut)
    trng = has_sig(dut, "trng_key_valid")

    def snap():
        s = {
            "round_cntr"  : int(core.round_cntr.value),
            "fsm_state"   : int(core.fsm_state.value),
            "cipher_done" : int(dut.cipher_done.value),
            "ark_done"    : int(dut.ark_done.value),
        }
        if trng:
            s["trng_key_valid"] = int(dut.trng_key_valid.value)
            s["trng_dead_flag"] = int(dut.trng_dead_flag.value)
        return s

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


async def bringup(dut, seed, monitor_label=None):
    """Standard per-test bring-up: flavor check, clocks, noise, reset, monitor."""
    check_flavor(dut)
    start_clocks(dut)
    start_noise(dut, seed=seed)
    await reset_dut(dut)
    if monitor_label:
        cocotb.start_soon(signal_monitor(dut, label=monitor_label))


async def run_encryption(dut, key_bytes, pt_bytes, key_size_code=None,
                         timeout=ENCRYPT_TIMEOUT, already_running=False,
                         next_pt_bytes=None):
    """Drive one encryption and wait for cipher_done.

    Returns (ct_nist_bytes, model, trace, dut_round_trace) where
    dut_round_trace is a list of (round_cntr, temp_state_int) captured at every
    round boundary -- temp_state holds that round's addRoundKey output.

    key_size_code defaults to the encoding implied by len(key_bytes); it is only
    driven on DUTs that actually have a key_size port (unmasked_cipher hard-wires
    AES-256, so it has none). Asking a DUT for an unsupported size is rejected
    here rather than silently producing a bogus mismatch downstream.

    If already_running (back-to-back test), only `state` is updated; the DUT
    picks it up when its internal round counter wraps to 0.

    next_pt_bytes: for chaining a second back-to-back block. The cipher samples
    `state` into `ark_state` on essentially every cycle round_cntr==0 is
    active, starting the very cycle round_cntr wraps -- reacting to
    cipher_done and only then driving the next plaintext lands one cycle too
    late for that first sample. If given, this drives `state` proactively the
    cycle round_cntr first reaches Nr (the final round), well before
    cipher_done, so it's already settled by the time round_cntr wraps.
    """
    key_bits = len(key_bytes) * 8
    assert supports(key_bits), (
        f"AES-{key_bits} requested but the '{DUT_FLAVOR}' DUT only supports "
        f"{'/'.join(str(k) for k in SUPPORTED_KEY_BITS)}-bit keys")
    if key_size_code is None:
        key_size_code = KEY_SIZE_CODE[len(key_bytes)]

    model = AESEncryptModel(key_bytes)
    ct_expect, trace = model.encrypt_trace(list(pt_bytes))
    core = cipher_core(dut)

    # Present the plaintext BEFORE the start condition: the cipher's round-0
    # handshake raises ark_done one cycle after it is enabled, and the
    # addRoundKey input register (ark_state) needs a cycle to pick up `state`.
    dut.state.value = nist_bytes_to_rtl_state(list(pt_bytes))
    if not already_running:
        await ClockCycles(dut.clk, 2)
        dut.master_key.value = model.master_key_rtl_int()
        if has_sig(dut, "key_size"):
            dut.key_size.value = key_size_code
        dut.enb_n.value = 0

    dut_rounds = []
    prev_round = int(core.round_cntr.value)
    next_state_driven = next_pt_bytes is None
    for _ in range(timeout):
        await RisingEdge(dut.clk)
        cur_round = int(core.round_cntr.value)
        if cur_round != prev_round:
            # temp_state just captured round prev_round's addRoundKey output
            dut_rounds.append((prev_round, int(core.temp_state.value)))
            prev_round = cur_round
        if not next_state_driven and cur_round == model.Nr:
            dut.state.value = nist_bytes_to_rtl_state(list(next_pt_bytes))
            next_state_driven = True
        if int(dut.cipher_done.value) == 1:
            ct_rtl = int(dut.cipher_state.value)
            return rtl_state_to_nist_bytes(ct_rtl), model, trace, dut_rounds

    extra = ""
    if has_sig(dut, "trng_key_valid"):
        extra = (f", trng_key_valid={int(dut.trng_key_valid.value)}"
                 f", trng_dead_flag={int(dut.trng_dead_flag.value)}")
    raise AssertionError(
        f"TIMEOUT ({timeout} cycles): cipher_done never asserted "
        f"(round_cntr={int(core.round_cntr.value)}, "
        f"fsm_state={int(core.fsm_state.value)}, "
        f"enb_n={int(dut.enb_n.value)}{extra})")


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


def check_ct(dut, what, ct_dut, model, trace, dut_rounds):
    """Compare a DUT ciphertext against the model, dumping the per-round trace
    on mismatch before failing."""
    ct_ref = trace[-1]["after_ark"]
    dut._log.info(f"  {what}: DUT={hexs(ct_dut)}  NIST={hexs(ct_ref)}")
    if ct_dut != ct_ref:
        report_round_divergence(dut, model, trace, dut_rounds)
        raise AssertionError(
            f"{what} ciphertext mismatch: DUT={hexs(ct_dut)} NIST={hexs(ct_ref)}")


# TC1: Reset, enable gating & (masked only) TRNG liveness
@cocotb.test()
async def tc1_reset_and_liveness(dut):
    """TC1: outputs are zero after reset and the cipher stays parked while
    enb_n=1. Once the cipher is actually enabled -- as any real controller
    driving this AES engine would do -- it comes alive: on cipher_top the
    embedded TRNG starts up on its own (noise source -> health tests -> Keccak)
    and trng_key_valid asserts; on unmasked_cipher there is no TRNG, so liveness
    is the round counter leaving round 0. The cipher is then parked again.

    Note: the cipher's own clock is gated off entirely while enb_n=1 (an ICG
    cell, the same power-saving pattern used by invCipher.sv), so the FSM --
    and, on cipher_top, the shared SBox it would otherwise drive -- makes no
    progress in that state. That's expected: a power-gated block making no
    progress while nothing enables it isn't a bug, it's the point of the
    gating. So liveness is checked during actual operation, not while
    deliberately parked. (Same reasoning as invCipher_tb's TC1.)
    """
    dut._log.info("=" * 60)
    dut._log.info(f"TC1: Reset behavior + liveness ({DUT_FLAVOR} cipher)")
    dut._log.info("=" * 60)

    await bringup(dut, seed=1001)
    core = cipher_core(dut)

    assert int(dut.cipher_state.value) == 0, \
        f"cipher_state not zero after reset: 0x{int(dut.cipher_state.value):032x}"
    assert int(dut.cipher_done.value) == 0, "cipher_done not zero after reset"
    dut._log.info(" cipher_state = 0 and cipher_done = 0 after reset")

    # enb_n=1 parks the cipher: no done pulse may ever appear, round_cntr stays 0
    await ClockCycles(dut.clk, 20)
    assert int(dut.cipher_done.value) == 0, \
        "cipher_done asserted while cipher is disabled (enb_n=1)"
    assert int(core.round_cntr.value) == 0, \
        "cipher advanced past round 0 while disabled (enb_n=1)"
    dut._log.info(" cipher stays parked while enb_n=1")

    # Now actually enable the cipher (a real controller would do this to use
    # the AES engine) and confirm it comes alive.
    key = GEN_KEY
    model = AESEncryptModel(key)
    dut.master_key.value = model.master_key_rtl_int()
    dut.state.value      = nist_bytes_to_rtl_state(list(bytes.fromhex(
        "3243f6a8885a308d313198a2e0370734")))
    if has_sig(dut, "key_size"):
        dut.key_size.value = KEY_SIZE_CODE[len(key)]
    dut.enb_n.value = 0
    dut._log.info(f" cipher enabled (enb_n=0, AES-{GEN_KEY_BITS}) -- waiting for liveness")

    if has_sig(dut, "trng_key_valid"):
        for i in range(20000):
            await RisingEdge(dut.clk)
            if int(dut.trng_key_valid.value) == 1:
                dut._log.info(f" trng_key_valid asserted after {i+1} cycles")
                break
        else:
            raise AssertionError("TIMEOUT: trng_key_valid never asserted (20000 cycles)")
        assert int(dut.trng_dead_flag.value) == 0, "trng_dead_flag asserted with live noise"
    else:
        # No TRNG to wait on: the LUT SBox never stalls, so the round FSM must
        # start advancing within a handful of cycles of being enabled.
        for i in range(100):
            await RisingEdge(dut.clk)
            if int(core.round_cntr.value) != 0:
                dut._log.info(f" round_cntr left round 0 after {i+1} cycles "
                              f"(now {int(core.round_cntr.value)})")
                break
        else:
            raise AssertionError(
                "TIMEOUT: round_cntr never left round 0 after enabling the cipher "
                "(100 cycles) -- the round FSM is not advancing")

    # Park the cipher again so TC1 leaves the engine in a clean disabled state
    dut.enb_n.value = 1
    if has_sig(dut, "key_size"):
        dut.key_size.value = 0
    await ClockCycles(dut.clk, 4)
    dut._log.info(" cipher parked again (enb_n=1)")
    dut._log.info(" TC1 PASSED")


# TC2: AES-128, FIPS 197 Appendix B vector
@cocotb.test(skip=not supports(128))
async def tc2_aes128_appendix_b(dut):
    """TC2: AES-128 known-answer test, FIPS 197 Appendix B.
    key=2b7e1516... pt=3243f6a8... → ct=3925841d02dc09fbdc118597196a0b32
    Skipped on unmasked_cipher (AES-256 only)."""
    dut._log.info("=" * 60)
    dut._log.info("TC2: AES-128 FIPS 197 Appendix B")
    dut._log.info("=" * 60)

    await bringup(dut, seed=2002, monitor_label="TC2")

    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt  = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    dut._log.info(f"  plaintext : {pt.hex()}")
    dut._log.info(f"  key       : {key.hex()}")

    check_ct(dut, "AES-128 Appendix B", *await run_encryption(dut, key, pt))
    dut._log.info(" TC2 PASSED")


# TC3: AES-128, FIPS 197 Appendix C.1 vector
@cocotb.test(skip=not supports(128))
async def tc3_aes128_c1(dut):
    """TC3: AES-128 known-answer test, FIPS 197 Appendix C.1
    (expect ct=69c4e0d86a7b0430d8cdb78070b4c55a).
    Skipped on unmasked_cipher (AES-256 only)."""
    dut._log.info("=" * 60)
    dut._log.info("TC3: AES-128 FIPS 197 Appendix C.1")
    dut._log.info("=" * 60)

    await bringup(dut, seed=3003, monitor_label="TC3")

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt  = bytes.fromhex("00112233445566778899aabbccddeeff")

    check_ct(dut, "AES-128 C.1", *await run_encryption(dut, key, pt))
    dut._log.info(" TC3 PASSED")


# TC4: AES-192, FIPS 197 Appendix C.2 vector
@cocotb.test(skip=not supports(192))
async def tc4_aes192_c2(dut):
    """TC4: AES-192 known-answer test, FIPS 197 Appendix C.2
    (expect ct=dda97ca4864cdfe06eaf70a0ec0d7191).
    Skipped on unmasked_cipher (AES-256 only)."""
    dut._log.info("=" * 60)
    dut._log.info("TC4: AES-192 FIPS 197 Appendix C.2")
    dut._log.info("=" * 60)

    await bringup(dut, seed=4004, monitor_label="TC4")

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
    pt  = bytes.fromhex("00112233445566778899aabbccddeeff")

    check_ct(dut, "AES-192 C.2", *await run_encryption(dut, key, pt))
    dut._log.info(" TC4 PASSED")


# TC5: AES-256, FIPS 197 Appendix C.3 vector
@cocotb.test(skip=not supports(256))
async def tc5_aes256_c3(dut):
    """TC5: AES-256 known-answer test, FIPS 197 Appendix C.3
    (expect ct=8ea2b7ca516745bfeafc49904b496089).
    Runs on both flavors -- this is the primary known-answer test for
    unmasked_cipher, which is AES-256 only."""
    dut._log.info("=" * 60)
    dut._log.info("TC5: AES-256 FIPS 197 Appendix C.3")
    dut._log.info("=" * 60)

    await bringup(dut, seed=5005, monitor_label="TC5")

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    pt  = bytes.fromhex("00112233445566778899aabbccddeeff")

    check_ct(dut, "AES-256 C.3", *await run_encryption(dut, key, pt))
    dut._log.info(" TC5 PASSED")


# TC6: back-to-back encryptions (same key)
@cocotb.test()
async def tc6_back_to_back(dut):
    """TC6: two consecutive encryptions without reset. After cipher_done the
    round counter wraps and the DUT re-encrypts whatever is on `state`; swap in
    a new plaintext and check the second ciphertext too.

    Runs at AES-128 on cipher_top and AES-256 on unmasked_cipher (GEN_KEY)."""
    dut._log.info("=" * 60)
    dut._log.info(f"TC6: Back-to-back AES-{GEN_KEY_BITS} encryptions")
    dut._log.info("=" * 60)

    await bringup(dut, seed=6006, monitor_label="TC6")

    key = GEN_KEY
    pt1 = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    pt2 = bytes.fromhex("00112233445566778899aabbccddeeff")

    check_ct(dut, "Block 1",
             *await run_encryption(dut, key, pt1, next_pt_bytes=pt2))

    # `state` for block 2 was already driven proactively (see next_pt_bytes
    # above) during block 1's final round -- the cipher samples `state` into
    # ark_state starting the very cycle round_cntr wraps, so reacting to
    # cipher_done here and driving state only now would be one cycle too late.
    check_ct(dut, "Block 2",
             *await run_encryption(dut, key, pt2, already_running=True))

    dut._log.info(" TC6 PASSED")


# TC7: random stimulus vs reference model
@cocotb.test()
async def tc7_random_vector(dut):
    """TC7: a random key/plaintext checked against the reference model.
    Runs at AES-128 on cipher_top and AES-256 on unmasked_cipher."""
    dut._log.info("=" * 60)
    dut._log.info(f"TC7: Random AES-{GEN_KEY_BITS} vector vs reference model")
    dut._log.info("=" * 60)

    await bringup(dut, seed=7007, monitor_label="TC7")

    rng = random.Random(0xAE5)
    key = bytes(rng.getrandbits(8) for _ in range(GEN_KEY_BITS // 8))
    pt  = bytes(rng.getrandbits(8) for _ in range(16))
    dut._log.info(f"  key: {key.hex()}  pt: {pt.hex()}")

    check_ct(dut, f"Random AES-{GEN_KEY_BITS}",
             *await run_encryption(dut, key, pt))
    dut._log.info(" TC7 PASSED")


# TC8: AES-256 random sweep -- several independent key/plaintext pairs
@cocotb.test(skip=not supports(256))
async def tc8_aes256_random_sweep(dut):
    """TC8: several independent AES-256 encryptions, each with a fresh random
    key and plaintext and a reset in between, checked against the reference
    model. AES-256 is the only mode unmasked_cipher implements (CBC-MAC and
    CTR_DRBG both need it), so this widens the key-schedule coverage well past
    the single Appendix C.3 vector -- in particular it exercises the i%8==0
    (RotWord+Rcon) and i%8==4 (SubWord-only) key-expansion branches with many
    different key words."""
    n_blocks = 4 if IS_UNMASKED else 2  # the masked SBox is far slower per round
    dut._log.info("=" * 60)
    dut._log.info(f"TC8: {n_blocks} random AES-256 vectors vs reference model")
    dut._log.info("=" * 60)

    # Clocks and the noise driver are started exactly once: cocotb kills a
    # test's tasks when it ends, but within one test a second Clock on dut.clk
    # would fight the first. Blocks after the first re-reset instead, which
    # parks the cipher and clears its round FSM before the next key is loaded.
    await bringup(dut, seed=8008, monitor_label="TC8")

    rng = random.Random(0x256AE5)
    for blk in range(n_blocks):
        if blk:
            await reset_dut(dut)
        key = bytes(rng.getrandbits(8) for _ in range(32))
        pt  = bytes(rng.getrandbits(8) for _ in range(16))
        dut._log.info(f"  [{blk}] key: {key.hex()}")
        dut._log.info(f"  [{blk}] pt : {pt.hex()}")
        check_ct(dut, f"Random AES-256 #{blk}",
                 *await run_encryption(dut, key, pt))

    dut._log.info(" TC8 PASSED")
