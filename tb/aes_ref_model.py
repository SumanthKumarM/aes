"""
Golden reference model for the AES top block (`aes.sv`) -- all five modes.

This module owns the *mode* layer only. The block cipher underneath it is
imported, never re-implemented: `AESEncryptModel` (FIPS 197 CIPHER + key
schedule) comes from cipher_tb.py and `AESDecryptModel` (FIPS 197 INVCIPHER)
from invCipher_tb.py, which is the same import-don't-copy rule cbc_mac_tb.py
and iv_gen_tb.py already follow. Adding a seventh copy of the S-box table to
this repo would be a step backwards.

WHICH NUMBER SPACE THIS MODEL WORKS IN
--------------------------------------
Everything here is a 128-bit Python int in *RTL port packing*, not a NIST byte
string. That is a deliberate choice, and the reason is CTR and CFB:

  * `aes.sv`'s 128-bit ports (`input_block`, `output_block`, `encCntxtIn`,
    `encCntxtOut`) are `u128_t`, but they are assigned straight into `cipherIn`
    and on into `cipher.sv`'s `state_matrix_t` port, so the bits on the wire are
    in state-matrix order: RTL row (3-r) holds NIST row r, i.e. NIST byte
    b[r + 4c] sits at bit ((3-r)*4 + c)*8. `nist_bytes_to_rtl_state()` is that
    permutation. (Confirmed empirically: driving a FIPS 197 C.1 vector through
    this packing reproduces the published ciphertext exactly.)

  * ECB, CBC and OFB only ever XOR and encrypt, and XOR commutes with a bit
    permutation, so for those three it would not matter which space we model in.
    CTR does not commute: `ctr_mode_cntr + 1` (aes.sv:682) is ordinary
    arithmetic on the *permuted* integer, so "increment the counter" means
    something different in the two spaces. CFB with a sub-128-bit segment is the
    same story -- `temp[(seg_cntr << 3) +: 8]` slices the permuted integer.

  So the model works in RTL space throughout and converts only at the edges,
  where a published NIST vector has to be compared. Mixing the two spaces
  per-mode would be the single easiest way to write a testbench that agrees with
  the DUT for the wrong reason.

KNOWN-ANSWER VECTORS
--------------------
NIST SP 800-38A Appendix F (F.1 ECB, F.2 CBC, F.3 CFB, F.4 OFB, F.5 CTR) for all
three key sizes, plus the FIPS 197 block vectors inherited from cipher_tb. None
of these existed anywhere in this repo before; the block-level TBs only ever had
raw-CIPHER vectors. `self_check()` runs the whole table at import time, so a
modelling mistake aborts the run before any DUT signal is touched.

SEGMENT / COUNTER CONVENTIONS TAKEN FROM THE RTL
------------------------------------------------
These are read out of `aes.sv` rather than out of SP 800-38A, because the RTL
defines them and the point of the model is to say what the RTL *should* produce
under its own stated algorithm:

  * CFB segment j occupies bits [s*j +: s] of the 128-bit word, ascending from
    the LSB (`temp[(7'(seg_cntr) << 3) +: 8]`, aes.sv:549-574). Segment 0 is
    therefore the *least* significant s bits, not the most significant.
  * CFB feedback shifts the register left by s and appends the new segment at
    the bottom: I(j+1) = ((I(j) << s) | c_j) mod 2**128 (aes.sv:520-528).
  * OFB feeds back the raw cipher output O(j), not the ciphertext (aes.sv:625).
  * CTR increments the whole 128-bit counter by 1 per block, mod 2**128
    (aes.sv:682).
  * Partial final blocks keep the *most significant* `valid_bits` bits and zero
    the rest: `& ({128{1'b1}} << (128 - valid_bits))` (aes.sv:637, 686).

Where the RTL's own convention differs from SP 800-38A's byte-stream ordering
(CFB with s < 128 is the notable one -- the standard segments a byte stream
MSB-first, the RTL segments a permuted word LSB-first) the difference is
recorded in `CFB_SEGMENT_ORDER_NOTE` and the affected KATs are marked, rather
than being quietly bent to match.
"""

from cipher_tb import (
    AESEncryptModel,
    nist_bytes_to_rtl_state,
    rtl_state_to_nist_bytes,
)
from invCipher_tb import AESDecryptModel

__all__ = [
    "MASK128", "KEY_SIZE_CODE", "MODE_CODE", "CFB_SEG_CODE", "CFB_SEG_BITS",
    "AesModeModel", "self_check",
    "SP800_38A_ECB", "SP800_38A_CBC", "SP800_38A_OFB", "SP800_38A_CTR",
    "SP800_38A_CFB128", "CFB_SEGMENT_ORDER_NOTE", "CTR_INCREMENT_NOTE",
    "nist_bytes_to_rtl_state", "rtl_state_to_nist_bytes",
    "hexs", "rtl_hex",
]

MASK128 = (1 << 128) - 1

# aes_interface encodings (rtl/aes.sv:31-55, 91-100)
KEY_SIZE_CODE = {128: 0b01, 192: 0b10, 256: 0b11}
MODE_CODE = {"ECB": 0b001, "CBC": 0b010, "CFB": 0b011, "OFB": 0b100, "CTR": 0b101}
CFB_SEG_CODE = {8: 0b001, 16: 0b010, 32: 0b011, 64: 0b100, 128: 0b101}
CFB_SEG_BITS = {v: k for k, v in CFB_SEG_CODE.items()}

CFB_SEGMENT_ORDER_NOTE = (
    "aes.sv segments a 128-bit block LSB-first over the state-matrix-permuted "
    "word (segment j = bits [s*j +: s]), whereas SP 800-38A segments a byte "
    "stream MSB-first. The two agree only for CFB128, where the segment is the "
    "whole block; for CFB8/16/32/64 the published F.3 vectors therefore cannot "
    "be applied directly and this model follows the RTL's own convention."
)

CTR_INCREMENT_NOTE = (
    "aes.sv:682 increments ctr_mode_cntr as a plain 128-bit integer, but that "
    "register is in state-matrix bit order, so +1 lands in what NIST calls byte "
    "b[3] rather than b[15]. SP 800-38A B.1's standard incrementing function "
    "increments the counter BLOCK in its natural byte order. Both give unique "
    "counters (the security property CTR actually needs), but they generate "
    "different sequences, so this CTR cannot interoperate with a standard peer "
    "given only encCntxtOut. AesModeModel.ctr(increment=...) selects which one."
)


def hexs(b16):
    """Byte sequence -> lowercase hex string."""
    return "".join(f"{b:02x}" for b in b16)


def rtl_hex(val):
    """128-bit RTL-packed int -> the NIST-order hex string it represents."""
    return hexs(rtl_state_to_nist_bytes(val & MASK128))


class AesModeModel:
    """Reference for one (key, mode) configuration, in RTL packing throughout.

    Every method takes and returns 128-bit ints exactly as they appear on
    `input_block` / `output_block` / `encCntxtIn` / `encCntxtOut`, so a test can
    compare against `int(dut.output_block.value)` with no further conversion.
    """

    def __init__(self, key_bytes):
        key_bytes = bytes(key_bytes)
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError(f"key must be 16/24/32 bytes, got {len(key_bytes)}")
        self.key = key_bytes
        self.key_bits = len(key_bytes) * 8
        self.key_size_code = KEY_SIZE_CODE[self.key_bits]
        self._enc = AESEncryptModel(key_bytes)
        self._dec = AESDecryptModel(key_bytes)

    # ---- master_key wire value -------------------------------------------
    @property
    def master_key_rtl(self):
        """`master_key` port value: NIST key word w[i] at bits [32*i +: 32]."""
        return self._enc.master_key_rtl_int()

    # ---- raw block cipher, RTL packing in and out ------------------------
    def encrypt_block(self, blk):
        """CIPHER(blk). Both sides are RTL-packed 128-bit ints."""
        return nist_bytes_to_rtl_state(
            self._enc.encrypt(rtl_state_to_nist_bytes(blk & MASK128)))

    def decrypt_block(self, blk):
        """INVCIPHER(blk). Both sides are RTL-packed 128-bit ints."""
        return nist_bytes_to_rtl_state(
            self._dec.decrypt(rtl_state_to_nist_bytes(blk & MASK128)))

    # ---- ECB (SP 800-38A 6.1) --------------------------------------------
    def ecb_encrypt(self, blocks):
        return [self.encrypt_block(p) for p in blocks]

    def ecb_decrypt(self, blocks):
        return [self.decrypt_block(c) for c in blocks]

    # ---- CBC (SP 800-38A 6.2) --------------------------------------------
    def cbc_encrypt(self, blocks, iv):
        """C(0) = E(P(0) ^ IV); C(j) = E(P(j) ^ C(j-1))."""
        out, prev = [], iv & MASK128
        for p in blocks:
            prev = self.encrypt_block((p ^ prev) & MASK128)
            out.append(prev)
        return out

    def cbc_decrypt(self, blocks, iv):
        """P(0) = D(C(0)) ^ IV; P(j) = D(C(j)) ^ C(j-1)."""
        out, prev = [], iv & MASK128
        for c in blocks:
            out.append((self.decrypt_block(c) ^ prev) & MASK128)
            prev = c & MASK128
        return out

    # ---- CFB (SP 800-38A 6.3, segmented per aes.sv) ----------------------
    def cfb_encrypt(self, blocks, iv, seg_bits):
        """One 128-bit block at a time, split into 128/seg_bits segments.

        Segment j is bits [seg_bits*j +: seg_bits] (LSB-first, see the module
        docstring), and the shift register takes the *ciphertext* segment:
        I(j+1) = ((I(j) << s) | c_j).
        """
        return self._cfb(blocks, iv, seg_bits, decrypt=False)[0]

    def cfb_decrypt(self, blocks, iv, seg_bits):
        """CFB decryption. The feedback register must take the *ciphertext*
        segment here too -- that is what makes CFB self-inverting, and it is
        exactly the point aes.sv:520-528 gets wrong by feeding back
        `output_block` (which holds plaintext on the decrypt path)."""
        return self._cfb(blocks, iv, seg_bits, decrypt=True)[0]

    def cfb_feedback_trace(self, blocks, iv, seg_bits, decrypt=False):
        """(outputs, [I(j) for every segment]) -- for divergence reporting."""
        return self._cfb(blocks, iv, seg_bits, decrypt=decrypt)

    def _cfb(self, blocks, iv, seg_bits, decrypt):
        s = seg_bits
        seg_mask = (1 << s) - 1
        n_seg = 128 // s
        reg = iv & MASK128
        outs, trace = [], []
        for blk in blocks:
            acc = 0
            for j in range(n_seg):
                trace.append(reg)
                keystream = self.encrypt_block(reg) >> (128 - s)   # MSB_s(O)
                in_seg = (blk >> (s * j)) & seg_mask
                out_seg = (in_seg ^ keystream) & seg_mask
                acc |= out_seg << (s * j)
                # CFB always feeds back the CIPHERTEXT segment: that is the
                # input segment when decrypting, the output segment when
                # encrypting.
                fb = in_seg if decrypt else out_seg
                reg = ((reg << s) | fb) & MASK128
            outs.append(acc)
        return outs, trace

    # ---- OFB (SP 800-38A 6.4) --------------------------------------------
    def ofb(self, blocks, iv, partial_bits=None):
        """Keystream mode: identical for encryption and decryption.

        I(0) = IV; I(j) = O(j-1); O(j) = E(I(j)); out(j) = in(j) ^ O(j).
        `partial_bits`, when given, applies to the FINAL block only and keeps
        its most significant `partial_bits` bits (aes.sv:637).
        """
        outs, reg = [], iv & MASK128
        for idx, blk in enumerate(blocks):
            ks = self.encrypt_block(reg)
            out = (blk ^ ks) & MASK128
            if partial_bits is not None and idx == len(blocks) - 1:
                out &= self.partial_mask(partial_bits)
            outs.append(out)
            reg = ks
        return outs

    def ofb_keystream(self, n, iv):
        """The first n OFB keystream blocks for IV -- lets a test show that the
        feedback is O(j-1) (OFB) and not C(j-1) (which would be CFB128)."""
        ks, reg = [], iv & MASK128
        for _ in range(n):
            reg = self.encrypt_block(reg)
            ks.append(reg)
        return ks

    # ---- CTR (SP 800-38A 6.5) --------------------------------------------
    #
    # The incrementing function is where aes.sv and SP 800-38A part company, so
    # it is a parameter rather than a hard-coded `+ 1`. See CTR_INCREMENT_NOTE.
    @staticmethod
    def ctr_next_rtl(c):
        """aes.sv:682 -- `ctr_mode_cntr + 1` on the state-matrix-packed word."""
        return (c + 1) & MASK128

    @staticmethod
    def ctr_next_nist(c):
        """SP 800-38A B.1 standard incrementing function on the counter BLOCK,
        i.e. ordinary big-endian +1 in NIST byte order."""
        v = int.from_bytes(bytes(rtl_state_to_nist_bytes(c)), "big")
        return nist_bytes_to_rtl_state(list(((v + 1) & MASK128).to_bytes(16, "big")))

    def ctr(self, blocks, counter0, partial_bits=None, increment="rtl"):
        """out(j) = in(j) ^ E(T(j)), T(0) = counter0, T(j+1) = incr(T(j)).

        increment="rtl"  -> the successor aes.sv actually implements
        increment="nist" -> the successor SP 800-38A Appendix F.5 assumes
        """
        step = self.ctr_next_rtl if increment == "rtl" else self.ctr_next_nist
        outs, ctr = [], counter0 & MASK128
        for idx, blk in enumerate(blocks):
            out = (blk ^ self.encrypt_block(ctr)) & MASK128
            if partial_bits is not None and idx == len(blocks) - 1:
                out &= self.partial_mask(partial_bits)
            outs.append(out)
            ctr = step(ctr)
        return outs

    def ctr_sequence(self, n, counter0, increment="rtl"):
        """The first n counter blocks -- lets a test assert on the successor
        function the DUT actually uses instead of inferring it from ciphertext."""
        step = self.ctr_next_rtl if increment == "rtl" else self.ctr_next_nist
        seq, ctr = [], counter0 & MASK128
        for _ in range(n):
            seq.append(ctr)
            ctr = step(ctr)
        return seq

    # ---- partial-block masking -------------------------------------------
    @staticmethod
    def partial_mask(valid_bits):
        """aes.sv:637/686: `{128{1'b1}} << (~valid_bits + 7'd1)`.

        `~valid_bits + 1` is 7-bit two's complement, i.e. (128 - valid_bits)
        mod 128, so the mask keeps the top `valid_bits` bits. valid_bits == 0
        degenerates to a shift of 0 and therefore an all-ones mask -- that is
        the RTL's actual behaviour, reproduced here rather than corrected, so a
        test can assert on it deliberately.
        """
        shift = ((~valid_bits) + 1) & 0x7F
        return (MASK128 << shift) & MASK128


# ===========================================================================
# Known-answer vectors -- NIST SP 800-38A Appendix F
# ===========================================================================
# Keys and IV/counter shared by the whole appendix.
_K128 = "2b7e151628aed2a6abf7158809cf4f3c"
_K192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
_K256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
_IV = "000102030405060708090a0b0c0d0e0f"
_CTR0 = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

# The four-block plaintext used by every mode in Appendix F.
_PT = [
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
]

# F.1 ECB
SP800_38A_ECB = {
    128: (_K128, ["3ad77bb40d7a3660a89ecaf32466ef97", "f5d3d58503b9699de785895a96fdbaaf",
                  "43b1cd7f598ece23881b00e3ed030688", "7b0c785e27e8ad3f8223207104725dd4"]),
    192: (_K192, ["bd334f1d6e45f25ff712a214571fa5cc", "974104846d0ad3ad7734ecb3ecee4eef",
                  "ef7afd2270e2e60adce0ba2face6444e", "9a4b41ba738d6c72fb16691603c18e0e"]),
    256: (_K256, ["f3eed1bdb5d2a03c064b5a7e3db181f8", "591ccb10d410ed26dc5ba74a31362870",
                  "b6ed21b99ca6f4f9f153e7b1beafed1d", "23304b7a39f9f3ff067d8d8f9e24ecc7"]),
}

# F.2 CBC
SP800_38A_CBC = {
    128: (_K128, ["7649abac8119b246cee98e9b12e9197d", "5086cb9b507219ee95db113a917678b2",
                  "73bed6b8e3c1743b7116e69e22229516", "3ff1caa1681fac09120eca307586e1a7"]),
    192: (_K192, ["4f021db243bc633d7178183a9fa071e8", "b4d9ada9ad7dedf4e5e738763f69145a",
                  "571b242012fb7ae07fa9baac3df102e0", "08b0e27988598881d920a9e64f5615cd"]),
    256: (_K256, ["f58c4c04d6e5f1ba779eabfb5f7bfbd6", "9cfc4e967edb808d679f777bc6702c7d",
                  "39f23369a9d9bacfa530e26304231461", "b2eb05e2c39be9fcda6c19078c6a9d1b"]),
}

# F.4 OFB
SP800_38A_OFB = {
    128: (_K128, ["3b3fd92eb72dad20333449f8e83cfb4a", "7789508d16918f03f53c52dac54ed825",
                  "9740051e9c5fecf64344f7a82260edcc", "304c6528f659c77866a510d9c1d6ae5e"]),
    192: (_K192, ["cdc80d6fddf18cab34c25909c99a4174", "fcc28b8d4c63837c09e81700c1100401",
                  "8d9a9aeac0f6596f559c6d4daf59a5f2", "6d9f200857ca6c3e9cac524bd9acc92a"]),
    256: (_K256, ["dc7e84bfda79164b7ecd8486985d3860", "4febdc6740d20b3ac88f6ad82a4fb08d",
                  "71ab47a086e86eedf39d1c5bba97c408", "0126141d67f37be8538f5a8be740e484"]),
}

# F.5 CTR (counter block starts at f0f1...ff and increments by 1)
SP800_38A_CTR = {
    128: (_K128, ["874d6191b620e3261bef6864990db6ce", "9806f66b7970fdff8617187bb9fffdff",
                  "5ae4df3edbd5d35e5b4f09020db03eab", "1e031dda2fbe03d1792170a0f3009cee"]),
    192: (_K192, ["1abc932417521ca24f2b0459fe7e6e0b", "090339ec0aa6faefd5ccc2c6f4ce8e94",
                  "1e36b26bd1ebc670d1bd1d665620abf7", "4f78a7f6d29809585a97daec58c6b050"]),
    256: (_K256, ["601ec313775789a5b7a7f504bbf3d228", "f443e3ca4d62b59aca84e990cacaf5c5",
                  "2b0930daa23de94ce87017ba2d84988d", "dfc9c58db67aada613c2dd08457941a6"]),
}

# F.3.13/F.3.15/F.3.17 CFB128. Only CFB128 is listed: for s < 128 the RTL's
# segment ordering differs from the standard's (CFB_SEGMENT_ORDER_NOTE), so the
# published F.3.1-F.3.12 vectors are not applicable without silently changing
# what is being tested.
SP800_38A_CFB128 = {
    128: (_K128, ["3b3fd92eb72dad20333449f8e83cfb4a", "c8a64537a0b3a93fcde3cdad9f1ce58b",
                  "26751f67a3cbb140b1808cf187a4f4df", "c04b05357c5d1c0eeac4c66f9ff7f2e6"]),
    192: (_K192, ["cdc80d6fddf18cab34c25909c99a4174", "67ce7f7f81173621961a2b70171d3d7a",
                  "2e1e8a1dd59b88b1c8e60fed1efac4c9", "c05f9f9ca9834fa042ae8fba584b09ff"]),
    256: (_K256, ["dc7e84bfda79164b7ecd8486985d3860", "39ffed143b28b1c832113c6331e5407b",
                  "df10132415e54b92a13ed0a8267ae2f9", "75a385741ab9cef82031623d55b1e471"]),
}


def _rtl_blocks(hex_list):
    return [nist_bytes_to_rtl_state(list(bytes.fromhex(h))) for h in hex_list]


def self_check():
    """Validate every mode of the model against SP 800-38A Appendix F.

    Runs at import. A failure here means the *testbench* is wrong, and it is
    far better to find that out before a single DUT signal has been driven.
    """
    pt = _rtl_blocks(_PT)
    iv = nist_bytes_to_rtl_state(list(bytes.fromhex(_IV)))
    ctr0 = nist_bytes_to_rtl_state(list(bytes.fromhex(_CTR0)))

    for bits, (key_hex, ct_hex) in SP800_38A_ECB.items():
        m = AesModeModel(bytes.fromhex(key_hex))
        ct = _rtl_blocks(ct_hex)
        assert m.ecb_encrypt(pt) == ct, f"ECB-{bits} encrypt self-check failed"
        assert m.ecb_decrypt(ct) == pt, f"ECB-{bits} decrypt self-check failed"

    for bits, (key_hex, ct_hex) in SP800_38A_CBC.items():
        m = AesModeModel(bytes.fromhex(key_hex))
        ct = _rtl_blocks(ct_hex)
        assert m.cbc_encrypt(pt, iv) == ct, f"CBC-{bits} encrypt self-check failed"
        assert m.cbc_decrypt(ct, iv) == pt, f"CBC-{bits} decrypt self-check failed"

    for bits, (key_hex, ct_hex) in SP800_38A_OFB.items():
        m = AesModeModel(bytes.fromhex(key_hex))
        ct = _rtl_blocks(ct_hex)
        assert m.ofb(pt, iv) == ct, f"OFB-{bits} self-check failed"
        assert m.ofb(ct, iv) == pt, f"OFB-{bits} is not an involution"

    for bits, (key_hex, ct_hex) in SP800_38A_CTR.items():
        m = AesModeModel(bytes.fromhex(key_hex))
        ct = _rtl_blocks(ct_hex)
        # The published F.5 vectors necessarily use the standard incrementing
        # function; the RTL successor is checked separately below.
        assert m.ctr(pt, ctr0, increment="nist") == ct, f"CTR-{bits} self-check failed"
        assert m.ctr(ct, ctr0, increment="nist") == pt, f"CTR-{bits} is not an involution"
        assert m.ctr(m.ctr(pt, ctr0), ctr0) == pt, (
            f"CTR-{bits} with the RTL successor is not an involution")

    # The two successor functions must genuinely differ, otherwise the
    # distinction this model draws would be vacuous and the CTR interop test
    # would be asserting nothing.
    _m = AesModeModel(bytes.fromhex(_K128))
    assert _m.ctr_sequence(4, ctr0) != _m.ctr_sequence(4, ctr0, increment="nist"), (
        "RTL and NIST counter successors coincide for this start value -- pick "
        "a start value where they differ or CTR_INCREMENT_NOTE is wrong")

    for bits, (key_hex, ct_hex) in SP800_38A_CFB128.items():
        m = AesModeModel(bytes.fromhex(key_hex))
        ct = _rtl_blocks(ct_hex)
        assert m.cfb_encrypt(pt, iv, 128) == ct, f"CFB128-{bits} encrypt self-check failed"
        assert m.cfb_decrypt(ct, iv, 128) == pt, f"CFB128-{bits} decrypt self-check failed"

    # Sub-128-bit CFB has no applicable published vector, so check the property
    # that actually matters instead: decryption must invert encryption for every
    # segment size, which is exactly what a plaintext-feedback bug destroys.
    m = AesModeModel(bytes.fromhex(_K128))
    for s in (8, 16, 32, 64, 128):
        ct = m.cfb_encrypt(pt, iv, s)
        assert m.cfb_decrypt(ct, iv, s) == pt, f"CFB{s} model does not round-trip"

    # Partial-block masking, including the valid_bits==0 degenerate case that the
    # RTL's 7-bit two's complement produces.
    assert AesModeModel.partial_mask(128) == MASK128
    assert AesModeModel.partial_mask(0) == MASK128, "valid_bits=0 must degenerate to all-ones"
    assert AesModeModel.partial_mask(1) == (1 << 127)
    assert AesModeModel.partial_mask(64) == (MASK128 << 64) & MASK128


self_check()
