"""Diagnostic probes for aes.sv -- NOT part of the regression suite.

`make run_test_suite block=aes_top` collects `aes_sequence` only (Makefile:
`TB_MODULE_aes_top := aes_sequence`), so nothing here affects the pass count.
Run one explicitly:

    make run_test_suite block=aes_top COCOTB_TEST_MODULES=aes_probes \
         test='probe_cfb128_encrypt'

These print cycle-by-cycle traces rather than asserting a golden value. They
are what located defects 3a, 3b and 10 in docs/response.md, and they are the
tool to reach for when a mode "produces the wrong number" and you need to know
whether the formula, the routing or the cipher's own answer is at fault.

To try an RTL change without touching aes/rtl/, build a scratch tree and point
the Makefile at it:

    mkdir -p /tmp/scratch_rtl
    for f in aes/rtl/*; do ln -sf "$(realpath $f)" /tmp/scratch_rtl/; done
    rm /tmp/scratch_rtl/aes.sv && cp aes/rtl/aes.sv /tmp/scratch_rtl/aes.sv
    # edit /tmp/scratch_rtl/aes.sv, then:
    make run_test_suite block=aes_top RTL_DIR=/tmp/scratch_rtl
"""
import cocotb
from cocotb.triggers import RisingEdge, FallingEdge, ClockCycles

from aes_testbench import (AesConfig, bringup, reset_dut, apply_config, send_block,
                           recv_block, probe, rand_blocks)
from aes_sequence import TIMEOUT_MS, IV_38A, PT_38A, KEY_128
from aes_ref_model import AesModeModel

NAMES = ["AES.fsm_state", "AES.seg_cntr", "AES.cipher_enb_n", "AES.cipher_done",
         "AES.cipherIn", "AES.temp", "AES.generated_IV", "AES.iv_valid",
         "AES.aes_iv_ready", "AES.cipherOut"]

def snap(dut, pr):
    d = {}
    for n, h in pr.items():
        if h is None:
            continue
        try:
            d[n] = int(h.value)
        except Exception:
            d[n] = -1
    d["inVALID"] = int(dut.inVALID.value)
    d["inREADY"] = int(dut.inREADY.value)
    d["outVALID"] = int(dut.outVALID.value)
    d["out"] = int(dut.output_block.value)
    d["ectx"] = int(dut.encCntxtOut.value)
    return d

def fmt(d):
    return (f"fsm={d['AES.fsm_state']} seg={d['AES.seg_cntr']} "
            f"cenb={d['AES.cipher_enb_n']} cdone={d['AES.cipher_done']} "
            f"ivv={d['AES.iv_valid']} ivrdy={d['AES.aes_iv_ready']} "
            f"iV={int(d['AES.inVALID']) if 'AES.inVALID' in d else d['inVALID']} "
            f"iR={d['inREADY']} oV={d['outVALID']}\n"
            f"        cipherIn={d['AES.cipherIn']:032x} temp={d['AES.temp']:032x}\n"
            f"        genIV   ={d['AES.generated_IV']:032x} ectx={d['ectx']:032x} out={d['out']:032x}")


async def tracer(dut, pr, log, keys=None):
    prev = None
    n = 0
    while True:
        await FallingEdge(dut.clk)
        n += 1
        cur = snap(dut, pr)
        watch = {k: cur[k] for k in cur if keys is None or k in keys}
        if prev is None or watch != prev:
            log.append((n, cur))
        prev = watch


@cocotb.test(timeout_time=TIMEOUT_MS, timeout_unit="ms")
async def probe_cfb128_encrypt(dut):
    env = await bringup(dut)
    pr = {n: probe(dut, n) for n in NAMES}
    cfg = AesConfig("CFB", KEY_128, cfb_seg_bits=128)
    await reset_dut(dut)
    apply_config(dut, cfg)
    blocks = rand_blocks(__import__("random").Random(0x5E65), 2)
    log = []
    t = cocotb.start_soon(tracer(dut, pr, log,
        keys=["AES.fsm_state","AES.seg_cntr","AES.cipher_enb_n","AES.cipher_done",
              "AES.cipherIn","AES.temp","AES.iv_valid","AES.aes_iv_ready","inVALID","inREADY","outVALID","ectx"]))
    outs = []
    for i, b in enumerate(blocks):
        await send_block(dut, b, first=(i == 0))
        r = await recv_block(dut)
        outs.append(r.data)
        if i == 0:
            iv = r.enc_cntxt_out
    t.kill()
    dut._log.info("=== TRACE (only changed cycles) ===")
    for n, d in log:
        dut._log.info(f"  cyc {n:5d} | " + fmt(d))
    m = cfg.model()
    want = m.cfb_encrypt(blocks, iv, 128)
    dut._log.info(f"encCntxtOut = {iv:032x}")
    for i, (g, w) in enumerate(zip(outs, want)):
        dut._log.info(f"blk{i} got {g:032x} want {w:032x} {'OK' if g==w else 'MISMATCH'}")


@cocotb.test(timeout_time=TIMEOUT_MS, timeout_unit="ms")
async def probe_cfb_seg_encrypt(dut):
    """Trace cipherIn / seg_cntr across every ARM visit for CFB64 and CFB32."""
    import random as _r
    env = await bringup(dut)
    pr = {n: probe(dut, n) for n in NAMES}
    for s in (64, 32):
        cfg = AesConfig("CFB", KEY_128, cfb_seg_bits=s)
        await reset_dut(dut)
        apply_config(dut, cfg)
        blocks = rand_blocks(_r.Random(0x5E65), 2)
        log = []
        t = cocotb.start_soon(tracer(dut, pr, log,
            keys=["AES.fsm_state","AES.seg_cntr","AES.cipher_enb_n","AES.cipherIn",
                  "inREADY","inVALID","outVALID"]))
        outs = []
        for i, b in enumerate(blocks):
            await send_block(dut, b, first=(i == 0))
            r = await recv_block(dut)
            outs.append(r.data)
            if i == 0:
                iv = r.enc_cntxt_out
        t.kill()
        dut._log.info(f"===== CFB{s} : ARM/cipherIn history =====")
        for n, d in log:
            dut._log.info(f"  cyc {n:5d} fsm={'ARM ' if d['AES.fsm_state']==0 else 'SHOT'} "
                          f"seg={d['AES.seg_cntr']} cenb={d['AES.cipher_enb_n']} "
                          f"iR={d['inREADY']} iV={d['inVALID']} oV={d['outVALID']} "
                          f"cipherIn={d['AES.cipherIn']:032x} out={d['out']:032x}")
        want = cfg.model().cfb_encrypt(blocks, iv, s)
        for i, (g, w) in enumerate(zip(outs, want)):
            dut._log.info(f"  CFB{s} blk{i} got {g:032x} want {w:032x} "
                          f"{'OK' if g==w else 'MISMATCH'}")


@cocotb.test(timeout_time=TIMEOUT_MS, timeout_unit="ms")
async def probe_back_to_back_messages(dut):
    """Two CFB128 messages, no reset between them -- the stale-inREADY window.

    After message 1 the DUT idles in ARM with seg_cntr==0 and first==0, so
    `inREADY <= 1` even though the IV it just consumed has not been replaced.
    A sender that then starts a NEW message (first=1) is granted immediately,
    on an inREADY computed from the previous cycle's first==0.
    """
    import random as _r
    env = await bringup(dut)
    pr = {n: probe(dut, n) for n in NAMES}
    cfg = AesConfig("CFB", KEY_128, cfb_seg_bits=128)
    await reset_dut(dut)
    apply_config(dut, cfg)
    rng = _r.Random(0xB2B)
    ok = True
    for msg in range(2):
        blk = rng.getrandbits(128)
        # state the sender sees the instant before it presents `first`
        ivv = int(pr["AES.iv_valid"].value)
        dut._log.info(f"--- message {msg}: before presenting first=1, "
                      f"inREADY={int(dut.inREADY.value)} iv_valid={ivv}")
        await send_block(dut, blk, first=True)
        r = await recv_block(dut)
        used = cfg.model().ecb_encrypt([r.enc_cntxt_out])[0] ^ blk
        good = used == r.data
        ok &= good
        dut._log.info(f"    encCntxtOut  = {r.enc_cntxt_out:032x}")
        dut._log.info(f"    output       = {r.data:032x}")
        dut._log.info(f"    P ^ AES(ctx) = {used:032x}   "
                      f"{'CONSISTENT' if good else 'INCONSISTENT -- reported IV is not the IV used'}")
    assert ok, "encCntxtOut does not describe the IV actually used"


@cocotb.test(timeout_time=TIMEOUT_MS, timeout_unit="ms")
async def probe_idle_gap_then_new_message(dut):
    """Same, but the sender idles a few cycles before starting message 2.

    Those idle ARM cycles take the `first == 0` leg of the inREADY assignment,
    so inREADY latches 1 while iv_valid is still 0 (the IV consumed by message 1
    has not been replaced yet -- the generator needs ~250 cycles). The sender
    then raises first=1 and is granted on that stale inREADY.
    """
    import random as _r
    env = await bringup(dut)
    pr = {n: probe(dut, n) for n in NAMES}
    cfg = AesConfig("CFB", KEY_128, cfb_seg_bits=128)
    await reset_dut(dut)
    apply_config(dut, cfg)
    rng = _r.Random(0xB2B)
    ok = True
    for msg in range(2):
        if msg:
            await ClockCycles(dut.clk, 5)          # idle in ARM, first=0, inVALID=0
        blk = rng.getrandbits(128)
        dut._log.info(f"--- message {msg}: before presenting first=1, "
                      f"inREADY={int(dut.inREADY.value)} "
                      f"iv_valid={int(pr['AES.iv_valid'].value)} "
                      f"genIV={int(pr['AES.generated_IV'].value):032x}")
        await send_block(dut, blk, first=True)
        r = await recv_block(dut)
        used = cfg.model().ecb_encrypt([r.enc_cntxt_out])[0] ^ blk
        good = used == r.data
        ok &= good
        dut._log.info(f"    encCntxtOut  = {r.enc_cntxt_out:032x}")
        dut._log.info(f"    output       = {r.data:032x}")
        dut._log.info(f"    P ^ AES(ctx) = {used:032x}   "
                      f"{'CONSISTENT' if good else 'INCONSISTENT -- reported IV is not the IV used'}")
    assert ok, "encCntxtOut does not describe the IV actually used"


@cocotb.test(timeout_time=TIMEOUT_MS, timeout_unit="ms")
async def probe_stale_ready_two_block_msg(dut):
    """message 1 = TWO blocks, idle gap, message 2 = one block with first=1.

    After a two-block message `cipherIn` holds C0, which is NOT equal to
    `generated_IV` any more -- so this is the case where "hold cipherIn" and
    "load generated_IV" give different answers.
    """
    import random as _r
    env = await bringup(dut)
    pr = {n: probe(dut, n) for n in NAMES}
    cfg = AesConfig("CFB", KEY_128, cfb_seg_bits=128)
    await reset_dut(dut)
    apply_config(dut, cfg)
    rng = _r.Random(0xB2B2)
    ctxs = []
    for msg, nblk in enumerate((2, 1)):
        if msg:
            await ClockCycles(dut.clk, 5)
        blocks = [rng.getrandbits(128) for _ in range(nblk)]
        dut._log.info(f"--- message {msg} ({nblk} block(s)): inREADY={int(dut.inREADY.value)} "
                      f"iv_valid={int(pr['AES.iv_valid'].value)} "
                      f"cipherIn={int(pr['AES.cipherIn'].value):032x}")
        outs = []
        for i, b in enumerate(blocks):
            await send_block(dut, b, first=(i == 0))
            r = await recv_block(dut)
            outs.append(r.data)
            if i == 0:
                ctx = r.enc_cntxt_out
        ctxs.append(ctx)
        want = cfg.model().cfb_encrypt(blocks, ctx, 128)
        good = outs == want
        dut._log.info(f"    encCntxtOut = {ctx:032x}")
        dut._log.info(f"    blk0 got {outs[0]:032x} want {want[0]:032x}   "
                      f"{'CONSISTENT with reported IV' if good else 'INCONSISTENT -- reported IV is not the IV used'}")
    dut._log.info(f"    IV reuse across the two messages: "
                  f"{'YES -- same IV twice under one key' if ctxs[0] == ctxs[1] else 'no'}")
