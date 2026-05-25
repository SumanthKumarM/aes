import cocotb
import numpy as np
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles
import logging

# SIMULATION PARAMETERS
CLK_PERIOD_NS = 10 # Main clock (150 MHz)
SCLK_PERIOD_NS = 2 # Sampling clock (500 MHz)
RESET_CYCLES = 8 # Reset duration

# NIST FIPS 197 AES S-box Table
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

# SBOX FSM states
SBOX_STATES = {
    0: "TOWER_FIELD",
    1: "MASKED_D",
    2: "MASKED_D_INV",
    3: "MASKED_A_INV",
    4: "MASKED_B_INV",
    5: "SUB_BYTES",
    6: "RESET_TRNG"
}

# monitor logger
_mon_log = logging.getLogger("cocotb.monitor")

# noise model integration
class NoiseBitBuffer:
    """
    Noise bit buffer using noise_source_model.py for realistic entropy.
    Falls back to numpy random if model not available.
    """
    
    def __init__(self, mode='physics', n_bits=10000, seed=None):
        self._mode = mode
        self._seed = seed if seed is not None else np.random.randint(0, 2**32)
        self._idx = 0
        self._buf = self._generate(n_bits)
        cocotb.log.info(f"[NoiseBitBuffer] Initialized with {len(self._buf)} bits (mode: {self._mode}, seed: {self._seed})")
    
    def _generate(self, n):
        """Generate noise bits using physics-based model or fallback to numpy random."""
        try:
            if self._mode == 'physics':
                from noise_source_model import TRNGNoiseSource
                cocotb.log.info(f"[NoiseBitBuffer]  Using PHYSICS-BASED noise model (noise_source_model.py)")
                src = TRNGNoiseSource(n_ro=32, n_inv=13, fs_MHz=150.0, seed=self._seed)
                bits = src.generate_bits(n)
                cocotb.log.info(f"[NoiseBitBuffer]  Generated {len(bits)} physics-based random bits")
                return bits
            else:
                raise ImportError("Not using physics mode")
        except ImportError as e:
            cocotb.log.warning(f"[NoiseBitBuffer] ⚠ Physics model not available ({e}) - using numpy random")
            rng = np.random.default_rng(self._seed)
            return rng.integers(0, 2, size=n, dtype=np.uint8)
    
    def next_bit(self) -> int:
        """Get next bit from buffer."""
        if self._idx >= len(self._buf):
            self._idx = 0
        b = int(self._buf[self._idx])
        self._idx += 1
        return b

async def noise_driver(dut, buf):
    """Drive raw_rand_bit from noise buffer on every sampling_clk edge."""
    while True:
        await RisingEdge(dut.sampling_clk)
        dut.raw_rand_bit.value = buf.next_bit()

# monitor
async def signal_monitor(dut, label=""):
    """
    COMPREHENSIVE signal monitor that logs ALL important signals.
    This helps debug why inputs might not be captured correctly.
    """
    pfx = f"[MON {label}]" if label else "[MON]"
    
    def snap():
        """Snapshot all critical signals."""
        return {
            "ext_rst_n"     : int(dut.ext_rst_n.value),
            "clk"           : int(dut.clk.value),
            "sbox_input"   : dut.sbox_input.value,
            "subBytes"      : int(dut.subBytes.value),
            "sbox_ready"   : int(dut.sbox_ready.value),
            "op_done"       : int(dut.op_done.value),
            "trng_key_valid": int(dut.trng_key_valid.value),
            "dead_flag"     : int(dut.dead_flag.value),
            "sbox_fsm"      : int(dut.Sbox.fsm_state.value),
            "raw_rand_bit"  : int(dut.raw_rand_bit.value),
        }
    
    def fmt(k, v):
        """Format signal value for logging."""
        if k == "sbox_fsm":
            return SBOX_STATES.get(v, f"UNKNOWN({v})")
        if k == "sbox_input":
            # v is a nested list [4][4] of bytes
            try:
                flat = [v[i][j] for i in range(4) for j in range(4)]
                return f"0x{''.join(f'{b:02x}' for b in flat)}"
            except:
                return str(v)
        if k == "subBytes":
            return f"0x{v:032x}"
        if k == "raw_rand_bit":
            return str(v)
        # For all other signals, if they're large numbers, print in hex
        if isinstance(v, int) and v > 255:
            return f"0x{v:x}"
        return str(v)
    
    # Log initial state
    await RisingEdge(dut.clk)
    prev = snap()
    
    _mon_log.info(
        f"{pfx} === INITIAL STATE ===  " +
        "  ".join(f"{k}={fmt(k,v)}" for k, v in prev.items())
    )
    
    # Monitor on every clock edge
    cyc = 0
    while True:
        await RisingEdge(dut.clk)
        cyc += 1
        cur = snap()
        
        # Log on any signal change
        diff = [(k, prev[k], cur[k]) for k in cur if prev[k] != cur[k]]
        
        if diff:
            changes = "  ".join(
                f"{k}: {fmt(k,ov)}->{fmt(k,nv)}" for k, ov, nv in diff
            )
            _mon_log.info(f"{pfx} cyc={cyc:5d}  {changes}")
        
        # Special detailed logging for critical events
        if cur["op_done"] == 1 and prev["op_done"] == 0:
            out_bytes = int_to_bytes(cur["subBytes"])
            out_str = " ".join(f"{b:02x}" for b in out_bytes)
            _mon_log.info(f"{pfx} cyc={cyc:5d}  *** [OP_DONE] *** subBytes output: {out_str}")
        
        if cur["trng_key_valid"] == 1 and prev["trng_key_valid"] == 0:
            _mon_log.info(f"{pfx} cyc={cyc:5d}  *** [TRNG_KEY_VALID] *** Random bits ready")
        
        if cur["sbox_fsm"] != prev["sbox_fsm"]:
            old_state = SBOX_STATES.get(prev["sbox_fsm"], "UNKNOWN")
            new_state = SBOX_STATES.get(cur["sbox_fsm"], "UNKNOWN")
            _mon_log.info(f"{pfx} cyc={cyc:5d}  *** [FSM] *** {old_state} -> {new_state}")
        
        if cur["sbox_input"] != prev["sbox_input"]:
            try:
                inp_bytes = [cur["sbox_input"][i][j] for i in range(4) for j in range(4)]
                inp_str = " ".join(f"{b:02x}" for b in inp_bytes)
                _mon_log.info(f"{pfx} cyc={cyc:5d}  *** [INPUT_CHANGE] *** sbox_input: {inp_str}")
            except:
                _mon_log.info(f"{pfx} cyc={cyc:5d}  *** [INPUT_CHANGE] *** sbox_input changed")
        
        prev = cur

# helper functions
def start_clocks(dut):
    """Start main and sampling clocks."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, unit="ns").start())
    cocotb.start_soon(Clock(dut.sampling_clk, SCLK_PERIOD_NS, unit="ns").start())

async def reset_dut(dut):
    """Perform DUT reset with detailed logging."""
    dut._log.info("Resetting DUT...")
    dut.ext_rst_n.value = 0
    dut.raw_rand_bit.value = 0
    
    dut._log.info(f"  ext_rst_n = 0 for {RESET_CYCLES} cycles")
    await ClockCycles(dut.clk, RESET_CYCLES)
    
    dut.ext_rst_n.value = 1
    await RisingEdge(dut.clk)
    dut._log.info(" DUT reset complete")

async def wait_signal(signal, value=1, timeout=100000, clk=None):
    """Wait for signal to reach value within timeout cycles."""
    for i in range(timeout):
        await RisingEdge(clk)
        if int(signal.value) == value:
            return i + 1
    raise AssertionError(f"TIMEOUT ({timeout} cyc): {signal._path} never reached {value}")

async def wait_trng_ready(dut):
    """Wait for TRNG to generate initial random bits."""
    dut._log.info("Waiting for TRNG to compute 1600 random bits...")
    cycles = await wait_signal(dut.trng_key_valid, value=1, timeout=20000, clk=dut.clk)
    dut._log.info(f" TRNG ready after {cycles} cycles")

def bytes_to_int(byte_list):
    """Convert list of bytes to 128-bit integer (big-endian)."""
    result = 0
    for b in byte_list:
        result = (result << 8) | b
    return result

def int_to_bytes(value, num_bytes=16):
    """Convert integer to list of bytes (big-endian)."""
    result = []
    for i in range(num_bytes - 1, -1, -1):
        result.append((value >> (8 * i)) & 0xFF)
    return result

def apply_sbox(input_bytes):
    """Apply NIST S-box to all 16 input bytes."""
    return [NIST_SBOX[b] for b in input_bytes]

def transpose_state_matrix(plaintext_bytes):
    """
    Apply S-box with proper state matrix interpretation.
    
    The testbench loads plaintext into a state matrix using row-major indexing:
        state[i][j] = plaintext[i + 4*j]
    
    This creates the state matrix, applies S-box, and outputs row-major order.
    """
    # Create state matrix using testbench's row-major indexing
    state = [[plaintext_bytes[i + 4*j] for j in range(4)] for i in range(4)]
    
    # Apply S-box to each element of the state matrix
    sbox_output = [[NIST_SBOX[state[i][j]] for j in range(4)] for i in range(4)]
    
    # Flatten row-by-row (this matches how RTL outputs it)
    result = []
    for row in range(4):
        for col in range(4):
            result.append(sbox_output[row][col])
    
    return result

# test case-1
@cocotb.test()
async def test_sbox_single_vector(dut):
    """
    TC1: Single test vector with INTENSIVE signal monitoring.
    
    MONITORS:
    - ALL signal transitions (sbox_input, subBytes, op_done, FSM, etc.)
    - Input capture process (does RTL see the plaintext?)
    - Output generation (what does SBOX produce?)
    
    ISSUES THIS WILL REVEAL:
    - If sbox_input is not being captured by RTL
    - If FSM is not progressing through states
    - If op_done is not asserting
    - If output is all 0x63 (meaning all inputs treated as 0x00)
    """
    dut._log.info("=" * 90)
    dut._log.info("TC1: Single Test Vector with INTENSIVE MONITORING")
    dut._log.info("=" * 90)
    
    # Setup
    start_clocks(dut)
    buf = NoiseBitBuffer(mode='physics', seed=12345)  # Uses noise_source_model.py!
    await reset_dut(dut)
    
    # Start background intensive monitoring
    dut._log.info("\n[*] Starting signal monitor (logs all transitions)...")
    cocotb.start_soon(signal_monitor(dut, label="TC1"))
    cocotb.start_soon(noise_driver(dut, buf))
    
    # Test vector - PREPARE BEFORE RESET
    plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    expected = transpose_state_matrix(plaintext)

    dut._log.info("\n[STAGE 1] Preparing plaintext...")
    dut._log.info(f"Input:    {' '.join(f'{b:02x}' for b in plaintext)}")
    dut._log.info(f"Expected: {' '.join(f'{b:02x}' for b in expected)}")

    # CREATE STATE MATRIX
    state_matrix = [[0]*4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state_matrix[i][j] = plaintext[i + 4*j]

    dut._log.info(f"\n[STAGE 2] Driving sbox_input FROM BEGINNING (before reset)...")
    flat_bytes = [state_matrix[i][j] for i in range(4) for j in range(4)]
    state_int = bytes_to_int(flat_bytes)
    dut.sbox_input.value = state_int
    dut._log.info(f"sbox_input = 0x{state_int:032x}")

    # Now do reset (input already set)
    # await reset_dut(dut)

    dut._log.info("\n[STAGE 3] Starting signal monitor and noise driver...")
    cocotb.start_soon(signal_monitor(dut, label="TC1"))
    cocotb.start_soon(noise_driver(dut, buf))

    # Wait for TRNG
    dut._log.info("\n[STAGE 4] Waiting for TRNG...")
    await wait_trng_ready(dut)

    # Monitor for 5 cycles to see if input is stable
    dut._log.info(f"\n[STAGE 5] Monitoring input stability for 5 cycles...")
    for i in range(5):
        await RisingEdge(dut.clk)
        try:
            inp_bytes = [dut.sbox_input.value[i_idx][j_idx] for i_idx in range(4) for j_idx in range(4)]
            inp_str = " ".join(f"{b:02x}" for b in inp_bytes)
        except:
            inp_str = f"0x{int(dut.sbox_input.value):032x}"
        fsm = SBOX_STATES.get(int(dut.Sbox.fsm_state.value), "UNKNOWN")
        dut._log.info(f"  Cycle {i+1}: sbox_input = {inp_str}, FSM = {fsm}")
    
    # Wait for op_done
    dut._log.info(f"\n[STAGE 5] Waiting for op_done...")
    cycles = await wait_signal(dut.op_done, value=1, timeout=100, clk=dut.clk)
    dut._log.info(f" op_done asserted after {cycles} cycles")
    
    # Read output
    dut._log.info(f"\n[STAGE 6] Reading output...")
    output_rtl = int(dut.subBytes.value)
    output_bytes = int_to_bytes(output_rtl)
    
    dut._log.info(f"RTL output: {' '.join(f'{b:02x}' for b in output_bytes)}")
    
    # Verify
    dut._log.info(f"\n[STAGE 7] Verification...")
    all_match = True
    for i in range(16):
        if expected[i] != output_bytes[i]:
            dut._log.error(f"Byte {i}: expected 0x{expected[i]:02x}, got 0x{output_bytes[i]:02x}")
            all_match = False
    
    if all_match:
        dut._log.info(" TC1 PASSED ")
    else:
        dut._log.error(" TC1 FAILED ")
        if all(b == 0x63 for b in output_bytes):
            dut._log.error("\n*** DEBUG: All outputs are 0x63 (SBOX[0x00]) ***")
            dut._log.error("This means RTL is treating ALL input bytes as 0x00")
            dut._log.error("CHECK: Is sbox_input signal connected properly in RTL?")
        raise AssertionError("Test failed - check monitor logs above for signal transitions")

# test case-2
@cocotb.test()
async def test_sbox_pipelined(dut):
    """
    TC2: Pipelined test vectors using op_done signal.
    
    After initial setup and first op_done, drive next plaintext
    on the same cycle as op_done, then read output.
    """
    dut._log.info("=" * 90)
    dut._log.info("TC2: Pipelined Test Vectors")
    dut._log.info("=" * 90)
    
    # Setup clocks and noise
    start_clocks(dut)
    buf = NoiseBitBuffer(mode='physics', seed=54321)
    
    # Test vectors for pipeline
    test_vectors = [
        ("ZEROS", [0x00] * 16),
        ("ONES", [0xFF] * 16),
        ("NIST_EXAMPLE", [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                          0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        ("SEQUENTIAL", list(range(16))),
        ("RANDOM_1", [0xAB, 0xCD, 0xEF, 0x01] * 4),
    ]
    
    dut._log.info(f"\n[STAGE 1] Preparing {len(test_vectors)} test vectors...")
    for name, plaintext in test_vectors:
        expected = transpose_state_matrix(plaintext)
        dut._log.info(f"  {name}: input {' '.join(f'{b:02x}' for b in plaintext[:4])}...")
    
    # Drive FIRST plaintext BEFORE reset
    plaintext = test_vectors[0][1]
    state_matrix = [[0]*4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state_matrix[i][j] = plaintext[i + 4*j]
    flat_bytes = [state_matrix[i][j] for i in range(4) for j in range(4)]
    state_int = bytes_to_int(flat_bytes)
    
    dut._log.info(f"\n[STAGE 2] Driving first plaintext ({test_vectors[0][0]})...")
    dut.sbox_input.value = state_int
    
    # Reset
    await reset_dut(dut)
    
    dut._log.info(f"\n[STAGE 3] Starting monitor and noise driver...")
    cocotb.start_soon(signal_monitor(dut, label="TC2"))
    cocotb.start_soon(noise_driver(dut, buf))
    
    # Wait for TRNG
    dut._log.info(f"\n[STAGE 4] Waiting for TRNG...")
    await wait_trng_ready(dut)
    
    # Pipeline loop
    dut._log.info(f"\n[STAGE 5] Pipelined operation...")
    for vec_idx in range(len(test_vectors)):
        # Wait for op_done
        dut._log.info(f"  Vector {vec_idx}: Waiting for op_done...")
        await wait_signal(dut.op_done, value=1, timeout=100, clk=dut.clk)
        
        # Read output
        output_rtl = int(dut.subBytes.value)
        output_bytes = int_to_bytes(output_rtl)
        
        # Verify
        plaintext_curr = test_vectors[vec_idx][1]
        expected_curr = transpose_state_matrix(plaintext_curr)
        
        all_match = all(expected_curr[i] == output_bytes[i] for i in range(16))
        status = "✓ PASS" if all_match else "✗ FAIL"
        dut._log.info(f"  Vector {vec_idx} ({test_vectors[vec_idx][0]}): {status}")
        
        if not all_match:
            for i in range(16):
                if expected_curr[i] != output_bytes[i]:
                    dut._log.error(f"    Byte {i}: expected 0x{expected_curr[i]:02x}, got 0x{output_bytes[i]:02x}")
            raise AssertionError(f"Vector {vec_idx} failed")
        
        # Drive next vector (if available)
        if vec_idx < len(test_vectors) - 1:
            plaintext_next = test_vectors[vec_idx + 1][1]
            state_matrix = [[0]*4 for _ in range(4)]
            for i in range(4):
                for j in range(4):
                    state_matrix[i][j] = plaintext_next[i + 4*j]
            flat_bytes = [state_matrix[i][j] for i in range(4) for j in range(4)]
            state_int = bytes_to_int(flat_bytes)
            dut.sbox_input.value = state_int
            dut._log.info(f"  Vector {vec_idx + 1}: Input driven")
            await RisingEdge(dut.clk)
    
    dut._log.info(f"\n✓ TC2 PASSED - All {len(test_vectors)} vectors verified")

# test case-3
@cocotb.test()
async def test_sbox_edge_cases(dut):
    """
    TC3: Edge case test vectors.
    
    Tests: all zeros, all ones, alternating patterns, etc.
    """
    dut._log.info("=" * 90)
    dut._log.info("TC3: Edge Case Vectors")
    dut._log.info("=" * 90)
    
    start_clocks(dut)
    buf = NoiseBitBuffer(mode='physics', seed=99999)
    
    # Edge cases
    edge_cases = [
        ("ALL_ZEROS", [0x00] * 16),
        ("ALL_ONES", [0xFF] * 16),
        ("ALT_AA", [0xAA] * 16),
        ("ALT_55", [0x55] * 16),
        ("INCR", list(range(16))),
        ("DECR", list(range(15, -1, -1))),
    ]
    
    dut._log.info(f"\n[STAGE 1] Preparing {len(edge_cases)} edge case vectors...")
    
    # Drive first edge case before reset
    plaintext = edge_cases[0][1]
    state_matrix = [[0]*4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state_matrix[i][j] = plaintext[i + 4*j]
    flat_bytes = [state_matrix[i][j] for i in range(4) for j in range(4)]
    state_int = bytes_to_int(flat_bytes)
    dut.sbox_input.value = state_int
    
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC3"))
    cocotb.start_soon(noise_driver(dut, buf))
    
    await wait_trng_ready(dut)
    
    dut._log.info(f"\n[STAGE 2] Testing edge cases...")
    for idx, (name, plaintext) in enumerate(edge_cases):
        expected = transpose_state_matrix(plaintext)
        
        # Wait for op_done
        await wait_signal(dut.op_done, value=1, timeout=100, clk=dut.clk)
        
        # Read and verify
        output_rtl = int(dut.subBytes.value)
        output_bytes = int_to_bytes(output_rtl)
        
        all_match = all(expected[i] == output_bytes[i] for i in range(16))
        status = "✓ PASS" if all_match else "✗ FAIL"
        dut._log.info(f"  Case {idx}: {name:15s} {status}")
        
        if not all_match:
            raise AssertionError(f"Edge case {name} failed")
        
        # Drive next case
        if idx < len(edge_cases) - 1:
            plaintext = edge_cases[idx + 1][1]
            state_matrix = [[0]*4 for _ in range(4)]
            for i in range(4):
                for j in range(4):
                    state_matrix[i][j] = plaintext[i + 4*j]
            flat_bytes = [state_matrix[i][j] for i in range(4) for j in range(4)]
            state_int = bytes_to_int(flat_bytes)
            dut.sbox_input.value = state_int
            await RisingEdge(dut.clk)
    
    dut._log.info(f"\n✓ TC3 PASSED - All {len(edge_cases)} edge cases verified")

# test case-4
@cocotb.test()
async def test_sbox_stress(dut):
    """
    TC4: Stress test with 10 random vectors.
    
    Tests consistent operation over multiple iterations.
    """
    dut._log.info("=" * 90)
    dut._log.info("TC4: Stress Test (10 Random Vectors)")
    dut._log.info("=" * 90)
    
    start_clocks(dut)
    buf = NoiseBitBuffer(mode='physics', seed=11111)
    
    # Generate 10 random test vectors
    import random
    n_vectors = 10
    test_vectors = []
    for i in range(n_vectors):
        plaintext = [random.randint(0, 255) for _ in range(16)]
        test_vectors.append((f"RAND_{i}", plaintext))
    
    dut._log.info(f"\n[STAGE 1] Preparing {n_vectors} random vectors...")
    
    # Drive first vector before reset
    plaintext = test_vectors[0][1]
    state_matrix = [[0]*4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state_matrix[i][j] = plaintext[i + 4*j]
    flat_bytes = [state_matrix[i][j] for i in range(4) for j in range(4)]
    state_int = bytes_to_int(flat_bytes)
    dut.sbox_input.value = state_int
    
    await reset_dut(dut)
    cocotb.start_soon(signal_monitor(dut, label="TC4"))
    cocotb.start_soon(noise_driver(dut, buf))
    
    await wait_trng_ready(dut)
    
    dut._log.info(f"\n[STAGE 2] Running stress test...")
    for vec_idx in range(n_vectors):
        # Wait for op_done
        await wait_signal(dut.op_done, value=1, timeout=100, clk=dut.clk)
        
        # Read and verify
        output_rtl = int(dut.subBytes.value)
        output_bytes = int_to_bytes(output_rtl)
        
        plaintext_curr = test_vectors[vec_idx][1]
        expected_curr = transpose_state_matrix(plaintext_curr)
        
        all_match = all(expected_curr[i] == output_bytes[i] for i in range(16))
        if not all_match:
            dut._log.error(f"  Vector {vec_idx}: ✗ FAIL")
            raise AssertionError(f"Stress test failed at vector {vec_idx}")
        
        dut._log.info(f"  Vector {vec_idx}: ✓ PASS")
        
        # Drive next vector
        if vec_idx < n_vectors - 1:
            plaintext_next = test_vectors[vec_idx + 1][1]
            state_matrix = [[0]*4 for _ in range(4)]
            for i in range(4):
                for j in range(4):
                    state_matrix[i][j] = plaintext_next[i + 4*j]
            flat_bytes = [state_matrix[i][j] for i in range(4) for j in range(4)]
            state_int = bytes_to_int(flat_bytes)
            dut.sbox_input.value = state_int
            await RisingEdge(dut.clk)
    
    dut._log.info(f"\n✓ TC4 PASSED - All {n_vectors} random vectors verified")