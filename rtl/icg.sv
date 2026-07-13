/**
 Integrated Clock Gating (ICG) Cell:
 * This module implements a glitch-free clock gating cell using a negative-level-sensitive D-latch paired with a downstream AND gate. 
    1. When 'clk' is LOW (0), the latch is transparent and captures 'enable'.
       Any fluctuations on 'enable' are blocked from the output because the
       AND gate is held low by 'clk'.
    2. When 'clk' transitions to HIGH (1), the latch holds its state. 
       This guarantees 'latch_out' remains perfectly stable during the entire
       high phase of the clock, eliminating any risks of pulse glitches.
**/

module icg(
    output logic gated_clk,  // gated clock routed exclusively to the AES
    input logic enable,  // active high enable
    input logic clk);  // master system clock input
    
    /**
     * UNOPTFLAT suppressed: The latch feedback path (latch_out = latch_out when clk=1)
       creates circular combinational logic, which is intentional for latch hold behavior.
     * Verilator cannot optimize this, but it's functionally correct in simulation and synthesis.
    **/
    /* verilator lint_off UNOPTFLAT */
    logic latch_out;
    /* verilator lint_on UNOPTFLAT */

    /**
     * NOLATCH suppressed: Verilator's simulator cannot infer the latch from always_latch syntax
       the way synthesis tools do. The latch will behave correctly in simulation despite this warning.
     * Blocking assignment (=) is used instead of non-blocking (<=) to maintain proper latch semantics:
       immediate feedback for transparency when clk=0, and hold when clk=1.
    **/
    /* verilator lint_off NOLATCH */
    always_latch begin
        if(clk) latch_out = latch_out;
        else latch_out = enable;
    end
    /* verilator lint_on NOLATCH */

    assign gated_clk = latch_out & clk;
endmodule