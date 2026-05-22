// top module where TRNG and Sbox are instantiated and connected to each other
import type_defs_pkg::*;

module trng_sbox_top(
    // S-box output (SubBytes result)
    output state_matrix_t subBytes,  // 4x4 state matrix (16 bytes total)
    output logic s_box_ready,  // S-box ready for next input
    output logic dead_flag,  // TRNG has encountered fatal error
    output logic trng_dead_flag,  // TRNG error signal
    output logic op_done,
    input logic clk,  // Main clock
    input logic sampling_clk,  // High-frequency clock for noise source
    input logic ext_rst_n,  // External reset (active low)
    input logic raw_rand_bit,  // Raw random bit from noise source (py model)
    input state_matrix_t s_box_input);  // 128-bit plaintext
    
    // TRNG to S-box connections
    logic [1343:0] rand_word;  // 1344-bit random data from TRNG
    logic trng_key_valid;  // TRNG: data is valid
    logic s_box_ready_to_trng;  // S-box ready signal (to TRNG)
    logic local_rst_n;  // Local reset (synchronized)
    logic trng_dead;  // TRNG dead flag
    logic rst_trng;  // S-box can reset TRNG if needed

    trng TRNG(rand_word, trng_key_valid, trng_dead, s_box_ready_to_trng, raw_rand_bit, sampling_clk, clk, ext_rst_n);
    s_box Sbox(subBytes, s_box_ready_to_trng, rst_trng, op_done, trng_dead, s_box_input, rand_word, trng_key_valid, ext_rst_n, clk);
    
    // Output the S-box ready signal to external interface
    assign s_box_ready = s_box_ready_to_trng;
    
    // Output TRNG status to external interface
    assign trng_dead_flag = trng_dead;
    assign dead_flag = trng_dead;
endmodule
