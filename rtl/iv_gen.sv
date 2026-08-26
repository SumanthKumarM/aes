/**
 * This is the IV generator module which uses both CBC-MAC conditioner and CTR-DRBG to generate an IV using noise source
 * This module has a VALID-READY handshake with AES which gives valid IV when AES needs it 
**/

import type_defs_pkg::*;

module iv_gen(
    output u128_t generated_iv,  // this is the IV required for AES operations
    output logic iv_valid,  // becomes high when CTR-DRBG is done computing IV
    input logic aes_ready,  // READY signal from AES to let CTR-DRBG know that it's ready to consume IV
    input logic entropy,  // raw entropy bit from noise source
    input logic enb_n, rst_n, clk);

    logic gated_clk;  // gated clock to reduce dynamic power consumption
    logic cbcmac_enb_n;  // active low enable signal for CBC-MAC
    u384_t seed;  // 384-bit conditioned random word output from CBC-MAC conditioner to CTR-DRBG
    logic health_error;  // becomes high when health tests fail in CBC-MAC conditioner
    logic rst_cbcmac;  // CTR-DRBG resets CBC-MAC when it encounters error from health tests
    logic cbcmac_valid;  // becomes high when CBC-MAC conditioner has finished producing conditioned SEED
    logic ctr_drbg_ready;  // ready signal from CTR-DRBG to indicate that it is ready to receive conditioned SEED

    /**
     * When CBC-MAC conputes conditioned SEED it asserts VALID and keeps waiting for CTR-DRBG to consume
     * Once CTR-DRBG consumes a SEED from CBC-MAC while in INSTANTIATE state it transitions to GENERATE_IV
       state and operates in same state for 1024 times which almost take ~265000 cycles
     * During these 265000 cycles CBC-MAC has nothing to do but wait in RELEASE state until CTR-DRBG consumes
       the SEED. So CBC-MAC getting clk during this window just consumes power unnecessarily.
     * To avoid this below enable signal is used to disable the CBC-MAC conditioner after it generates a new SEED
       and CTR-DRBG is not ready to consume the SEED which reduces power consumption
    **/
    assign cbcmac_enb_n = cbcmac_valid & ~ctr_drbg_ready;

    // sub-modules
    icg ICG(gated_clk, (~enb_n | ~rst_n), clk);  // ICG cell to reduce dynamic power consumption
    cbc_mac CBC_MAC(seed, cbcmac_valid, health_error, ctr_drbg_ready, entropy, (enb_n | cbcmac_enb_n), (rst_n & rst_cbcmac), gated_clk);
    ctr_drbg CTR_DRBG(generated_iv, iv_valid, ctr_drbg_ready, rst_cbcmac, seed, aes_ready, health_error, cbcmac_valid, enb_n, rst_n, gated_clk);
endmodule