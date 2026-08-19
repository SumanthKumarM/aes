/**
 * This module implements the CBC-MAC conditioner that takes raw entropy bits from noise source and produces conditioned random words. 
 * The CBC-MAC conditioner uses unmasked CIPHER as encryption function and it is invoked twice. 
 * The CBC-MAC conditioner also performs NIST standard health tests on the raw entropy bits to ensure that the noise source is functioning properly.
**/

import type_defs_pkg::*;

module cbc_mac(
    output u128_t random_word,  // 128-bit conditioned random word output from CBC-MAC conditioner
    output logic cbcmac_done,  // becomes high when CBC-MAC conditioner has finished producing conditioned random word
    output logic health_error,  // becomes high when health tests fail
    input logic entropy,  // raw entropy bit from noise source
    input logic enb_n, rst_n, clk);
    
    // hex digits of pi (fractional part) used by unmasked CIPHER as master key for key expansion
    localparam u256_t MASTER_KEY = 256'h243F6A88_85A308D3_13198A2E_03707344_A4093822_299F31D0_082EFA98_EC4E6C89;

    logic gated_clk;  // gated clock to reduce dynamic power consumption
    logic [1:0] enc_cntr;  // counter to keep track of number of times unmasked CIPHER has been invoked
    u128_t regV;  // stores intermediate outputs of unmasked CIPHER
    u128_t entropy_word;  // 128-bit word collected from noise source
    logic valid, ready;  // valid-ready handshake signals for entropy word transfer from entropy collector to CBC-MAC conditioner
    logic cipher_enb_n;  // active low enable signal for unmasked CIPHER
    u128_t cipher_state_in;  // state matrix that is fed to unmasked CIPHER
    u128_t cipher_state;  // state matrix that has gone through whole CIPHER algorithm
    logic cipher_done;  // becomes high when CIPHER is done computing transformed state
    cbc_mac_states fsm_state;

    // sub-module instances
    icg ICG(gated_clk, (~enb_n | ~rst_n), clk);  // ICG cell to reduce dynamic power consumption
    health_tests HEALTH_TESTS(health_error, entropy, enb_n, clk, rst_n);
    entropy_clctr#(128) ENTROPY_COLLECTOR(entropy_word, valid, entropy, ready, gated_clk, rst_n);
    unmasked_cipher CIPHER(cipher_state, cipher_done, cipher_state_in, MASTER_KEY, cipher_enb_n, rst_n, gated_clk);

    always_ff @(posedge clk) begin
        if(!rst_n) begin
            enc_cntr <= 0;
            regV <= 0;
            cipher_state_in <= 0;
            cipher_enb_n <= 1;
            ready <= 0;
            fsm_state <= CONSUME;
        end
        else begin
            if(!enb_n) begin
                case(fsm_state)
                    CONSUME: begin  // this state just consumes 128-bit words from entropy collector 
                        ready <= 1;
                        cipher_enb_n <= 1;  // disable unmasked CIPHER as it is not needed in this state
                        fsm_state <= (health_error) ? ERROR : ((valid) ? OPERATE : CONSUME);  // when valid is high, it means that entropy collector has sent 128-bit word to CBC-MAC conditioner
                    end
                    OPERATE: begin  // this state performs CBC-MAC operation on the 128-bit word received from entropy collector
                        ready <= 0;  // deasserting ready as CBC-MAC conditioner is now processing the 128-bit word received from entropy collector
                        cipher_enb_n <= 0;  // enable unmasked CIPHER to start processing the state matrix
                        cipher_state_in <= regV ^ entropy_word;  // XORing the intermediate output of unmasked CIPHER with the new 128-bit word received from entropy collector
                        regV <= (cipher_done) ? cipher_state : regV;
                        enc_cntr <= (enc_cntr == 2) ? 0 : ((cipher_done) ? enc_cntr + 1 : enc_cntr);  // incrementing the counter when unmasked CIPHER has finished processing the state matrix
                        fsm_state <= (health_error) ? ERROR : ((cipher_done) ? CONSUME : OPERATE);  // since CIPHER has computed the transformed state, it goes back to CONSUME state to consume next 128-bit word from entropy collector
                    end
                    ERROR: begin  // this state is entered when health tests fail and it stays in this state until external reset
                        ready <= 0;
                        cipher_enb_n <= 1;
                        cipher_state_in <= 0;
                        regV <= 0;
                        enc_cntr <= 0;
                        fsm_state <= ERROR;  // waits in this state until external reset is asserted
                    end
                    default: begin
                        ready <= 0;
                        cipher_enb_n <= 1;
                        cipher_state_in <= 0;
                        regV <= 0;
                        enc_cntr <= 0;
                        fsm_state <= CONSUME;  // default state is CONSUME
                    end
                endcase
            end
            else begin
                ready <= 0;
                cipher_enb_n <= 1;
                cipher_state_in <= cipher_state_in;
                regV <= regV;
                enc_cntr <= enc_cntr;
                fsm_state <= fsm_state;
            end
        end
    end

    // when unmasked CIPHER has been invoked 2 times, the final output is sent to random_word output port
    assign cbcmac_done = (enc_cntr == 2) ? 1 : 0;  
    assign random_word = (enc_cntr == 2) ? regV : 0;
endmodule
