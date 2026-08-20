/**
 * This module implements the CBC-MAC conditioner that takes raw entropy bits from noise source and produces conditioned random words. 
 * The CBC-MAC conditioner uses unmasked CIPHER as encryption function and it is invoked twice. 
 * The CBC-MAC conditioner also performs NIST standard health tests on the raw entropy bits to ensure that the noise source is functioning properly.
**/

import type_defs_pkg::*;

module cbc_mac(
    output logic [383:0] random_word,  // 384-bit conditioned random word output from CBC-MAC conditioner
    output logic cbcmac_valid,  // becomes high when CBC-MAC conditioner has finished producing conditioned random word
    output logic health_error,  // becomes high when health tests fail
    input logic ctr_drbg_ready,  // ready signal from CTR_DRBG module to indicate that it is ready to receive conditioned random word
    input logic entropy,  // raw entropy bit from noise source
    input logic enb_n, rst_n, clk);
    
    // hex digits of pi (fractional part) used by unmasked CIPHER as master key for key expansion
    localparam u256_t MASTER_KEY = 256'h243F6A88_85A308D3_13198A2E_03707344_A4093822_299F31D0_082EFA98_EC4E6C89;

    logic gated_clk;  // gated clock to reduce dynamic power consumption
    logic [2:0] enc_cntr;  // counter to keep track of number of times unmasked CIPHER has been invoked
    u128_t regV;  // stores intermediate outputs of unmasked CIPHER
    logic [383:0] acc;  // accumulates the 128-bit outputs of unmasked CIPHER to produce 384-bit conditioned random word
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
            cbcmac_valid <= 0;
            enc_cntr <= 0;
            regV <= 0;
            acc <= 0;
            cipher_state_in <= 0;
            cipher_enb_n <= 1;
            ready <= 0;
            fsm_state <= CONSUME;
        end
        else begin
            if(!enb_n) begin
                case(fsm_state)
                    CONSUME: begin  // this state just consumes 128-bit words from entropy collector 
                        // unmasked CIPHER will be invoked 2 times to produce 128-bit conditioned random word. Since 3 such conditioned random
                        // words are needed to regV is required to reset to 0 for every such conditioned random word generation
                        // so regV is reset to 0 when enc_cntr becomes even which is exactly when 128-bit conditioned random word is generated
                        regV <= (enc_cntr[0] == 0) ? 0 : regV;

                        cbcmac_valid <= 0;
                        ready <= 1;
                        cipher_enb_n <= 1;  // disable unmasked CIPHER as it is not needed in this state
                        cipher_state_in <= (valid) ? regV ^ entropy_word : cipher_state_in;  // XORing the intermediate output of unmasked CIPHER with the new 128-bit word received from entropy collector
                        fsm_state <= (health_error) ? ERROR : ((valid) ? OPERATE : CONSUME);  // when valid is high, it means that entropy collector has sent 128-bit word to CBC-MAC conditioner
                    end
                    OPERATE: begin  // this state performs CBC-MAC operation on the 128-bit word received from entropy collector
                        cbcmac_valid <= 0;
                        ready <= 0;  // deasserting ready as CBC-MAC conditioner is now processing the 128-bit word received from entropy collector
                        cipher_enb_n <= 0;  // enable unmasked CIPHER to start processing the state matrix
                        regV <= (cipher_done) ? cipher_state : regV;
                        enc_cntr <= (enc_cntr == 6) ? 0 : ((cipher_done) ? enc_cntr + 1 : enc_cntr);  // incrementing the counter when unmasked CIPHER has finished processing the state matrix

                        if(health_error) fsm_state <= ERROR;  // if health tests fail, CBC-MAC conditioner goes to ERROR state
                        else begin
                            if(enc_cntr == 6) fsm_state <= RELEASE;
                            else fsm_state <= (cipher_done) ? CONSUME : OPERATE;
                        end
                    end
                    RELEASE: begin
                        cbcmac_valid <= 1;
                        ready <= 0;
                        cipher_enb_n <= 1;

                        // CBC-MAC keeps on waiting for CTR-DRBG to consume conditioned random bits while holding them
                        // it goes back to CONSUME state to produce next batch only when CTR-DRBG consumes current batch
                        fsm_state <= (ctr_drbg_ready) ? CONSUME : RELEASE;
                    end
                    ERROR: begin  // this state is entered when health tests fail and it stays in this state until external reset
                        cbcmac_valid <= 0;
                        ready <= 0;
                        cipher_enb_n <= 1;
                        cipher_state_in <= 0;
                        regV <= 0;
                        enc_cntr <= 0;
                        fsm_state <= ERROR;  // waits in this state until external reset is asserted
                    end
                endcase

                // accumulating regV into 'acc' register to produce 384-bit conditioned random word
                acc[127:0] <= (enc_cntr == 1 && cipher_done) ? cipher_state : acc[127:0];
                acc[255:128] <= (enc_cntr == 3 && cipher_done) ? cipher_state : acc[255:128];
                acc[383:256] <= (enc_cntr == 5 && cipher_done) ? cipher_state : acc[383:256];
            end
            else begin
                cbcmac_valid <= 0;
                ready <= 0;
                cipher_enb_n <= 1;
                cipher_state_in <= cipher_state_in;
                regV <= regV;
                acc <= acc;
                enc_cntr <= enc_cntr;
                fsm_state <= fsm_state;
            end
        end
    end

    // random_word will be given out only when CBC-MAC is done producing conditioned random bits and CTR-DRBG is ready to accept it 
    assign random_word = (cbcmac_valid && ctr_drbg_ready) ? acc : 0;
endmodule
