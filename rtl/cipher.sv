/**
 * This is the CIPHER block which instantiates Sbox, ShiftRows, MixColumns and AddRoundKey as sub-modules where input plain-text undergoes all these transformations
 * This block receives a total of 1680 random bits from TRNG which goes to Sbox internally
 * CIPHER has no direct handshake with TRNG but governs TRNG - SBox local handshake. Handshake between TRNG and SBox only happens when CIPHER enables Sbox
 * CIPHER manages the SBox and AddRoundKey while having them at same level as CIPHER in module hierarchy as SBox and AddRoundKey are common to both CIPHER and inverse CIPHER
**/

import type_defs_pkg::*;

module cipher(
    output state_matrix_t cipher_state,  // state matrix that has gone through whole CIPHER algorithm
    output unibble round_cntr,  // keeps track of CIPHER round count
    output logic cipher_done,  // becomes high when CIPHER is done computing transformed state
    output state_matrix_t ark_state,  // input state to addRoundKey
    output u128_t sbox_state,  // input state matrix to SBox
    output logic [1:0] sbox_enb_n,  // SBox enable signal
    output logic sbox_proceed,  // signal from CIPHER to SBox to advance to next state only when CIPHER has aknowledged
    output logic ark_enb_n,  // addRoundKey enable signal
    input state_matrix_t state,  // input state matrix (plain text)
    input u256_t master_key,  // MASTER KEY required for key expansion
    input u128_t subBytes,  // subBytes computed by Sbox for given state matrix
    input state_matrix_t addRoundKeyOut,  // output of AddRoundKey module
    input word_t ark_sbox_word,  // generated KEY from AddRundKey to SBox
    input logic [1:0] ark_sbox_enb_n,  // AddRoundKey enabling sbox
    input logic [1:0] key_size,  // AES KEY size from CONTROL register
    input logic sbox_done_pulse,  // signal from SBox which becomes high when Sbox is done computing sbuBytes
    input logic ark_done,  // indicates that addRoundKey has computed the output
    input logic enb_n, rst_n, clk);
    
    logic gated_clk;
    state_matrix_t temp_state;
    unibble Nr;  // number of CIPHER rounds based on KEY size
    state_matrix_t subBytes_matrix;  // matrix version of subBytes
    state_matrix_t shift_rows;  // stores state that has gone through shiftRows
    state_matrix_t mix_columns;  // stores state that has gone through mixColumns
    cipher_internal_states fsm_state;

    // sub-module instances
    icg ICG(gated_clk, ~enb_n, clk);  // ICG cell to reduce dynamic power consumption
    shiftRows ShiftRows(shift_rows, subBytes_matrix);
    mixColumns MixColumns(mix_columns, shift_rows);

    always_comb begin
        // number of total CIPHER rounds (Nr) based on KEY size
        //   KEY size = 01 (AES-128): Nr = 10
        //   KEY size = 10 (AES-192): Nr = 12
        //   KEY size = 11 (AES-256): Nr = 14
        Nr = {(key_size[1] | key_size[0]), key_size[1], key_size[0], 1'b0};

        // rerouting subBytes to subBytes_matrix as both of them in different formats
        for(int i=0; i<16; i++)
            subBytes_matrix[i%4][i/4] = subBytes[((8*(i%4))+(32*(i/4))) +: 8];
    end

    /**
        sequential block based on NIST standard CIPHER algorithm:
        procedure CIPHER(in, Nr, w)
            state ← in
            state ← ADDROUNDKEY(state,w[0..3])
            for round from 1 to Nr − 1 do 
                state ← SUBBYTES(state)
                state ← SHIFTROWS(state)
                state ← MIXCOLUMNS(state)
                state ← ADDROUNDKEY(state,w[4 ∗ round..4 ∗ round + 3]) 
            end for 
            state ← SUBBYTES(state) 
            state ← SHIFTROWS(state) 
            state ← ADDROUNDKEY(state,w[4 ∗ Nr..4 ∗ Nr + 3]) 
            return state
        end procedure
    **/
    always_ff @(posedge gated_clk) begin
        if(!rst_n) begin
            round_cntr <= 0;
            sbox_enb_n <= 2'b11;
            sbox_proceed <= 0;
            ark_enb_n <= 1;
            cipher_done <= 0;
            fsm_state <= PRE_ADDROUNDKEY;

            for(int i=0; i<16; i++) begin
                cipher_state[i%4][i/4] <= 8'h00;
                temp_state[i%4][i/4] <= 8'h00;
                sbox_state[((8*(i%4))+(32*(i/4))) +: 8] <= 8'h00;
                ark_state[i%4][i/4] <= 8'h00;
            end
        end
        else begin  // (for round from 1 to Nr − 1 do ... end for) & last round
            if(!enb_n) begin  // CIPHER operates when enabled
                if(round_cntr == 0) begin  // only AddRoundKey is performed in first cipher round
                    sbox_enb_n <= 2'b11;  // Sbox is not required yet
                    ark_enb_n <= 0;  // addRoundKey is enabled
                    ark_state <= state;  // loading input of addRoundKey
                    temp_state <= (ark_done) ? addRoundKeyOut : temp_state;
                    round_cntr <= (ark_done) ? 1 : 0;
                    cipher_done <= 0;  // CIPHER is not done computing transformed state yet
                    fsm_state <= PRE_ADDROUNDKEY;
                end
                else begin
                    case(fsm_state)
                        PRE_ADDROUNDKEY: begin
                            sbox_enb_n <= 2'b01;  // enabling Sbox as it's required to compute subBytes
                            ark_enb_n <= 1;
                            cipher_done <= 0;  // CIPHER is not done computing transformed state yet
                            
                            for(int i=0; i<16; i++)  // loading Sbox input with previous addRoundKey's output
                                sbox_state[((8*(i%4))+(32*(i/4))) +: 8] <= temp_state[i%4][i/4];

                            // since SBox is done computing subBytes it will traverse through ShiftRows and MixColumns which are pure combinational giving MixColumn's / ShiftRow's output
                            temp_state <= (sbox_done_pulse) ? ((round_cntr == Nr) ? shift_rows : mix_columns) : temp_state;
                            sbox_proceed <= sbox_done_pulse;  // CIPHER will allow SBox to advance to next state only when SBox has computed subBytes
                            fsm_state <= (sbox_done_pulse) ? ADDROUNDKEY : PRE_ADDROUNDKEY;
                        end 
                        ADDROUNDKEY: begin
                            sbox_enb_n <= ark_sbox_enb_n;  // AddRoundKey decides when to enable/disable SBox

                            // AddRoundKey is disabled when it has computed the output to protect it from using stale previous cycle output when it enters 'if(round_cntr == 0) or PRE_ADDROUNDKEY'
                            ark_enb_n <= (ark_done) ? 1 : 0;

                            // since AddRoundKey is enabled, wiring AddRoundKey generated KEY to SBox
                            sbox_state[127:32] <= 96'd0;  // these bits are not required for SBox as AddRoundKey only generates 32-bit KEY for SBox to consume
                            sbox_state[31:0] <= ark_sbox_word;

                            ark_state <= temp_state;  // loading addRoundKey input with MixColumn's / ShiftRow's output
                            temp_state <= (ark_done) ? addRoundKeyOut : temp_state;

                            if(ark_done) begin
                                if(round_cntr == Nr) begin 
                                    cipher_state <= addRoundKeyOut;
                                    cipher_done <= 1;
                                    round_cntr <= 0;  // starting over CIPHER counter as it's reached maximum rounds for this KEY size
                                end
                                else begin 
                                    cipher_done <= 0;  // CIPHER is not done computing transformed state yet
                                    round_cntr <= round_cntr + 1;  // updating CIPHER counter as state has been updated
                                end

                                sbox_proceed <= 1;  // AddRoundKey will allow SBox to advance to next state only when SBox has computed subBytes
                                fsm_state <= PRE_ADDROUNDKEY;
                            end
                            else begin 
                                cipher_done <= 0;  // CIPHER is not done computing transformed state yet
                                sbox_proceed <= 0;
                                round_cntr <= round_cntr;
                                fsm_state <= ADDROUNDKEY;
                            end
                        end
                    endcase
                end
            end
            else begin  // when CIPHER is disabled it holds the state
                round_cntr <= round_cntr;
                sbox_enb_n <= 2'b11;
                sbox_proceed <= 0;
                ark_enb_n <= 1;
                cipher_done <= 0;
                fsm_state <= fsm_state;
                cipher_state <= cipher_state;
                temp_state <= temp_state;
                sbox_state <= sbox_state;
                ark_state <= ark_state;
            end
        end
    end
endmodule