/**
 * This is the CIPHER block which instantiates Sbox, ShiftRows, MixColumns and AddRoundKey as sub-modules where input plain-text undergoes all these transformations
 * This block receives a total of 1680 random bits from TRNG and distributes them to Sbox and AddRoundKey which internally has another Sbox
 * CIPHER has no direct handshake with TRNG but governs TRNG - SBox local handshake. Handshake between TRNG and SBox only happens when CIPHER enables Sbox
**/

import type_defs_pkg::*;

module cipher(
    output state_matrix_t cipher_state,  // state matrix that has gone through whole CIPHER algorithm
    output logic cipher_done,  // becomes high when CIPHER is done computing transformed state
    output logic sbox_ready,  // sbox acknowledges receiption of random words
    output logic rst_trng,  // resets TRNG when health test results in fatal failures
    input state_matrix_t state,  // input state matrix (plain text)
    input logic [1679:0] rand_num,  // 1680-bit random bits from TRNG
    input logic [255:0] master_key,  // MASTER KEY required for key expansion
    input logic [1:0] key_size,  // AES KEY size from CONTROL register
    input logic trng_key_valid,  // tells S-box that random words are ready
    input logic trng_dead_flag,  // asserted by TRNG to signify that it has encountered fatal failure
    input logic rst_n, clk);
    
    state_matrix_t temp_state;
    unibble Nr;  // number of CIPHER rounds based on KEY size
    unibble round_cntr;  // keeps track of CIPHER round count
    logic [1:0] sbox_enb_n;  // SBox enable signal
    logic [1:0] ark_sbox_enb_n;  // AddRoundKey enabling sbox
    logic sbox_done_pulse;  // signal from SBox which becomes high when Sbox is done computing sbuBytes
    logic sbox_proceed;  // signal from CIPHER/AddRoundKey to SBox to advance to next state only when CIPHER/AddRoundKey has aknowledged
    logic ark_enb_n;  // addRoundKey enable signal
    logic ark_done;  // indicates that addRoundKey has computed the output
    logic [127:0] sbox_state;  // state matrix to SBox
    logic [127:0] subBytes;  // subBytes computed by Sbox for given state matrix
    state_matrix_t subBytes_matrix;  // matrix version of subBytes
    state_matrix_t shift_rows;  // stores state that has gone through shiftRows
    state_matrix_t mix_columns;  // stores state that has gone through mixColumns
    word_t ark_sbox_word;  // generated KEY from AddROundKey to SBox
    state_matrix_t ark_state;  // input state to addRoundKey
    state_matrix_t addRoundKeyOut;  // output of AddRoundKey module
    cipher_internal_states fsm_state;

    // sub-module instances
    sbox SBox(subBytes, sbox_ready, sbox_done_pulse, rst_trng, trng_dead_flag, sbox_state, rand_num, trng_key_valid, sbox_proceed, sbox_enb_n[1], sbox_enb_n[0], rst_n, clk); 
    shiftRows ShiftRows(shift_rows, subBytes_matrix);
    mixColumns MixColumns(mix_columns, shift_rows);
    addRoundKey AddRoundKey(addRoundKeyOut, ark_done, ark_sbox_word, ark_sbox_enb_n, ark_state, master_key, subBytes[31:0], round_cntr, key_size, sbox_done_pulse, ark_enb_n, rst_n, clk);

    always_comb begin
        // number of total CIPHER rounds (Nr) based on KEY size
        case(key_size)
            2'b01: Nr = 4'hA;
            2'b10: Nr = 4'hC;
            2'b11: Nr = 4'hE;
            default: Nr = 4'h0;
        endcase

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
    always_ff @(posedge clk) begin
        if(!rst_n) begin
            round_cntr <= 0;
            sbox_enb_n <= 2'b11;
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
    end
endmodule