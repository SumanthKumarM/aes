/**
 * This is the inverse CIPHER block which instantiates invSbox, invShiftRows and invMixColumns as sub-modules while AddRoundKey stays in same 
   level as CIPHER/invCIPHER in module hierarchy because AddRoundKey is common to both CIPHER & invCIPHER
 * This block receives a 1344 random bits from TRNG send it to Sbox internally
 * invCIPHER has no direct handshake with TRNG but governs TRNG - invSBox local handshake. Handshake between TRNG and invSBox only happens when invCIPHER enables invSbox
**/

import type_defs_pkg::*;

module invCipher(
    output state_matrix_t invCipher_state,  // state matrix that has gone through whole invCIPHER algorithm
    output logic invCipher_done,  // becomes high when invCIPHER is done computing transformed state
    output logic internal_state,  // state in which invCipher is currently operating in
    output state_matrix_t ark_state_in,  // input state to AddRoundKey from invSbox
    output logic ark_enb_n,  // enable signal to AddRoundKey
    output unibble ark_round_num,  // invCIPHER round number output to AddRoundKey
    output logic invSbox_ready,  // tells TRNG that invSbox is ready to accept random bits
    output logic rst_trng,  // resets TRNG when health test results in fatal failures
    input state_matrix_t state,  // input state matrix (encrypted text)
    input logic [1343:0] rand_num,  // 1344 random bits from TRNG to invSbox
    input state_matrix_t ark_state_out,  // output of AddRoundKey
    input logic ark_done,  // signal from AddRoundKey which is asserted when AddRoundKey has computed the output
    input logic [1:0] key_size,  // AES KEY size to decide number of rounds
    input logic trng_key_valid,  // tells invSbox that random words are ready
    input logic trng_dead_flag,  // asserted by TRNG to signify that it has encountered fatal failure
    input enb_n,  // active low enable signal for invCipher
    input logic rst_n, clk);

    state_matrix_t temp_state;
    logic gated_clk;  // gated clock to reduce dynamic power consumption
    logic delay;  // used to cause 1-clk cycle delay during which round_cntr can be updated
    unibble Nr;  // number of invCIPHER rounds based on KEY size
    unibble round_cntr;  // keeps track of invCIPHER round count
    u128_t invSbox_state;  // 128-bit input state matrix to invSbox
    u128_t invSubBytes;  // invSubByte of each encrypted element of state array
    logic invSbox_done_pulse;  // indicates that invSbox has computed required invSubBytes
    logic invSbox_proceed;  // asserted by invCIPHER to allow invSBox to advance to next state only when invCIPHER has aknowledged
    logic invSbox_enb_n;  // active low enable signal to invSbox
    state_matrix_t invsr_state_in;  // input state matrix to invShiftRows
    state_matrix_t invsr_state_out;  // output of invShiftRows
    state_matrix_t invmc_state_out;  // output of invMixColumns
    invCipher_internal_states fsm_state;

    // sub-module instances
    icg ICG(gated_clk, ~enb_n, clk);  // ICG cell to reduce dynamic power consumption
    invShiftRows InvShiftRows(invsr_state_out, invsr_state_in);
    invSbox InvSBox(invSubBytes, invSbox_ready, invSbox_done_pulse, rst_trng, invSbox_state, rand_num, trng_dead_flag, trng_key_valid, invSbox_proceed, invSbox_enb_n, rst_n, clk);
    invMixColumns InvMixColumns(invmc_state_out, ark_state_out);

    always_comb begin
        internal_state = fsm_state;

        // number of total invCIPHER rounds (Nr) based on KEY size
        case(key_size)
            2'b01: Nr = 4'hA;
            2'b10: Nr = 4'hc;
            2'b11: Nr = 4'hE; 
            default: Nr = 4'h0;
        endcase

        // invCIPHER counts round number from Nr down to 0 but AddRoundKey requires it from 0 to Nr so mapping it accordingly
        ark_round_num = Nr - round_cntr;

        // rerouting invsr_state_out to invSbox_state as both of them are in different formats
        for(int i=0; i<16; i++)
            invSbox_state[((8*(i%4))+(32*(i/4))) +: 8] = invsr_state_out[i%4][i/4];
    end

    /**
        sequential block based on NIST standard invCIPHER algorithm:
        procedure INVCIPHER(in, Nr, w)
            state ← in
            state ← ADDROUNDKEY(state,w[4 ∗ Nr..4 ∗ Nr + 3])
            for round from Nr − 1 downto 1 do
                state ← INVSHIFTROWS(state)
                state ← INVSUBBYTES(state)
                state ← ADDROUNDKEY(state,w[4 ∗ round..4 ∗ round + 3]) 
                state ← INVMIXCOLUMNS(state)
            end for 
            state ← INVSHIFTROWS(state) 
            state ← INVSUBBYTES(state) 
            state ← ADDROUNDKEY(state,w[0..3]) 
            return state 
        end procedure 
    **/
    always_ff @(posedge gated_clk) begin
        if(!rst_n) begin
            delay <= 0;
            round_cntr <= 0;
            ark_enb_n <= 1;
            invSbox_enb_n <= 1;
            invSbox_proceed <= 0;
            invCipher_done <= 0;
            fsm_state <= INVC_PRE_ADDROUNDKEY;

            for(int i=0; i<16; i++) begin
                invCipher_state[i%4][i/4] <= 8'h00;
                temp_state[i%4][i/4] <= 8'h00;
                invsr_state_in[i%4][i/4] <= 8'h00;
                ark_state_in[i%4][i/4] <= 8'h00;
            end
        end
        else begin  // (for round from Nr − 1 downto 1 do ... end for) & last round
            // key_size isn't set until reset is released so round_cntr needs another cycle to actually get correct Nr value
            if(!enb_n && !delay) begin
                round_cntr <= Nr;
                ark_enb_n <= 1;
                invSbox_enb_n <= 1;
                invSbox_proceed <= 0;
                invCipher_done <= 0;
                fsm_state <= INVC_PRE_ADDROUNDKEY;

                for(int i=0; i<16; i++) begin
                    invCipher_state[i%4][i/4] <= 8'h00;
                    temp_state[i%4][i/4] <= 8'h00;
                    invsr_state_in[i%4][i/4] <= 8'h00;
                    ark_state_in[i%4][i/4] <= 8'h00;
                end
            end
            else if(!enb_n && delay) begin  // invCipher is enabled
                if(round_cntr == Nr) begin  // only AddRoundKey is performed in this invCipher round
                    invSbox_enb_n <= 1;  // invSbox is not required yet
                    invSbox_proceed <= 0;
                    ark_enb_n <= 0;  // AddROundKey is enabled
                    ark_state_in <= state;  // loading input of AddRoundKey
                    temp_state <= (ark_done) ? ark_state_out : temp_state;
                    round_cntr <= (ark_done) ? (Nr - 1) : round_cntr;
                    invCipher_done <= 0;  // invCipher is not done computing transformed state yet
                    fsm_state <= INVC_PRE_ADDROUNDKEY;
                end
                else begin
                    case(fsm_state)
                        INVC_PRE_ADDROUNDKEY: begin
                            invSbox_enb_n <= 0;  // enabling invSbox as it's required to compute invSubBytes
                            ark_enb_n <= 1;
                            invCipher_done <= 0;
                            invsr_state_in <= temp_state;  // loading input of invShiftRows
                            temp_state <= (invSbox_done_pulse) ? invSubBytes : temp_state;
                            invSbox_proceed <= invSbox_done_pulse;  // invCIPHER will allow invSbox to advance to next state only when invSbox has computed invSubBytes
                            fsm_state <= (invSbox_done_pulse) ? INVC_ADDROUNDKEY : INVC_PRE_ADDROUNDKEY;
                        end 
                        INVC_ADDROUNDKEY: begin
                            invSbox_enb_n <= 1;  // disabled invSbox since it's not required here
                            invSbox_proceed <= 0;

                            // AddRoundKey is disabled when it has computed the output to protect it from using stale previous cycle output when it enters 'if(round_cntr == Nr) or INVC_PRE_ADDROUNDKEY'
                            ark_enb_n <= (ark_done) ? 1 : 0;
                            ark_state_in <= temp_state;  // loading AddRounKey input with invSubBytes

                            if(ark_done) begin
                                if(round_cntr == 0) begin
                                    temp_state <= ark_state_out;
                                    invCipher_state <= ark_state_out;
                                    invCipher_done <= 1;
                                    round_cntr <= Nr;
                                end
                                else begin
                                    temp_state <= invmc_state_out;
                                    invCipher_done <= 0;
                                    round_cntr <= round_cntr - 1;
                                end

                                fsm_state <= INVC_PRE_ADDROUNDKEY;
                            end
                            else begin
                                invCipher_done <= 0;
                                fsm_state <= INVC_ADDROUNDKEY;
                            end
                        end
                    endcase
                end
            end
            else begin  // invCipher is disabled
                round_cntr <= round_cntr;
                ark_enb_n <= 1;
                invSbox_enb_n <= 1;
                invSbox_proceed <= 0;
                invCipher_done <= 0;
                fsm_state <= fsm_state;
                invCipher_state <= invCipher_state;
                temp_state <= temp_state;
                invsr_state_in <= invsr_state_in;
                ark_state_in <= ark_state_in;
            end

            delay <= ~enb_n;  // this helps to create a cycle gap so round_cntr can be updated
        end
    end
endmodule