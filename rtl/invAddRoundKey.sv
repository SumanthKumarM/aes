/**
 * This module is similar to AddRoundKey but this receives all expanded KEYs from AddRoundKey
 * After receiving all expanded KEYs from KEY-expansion logic in AddRoundKey, this modules adds KEYs to input state
   in backward as inverse CIPHER wants 
**/

import type_defs_pkg::*;

module invAddRoundKey(
    output state_matrix_t invAddRoundKeyOut,  // output of invAddRoundKey
    output unibble round_cntr,  // this counter drives AddRoundKey to give corresponding KEY
    output logic invARK_done,  // lets invCIPHER know when to consume invAddRoundKey's output
    output logic ark_enb_n,  // enable signal for AddRoundKey
    input state_matrix_t exp_key,  // expanded KEY from AddRoundKey
    input u256_t master_key,  // input master KEY
    input logic [1:0] key_size,  // AES KEY size
    input unibble invCipher_round,  // this is the current inverse CIPHER round value
    input state_matrix_t state,  // input state matrix
    input logic ark_done,  // signal from AddRoundKey which indicates that AddRoundKey has computed required KEY
    input enb_n, rst_n, clk);

    logic gated_clk;  // gated clock to reduce dynamic power consumption
    logic [3:0][59:0][7:0] key_mem;  // this stores all the expanded KEYs given by AddRoundKey along with master KEY
    unibble round_cntr_d;  // 1-clk-cycle delayed version of round_cntr
    unibble Nr;  // number of rounds based on KEY size
    logic keys_received;  // becomes high when all required KEYs are received
    logic ark_done_d;  // 1-clk-cycle delayed version of ark_done

    // ICG cell to reduce dynamic power consumption
    icg ICG(gated_clk, (~enb_n | ~rst_n | invARK_done), clk);  // invARK_done is also included in enable because invAddRoundKey needs another clk cycle so that it enters disable branch and clears invARK_done 

    // number of total CIPHER rounds (Nr) based on KEY size
    //   KEY size = 01 (AES-128): Nr = 10
    //   KEY size = 10 (AES-192): Nr = 12
    //   KEY size = 11 (AES-256): Nr = 14
    assign Nr = {(key_size[1] | key_size[0]), key_size[1], key_size[0], 1'b0};

    always_ff @(posedge gated_clk) begin
        if(!rst_n) begin
            round_cntr <= 0;
            round_cntr_d <= 0;
            ark_enb_n <= 1;
            ark_done_d <= 0;
            keys_received <= 0;
            invARK_done <= 0;
            for(int i=0; i<240; i++) key_mem[i/60][i%60] <= 8'h00;
            for(int i=0; i<16; i++) invAddRoundKeyOut[i/4][i%4] <= 8'h00;
        end
        else begin
            if(!enb_n) begin
                if(!keys_received) begin
                    ark_enb_n <= 0;  // enabling AddRoundKey
                    invARK_done <= 0;

                    // storing KEYs in memory
                    for(int i=0; i<4; i++)  // loading memory with KEYs
                        {key_mem[3][(6'(round_cntr)<<2)+6'(i)], key_mem[2][(6'(round_cntr)<<2)+6'(i)], key_mem[1][(6'(round_cntr)<<2)+6'(i)], key_mem[0][(6'(round_cntr)<<2)+6'(i)]}
                            <= (ark_done) ? {exp_key[3][i], exp_key[2][i], exp_key[1][i], exp_key[0][i]} 
                                          : {key_mem[3][(6'(round_cntr)<<2)+6'(i)], key_mem[2][(6'(round_cntr)<<2)+6'(i)], key_mem[1][(6'(round_cntr)<<2)+6'(i)], key_mem[0][(6'(round_cntr)<<2)+6'(i)]};
                    
                    // in AES-256 ark_done stays high for consecutive cycles resulting in round_cntr getting ahead of KEY reception
                    // so holding off round_cntr for another cycle to make sure round_cntr and KEY reception stay in sync
                    if(key_size == 2'b11 && round_cntr < 2) round_cntr <= (ark_done && round_cntr == round_cntr_d) ? round_cntr + 1 : round_cntr;
                    else round_cntr <= (ark_done && !ark_done_d) ? ((round_cntr == Nr) ? 0 : round_cntr + 1) : round_cntr;
                    
                    // keys_received is changed when rising-edge of ark_done is detected as ark_done might stay 
                    // high for multiple cycles which might result in unnecessary change in keys_received
                    keys_received <= (round_cntr == Nr && ark_done && !ark_done_d) ? 1 : 0;
                end
                else begin  // since all KEYs have been received, KEYs will be added to input state matrix
                    ark_enb_n <= 1;  // disabling AddRoundKey since all required KEYs are obtained

                    for(int i=0; i<4; i++)
                        {invAddRoundKeyOut[3][i], invAddRoundKeyOut[2][i], invAddRoundKeyOut[1][i], invAddRoundKeyOut[0][i]} <= 
                            {state[3][i], state[2][i], state[1][i], state[0][i]} ^ {key_mem[3][(6'(invCipher_round)<<2)+6'(i)], key_mem[2][(6'(invCipher_round)<<2)+6'(i)], key_mem[1][(6'(invCipher_round)<<2)+6'(i)], key_mem[0][(6'(invCipher_round)<<2)+6'(i)]};

                    keys_received <= (invCipher_round == 0) ? 0 : 1;  // again returns to KEY reception path when invCipher consumes last KEY word from the memory
                    invARK_done <= 1;
                end

                ark_done_d <= ark_done;  // delayed version of ark_done which helps to detect edges of ark_done
                round_cntr_d <= round_cntr;  // helps to hold off round_cntr
            end
            else begin
                ark_enb_n <= 1;
                ark_done_d <= 0;
                invARK_done <= 0;
                round_cntr <= round_cntr;
                round_cntr_d <= round_cntr_d;
                keys_received <= keys_received;
                key_mem <= key_mem;
                invAddRoundKeyOut <= invAddRoundKeyOut;
            end
        end
    end
endmodule