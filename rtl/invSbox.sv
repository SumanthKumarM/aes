/**
 * This Inverse SBox utilizes same composite field math as SBox and align them as per inverse SBox algorithm
 * TRNG and inverse SBox have same handshake as SBox and this block consumes 1344 random bits from TRNG and 
   consumption is similar to SBox when it operates in matrix mode
**/

import type_defs_pkg::*;
import composite_field_math_pkg::*;

module invSbox(
    output u128_t invSubBytes,  // invSubByte of each encrypted element of state array
    output logic invSbox_ready,  // tells TRNG that invSbox is ready to accept random bits
    output logic invSbox_done_pulse,  // indicates that invSbox has computed required invSubBytes
    output logic rst_trng,  // resets TRNG when health test results in fatal failures
    input u128_t state,  // 128-bit input state matrix to invSbox
    input logic [1343:0] rand_num,  // 1344-bit random number from TRNG to be used in invSbox
    input logic trng_dead_flag,  // asserted by TRNG to signify that it has encountered fatal failure
    input logic trng_key_valid,  // asserted by TRNG when it has random bits to give
    input logic proceed,  // asserted by invCIPHER to allow invSBox to advance to next state only when invCIPHER has aknowledged
    input logic enb_n,  // active low enable signal to invSbox
    input logic rst_n, clk);

    logic gated_clk;  // gated clock to reduce dynamic power consumption
    u128_t masked_a_byte;  // to store a1 and a0
    u128_t denominator;  // stores denominator value corresponding to every state element
    u128_t masked_d_inv;  // stores inverse of denominator of every state element
    u256_t masks_of_A_inv;  // stores every element of state array in tower field inversion form
    logic [16:0][1:0] invSbox_cntr;  // keeps track of how many times invSbox has computed invSubBytes
    logic invSbox_done, invSbox_done_d;  // these are registered done signals which stay high more than 1 cycle
    logic [15:0][9:0] slice_sel;  // required to select particular slice of rand_num
    invSbox_states fsm_state;
    genvar i;

    // ICG cell to reduce dynamic power consumption
    icg ICG(gated_clk, ~enb_n, clk);

    // separate sequental block is used to update FSM states, sbox_done and rst_trng so as to avoid being driven for multiple times
    always_ff @(posedge gated_clk) begin
        if(!rst_n) begin
            invSbox_ready <= 0;
            rst_trng <= 1;
            invSbox_done <= 0;
            invSbox_done_d <= 0;
            invSbox_cntr[0] <= 0;
            fsm_state <= ISB_INIT;
        end
        else begin
            if(!enb_n) begin  // invSbox functions since it's enabled
                case(fsm_state)
                    ISB_INIT: begin  // this state handles the handshake and accepting invSBox inputs
                        // invSbox is ready to accept random bits only when all random bits are consumed
                        invSbox_ready <= (invSbox_cntr[0] == 0) ? 1 : 0;
                        rst_trng <= 1;
                        invSbox_done <= 0;

                        if(trng_dead_flag) fsm_state <= ISB_RESET_TRNG;
                        else begin
                            if(invSbox_cntr[0] == 0) fsm_state <= (trng_key_valid && invSbox_ready) ? INV_AFFINE_TOWER_FIELD : ISB_INIT;
                            else fsm_state <= INV_AFFINE_TOWER_FIELD;
                        end
                    end
                    INV_AFFINE_TOWER_FIELD: begin
                        invSbox_ready <= 0;
                        rst_trng <= 1;
                        invSbox_done <= 0;
                        fsm_state <= (trng_dead_flag) ? ISB_RESET_TRNG : ISB_MASKED_D;
                    end
                    ISB_MASKED_D: begin
                        invSbox_ready <= 0;
                        rst_trng <= 1;
                        invSbox_done <= 0;
                        fsm_state <= (trng_dead_flag) ? ISB_RESET_TRNG : ISB_MASKED_D_INV;
                    end
                    ISB_MASKED_D_INV: begin
                        invSbox_ready <= 0;
                        rst_trng <= 1;
                        invSbox_done <= 0;
                        fsm_state <= (trng_dead_flag) ? ISB_RESET_TRNG : ISB_MASKED_A_INV;
                    end
                    ISB_MASKED_A_INV: begin
                        invSbox_ready <= 0;
                        rst_trng <= 1;
                        invSbox_done <= 0;
                        fsm_state <= (trng_dead_flag) ? ISB_RESET_TRNG : INV_SUB_BYTES;
                    end
                    INV_SUB_BYTES: begin
                        invSbox_ready <= 0;
                        rst_trng <= 1;
                        invSbox_done <= 1;  // indicates that InvSbox is done computing invSubBytes
                        invSbox_cntr[0] <= (!proceed) ? invSbox_cntr[0] : ((invSbox_cntr[0] == 2) ? 0 : invSbox_cntr[0] + 1);
                        fsm_state <= (trng_dead_flag) ? ISB_RESET_TRNG : ((proceed) ? ISB_INIT : INV_SUB_BYTES);
                    end
                    ISB_RESET_TRNG: begin
                        rst_trng <= 0;  // resets TRNG as fatal error has occurred
                        invSbox_ready <= 0;
                        invSbox_done <= 0;
                        invSbox_cntr[0] <= 0;
                        fsm_state <= ISB_INIT;
                    end
                    default: begin
                        invSbox_ready <= 0;
                        rst_trng <= 1;
                        invSbox_done <= 0;
                        invSbox_cntr[0] <= 0;
                        fsm_state <= ISB_INIT;
                    end
                endcase
            end
            else begin  // invSbox freezes since it's disabled
                invSbox_done <= 0;
                rst_trng <= 1;
                invSbox_ready <= 0;
                invSbox_cntr[0] <= invSbox_cntr[0];
                fsm_state <= fsm_state;
            end

            invSbox_done_d <= invSbox_done;  // 1 cycle delayed version of sbox_done is used to generate a pulse of 1 clock cycle when Sbox has computed subBytes
        end
    end

    // slice_sel helps to select required 448-bit slice of rand_num 
    generate
        for(i=0; i<16; i++) begin
            always_comb begin
                case(invSbox_cntr[i+1])
                    2'b00: slice_sel[i] = 0;
                    2'b01: slice_sel[i] = 448;
                    2'b10: slice_sel[i] = 896;
                    default: slice_sel[i] = 0;
                endcase
            end
        end
    endgenerate

    assign invSbox_done_pulse = invSbox_done && !invSbox_done_d;  // generating a pulse of 1 clock cycle when Sbox has computed subBytes

    // this block computes corresponding values for every byte of input state array
    generate
        for(i=0; i<16; i++) begin
            always_ff @(posedge gated_clk) begin
                if(!rst_n) begin
                    invSbox_cntr[i+1] <= 0;
                    masked_a_byte[(8*i) +: 8] <= 0;
                    denominator[(8*i) +: 8] <= 0;
                    masked_d_inv[(8*i) +: 8] <= 0;
                    masks_of_A_inv[(16*i) +: 16] <= 0;
                    invSubBytes[(8*i) +: 8] <= 0;
                end
                else begin
                    if(!enb_n) begin
                        case(fsm_state)
                            ISB_INIT: begin  // this state doesn't handle any computation, it just handles handshake and accepting inputs
                                masked_a_byte[(8*i) +: 8] <= masked_a_byte[(8*i) +: 8];
                                denominator[(8*i) +: 8] <= denominator[(8*i) +: 8];
                                masked_d_inv[(8*i) +: 8] <= masked_d_inv[(8*i) +: 8];
                                masks_of_A_inv[(16*i) +: 16] <= masks_of_A_inv[(16*i) +: 16];
                                invSubBytes[(8*i) +: 8] <= invSubBytes[(8*i) +: 8];
                            end
                            INV_AFFINE_TOWER_FIELD: masked_a_byte[(8*i) +: 8] <= tower_field(invAffine(state[(8*i) +: 8]), {rand_num[((28*i)+4+slice_sel[i]) +: 4], rand_num[((28*i)+slice_sel[i]) +: 4]});
                            ISB_MASKED_D: denominator[(8*i) +: 8] <= masked_denominator(masked_a_byte[(8*i) +: 8], {rand_num[((28*i)+8+slice_sel[i]) +: 4], rand_num[((28*i)+4+slice_sel[i]) +: 4], rand_num[((28*i)+slice_sel[i]) +: 4]});
                            ISB_MASKED_D_INV: masked_d_inv[(8*i) +: 8] <= masked_d_inverse(denominator[(8*i) +: 8], {rand_num[((28*i)+16+slice_sel[i]) +: 4], rand_num[((28*i)+12+slice_sel[i]) +: 4]});
                            ISB_MASKED_A_INV: masks_of_A_inv[(16*i) +: 16] <= masked_A_inverse(masked_d_inv[(8*i) +: 8], masked_a_byte[(8*i) +: 8], {rand_num[((28*i)+24+slice_sel[i]) +: 4], rand_num[((28*i)+20+slice_sel[i]) +: 4], rand_num[((28*i)+4+slice_sel[i]) +: 4], rand_num[((28*i)+slice_sel[i]) +: 4]});
                            INV_SUB_BYTES: begin
                                // every bute has it's local sbox_cntr so a large fan out can be avoid which might improve timing performance
                                invSbox_cntr[i+1] <= (!proceed) ? invSbox_cntr[i+1] : ((invSbox_cntr[i+1] == 2) ? 0 : invSbox_cntr[i+1] + 1);
                                invSubBytes[(8*i) +: 8] <= invBasis_masks_xor(masks_of_A_inv[(16*i) +: 16]);
                            end
                            default: begin
                                invSbox_cntr[i+1] <= 0;
                                masked_a_byte[(8*i) +: 8] <= 0;
                                denominator[(8*i) +: 8] <= 0;
                                masked_d_inv[(8*i) +: 8] <= 0;
                                masks_of_A_inv[(16*i) +: 16] <= 0;
                                invSubBytes[(8*i) +: 8] <= 0;
                            end 
                        endcase
                    end
                    else begin
                        invSbox_cntr[i+1] <= invSbox_cntr[i+1];
                        masked_a_byte[(8*i) +: 8] <= masked_a_byte[(8*i) +: 8];
                        denominator[(8*i) +: 8] <= denominator[(8*i) +: 8];
                        masked_d_inv[(8*i) +: 8] <= masked_d_inv[(8*i) +: 8];
                        masks_of_A_inv[(16*i) +: 16] <= masks_of_A_inv[(16*i) +: 16];
                        invSubBytes[(8*i) +: 8] <= invSubBytes[(8*i) +: 8];
                    end
                end
            end
        end
    endgenerate
endmodule