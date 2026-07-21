/**
 * This Sbox module is designed to operate on both state matrix and a single word (32-bits) itself.
 * The reason this block is designd that way is AddRoundKey also uses this Sbox to compute subBytes of word in KeyExpansion logic.
 * Sbox needs 448 random bits when it's operating on state matrix because each byte uses 28 random bits. 
 * When operating on word it only needs 112 random bits. So random number input port accountes for both accordingly.
 * When Sbox is working with only a single word then it doesn't need VALID signal from TRNG because all required random bits are provided
   upfront in CIPHER block. So, it doesn't have to drive READY signal as it's not looking for any handshake with TRNG.
 * 2 enable signals are present in port list which are enb_n and _enb_n. When enb_n is low whole SBox is enabled and when _enb_n is low only 
   a portion of SBox is enabled. Both of enable signals can't be low, this is an invalid configuration.
**/

import type_defs_pkg::*;
import composite_field_math_pkg::*;

module sbox(
    output u128_t subBytes,  // subByte of each element of state array
    output logic sbox_ready,  // tells trng that s-box is ready to accept random bits
    output logic sbox_done_pulse,  // indicates that Sbox has computed required subBytes
    output logic rst_trng,  // resets TRNG when health test results in fatal failures
    input logic trng_dead_flag,  // asserted by TRNG to signify that it has encountered fatal failure
    input u128_t state,  // 128-bit input state matrix to s-box
    input logic [1679:0] rand_num,  // random bits from TRNG
    input logic trng_key_valid,  // asserted by TRNG when it has random bits to give to s-box
    input logic proceed,  // asserted by CIPHER/AddRoundKey to allow SBox to advance to next state only when CIPHER/AddRoundKey has aknowledged
    input logic enb_n,  // this signal enables all of SBox which can operate on state matrix
    input logic _enb_n,  // this signal enable only a portion of SBox which is enough to process a 32-bit word
    input logic rst_n, clk);

    logic gated_clk;  // gated clock to reduce dynamic power consumption
    u128_t masked_a_byte;  // to store a1 and a0
    u128_t denominator;  // stores denominator value corresponding to every state element
    u128_t masked_d_inv;  // stores inverse of denominator of every state element
    u256_t masks_of_A_inv;  // stores every element of state array in tower field inversion form
    u256_t masks_of_b_inv;  // stores inverse of every elemnt of state array
    logic [16:0][1:0] sbox_cntr;  // keeps track of how many times Sbox has computed subBytes
    logic sbox_done, sbox_done_d;  // these are registered done signals which stay high more than 1 cycle
    logic [15:0][10:0] slice_sel;  // required to select particular slice of rand_num
    sbox_states fsm_state;
    genvar i;

    // ICG cell to reduce dynamic power consumption
    icg ICG(gated_clk, (enb_n ^ _enb_n | ~rst_n), clk);

    // separate sequental block is used to update FSM states, sbox_done and rst_trng so as to avoid being driven for multiple times
    always_ff @(posedge gated_clk) begin
        if(!rst_n) begin
            sbox_ready <= 0;
            rst_trng <= 1;
            sbox_done <= 0;
            sbox_done_d <= 0;
            sbox_cntr[0] <= 0;
            fsm_state <= INIT;
        end
        else begin
            if((!enb_n && _enb_n) || (enb_n && !_enb_n)) begin  // whole SBox or SBox that operates on a word is enabled which operates on state matrix
                case(fsm_state)
                    INIT: begin  // this state handles the handshake and accepting SBox inputs
                        // s-box is ready to accept random bits only when all random bits are consumed and this signal functions only when enb_n = 0 else it freezes
                        sbox_ready <= (enb_n && !_enb_n) ? 0 : ((sbox_cntr[0] == 0) ? 1 : 0);
                        rst_trng <= 1;
                        sbox_done <= 0;

                        if(trng_dead_flag) fsm_state <= RESET_TRNG;
                        else begin
                            if(enb_n && !_enb_n) fsm_state <= TOWER_FIELD;  // when only portion of SBox is required
                            else begin  // when whole SBox is enabled
                                // fsm waits for both signals so TRNG updating random bits and SBox transitioning to next happen stay in sync
                                // which lets TOWER_FIELD state get actual new batch of random bits from TRNG 
                                if(sbox_cntr[0] == 0) fsm_state <= (trng_key_valid && sbox_ready) ? TOWER_FIELD : INIT;
                                else fsm_state <= TOWER_FIELD;
                            end
                        end
                    end
                    TOWER_FIELD: begin
                        sbox_ready <= 0;
                        rst_trng <= 1;
                        sbox_done <= 0;
                        fsm_state <= (trng_dead_flag) ? RESET_TRNG : MASKED_D;
                    end 
                    MASKED_D: begin
                        sbox_ready <= 0;
                        rst_trng <= 1;
                        sbox_done <= 0;
                        fsm_state <= (trng_dead_flag) ? RESET_TRNG : MASKED_D_INV;
                    end
                    MASKED_D_INV: begin
                        sbox_ready <= 0;
                        rst_trng <= 1;
                        sbox_done <= 0;
                        fsm_state <= (trng_dead_flag) ? RESET_TRNG : MASKED_A_INV;
                    end
                    MASKED_A_INV: begin
                        sbox_ready <= 0;
                        rst_trng <= 1;
                        sbox_done <= 0;
                        fsm_state <= (trng_dead_flag) ? RESET_TRNG : MASKED_B_INV;
                    end
                    MASKED_B_INV: begin
                        sbox_ready <= 0;
                        rst_trng <= 1;
                        sbox_done <= 0;
                        fsm_state <= (trng_dead_flag) ? RESET_TRNG : SUB_BYTES;
                    end
                    SUB_BYTES: begin
                        sbox_ready <= 0;
                        rst_trng <= 1;

                        // updating since Sbox has computed subBytes only when enb_n is low
                        if(enb_n && !_enb_n) sbox_cntr[0] <= sbox_cntr[0];
                        else sbox_cntr[0] <= (!proceed) ? sbox_cntr[0] : ((sbox_cntr[0] == 2) ? 0 : sbox_cntr[0] + 1);

                        sbox_done <= 1;  // asserting this signal to signify that subBytes have been computed
                        fsm_state <= (trng_dead_flag) ? RESET_TRNG : ((proceed) ? INIT : SUB_BYTES);  // Sbox will advance to next state only when CIPHER/AddRoundKey has aknowledged
                    end
                    RESET_TRNG: begin
                        rst_trng <= 0;  // resets TRNG as fatal failure has occurred
                        sbox_ready <= 0;
                        sbox_done <= 0;
                        sbox_cntr[0] <= 0;
                        fsm_state <= INIT;
                    end
                endcase
            end
            else begin  // as Sbox is disabled it will freeze it's state
                sbox_ready <= 0;
                rst_trng <= 1;  // as Sbox is disabled, it's not going to drive TRNG's reset
                sbox_done <= 0;  // as Sbox is in freeze state it's not going to assert done signal
                sbox_cntr[0] <= sbox_cntr[0];
                fsm_state <= fsm_state;  // state has been freezed or on hold
            end

            sbox_done_d <= sbox_done;  // 1 cycle delayed version of sbox_done is used to generate a pulse of 1 clock cycle when Sbox has computed subBytes
        end
    end

    // slice_sel helps to select required 448-bit/112-bit slice of rand_num 
    generate
        for(i=0; i<16; i++) begin
            always_comb begin
                case(sbox_cntr[i+1])
                    2'b00: slice_sel[i] = (!enb_n && _enb_n) ? 0 : ((enb_n && !_enb_n) ? 448 : 0);
                    2'b01: slice_sel[i] = (!enb_n && _enb_n) ? 560 : ((enb_n && !_enb_n) ? 1008 : 0);
                    2'b10: slice_sel[i] = (!enb_n && _enb_n) ? 1120 : ((enb_n && !_enb_n) ? 1568 : 0);
                    default: slice_sel[i] = 0;
                endcase
            end
        end
    endgenerate

    assign sbox_done_pulse = sbox_done && !sbox_done_d;  // generating a pulse of 1 clock cycle when Sbox has computed subBytes

    // this block computes corresponding values for every byte of input state array
    generate
        for(i=0; i<4; i++) begin  // this portion is common for both modes
            always_ff@(posedge gated_clk) begin
                if(!rst_n) begin
                    masked_a_byte[(8*i) +: 8] <= 0;
                    denominator[(8*i) +: 8] <= 0;
                    masked_d_inv[(8*i) +: 8] <= 0;
                    masks_of_A_inv[(16*i) +: 16] <= 0;
                    masks_of_b_inv[(16*i) +: 16] <= 0;
                    subBytes[(8*i) +: 8] <= 0;
                end
                else begin
                    if((!enb_n && _enb_n) || (enb_n && !_enb_n)) begin  // since Sbox is enable it will continue to operate
                        // the combinational block is broken into individual fsm states so that clock time peroid
                        // can be >= worst individual sub block's critical path delay instead of sum of delays of all sub blocks
                        case(fsm_state)
                            INIT: begin  // this state doesn't handle any computation, it just handles handshake and accepting inputs
                                masked_a_byte[(8*i) +: 8] <= masked_a_byte[(8*i) +: 8];
                                denominator[(8*i) +: 8] <= denominator[(8*i) +: 8];
                                masked_d_inv[(8*i) +: 8] <= masked_d_inv[(8*i) +: 8];
                                masks_of_A_inv[(16*i) +: 16] <= masks_of_A_inv[(16*i) +: 16];
                                masks_of_b_inv[(16*i) +: 16] <= masks_of_b_inv[(16*i) +: 16];
                                subBytes[(8*i) +: 8] <= subBytes[(8*i) +: 8];
                            end
                            TOWER_FIELD: masked_a_byte[(8*i) +: 8] <= tower_field(state[(8*i) +: 8], {rand_num[((28*i)+4+slice_sel[i]) +: 4], rand_num[((28*i)+slice_sel[i]) +: 4]});
                            MASKED_D: denominator[(8*i) +: 8] <= masked_denominator(masked_a_byte[(8*i) +: 8], {rand_num[((28*i)+8+slice_sel[i]) +: 4], rand_num[((28*i)+4+slice_sel[i]) +: 4], rand_num[((28*i)+slice_sel[i]) +: 4]});
                            MASKED_D_INV: masked_d_inv[(8*i) +: 8] <= masked_d_inverse(denominator[(8*i) +: 8], {rand_num[((28*i)+16+slice_sel[i]) +: 4], rand_num[((28*i)+12+slice_sel[i]) +: 4]});
                            MASKED_A_INV: masks_of_A_inv[(16*i) +: 16] <= masked_A_inverse(masked_d_inv[(8*i) +: 8], masked_a_byte[(8*i) +: 8], {rand_num[((28*i)+24+slice_sel[i]) +: 4], rand_num[((28*i)+20+slice_sel[i]) +: 4], rand_num[((28*i)+4+slice_sel[i]) +: 4], rand_num[((28*i)+slice_sel[i]) +: 4]});
                            MASKED_B_INV: masks_of_b_inv[(16*i) +: 16] <= masked_b_inverse(masks_of_A_inv[(16*i) +: 16]);
                            SUB_BYTES: begin
                                // every bute has it's local sbox_cntr so a large fan out can be avoid which might improve timing performance
                                if(enb_n && !_enb_n) sbox_cntr[i+1] <= sbox_cntr[i+1];
                                else sbox_cntr[i+1] <= (!proceed) ? sbox_cntr[i+1] : ((sbox_cntr[i+1] == 2) ? 0 : sbox_cntr[i+1] + 1);
                                subBytes[(8*i) +: 8] <= affine_transformation(masks_of_b_inv[(16*i) +: 16]);
                            end
                            default: begin
                                sbox_cntr[i+1] <= 0;
                                masked_a_byte[(8*i) +: 8] <= 0;
                                denominator[(8*i) +: 8] <= 0;
                                masked_d_inv[(8*i) +: 8] <= 0;
                                masks_of_A_inv[(16*i) +: 16] <= 0;
                                masks_of_b_inv[(16*i) +: 16] <= 0;
                                subBytes[(8*i) +: 8] <= 0;
                            end
                        endcase
                    end
                    else begin  // as Sbox is disabled it will freeze it's state or stays on hold
                        sbox_cntr[i+1] <= sbox_cntr[i+1];
                        masked_a_byte[(8*i) +: 8] <= masked_a_byte[(8*i) +: 8];
                        denominator[(8*i) +: 8] <= denominator[(8*i) +: 8];
                        masked_d_inv[(8*i) +: 8] <= masked_d_inv[(8*i) +: 8];
                        masks_of_A_inv[(16*i) +: 16] <= masks_of_A_inv[(16*i) +: 16];
                        masks_of_b_inv[(16*i) +: 16] <= masks_of_b_inv[(16*i) +: 16];
                        subBytes[(8*i) +: 8] <= subBytes[(8*i) +: 8];
                    end
                end
            end
        end

        for(i=4; i<16; i++) begin  // this portion is only functional when SBox is supposed to operate on state matrix
            always_ff@(posedge gated_clk) begin
                if(!rst_n) begin
                    sbox_cntr[i+1] <= 0;
                    masked_a_byte[(8*i) +: 8] <= 0;
                    denominator[(8*i) +: 8] <= 0;
                    masked_d_inv[(8*i) +: 8] <= 0;
                    masks_of_A_inv[(16*i) +: 16] <= 0;
                    masks_of_b_inv[(16*i) +: 16] <= 0;
                    subBytes[(8*i) +: 8] <= 0;
                end
                else begin
                    if(!enb_n && _enb_n) begin  // since whole Sbox is enabled it will continue to operate on state matrix
                        // the combinational block is broken into individual fsm states so that clock time peroid
                        // can be >= worst individual sub block's critical path delay instead of sum of delays of all sub blocks
                        case(fsm_state)
                            INIT: begin  // this state doesn't handle any computation, it just handles handshake and accepting inputs
                                masked_a_byte[(8*i) +: 8] <= masked_a_byte[(8*i) +: 8];
                                denominator[(8*i) +: 8] <= denominator[(8*i) +: 8];
                                masked_d_inv[(8*i) +: 8] <= masked_d_inv[(8*i) +: 8];
                                masks_of_A_inv[(16*i) +: 16] <= masks_of_A_inv[(16*i) +: 16];
                                masks_of_b_inv[(16*i) +: 16] <= masks_of_b_inv[(16*i) +: 16];
                                subBytes[(8*i) +: 8] <= subBytes[(8*i) +: 8];
                            end
                            TOWER_FIELD: masked_a_byte[(8*i) +: 8] <= tower_field(state[(8*i) +: 8], {rand_num[((28*i)+4+slice_sel[i]) +: 4], rand_num[((28*i)+slice_sel[i]) +: 4]});
                            MASKED_D: denominator[(8*i) +: 8] <= masked_denominator(masked_a_byte[(8*i) +: 8], {rand_num[((28*i)+8+slice_sel[i]) +: 4], rand_num[((28*i)+4+slice_sel[i]) +: 4], rand_num[((28*i)+slice_sel[i]) +: 4]});
                            MASKED_D_INV: masked_d_inv[(8*i) +: 8] <= masked_d_inverse(denominator[(8*i) +: 8], {rand_num[((28*i)+16+slice_sel[i]) +: 4], rand_num[((28*i)+12+slice_sel[i]) +: 4]});
                            MASKED_A_INV: masks_of_A_inv[(16*i) +: 16] <= masked_A_inverse(masked_d_inv[(8*i) +: 8], masked_a_byte[(8*i) +: 8], {rand_num[((28*i)+24+slice_sel[i]) +: 4], rand_num[((28*i)+20+slice_sel[i]) +: 4], rand_num[((28*i)+4+slice_sel[i]) +: 4], rand_num[((28*i)+slice_sel[i]) +: 4]});
                            MASKED_B_INV: masks_of_b_inv[(16*i) +: 16] <= masked_b_inverse(masks_of_A_inv[(16*i) +: 16]);
                            SUB_BYTES: begin
                                sbox_cntr[i+1] <= (!proceed) ? sbox_cntr[i+1] : ((sbox_cntr[i+1] == 2) ? 0 : sbox_cntr[i+1] + 1);
                                subBytes[(8*i) +: 8] <= affine_transformation(masks_of_b_inv[(16*i) +: 16]);
                            end
                            default: begin
                                sbox_cntr[i+1] <= 0;
                                masked_a_byte[(8*i) +: 8] <= 0;
                                denominator[(8*i) +: 8] <= 0;
                                masked_d_inv[(8*i) +: 8] <= 0;
                                masks_of_A_inv[(16*i) +: 16] <= 0;
                                masks_of_b_inv[(16*i) +: 16] <= 0;
                                subBytes[(8*i) +: 8] <= 0;
                            end
                        endcase
                    end
                    else begin  // as Sbox is disabled it will freeze it's state or stays on hold
                        sbox_cntr[i+1] <= sbox_cntr[i+1];
                        masked_a_byte[(8*i) +: 8] <= masked_a_byte[(8*i) +: 8];
                        denominator[(8*i) +: 8] <= denominator[(8*i) +: 8];
                        masked_d_inv[(8*i) +: 8] <= masked_d_inv[(8*i) +: 8];
                        masks_of_A_inv[(16*i) +: 16] <= masks_of_A_inv[(16*i) +: 16];
                        masks_of_b_inv[(16*i) +: 16] <= masks_of_b_inv[(16*i) +: 16];
                        subBytes[(8*i) +: 8] <= subBytes[(8*i) +: 8];
                    end
                end
            end
        end
    endgenerate
endmodule
