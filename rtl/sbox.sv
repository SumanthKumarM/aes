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

// this package holds the core logic of SBox
package sbox_funcs;
    import type_defs_pkg::*;

    // Multiplication in GF(2^4). Reduction polynomial is x^4 + x + 1. So reduction constant is (0011)
    function automatic unibble xTimes(input unibble m);
        return (m[3]) ? ((m << 1) ^ 4'b0011) : (m << 1);
    endfunction

    // multiplication of 2 values in GF(2^4)
    function automatic unibble gf4_mul(input unibble m, input unibble n);
        unibble x, x_sqr, x_cube, result;

        x = xTimes(n);
        x_sqr = xTimes(x);
        x_cube = xTimes(x_sqr);

        // m * n = m[0]*n + m[1]*(x*n) + m[2]*(x^2*b) + m[3]*(x^3*b)
        result = (m[0] ? n : 4'h0) ^ (m[1] ? x : 4'h0) ^ (m[2] ? x_sqr : 4'h0) ^ (m[3] ? x_cube : 4'h0);
        return result;
    endfunction

    // computes square of an element
    function automatic unibble sqr_func(input unibble inp);
        unibble inp_sqr;

        inp_sqr[3] = inp[3];
        inp_sqr[2] = inp[3] ^ inp[1];
        inp_sqr[1] = inp[2];
        inp_sqr[0] = inp[2] ^ inp[0];
        return inp_sqr;
    endfunction

    // masked multiplication for non-linear multiplications
    function automatic ubyte masked_mul(
        input ubyte in1_byte,  // concatenation of masked shares of one variable
        input ubyte in2_byte,  // concatenation of masked shares of another variable
        input unibble rand_word);  // randomness to be induced in the masked multiplication

        ubyte p;  // partial multiplication terms

        // computing p1 = (a1 * b1) xor R
        p[3:0] = gf4_mul(in1_byte[7:4], in2_byte[7:4]) ^ rand_word;

        // computing p2 = (a1 * b1) xor (a2 * b1) xor (a2 * b2) xor R
        p[7:4] = gf4_mul(in1_byte[7:4], in2_byte[3:0]) ^ gf4_mul(in1_byte[3:0], in2_byte[7:4]) ^ gf4_mul(in1_byte[3:0], in2_byte[3:0]) ^ rand_word;
        return p;
    endfunction

    // converting bytes to tower field representation and computing their masks (basis transformation)
    function automatic ubyte tower_field(
        input ubyte s_byte,  // raw state array element
        input ubyte rand_byte);  // random numbers used in masking tower field elements {a1r, a0r}

        ubyte a, masked_a;

        // basis transformation
        a[7] = s_byte[7] ^ s_byte[5];
        a[6] = s_byte[7] ^ s_byte[5] ^ s_byte[3] ^ s_byte[2];
        a[5] = s_byte[7] ^ s_byte[6] ^ s_byte[4] ^ s_byte[1];
        a[4] = s_byte[6] ^ s_byte[5] ^ s_byte[4];
        a[3] = s_byte[4] ^ s_byte[3];
        a[2] = s_byte[7] ^ s_byte[6] ^ s_byte[5] ^ s_byte[4] ^ s_byte[3] ^ s_byte[2];
        a[1] = s_byte[2];
        a[0] = s_byte[7] ^ s_byte[5] ^ s_byte[0];

        // creating masked shares for a1 (a[7:4]) and a0 (a[3:0])
        masked_a[7:4] = a[7:4] ^ rand_byte[7:4];  // so a1 can be split into a1_m (masked_a[7:4]) xor rand_w1
        masked_a[3:0] = a[3:0] ^ rand_byte[3:0];  // so a0 can be split into a0_m (masked_a[3:0]) xor rand_w0

        return masked_a; 
    endfunction

    // D = (a1^2)*(lambda) xor (a1 * a0) xor (a0^2)
    function automatic ubyte masked_denominator(
        input ubyte masked_a,  // concatenation of masks of tower field elements {a1m, a0m}
        input logic [11:0] rand_byte);  // random numbers used in masking {rand_w2, rand_w1, rand_w0}

        unibble a1m_sqr, a1r_sqr, a1_sqr, a0m_sqr, a0r_sqr, a0_sqr;
        unibble a1_sqr_lambda, a1_x_a0, a1m_sqr_lambda, a1r_sqr_lambda;
        unibble d1, d2;
        ubyte p;

        a1m_sqr = sqr_func(masked_a[7:4]);  // square of masked share a1m
        a1r_sqr = sqr_func(rand_byte[7:4]);  // square of random share a1r
        a1_sqr = a1m_sqr ^ a1r_sqr;  // computing a1^2 which is a1^2 = a1m^2 xor a1r^2

        a0m_sqr = sqr_func(masked_a[3:0]);  // square of masked share a0m
        a0r_sqr = sqr_func(rand_byte[3:0]);  // square of random share a0r
        a0_sqr = a0m_sqr ^ a0r_sqr;  // computing a0^2 which is a0^2 = a0m^2 xor a0r^2

        a1_sqr_lambda = xTimes(xTimes(xTimes(a1_sqr)));  // (a1^2)*lambda where lambda = 8 (x^3), a1^2 * x^3  
        a1m_sqr_lambda = xTimes(xTimes(xTimes(a1m_sqr)));  // (a1m^2)*lambda where lambda = 8 (x^3), a1^2 * x^3
        a1r_sqr_lambda = xTimes(xTimes(xTimes(a1r_sqr)));  // (a1r^2)*lambda where lambda = 8 (x^3), a1^2 * x^3 

        // computing a1 * a0, since this multiplication is non-linear "masked multiplication" is used
        p = masked_mul({masked_a[7:4], rand_byte[7:4]}, {masked_a[3:0], rand_byte[3:0]}, rand_byte[11:8]);  // rand_byte[11:8] = rand_w2
        a1_x_a0 = p[7:4] ^ p[3:0];  // a1 * a0 = p2 xor p1

        // computing masks of denominator D
        d1 = a1m_sqr_lambda ^ p[3:0] ^ a0m_sqr;  // d1 = ((a1m)^2 * lambda) xor p1 xor (a0m)^2
        d2 = a1r_sqr_lambda ^ p[7:4] ^ a0r_sqr;  // d2 = ((a1r)^2 * lambda) xor p2 xor (a0r)^2

        return {d2, d1};
    endfunction

    // computing inverse of D in masked form
    function automatic ubyte masked_d_inverse(
        input ubyte d,  // concatenation of masks of denominator {d2, d1}
        input ubyte rand_byte);  // random number used in masked multiplication {rand_w4, rand_w3}

        unibble d1_sqr, d2_sqr, d1_pow4, d2_pow4, d1_pow8, d2_pow8;
        unibble q1, q2, d_pow8_x_d_pow4, e1, e2;

        d1_sqr = sqr_func(d[3:0]);  // square of masked share d1
        d2_sqr = sqr_func(d[7:4]);  // square of masked share d2

        d1_pow4 = sqr_func(d1_sqr);  // masked share d1 raised to power 4
        d2_pow4 = sqr_func(d2_sqr);  // masked share d1 raised to power 4

        d1_pow8 = sqr_func(d1_pow4);  // masked share d1 raised to power 8
        d2_pow8 = sqr_func(d2_pow4);  // masked share d1 raised to power 8

        // computing d^8 * d^4
        q1 = gf4_mul(d1_pow8, d1_pow4) ^ rand_byte[3:0];  
        q2 = gf4_mul(d1_pow8, d2_pow4) ^ gf4_mul(d2_pow8, d1_pow4) ^ gf4_mul(d2_pow8, d2_pow4) ^ rand_byte[3:0];
        d_pow8_x_d_pow4 = q1 ^ q2;

        // computing masks of (d^8 * d^4) * d^2 which is inverse of d
        e1 = gf4_mul(q1, d1_sqr) ^ rand_byte[7:4];
        e2 = gf4_mul(q1, d2_sqr) ^ gf4_mul(q2, d1_sqr) ^ gf4_mul(q2, d2_sqr) ^ rand_byte[7:4];
        // so inverse of d is (e1 xor e2)

        return {e2, e1};
    endfunction

    // computing tower field inversion that is A^-1 in masked form
    function automatic logic [15:0] masked_A_inverse(
        input ubyte d_inv_masks,  // masks of inverse of denominator
        input ubyte a_masks,  // masks of tower field representation of state array byte
        input logic [15:0] rand_word);  // concatenation of random words {rand_w6, rand_w5, rand_w1, rand_w0}

        unibble f1, f2, g1, g2;
        logic [1:0][3:0] temp;

        temp[0] = a_masks[7:4] ^ a_masks[3:0];  // a1m xor a0m
        temp[1] = rand_word[7:4] ^ rand_word[3:0];  // a1r xor a0r

        // computing new_a1
        f1 = gf4_mul(d_inv_masks[3:0], a_masks[7:4]) ^ rand_word[11:8];  // (e1 * a1m) xor rand_w5
        f2 = gf4_mul(d_inv_masks[3:0], rand_word[7:4]) ^ gf4_mul(d_inv_masks[7:4], a_masks[7:4]) ^
             gf4_mul(d_inv_masks[7:4], rand_word[7:4]) ^ rand_word[11:8];  // (e1 * a1r) xor (e2 * a1m) xor (e2 * a1r) xor rand_w5
        // so new_a1 = f1 ^ f2;

        // computing new_a0
        g1 = gf4_mul(d_inv_masks[3:0], temp[0]) ^ rand_word[15:12];  // (e1 * (a1m xor a0m)) xor rand_w6
        // (e1 * (a1r xor a0r)) xor (e2 * (a1m xor a0m)) xor (e2 * (a1r xor a0r)) xor rand_w6
        g2 = gf4_mul(d_inv_masks[3:0], temp[1]) ^ gf4_mul(d_inv_masks[7:4], temp[0]) ^ gf4_mul(d_inv_masks[7:4], temp[1]) ^ rand_word[15:12];  
        // so new_a0 = g1 ^ g2;
        // now A_inverse = {new_a1, new_a0}

        return {f2, g2, f1, g1};
    endfunction

    // matrix multiplication between inverse basis matrix and a byte
    function automatic ubyte inverse_basis_matrix_mul(input ubyte inp_byte);
        ubyte res;

        res[7] = inp_byte[7] ^ inp_byte[6] ^ inp_byte[4] ^ inp_byte[2];
        res[6] = inp_byte[7] ^ inp_byte[3] ^ inp_byte[2] ^ inp_byte[1];
        res[5] = inp_byte[6] ^ inp_byte[4] ^ inp_byte[2];
        res[4] = inp_byte[7] ^ inp_byte[6] ^ inp_byte[3] ^ inp_byte[1];
        res[3] = inp_byte[7] ^ inp_byte[6] ^ inp_byte[1];
        res[2] = inp_byte[1];
        res[1] = inp_byte[7] ^ inp_byte[5] ^ inp_byte[4];
        res[0] = inp_byte[7] ^ inp_byte[0];
        return res;
    endfunction

    // matrix multiplication between AES standard defined matrix and b_inverse
    function automatic ubyte matrix_mul(input byte b_inv);
        ubyte res;

        res[0] = b_inv[0] ^ b_inv[4] ^ b_inv[5] ^ b_inv[6] ^ b_inv[7];
        res[1] = b_inv[0] ^ b_inv[1] ^ b_inv[5] ^ b_inv[6] ^ b_inv[7];
        res[2] = b_inv[0] ^ b_inv[1] ^ b_inv[2] ^ b_inv[6] ^ b_inv[7];
        res[3] = b_inv[0] ^ b_inv[1] ^ b_inv[2] ^ b_inv[3] ^ b_inv[7];
        res[4] = b_inv[0] ^ b_inv[1] ^ b_inv[2] ^ b_inv[3] ^ b_inv[4];
        res[5] = b_inv[1] ^ b_inv[2] ^ b_inv[3] ^ b_inv[4] ^ b_inv[5];
        res[6] = b_inv[2] ^ b_inv[3] ^ b_inv[4] ^ b_inv[5] ^ b_inv[6];
        res[7] = b_inv[3] ^ b_inv[4] ^ b_inv[5] ^ b_inv[6] ^ b_inv[7];
        return res;
    endfunction

    // converting A inverse back to GF(2^8) basis
    function automatic logic [15:0] masked_b_inverse(
        input logic [15:0] inp_masks);  // masks of new_a1 and new_a0 {f2, g2, f1, g1}

        ubyte b_inv_share1, b_inv_share2;  // shares of b_inverse

        b_inv_share1 = inverse_basis_matrix_mul(inp_masks[7:0]);  // T^-1 * {f1, g1}
        b_inv_share2 = inverse_basis_matrix_mul(inp_masks[15:8]);  // T^-1 * {f2, g2}
        // so b_inverse = b_inv_share1 xor b_inv_share2

        return {b_inv_share2, b_inv_share1};  
    endfunction
    
    // computing affine transformation
    function automatic ubyte affine_transformation(
        input logic [15:0] b_inv_shares);  // shares of b_inverse

        ubyte b_prime_share1, b_prime_share2;
        ubyte temp;

        // computing b_prime_share1
        temp = matrix_mul(b_inv_shares[7:0]);  // A * b_inv_share1
        b_prime_share1 = temp ^ 8'h63;  // (A * b_inv_share1) xor {0110_0011}

        // computing b_prime_share2
        b_prime_share2 = matrix_mul(b_inv_shares[15:8]);  // A * b_inv_share2

        return (b_prime_share1 ^ b_prime_share2);
    endfunction
endpackage

module sbox(
    output logic [127:0] subBytes,  // subByte of each element of state array
    output logic sbox_ready,  // tells trng that s-box is ready to accept random bits
    output logic sbox_done_pulse,  // indicates that Sbox has computed required subBytes
    output logic rst_trng,  // resets TRNG when health test results in fatal failures
    input logic trng_dead_flag,  // asserted by TRNG to signify that it has encountered fatal failure
    input logic [127:0] state,  // 128-bit input state matrix to s-box
    input logic [1679:0] rand_num,  // random bits from TRNG
    input logic trng_key_valid,  // asserted by TRNG when it has random bits to give to s-box
    input logic proceed,  // asserted by CIPHER/AddRoundKey to allow SBox to advance to next state only when CIPHER/AddRoundKey has aknowledged
    input logic enb_n,  // this signal enables all of SBox which can operate on state matrix
    input logic _enb_n,  // this signal enable only a portion of SBox which is enough to process a 32-bit word
    input logic rst_n, clk);  

    import sbox_funcs::*;

    logic gated_clk;  // gated clock to reduce dynamic power consumption
    logic [127:0] masked_a_byte;  // to store a1 and a0
    logic [127:0] denominator;  // stores denominator value corresponding to every state element
    logic [127:0] masked_d_inv;  // stores inverse of denominator of every state element
    logic [255:0] masks_of_A_inv;  // stores every element of state array in tower field inversion form
    logic [255:0] masks_of_b_inv;  // stores inverse of every elemnt of state array
    logic [1:0] sbox_cntr;  // keeps track of how many times Sbox has computed subBytes
    logic sbox_done, sbox_done_d;  // these are registered done signals which stay high more than 1 cycle
    logic [10:0] slice_sel;  // required to select particular slice of rand_num
    sbox_states fsm_state;
    genvar i;

    // ICG cell to reduce dynamic power consumption
    icg ICG(gated_clk, (enb_n ^ _enb_n), clk);

    // separate sequental block is used to update FSM states, sbox_done and rst_trng so as to avoid being driven for multiple times
    always_ff @(posedge gated_clk) begin
        if(!rst_n) begin
            sbox_ready <= 0;
            rst_trng <= 0;
            sbox_done <= 0;
            sbox_done_d <= 0;
            sbox_cntr <= 0;
            fsm_state <= INIT;
        end
        else begin
            if((!enb_n && _enb_n) || (enb_n && !_enb_n)) begin  // whole SBox or SBox that operates on a word is enabled which operates on state matrix
                case(fsm_state)
                    INIT: begin  // this state handles the handshake and accepting SBox inputs
                        // s-box is ready to accept random bits only when all random bits are consumed and this signal functions only when enb_n = 0 else it freezes
                        sbox_ready <= (enb_n && !_enb_n) ? sbox_ready : ((sbox_cntr == 0) ? 1 : 0);
                        rst_trng <= 0;
                        sbox_done <= 0;

                        if(trng_dead_flag) fsm_state <= RESET_TRNG;
                        else begin
                            if(enb_n && !_enb_n) fsm_state <= TOWER_FIELD;  // when only portion of SBox is required
                            else begin  // when whole SBox is enabled
                                if(sbox_cntr == 0) fsm_state <= (trng_key_valid) ? TOWER_FIELD : INIT;
                                else fsm_state <= TOWER_FIELD;
                            end
                        end
                    end
                    TOWER_FIELD: begin
                        sbox_ready <= (enb_n && !_enb_n) ? sbox_ready : 0;
                        rst_trng <= 0;
                        sbox_done <= 0;
                        fsm_state <= (trng_dead_flag) ? RESET_TRNG : MASKED_D;
                    end 
                    MASKED_D: begin
                        sbox_ready <= (enb_n && !_enb_n) ? sbox_ready : 0;
                        rst_trng <= 0;
                        sbox_done <= 0;
                        fsm_state <= (trng_dead_flag) ? RESET_TRNG : MASKED_D_INV;
                    end
                    MASKED_D_INV: begin
                        sbox_ready <= (enb_n && !_enb_n) ? sbox_ready : 0;
                        rst_trng <= 0;
                        sbox_done <= 0;
                        fsm_state <= (trng_dead_flag) ? RESET_TRNG : MASKED_A_INV;
                    end
                    MASKED_A_INV: begin
                        sbox_ready <= (enb_n && !_enb_n) ? sbox_ready : 0;
                        rst_trng <= 0;
                        sbox_done <= 0;
                        fsm_state <= (trng_dead_flag) ? RESET_TRNG : MASKED_B_INV;
                    end
                    MASKED_B_INV: begin
                        sbox_ready <= (enb_n && !_enb_n) ? sbox_ready : 0;
                        rst_trng <= 0;
                        sbox_done <= 0;
                        fsm_state <= (trng_dead_flag) ? RESET_TRNG : SUB_BYTES;
                    end
                    SUB_BYTES: begin
                        sbox_ready <= (enb_n && !_enb_n) ? sbox_ready : 0;
                        rst_trng <= 0;
                        sbox_cntr <= (enb_n && !_enb_n) ? sbox_cntr : ((sbox_cntr == 2) ? 0 : sbox_cntr + 1);  // updating since Sbox has computed subBytes only when enb_n is low
                        sbox_done <= 1;  // asserting this signal to signify that subBytes have been computed
                        fsm_state <= (trng_dead_flag) ? RESET_TRNG : ((proceed) ? INIT : SUB_BYTES);  // Sbox will advance to next state only when CIPHER/AddRoundKey has aknowledged
                    end
                    RESET_TRNG: begin
                        rst_trng <= 1;  // resets TRNG as fatal failure has occurred
                        sbox_ready <= 0;
                        sbox_done <= 0;
                        sbox_cntr <= 0;
                        fsm_state <= INIT;
                    end
                endcase
            end
            else begin  // as Sbox is disabled it will freeze it's state
                sbox_ready <= 0;
                rst_trng <= 0;  // as Sbox is disabled, it's not going to drive TRNG's reset
                sbox_done <= 0;  // as Sbox is in freeze state it's not going to assert done signal
                sbox_cntr <= sbox_cntr;
                fsm_state <= fsm_state;  // state has been freezed or on hold
            end

            sbox_done_d <= sbox_done;  // 1 cycle delayed version of sbox_done is used to generate a pulse of 1 clock cycle when Sbox has computed subBytes
        end
    end

    // slice_sel helps to select required 448-bit slice of rand_num 
    always_comb begin
        case(sbox_cntr)
            2'b00: slice_sel = (!enb_n && _enb_n) ? 0 : ((enb_n && !_enb_n) ? 448 : 0);
            2'b01: slice_sel = (!enb_n && _enb_n) ? 560 : ((enb_n && !_enb_n) ? 1008 : 0);
            2'b10: slice_sel = (!enb_n && _enb_n) ? 1120 : ((enb_n && !_enb_n) ? 1568 : 0);
            default: slice_sel = 0;
        endcase
    end

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
                            TOWER_FIELD: masked_a_byte[(8*i) +: 8] <= tower_field(state[(8*i) +: 8], {rand_num[((28*i)+4+slice_sel) +: 4], rand_num[((28*i)+slice_sel) +: 4]});
                            MASKED_D: denominator[(8*i) +: 8] <= masked_denominator(masked_a_byte[(8*i) +: 8], {rand_num[((28*i)+8+slice_sel) +: 4], rand_num[((28*i)+4+slice_sel) +: 4], rand_num[((28*i)+slice_sel) +: 4]});
                            MASKED_D_INV: masked_d_inv[(8*i) +: 8] <= masked_d_inverse(denominator[(8*i) +: 8], {rand_num[((28*i)+16+slice_sel) +: 4], rand_num[((28*i)+12+slice_sel) +: 4]});
                            MASKED_A_INV: masks_of_A_inv[(16*i) +: 16] <= masked_A_inverse(masked_d_inv[(8*i) +: 8], masked_a_byte[(8*i) +: 8], {rand_num[((28*i)+24+slice_sel) +: 4], rand_num[((28*i)+20+slice_sel) +: 4], rand_num[((28*i)+4+slice_sel) +: 4], rand_num[((28*i)+slice_sel) +: 4]});
                            MASKED_B_INV: masks_of_b_inv[(16*i) +: 16] <= masked_b_inverse(masks_of_A_inv[(16*i) +: 16]);
                            SUB_BYTES: subBytes[(8*i) +: 8] <= affine_transformation(masks_of_b_inv[(16*i) +: 16]);
                            default: begin
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
                            TOWER_FIELD: masked_a_byte[(8*i) +: 8] <= tower_field(state[(8*i) +: 8], {rand_num[((28*i)+4+slice_sel) +: 4], rand_num[((28*i)+slice_sel) +: 4]});
                            MASKED_D: denominator[(8*i) +: 8] <= masked_denominator(masked_a_byte[(8*i) +: 8], {rand_num[((28*i)+8+slice_sel) +: 4], rand_num[((28*i)+4+slice_sel) +: 4], rand_num[((28*i)+slice_sel) +: 4]});
                            MASKED_D_INV: masked_d_inv[(8*i) +: 8] <= masked_d_inverse(denominator[(8*i) +: 8], {rand_num[((28*i)+16+slice_sel) +: 4], rand_num[((28*i)+12+slice_sel) +: 4]});
                            MASKED_A_INV: masks_of_A_inv[(16*i) +: 16] <= masked_A_inverse(masked_d_inv[(8*i) +: 8], masked_a_byte[(8*i) +: 8], {rand_num[((28*i)+24+slice_sel) +: 4], rand_num[((28*i)+20+slice_sel) +: 4], rand_num[((28*i)+4+slice_sel) +: 4], rand_num[((28*i)+slice_sel) +: 4]});
                            MASKED_B_INV: masks_of_b_inv[(16*i) +: 16] <= masked_b_inverse(masks_of_A_inv[(16*i) +: 16]);
                            SUB_BYTES: subBytes[(8*i) +: 8] <= affine_transformation(masks_of_b_inv[(16*i) +: 16]);
                            default: begin
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
