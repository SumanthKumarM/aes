typedef logic [7:0] ubyte;
typedef logic [3:0] unibble;
typedef logic [3:0][3:0][7:0] state_t;

module s_box(
    output state_t subBytes,
    input state_t state,
    input logic [447:0] rand_num,
    input logic rst_n, clk);  

    state_t masked_a_byte; // to store a1 and a0
    state_t denominator;  // stores denominator value corresponding to every state element
    state_t masked_d_inv;  // stores inverse of denominator of every state element
    logic [3:0][3:0][15:0] masks_of_A_inv;  // stores every element of state array in tower field inversion form
    state_t masked_a_byte_delay2, masked_a_byte_delay3;  // delayed versions of masked_a_byte
    state_t rand_num_delay2, rand_num_delay3, rand_num_delay4;  // delayed versions of rand_num
    genvar i;

    // Multiplication in GF(2^4). Reduction polynomial is x^4 + x + 1. So reduction constant is (0011)
    function automatic unibble xTimes(input unibble m);
        return (m[3]==1) ? ((m << 1) ^ 4'b0011) : (m << 1);
    endfunction

    // computes square of an element
    function automatic unibble sqr_func(input unibble inp);
        unibble inp_sqr;

        inp_sqr[3] = inp;
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
        p[3:0] = (in1_byte[7:4] & in2_byte[7:4]) ^ rand_word;

        // computing p2 = (a1 * b1) xor (a2 * b1) xor (a2 * b2) xor R
        p[7:4] = (in1_byte[7:4] & in2_byte[3:0]) ^ (in1_byte[3:0] & in2_byte[7:4]) ^
                 (in1_byte[3:0] & in2_byte[3:0]) ^ rand_word;

        return p;
    endfunction

    // converting bytes to tower field representation and computing their masks
    function automatic logic[15:0] tower_field(
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
        q1 = (d1_pow8 & d1_pow4) ^ rand_byte[3:0];  
        q2 = (d1_pow8 & d2_pow4) ^ (d2_pow8 & d1_pow4) ^ (d2_pow8 & d2_pow4) ^ rand_byte[3:0];
        d_pow8_x_d_pow4 = q1 ^ q2;

        // computing masks of (d^8 * d^4) * d^2 which is inverse of d
        e1 = (q1 & d1_sqr) ^ rand_byte[7:4];
        e2 = (q1 & d2_sqr) ^ (q2 & d1_sqr) ^ (q2 & d2_sqr) ^ rand_byte[7:4];
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
        f1 = (d_inv_masks[3:0] & a_masks[7:4]) ^ rand_word[11:8];  // (e1 * a1m) xor rand_w5
        f2 = (d_inv_masks[3:0] & rand_word[7:4]) ^ (d_inv_masks[7:4] & a_masks[7:4]) ^
             (d_inv_masks[7:4] & rand_word[7:4]) ^ rand_word[11:8];  // (e1 * a1r) xor (e2 * a1m) xor (e2 * a1r) xor rand_w5
        // so new_a1 = f1 ^ f2;

        // computing new_a0
        g1 = (e1 & temp[0]) ^ rand_word[15:12];  // (e1 * (a1m xor a0m)) xor rand_w6
        // (e1 * (a1r xor a0r)) xor (e2 * (a1m xor a0m)) xor (e2 * (a1r xor a0r)) xor rand_w6
        g2 = (e1 & temp[1]) ^ (e2 & temp[0]) ^ (e2 & temp[1]) ^ rand_word[15:12];  
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

    // this block computes corresponding values for every byte of input state array
    generate
        for(i=0; i<16; i++) begin
            // piplining the operations 
            always_ff@(posedge clk) begin
                if(!rst_n) begin
                    masked_a_byte[i%4][i/4] <= 0;
                    denominator[i%4][i/4] <= 0;
                    masked_d_inv[i%4][i/4] <= 0;
                    masked_a_byte_delay2 <= 0;
                    masked_a_byte_delay3 <= 0;
                    rand_num_delay2 <= 0;
                    rand_num_delay3 <= 0;
                    masks_of_A_inv[i%4][i/4] <= 0;
                    subBytes <= 0;
                end
                else begin
                    // since masks_of_A_inv uses masked_a_byte and (rand_num[((28*i)+4) +: 4], rand_num[(28*i) +: 4]) 
                    // they have to be 3 and 4 cycles delayed as masks_of_A_inv is at 4 cycles delay in pipeline
                    masked_a_byte_delay2[i%4][i/4] <= masked_a_byte[i%4][i/4];
                    masked_a_byte_delay3[i%4][i/4] <= masked_a_byte_delay2[i%4][i/4];
                    rand_num_delay2[i%4][i/4] <= {rand_num[((28*i)+4) +: 4], rand_num[(28*i) +: 4]};
                    rand_num_delay3[i%4][i/4] <= rand_num_delay2[i%4][i/4];
                    rand_num_delay4[i%4][i/4] <= rand_num_delay3[i%4][i/4];

                    // different stages of s-box
                    masked_a_byte[i%4][i/4] <= tower_field(state[i%4][i/4], {rand_num[((28*i)+4) +: 4], rand_num[(28*i) +: 4]});
                    denominator[i%4][i/4] <= masked_denominator(masked_a_byte[i%4][i/4], {rand_num[((28*i)+8) +: 4], rand_num_delay2[i%4][i/4]});
                    masked_d_inv[i%4][i/4] <= masked_d_inverse(denominator[i%4][i/4], {rand_num[((28*i)+16) +: 4], rand_num[((28*i)+12) +: 4]});
                    masks_of_A_inv[i%4][i/4] <= masked_A_inverse(masked_d_inv[i%4][i/4], masked_a_byte_delay3[i%4][i/4], 
                                                {rand_num[((28*i)+24) +: 4], rand_num[((28*i)+20) +: 4], rand_num_delay4[i%4][i/4]});
                    subBytes[i%4][i/4] <= affine_transformation(masks_of_A_inv[i%4][i/4]);
                end
            end
        end
    endgenerate
endmodule
