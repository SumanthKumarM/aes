typedef logic [7:0] ubyte;
typedef logic [3:0] unibble;

module s_box(
    output var ubyte [3:0][3:0] subBytes,
    input ubyte [3:0][3:0] state);

    ubyte [3:0][3:0] a_byte; // to store a1 and a0
    unibble [3:0][3:0] d;
    genvar i;

    // converting bytes to tower field representation
    function automatic ubyte tower_field(input ubyte s_byte);
        ubyte a;
        // basis transformation
        a[7] = s_byte[7] ^ s_byte[5];
        a[6] = s_byte[7] ^ s_byte[5] ^ s_byte[3] ^ s_byte[2];
        a[5] = s_byte[7] ^ s_byte[6] ^ s_byte[4] ^ s_byte[1];
        a[4] = s_byte[6] ^ s_byte[5] ^ s_byte[4];
        a[3] = s_byte[4] ^ s_byte[3];
        a[2] = s_byte[7] ^ s_byte[6] ^ s_byte[5] ^ s_byte[4] ^ s_byte[3] ^ s_byte[2];
        a[1] = s_byte[2];
        a[0] = s_byte[7] ^ s_byte[5] ^ s_byte[0];

        return a; 
    endfunction

    // Multiplication in GF(2^4). Reduction polynomial is x^4 + x + 1. So reduction constant is (0011)
    function automatic unibble xTimes(input unibble m);
        return (m[3]==1) ? ((m << 1) ^ 4'b0011) : (m << 1);
    endfunction

    // D = (a1^2)*(lambda) xor (a1 * a0) xor (a0^2)
    function automatic unibble denominator(input ubyte a1_a0);
        unibble [3:0] xTimes_temp1, xTimes_temp2;
        unibble a1_sqr, a1_sqr_lambda, a1_x_a0, a0_sqr;

        // computing a1^2
        xTimes_temp1[0] = a1_a0[7:4]; // a1 * x^0
        xTimes_temp1[1] = xTimes(xTimes_temp1[0]); // a1 * x^1
        xTimes_temp1[2] = xTimes(xTimes_temp1[1]); // a1 * x^2
        xTimes_temp1[3] = xTimes(xTimes_temp1[2]); // a1 * x^3

        // conditionally performing XOR based on a1 bits
        a1_sqr = (a1_a0[4] ? xTimes_temp1[0] : 0) ^ (a1_a0[5] ? xTimes_temp1[1] : 0)
                ^ (a1_a0[6] ? xTimes_temp1[2] : 0) ^ (a1_a0[7] ? xTimes_temp1[3] : 0);

        // computing (a1^2)*lambda where lambda = 8 (x^3)
        a1_sqr_lambda = xTimes(xTimes(xTimes(a1_sqr))); // a1^2 * x^3

        // computing a1 * a0
        a1_x_a0 = (a1_a0[0] ? xTimes_temp1[0] : 0) ^ (a1_a0[1] ? xTimes_temp1[1] : 0)
                ^ (a1_a0[2] ? xTimes_temp1[2] : 0) ^ (a1_a0[3] ? xTimes_temp1[3] : 0);

        // computing a0^2
        xTimes_temp2[0] = a1_a0[3:0]; // a0 * x^0
        xTimes_temp2[1] = xTimes(xTimes_temp2[0]); // a0 * x^1
        xTimes_temp2[2] = xTimes(xTimes_temp2[1]); // a0 * x^2
        xTimes_temp2[3] = xTimes(xTimes_temp2[2]); // a0 * x^3
        // conditionally performing XOR based on a1 bits
        a0_sqr = (a1_a0[0] ? xTimes_temp2[0] : 0) ^ (a1_a0[1] ? xTimes_temp2[1] : 0)
                ^ (a1_a0[2] ? xTimes_temp2[2] : 0) ^ (a1_a0[3] ? xTimes_temp2[3] : 0);

        // computing denominator 
        return (a1_sqr_lambda ^ a1_x_a0 ^ a0_sqr);
    endfunction

    generate
        for(i=0; i<16; i++) begin
            // converting all bytes in state array to tower field
            assign a_byte[i%4][i/4] = tower_field(state[i%4][i/4]);

            // computing denominator term for every tower field
            assign d[i%4][i/4] = denominator(a_byte[i%4][i/4]);
        end
    endgenerate
endmodule
