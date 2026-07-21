import type_defs_pkg::*;

module invMixColumns(
    output state_matrix_t mix_columns,
    input state_matrix_t ark_state);

    // Multiplication in GF(2^8). Reduction polynomial is x^8 + x^4 + x^3 + x + 1. So reduction constant is (0001_1011)
    function automatic ubyte xTimes(input ubyte m);
        return (m[7]) ? ((m << 1) ^ 8'h1B) : (m << 1);
    endfunction

    // this function performs n * 0xe which is (n * x^3) + (n * x^2) + (n * x)
    function automatic ubyte byte_0xe(input ubyte n);
        ubyte t1, t2, t3, res;
        t1 = xTimes(n);
        t2 = xTimes(t1);
        t3 = xTimes(t2);
        res = t1 ^ t2 ^ t3;
        return res;
    endfunction

    // this function performs n * 0xb which is (n * x^3) + (n * x) + n
    function automatic ubyte byte_0xb(input ubyte n);
        ubyte t1, t2, res;
        t1 = xTimes(n);
        t2 = xTimes(xTimes(t1));
        res = t1 ^ t2 ^ n;
        return res;
    endfunction

    // this function performs n * 0xd which is (n * x^3) + (n * x^2) + n
    function automatic ubyte byte_0xd(input ubyte n);
        ubyte t1, t2, res;
        t1 = xTimes(xTimes(n));
        t2 = xTimes(t1);
        res = t1 ^ t2 ^ n;
        return res;
    endfunction

    // this function performs n * 0x9 which is (n * x^3) +  n
    function automatic ubyte byte_0x9(input ubyte n);
        ubyte t, res;
        t = xTimes(xTimes(xTimes(n)));
        res = t ^ n;
        return res;
    endfunction

    // performs matric multiplication between NIST standard defined matrix for MixColumn and column of shiftRows result
    function automatic logic [3:0][7:0] column_op(input logic [3:0][7:0] b);
        logic [3:0][7:0] b_temp;

        b_temp[3] = byte_0xe(b[3]) ^ byte_0xb(b[2]) ^ byte_0xd(b[1]) ^ byte_0x9(b[0]);
        b_temp[2] = byte_0x9(b[3]) ^ byte_0xe(b[2]) ^ byte_0xb(b[1]) ^ byte_0xd(b[0]);
        b_temp[1] = byte_0xd(b[3]) ^ byte_0x9(b[2]) ^ byte_0xe(b[1]) ^ byte_0xb(b[0]);
        b_temp[0] = byte_0xb(b[3]) ^ byte_0xd(b[2]) ^ byte_0x9(b[1]) ^ byte_0xe(b[0]);

        return b_temp;
    endfunction

    // applying MixColumns() operations for all columns of state matrix which went through ShiftRows()
    always_comb begin
        for(int i=0; i<4; i++) begin
            {mix_columns[3][i], mix_columns[2][i], mix_columns[1][i], mix_columns[0][i]} = column_op(
                {ark_state[3][i], ark_state[2][i], ark_state[1][i], ark_state[0][i]});
        end
    end
endmodule