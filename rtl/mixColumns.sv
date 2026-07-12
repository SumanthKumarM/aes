import type_defs_pkg::*;

module mixColumns(
    output state_matrix_t mix_columns,
    input state_matrix_t shift_rows);

    // Multiplication in GF(2^8). Reduction polynomial is x^8 + x^4 + x^3 + x + 1. So reduction constant is (0001_1011)
    function automatic ubyte xTimes(input ubyte m);
        return (m[7]) ? ((m << 1) ^ 8'h1B) : (m << 1);
    endfunction

    // performs matric multiplication between NIST standard defined matrix for MixColumn and column of shiftRows result
    function automatic logic [3:0][7:0] column_op(input logic [3:0][7:0] b);
        logic [3:0][7:0] b_temp;

        b_temp[3] = xTimes(b[3]) ^ (xTimes(b[2]) ^ b[2]) ^ b[1] ^ b[0];
        b_temp[2] = b[3] ^ xTimes(b[2]) ^ (xTimes(b[1]) ^ b[1]) ^ b[0];
        b_temp[1] = b[3] ^ b[2] ^ xTimes(b[1]) ^ (xTimes(b[0]) ^ b[0]);
        b_temp[0] = (xTimes(b[3]) ^ b[3]) ^ b[2] ^ b[1] ^ xTimes(b[0]);

        return b_temp;
    endfunction

    // applying MixColumns() operations for all columns of state matrix which went through ShiftRows()
    always_comb begin
        for(int i=0; i<4; i++) begin
            {mix_columns[3][i], mix_columns[2][i], mix_columns[1][i], mix_columns[0][i]} = column_op(
                {shift_rows[3][i], shift_rows[2][i], shift_rows[1][i], shift_rows[0][i]});
        end
    end
endmodule