import type_defs_pkg::state_matrix_t;

module shiftRows(
    output state_matrix_t shift_rows,
    input state_matrix_t subBytes);

    always_comb begin
        for(int i=0; i<16; i++)
            shift_rows[i/4][i%4] = subBytes[i/4][((i%4)+3-(i/4))%4];
    end
endmodule