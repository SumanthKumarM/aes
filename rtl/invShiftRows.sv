import type_defs_pkg::state_matrix_t;

module invShiftRows(
    output state_matrix_t invShift_rows,
    input state_matrix_t state);
    
    always_comb begin
        for(int i=0; i<16; i++)
            invShift_rows[i/4][i%4] = state[i/4][((i%4)+(i/4)+1)%4];
    end
endmodule