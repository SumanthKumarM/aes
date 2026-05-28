// this package contains all user defined data types used across all RTL files
package type_defs_pkg;
    typedef logic [7:0] ubyte;
    typedef logic [3:0] unibble;
    typedef logic [31:0] word_t;
    typedef logic [3:0][3:0][7:0] state_matrix_t;
    typedef logic [4:0][4:0][63:0] keccak_state_t;

    typedef enum logic [1:0] {
        ABSORB, 
        PERMUTE, 
        SQUEEZE
    } Keccak_states;

    typedef enum logic [2:0] {
        TOWER_FIELD, 
        MASKED_D,
        MASKED_D_INV,
        MASKED_A_INV,
        MASKED_B_INV,
        SUB_BYTES,
        RESET_TRNG
    } sbox_states;
endpackage