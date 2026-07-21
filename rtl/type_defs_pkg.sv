// this package contains all user defined data types used across all RTL files
package type_defs_pkg;
    typedef logic [3:0] unibble;
    typedef logic [7:0] ubyte;
    typedef logic [15:0] ushort;
    typedef logic [31:0] word_t;
    typedef logic [127:0] u128_t;
    typedef logic [255:0] u256_t;
    typedef logic [3:0][3:0][7:0] state_matrix_t;
    typedef logic [4:0][4:0][63:0] keccak_state_t;
    typedef logic [3:0][7:0][7:0] expKey_matrix_t;

    typedef enum logic [1:0] {
        ABSORB, 
        PERMUTE, 
        SQUEEZE
    } Keccak_states;

    typedef enum logic [1:0] {
        IDLE, 
        BIST,
        WAIT_FOR_XFER,
        DEAD
    } cu_states;

    typedef enum logic [2:0] {
        INIT,
        TOWER_FIELD,
        MASKED_D,
        MASKED_D_INV,
        MASKED_A_INV,
        MASKED_B_INV,
        SUB_BYTES,
        RESET_TRNG
    } sbox_states;

    typedef enum logic [2:0] {
        ISB_INIT,
        INV_AFFINE_TOWER_FIELD,
        ISB_MASKED_D,
        ISB_MASKED_D_INV,
        ISB_MASKED_A_INV,
        INV_SUB_BYTES,
        ISB_RESET_TRNG
    } invSbox_states;

    typedef enum logic {
        PRE_ADDROUNDKEY, 
        ADDROUNDKEY
    } cipher_internal_states;

    typedef enum logic {
        PRE_INVADDROUNDKEY,
        INVADDROUNDKEY
    } invCipher_internal_states;
endpackage