import type_defs_pkg::*;

// this package contains the core logic of inverse SBox
package invSbox_funcs;
    import type_defs_pkg::*;

    // function to compute inverse Affine transformation and XOR it with inverse Affine constant
    function automatic ubyte invAffine(ubyte input encByte);
        ubyte res;

        // inverse Affine transformation - invAffine(x) = A^-1 * x, where A^-1 is the inverse Affine matrix
        res[0] = encByte[2] ^ encByte[5] ^ encByte[7];
        res[1] = encByte[0] ^ encByte[3] ^ encByte[6];
        res[2] = encByte[1] ^ encByte[4] ^ encByte[7];
        res[3] = encByte[0] ^ encByte[2] ^ encByte[5];
        res[4] = encByte[1] ^ encByte[3] ^ encByte[6];
        res[5] = encByte[2] ^ encByte[4] ^ encByte[7];
        res[6] = encByte[0] ^ encByte[3] ^ encByte[5];
        res[7] = encByte[1] ^ encByte[4] ^ encByte[6];

        // XOR with inverse Affine constant (0x05)
        res = res ^ 8'h05;
        return res;
    endfunction
    
endpackage

module invSbox(
    output u128_t invSubBytes,  // invSubByte of each encrypted element of state array
    output logic invSbox_ready,  // tells trng that invSbox is ready to accept random bits
    output logic invSbox_done_pulse,  // indicates that invSbox has computed required invSubBytes
    output logic rst_trng,  // resets TRNG when health test results in fatal failures
    input u128_t state,  // 128-bit input state matrix to invSbox
    input logic [1343:0] rand_num,  // 1344-bit random number from TRNG to be used in invSbox
    input logic trng_dead_flag,  // asserted by TRNG to signify that it has encountered fatal failure
    input logic trng_key_valid,  // asserted by TRNG when it has random bits to give
    input logic proceed,  // asserted by invCIPHER/AddRoundKey to allow invSBox to advance to next state only when invCIPHER/AddRoundKey has aknowledged
    input logic enb_n,  // active low enable signal to invSbox
    input logic rst_n, clk);
    
    import invSbox_funcs::*;
    import sbox_funcs::*;

    logic gated_clk;  // gated clock to reduce dynamic power consumption
    u128_t masked_a_byte;
    logic [1:0] invSbox_cntr;  // keeps track of how many times invSbox has computed invSubBytes
    logic invSbox_done, invSbox_done_d;  // these are registered done signals which stay high more than 1 cycle
    logic [9:0] slice_sel;  // required to select particular slice of rand_num
    invSbox_states fsm_state;

    // ICG cell to reduce dynamic power consumption
    icg ICG(gated_clk, ~enb_n, clk);

    // separate sequental block is used to update FSM states, sbox_done and rst_trng so as to avoid being driven for multiple times
    always_ff @(posedge gated_clk) begin
        if(!rst_n) begin
            invSbox_ready <= 0;
            rst_trng <= 0;
            invSbox_done <= 0;
            invSbox_done_d <= 0;
            invSbox_cntr <= 0;
            fsm_state <= INIT;
        end
        else begin
            if(!enb_n) begin  // invSbox functions since it's enabled
                case(fsm_state)
                    INIT: begin  // this state handles the handshake and accepting invSBox inputs
                        // invSbox is ready to accept random bits only when all random bits are consumed and this signal functions only when enb_n = 0 else it freezes
                        invSbox_ready <= (invSbox_cntr == 0) ? 1 : 0;
                        rst_trng <= 0;
                        invSbox_done <= 0;

                        if(trng_dead_flag) fsm_state <= RESET_TRNG;
                        else begin
                            if(invSbox_cntr == 0) fsm_state <= (trng_key_valid) ? INV_AFFINE_TOWER_FIELD : INIT;
                            else fsm_state <= INV_AFFINE_TOWER_FIELD;
                        end
                    end
                    RESET_TRNG: begin
                        rst_trng <= 1;  // resets TRNG as fatal error has occurred
                        invSbox_ready <= 0;
                        invSbox_done <= 0;
                        invSbox_cntr <= 0;
                        fsm_state <= INIT;
                    end
                    default: begin
                        
                    end
                endcase
            end
            else begin  // invSbox freezes since it's disabled
                invSbox_done <= 0;
                rst_trng <= 0;
                invSbox_ready <= 0;
                invSbox_cntr <= invSbox_cntr;
                fsm_state <= fsm_state;
            end

            invSbox_done_d <= invSbox_done;  // 1 cycle delayed version of sbox_done is used to generate a pulse of 1 clock cycle when Sbox has computed subBytes
        end
    end

    // slice_sel helps to select required 448-bit slice of rand_num 
    always_comb begin
        case(invSbox_cntr)
            2'b00: slice_sel = 0;
            2'b01: slice_sel = 448;
            2'b10: slice_sel = 896;
            default: slice_sel = 0;
        endcase
    end

    assign invSbox_done_pulse = invSbox_done && !invSbox_done_d;  // generating a pulse of 1 clock cycle when Sbox has computed subBytes

    // this block computes corresponding values for every byte of input state array
    generate
        for(int i=0; i<16; i++) begin
            always_ff @(posedge gated_clk) begin
                if(!rst_n) begin
                    masked_a_byte[(8*i) +: 8] <= 0;
                end
                else begin
                    if(!enb_n) begin
                        case(fsm_state)
                            INIT: begin
                                masked_a_byte[(8*i) +: 8] <= masked_a_byte[(8*i) +: 8];
                            end
                            INV_AFFINE_TOWER_FIELD: masked_a_byte[(8*i) +: 8] <= tower_field(invAffine(state[(8*i) +: 8]), {rand_num[((28*i)+4+slice_sel) +: 4], rand_num[((28*i)+slice_sel) +: 4]})
                            default: 
                        endcase
                    end
                    else begin
                        masked_a_byte[(8*i) +: 8] <= masked_a_byte[(8*i) +: 8];
                    end
                end
            end
        end
    endgenerate
endmodule