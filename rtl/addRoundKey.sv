/**
 * This block can support all standard KEY sizes (i.e 128, 192 & 256-bit). So, this block is compatible with multi KEY size transactions
 * This blok internally instantiates Sbox which is used in KeyExpansion logic when speacial conditions are met which are defined in AES standard
**/

import type_defs_pkg::*;

module addRoundKey( 
    output state_matrix_t addRoundKeyOut,  // output of addRoundKey
    output logic rst_trng,  // output from sbox that resets TRNG when fatal error occurs in TRNG
    input state_matrix_t state,  // input state matrix
    input logic [255:0] master_key,  // input master KEY
    input logic [112:0] rand_num,  // random bits from TRNG for sbox
    input unibble round_num,  // input CIPHER which indicates number of AES rounds
    input logic trng_dead_flag,  // input to sbox from TRNG to indicate that TRNG has some fatal error
    input logic [1:0] key_size,  // input from CONTROL register specifying the KEY size
    input rst_n, clk);

    // AES Key Expansion Round Constants (Rcon) table as specified in FIPS 197
    // Index 0 is a dummy padding value to maintain 1-to-1 mapping with the spec index.
    localparam bit [31:0] RCON [0:10] = '{
        32'h0000_0000,  // Index 0: Padding
        32'h0100_0000,  // Index 1  (Round 1)
        32'h0200_0000,  // Index 2  (Round 2)
        32'h0400_0000,  // Index 3  (Round 3)
        32'h0000_0000,  // Index 4  (Round 4)
        32'h1000_0000,  // Index 5  (Round 5)
        32'h2000_0000,  // Index 6  (Round 6)
        32'h4000_0000,  // Index 7  (Round 7)
        32'h8000_0000,  // Index 8  (Round 8)
        32'h1B00_0000,  // Index 9  (Round 9)
        32'h3600_0000   // Index 10 (Round 10)
    };

    word_t subByte, sbox_state;  // input and outputs of sbox
    expKey_matrix_t expKey;  // expanded KEYs by KeyExpansion logic
    expKey_matrix_t prev_expKey;  // these are previous round KEYs which are used in current round 
    logic sbox_done;  // addRoundKey can know when Sbox is done with computing necessary subBytes

    // sbox that gives subBytes used when i % Nk = 0 in KeyExpansion
    sbox#(32) Sbox(subByte, sbox_done, rst_trng, trng_dead_flag, sbox_state, rand_num, rst_n, clk);

    // optimized modulus function, based on key_size corresponding modulus is performed
    // key_size = 01 - 128-bit KEY - so mod 4 is performed
    // key_size = 10 - 192-bit KEY - so mod 6 is performed
    // key_size = 11 - 256-bit KEY - so mod 8 and mod of 8 = 4 is performed
    function automatic bit mod_Nk(input logic [5:0] idx, input logic [1:0] keySize);
        logic [1:0] sum_even_pos, sum_odd_pos;
        bit is_div_by_3;

        case(keySize)
            2'b01, 2'b11: begin  // checks if idx % 4 = 0, idx % 8 = 0 and idx % 8 = 4
                if(idx[1:0] == 2'b00) return 1;
                else return 0;
            end
            2'b10: begin  // checks if idx % 6 = 0
                // since divisible by 2, proceeding to check if divisible by 3
                if(!idx[0]) begin 
                    sum_even_pos = {(idx[4] & idx[2]), (idx[4] ^ idx[2])};  // half adder logic
                    sum_odd_pos = {((idx[5] & idx[3]) | (idx[1] & (idx[5] ^ idx[3]))), (idx[5] ^ idx[3] ^ idx[1])};  // full adder logic
                    // since sum_even_pos can never have 2'b11 value, it is enough to check if sum_odd_pos = 2'b11 and sum_even_pos = 2'b00
                    // other than this condition, both sums being same also mean it is divisible by 3
                    is_div_by_3 = ((sum_even_pos == sum_odd_pos) || (sum_even_pos == 2'b00 && sum_odd_pos == 2'b11)) ? 1 : 0;
                    return is_div_by_3;
                end
                else begin  // since not divisible 2, it's also not divisible by 6
                    sum_even_pos = 0;
                    sum_odd_pos = 0;
                    is_div_by_3 = 0;
                    return 0;
                end  
            end
            default: return 0;
        endcase
    endfunction

    // optimized division function based on KEY size
    function automatic unibble div_Nk(input logic [5:0] idx, input unibble Nk);
        unibble div_res;

        case(Nk)
            4'h4: div_res = idx[5:2];  // idx >> 2 or idx/4
            4'h6: begin  // idx/6
                div_res[0] = idx[1];
                div_res[1] = idx[2] ^ idx[1];
                div_res[2] = (idx[5] & ~idx[4]) | (~idx[5] & idx[4] & idx[3]);
                div_res[3] = idx[5] & idx[4];
            end
            4'h8: div_res = {1'b0, idx[5:3]};  // idx >> 3 or idx/8
            default: div_res = 0;
        endcase
        return div_res;
    endfunction

    // function to left rotate the bytes in a given word
    function automatic word_t rotWord(input word_t word);
        word_t rot_word;
        rot_word[31:24] = word[7:0];
        rot_word[23:16] = word[31:24];
        rot_word[15:8] = word[23:16];
        rot_word[7:0] = word[15:8];
        return rot_word;
    endfunction

    // core logic of KeyExpansion()
    always_comb begin
        case(key_size)
            2'b01: begin  // AES-128
                if(round_num == 0) begin
                    for(int i=0; i<4; i++) 
                        {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = 32'h0000_0000;
                end
                else begin  // actual KeyExpansion starts from round=1
                    for(int i=0; i<4; i++) begin 
                        if(i == 0) begin  // since this index is multiple of 4 it satisfies i%Nk = 0. So special transformation is applied
                            sbox_state = rotWord({prev_expKey[3][3], prev_expKey[2][3], prev_expKey[1][3], prev_expKey[0][3]});  // loading Sbox input
                            {expKey[3][0], expKey[2][0], expKey[1][0], expKey[0][0]} = {prev_expKey[3][0], prev_expKey[2][0], prev_expKey[1][0], prev_expKey[0][0]} ^ subByte ^ RCON[div_Nk(6'(round_num << 2), 4)];
                        end
                        else  // remaining all indices don't satisfy i%Nk = 0. So normal transformation is applied
                            {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} ^ {expKey[3][i-1], expKey[2][i-1], expKey[1][i-1], expKey[0][i-1]};
                    end
                end
            end
            2'b10: begin  // AES-192
                
            end
            2'b11: begin  // AES-256
                
            end
            default: 
        endcase
    end

    // core logic of addRoundKey()
    always_ff @(posedge clk) begin
        if(!rst_n) begin
            for(int i=0; i<32; i++) prev_expKey[i/8][i%8] <= 8'h00;
            for(int i=0; i<16; i++) addRoundKeyOut[i/4][i%4] <= 8'h00;
        end
        else begin
            case(key_size)
                2'b01: begin  // AES-128
                    if(round_num == 0) begin  // first round simply uses master KEY
                        for(int i=0; i<4; i++) begin
                            // simply loading maskter KEY into expKey for further usage
                            {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= master_key[(32*i) +: 32];

                            // adding round KEY for round-0
                            {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ master_key[(32*i) +: 32];
                        end
                    end
                    else begin  // remianing rounds use expanded KEYs
                        for(int i=0; i<4; i++) begin
                            if(sbox_done) begin// updating the register since sbox_done is high  
                                // updating current round KEYs so that these can be used in next round as previous round KEYs
                                {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]};
                                {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]};
                            end
                            else begin  // holding the previous round KEYs since sbox_done is not high
                                {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]};
                                {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]};
                            end
                        end
                    end
                end 
                2'b10: begin  // AES-192
                    
                end
                2'b11: begin  // AES-256

                end
                default: 
            endcase
        end
    end
endmodule