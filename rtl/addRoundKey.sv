/**
 * This block can support all standard KEY sizes (i.e 128, 192 & 256-bit). So, this block is compatible with multi KEY size transactions
 * This blok internally instantiates Sbox which is used in KeyExpansion logic when speacial conditions are met which are defined in AES standard
**/

import type_defs_pkg::*;

module addRoundKey( 
    output state_matrix_t addRoundKeyOut,  // output of addRoundKey
    output logic rst_trng,  // output from sbox that resets TRNG when fatal error occurs in TRNG
    input logic [255:0] master_key,  // input master KEY
    input logic [112:0] rand_num,  // random bits from TRNG for sbox
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

    unibble round_cntr;  // keeps track of round number
    logic [3:0][5:0] idx;  // keeps track of word number
    word_t subByte, sbox_state;  // input and outputs of sbox
    state_matrix_t expKey;  // expanded KEYs by KeyExpansion logic

    // sbox that gives subBytes used when i % Nk = 0 in KeyExpansion
    sbox#(32) Sbox(subByte, rst_trng, trng_dead_flag, sbox_state, rand_num, rst_n, clk);

    // optimized modulus function, based on key_size corresponding modulus is performed
    // key_size = 00 - 128-bit KEY - so mod 4 is performed
    // key_size = 01 - 192-bit KEY - so mod 6 is performed
    // key_size = 10 - 256-bit KEY - so mod 8 and mod of 8 = 4 is performed
    function automatic bit mod_Nk(input logic [5:0] idx, input logic [1:0] keySize);
        logic [1:0] sum_even_pos, sum_odd_pos;
        bit is_div_by_3;

        case(keySize)
            2'b00, 2'b10: begin  // checks if idx % 4 = 0, idx % 8 = 0 and idx % 8 = 4
                if(idx[1:0] == 2'b00) return 1;
                else return 0;
            end
            2'b01: begin  // checks if idx % 6 = 0
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

    // optimized (num + 1) function
    // this function works on the idea: from lsb if there 'n' no. of consecutive numbers then 
    // any 1's from msb side remain in their position while remaining bits would become (1 << n)
    // in simple words, bit flips if and only if all lower-ranking bits are high
    // this function is used in keyExpansion to calculate corresponding word indeces based on round count
    function automatic unibble add_1(input unibble num);
        unibble result;

        result[0] = ~num[0];
        result[1] = num[1] ^ num[0];
        result[2] = num[2] ^ (num[1] & num[0]);
        result[3] = num[3] ^ (num[2] & num[1] & num[0]);
        return result;
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

    // core logic of addRoundKey()
    always_ff @(posedge clk) begin
        if(!rst_n) begin
            round_cntr <= 4'h0;
            sbox_state <= 0;
            subByte <= 0;
            for(int i=0; i<16; i++) begin 
                addRoundKeyOut[i/4][i%4] <= 8'h00;
                expKey[i/4][i%4] <= 8'h00;  
                idx[i/4][i%4] <= 0;
            end

            // selecting initial index of word based on KEY size
            case(key_size)
                2'b00: word_idx <= 4'h4;
                2'b01: word_idx <= 4'h6;
                2'b10: word_idx <= 4'h8; 
                default: word_idx <= 4'h4;
            endcase
        end
        else begin
            case(key_size)
                2'b00: begin
                    if(round_cntr == 0) begin
                        for(int i=0; i<4; i++) begin
                            // simply loading maskter KEY into expKey for further usage
                            {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} <= master_key[(32*i) +: 32];

                            // adding round KEY for round-0
                            {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= 
                            {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} ^ master_key[(32*i) +: 32];
                        end
                    end
                    else begin
                        idx[0] <= (round_cntr << 2);  // i = round * 4
                        idx[1] <= add_1(round_cntr << 2);  // i = (round * 4) + 1
                        idx[2] <= add_1(add_1(round_cntr << 2));  // i = (round * 4) + 2
                        idx[3] <= add_1(add_1(add_1(round_cntr << 2)));  // i = (round * 4) + 3

                        for(int i=0; i<4; i++) begin
                            if(i%2 == 0) begin  // since idx[0] and idx[2] are always even they might satisfy i % Nk = 0. so these indices need checking and based on that expanded KEYs are computed
                                if(mod_Nk(idx[i], key_size)) begin  // since condition is met, special transformation is applied
                                    sbox_state <= rotWord({expKey[3][idx[i]-1], expKey[2][idx[i]-1], expKey[1][idx[i]-1], expKey[0][idx[i]]-1});  // loading Sbox input
                                    {expKey[3][idx[i]], expKey[2][idx[i]], expKey[1][idx[i]], expKey[0][idx[i]]} <= {expKey[3][idx[i]-4], expKey[2][idx[i]-4], expKey[1][idx[i]-4], expKey[0][idx[i]-4]}
                                                                                                                    ^ subByte ^ RCON[div_Nk(idx[i], 4)];
                                end
                                else
                                    {expKey[3][idx[i]], expKey[2][idx[i]], expKey[1][idx[i]], expKey[0][idx[i]]} <= {expKey[3][idx[i]-4], expKey[2][idx[i]-4], expKey[1][idx[i]-4], expKey[0][idx[i]-4]}
                                                                                                        ^ {expKey[3][idx[i]-1], expKey[2][idx[i]-1], expKey[1][idx[i]-1], expKey[0][idx[i]]-1};
                            end
                            else  // since idx[1] and idx[3] are always odd, checking if(i % Nk = 0) for these indices is not needed. they always satisfy i % Nk != 0 since Nk is even (4)
                                {expKey[3][idx[i]], expKey[2][idx[i]], expKey[1][idx[i]], expKey[0][idx[i]]} <= {expKey[3][idx[i]-4], expKey[2][idx[i]-4], expKey[1][idx[i]-4], expKey[0][idx[i]-4]}
                                                                                                                ^ {expKey[3][idx[i]-1], expKey[2][idx[i]-1], expKey[1][idx[i]-1], expKey[0][idx[i]]-1};
                        end
                    end

                    round_cntr <= (round_cntr == 4'hA) ? 0 : round_cntr + 1;  // this key size only requires 11 rounds in total
                end 
                default: 
            endcase
        end
    end
endmodule