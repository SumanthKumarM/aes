import type_defs_pkg::*;

// this block can support all standard KEY sizes (i.e 128, 192 & 256-bit) 
// so this block is compatible with multi KEY size transactions
module keyExpansion ( 
    output state_matrix_t exp_word,  // expanded words
    input logic [255:0] master_key,  // input master KEY
    input logic [1:0] key_size,  // input from CONTROL register specifying the KEY size
    input rst_n, clk);

    logic [3:0] Nr, Nk round_cntr;

    // key_size = 00 - 128-bit KEY
    // key_size = 01 - 192-bit KEY
    // key_size = 10 - 256-bit KEY
    // calculating no. of rounds and words (word = 32 bits) per KEY based on KEY size
    always_comb begin
        case(key_size)
            2'b00: begin
                Nr = 4'hA;
                Nk = 4'h4;
            end 
            2'b01: begin 
                Nr = 4'C;
                Nk = 4'h6;
            end
            2'b10: begin 
                Nr = 4'hE; 
                Nk = 4'h8;
            end
            default: begin 
                Nr = 4'hA;
                Nk = 4'h4;
            end
        endcase
    end

    // optimized modulus function
    function automatic bit mod_Nk(input logic [5:0] idx, input logic [3:0] nk);
        logic [1:0] sum_even_pos, sum_odd_pos;
        bit is_div_by_3;

        case(nk)
            4'h4, 4'h8: begin  // checks if idx % 4 = 0, idx % 8 = 0 and idx % 8 = 4
                if(idx[1:0] == 2'b00) return 1;
                else return 0;
            end
            4'h6: begin  // checks if idx % 6 = 0
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

    // core logic if addRoundKey()
    always_ff @(posedge clk) begin
        if(!rst_n) begin
            round_cntr <= 4'h0;
            for(int i=0; i<16; i++) 
                exp_word[i/4][i%4] <= 8'h00;
        end
        else begin
            
        end
    end
endmodule