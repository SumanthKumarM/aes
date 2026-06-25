/**
 * This block can support all standard KEY sizes (i.e 128, 192 & 256-bit). So, this block is compatible with multi KEY size transactions
 * This blok internally instantiates Sbox which is used in KeyExpansion logic when special conditions are met which are defined in AES standard
 * KeyExpansion logic works based on the equations:
    - if i%Nk = 0 then w[i] = w[i-Nk] xor w[i-1]
    - if i%Nk != 0 then special transformation is applied, w[i] = w[i-Nk] xor subWord(RotWord(w[i-1])) xor RCON[i/Nk]
    - AES-256 has one extra rule and that is if i%Nk = 4 then w[i] = w[i-Nk] xor subWord(w[i-1])
**/

import type_defs_pkg::*;

module addRoundKey( 
    output state_matrix_t addRoundKeyOut,  // output of addRoundKey
    output logic sbox_ready,  // tells trng that s-box is ready to accept random bits
    output logic rst_trng,  // output from sbox that resets TRNG when fatal error occurs in TRNG
    input state_matrix_t state,  // input state matrix
    input logic [255:0] master_key,  // input master KEY
    input logic [111:0] rand_num,  // random bits from TRNG for sbox
    input unibble round_num,  // input CIPHER which indicates number of AES rounds
    input logic [1:0] key_size,  // input from CONTROL register specifying the KEY size
    input logic trng_dead_flag,  // input to sbox from TRNG to indicate that TRNG has some fatal error
    input logic trng_key_valid,  // asserted by TRNG when it has random bits to give to s-box
    input rst_n, clk);

    // AES Key Expansion Round Constants (Rcon) table as specified in FIPS 197
    // Index 0 is a dummy padding value to maintain 1-to-1 mapping with the spec index.
    localparam bit [31:0] RCON [0:10] = '{
        32'h0000_0000,  // Index 0: Padding
        32'h0100_0000,  // Index 1  (Round 1)
        32'h0200_0000,  // Index 2  (Round 2)
        32'h0400_0000,  // Index 3  (Round 3)
        32'h0800_0000,  // Index 4  (Round 4)
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
    logic sbox_enb_n;  // to enable or disable Sbox
    logic sbox_done;  // addRoundKey can know when Sbox is done with computing necessary subBytes

    // sbox that gives subBytes used when i % Nk = 0 in KeyExpansion
    sbox#(32) Sbox(subByte, sbox_ready, sbox_done, rst_trng, trng_dead_flag, sbox_state, rand_num, trng_key_valid, sbox_enb_n, rst_n, clk);

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

    // this function helps to determine which round number results in which concatenation of expanded KEY words
    function automatic logic [1:0] concatenate_sel(input unibble rnum);
        logic [2:0] temp;
        logic [1:0] res;

        temp[0] = ((rnum[3] ^ rnum[1]) & (rnum[2] ^ rnum[0]));  // rnum = 3, 6, 9, 12
        temp[1] = ((~rnum[3] & rnum[2]) & ~(rnum[1] ^ rnum[0])) | (~rnum[2] & ((~rnum[3] & ~rnum[1] & rnum[0]) | (rnum[3] & rnum[1] & ~rnum[0])));  // rnum = 1, 4, 7, 10
        temp[2] = ((rnum[3] & ~rnum[2]) & ~(rnum[1] ^ rnum[0])) | (~rnum[3] & ((~rnum[2] & rnum[1] & ~rnum[0]) | (rnum[2] & ~rnum[1] & rnum[0])));  // rnum = 2, 5, 8, 11
        res[0] = ~temp[0] & (temp[2] ^ temp[1]);
        res[1] = ~temp[1] & (temp[2] ^ temp[0]);
        return res;
    endfunction

    // function to left rotate the bytes in a given word
    function automatic word_t rotWord(input word_t word);
        word_t rot_word;
        rot_word[31:24] = word[23:16];
        rot_word[23:16] = word[15:8];
        rot_word[15:8] = word[7:0];
        rot_word[7:0] = word[31:24];
        return rot_word;
    endfunction

    // core logic of KeyExpansion()
    always_comb begin
        if(round_num == 0) begin  // round-0 uses master KEY so KEY expansion is not required
            // disabling Sbox as it's not required yet
            sbox_enb_n = 1;  
            sbox_state = 32'h0000_0000;

            for(int i=0; i<8; i++) 
                {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = 32'h0000_0000;
        end
        else begin  // actual KeyExpansion starts from round=1
            case(key_size)
                2'b01: begin  // AES-128
                    sbox_enb_n = 0;  // enabling Sbox since special transformation requires subByte
                    sbox_state = rotWord({prev_expKey[3][3], prev_expKey[2][3], prev_expKey[1][3], prev_expKey[0][3]});  // loading Sbox input

                    for(int i=0; i<4; i++) begin 
                        if(i == 0)  // since this index is multiple of 4 it satisfies i%Nk = 0. So special transformation is applied
                            {expKey[3][0], expKey[2][0], expKey[1][0], expKey[0][0]} = {prev_expKey[3][0], prev_expKey[2][0], prev_expKey[1][0], prev_expKey[0][0]} ^ subByte ^ RCON[div_Nk(6'(round_num << 2), 4)];
                        else  // remaining all indices don't satisfy i%Nk = 0. So normal transformation is applied
                            {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} ^ {expKey[3][i-1], expKey[2][i-1], expKey[1][i-1], expKey[0][i-1]};
                    end
                end
                2'b10: begin  // AES-192
                    if(concatenate_sel(round_num) == 2'b11) begin  // these rounds don't require new expanded KEYs, previous batch KEYs are enough
                        // disabling Sbox as it's not required for these rounds
                        sbox_enb_n = 1;  
                        sbox_state = 32'h0000_0000;

                        for(int i=0; i<8; i++) 
                            {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = 32'h0000_0000;
                    end
                    else begin
                        sbox_enb_n = 0;  // enabling Sbox since special transformation requires subByte
                        sbox_state = rotWord({prev_expKey[3][5], prev_expKey[2][5], prev_expKey[1][5], prev_expKey[0][5]});  // loading Sbox input
                        
                        for(int i=0; i<6; i++) begin
                            if(i == 0)  // since this index is multiple of 6 it satisfies i%Nk = 0. So special transformation is applied
                                {expKey[3][0], expKey[2][0], expKey[1][0], expKey[0][0]} = {prev_expKey[3][0], prev_expKey[2][0], prev_expKey[1][0], prev_expKey[0][0]} ^ subByte ^ RCON[div_Nk(6'(round_num << 2), 6)];
                            else  // remaining all indices don't satisfy i%Nk = 0. So normal transformation is applied
                                {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} ^ {expKey[3][i-1], expKey[2][i-1], expKey[1][i-1], expKey[0][i-1]};
                        end
                    end
                end
                2'b11: begin  // AES-256
                    sbox_enb_n = 0;  // enabling Sbox since it's required to compute subByte

                    if(round_num[0] == 0) begin  // even rounds require first 4 KEY words
                        sbox_state = rotWord({prev_expKey[3][7], prev_expKey[2][7], prev_expKey[1][7], prev_expKey[0][7]});  // loading Sbox input

                        for(int i=0; i<4; i++) begin
                            if(i == 0)  // since this index is multiple of 8 it satisfies i%Nk = 0. So special transformation is applied
                                {expKey[3][0], expKey[2][0], expKey[1][0], expKey[0][0]} = {prev_expKey[3][0], prev_expKey[2][0], prev_expKey[1][0], prev_expKey[0][0]} ^ subByte ^ RCON[div_Nk(6'(round_num << 2), 8)];
                            else  // remaining all indices in this loop range don't satisfy i%Nk = 0 or i%Nk = 4. So normal transformation is applied
                                {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} ^ {expKey[3][i-1], expKey[2][i-1], expKey[1][i-1], expKey[0][i-1]};
                        end

                        for(int i=4; i<8; i++)  // explicitly assignment to avoid latches
                            {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = 32'h0000_0000;
                    end
                    else begin  // odd rounds require last 4 KEY words 
                        sbox_state = {prev_expKey[3][3], prev_expKey[2][3], prev_expKey[1][3], prev_expKey[0][3]};  // loading Sbox input

                        for(int i=0; i<4; i++)  // explicitly assignment to avoid latches
                            {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = 32'h0000_0000;

                        for(int i=4; i<8; i++) begin
                            if(i == 4)  // since this index satisfies i%Nk = 4, special transformation is applied
                                {expKey[3][4], expKey[2][4], expKey[1][4], expKey[0][4]} = {prev_expKey[3][4], prev_expKey[2][4], prev_expKey[1][4], prev_expKey[0][4]} ^ subByte;
                            else  // remaining all indices in this loop range don't satisfy i%Nk = 0 or i%Nk = 4. So normal transformation is applied
                                {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} ^ {expKey[3][i-1], expKey[2][i-1], expKey[1][i-1], expKey[0][i-1]};
                        end
                    end
                end
                default: begin
                    // disabling Sbox as it's not required yet
                    sbox_enb_n = 1;  
                    sbox_state = 32'h0000_0000;

                    for(int i=0; i<8; i++) 
                        {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = 32'h0000_0000;
                end
            endcase
        end
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
                            if(sbox_done) begin  // updating the register since sbox_done is high  
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
                    if(round_num == 0) begin  // first round simply uses master KEY
                        for(int i=0; i<6; i++)  // simply loading maskter KEY into expKey for further usage
                            {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= master_key[(32*i) +: 32];

                        for(int i=0; i<4; i++)  // adding round KEY for round-0
                            {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ master_key[(32*i) +: 32];
                    end
                    else begin  // remianing rounds use expanded KEYs
                        case(concatenate_sel(round_num))
                            2'b01: begin
                                if(sbox_done) begin  // updating the register since sbox_done is high  
                                    for(int i=0; i<6; i++)  // updating current round KEYs so that these can be used in next round as previous round KEYs
                                        {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]};
                                    
                                    for(int i=0; i<4; i++)  // adding round KEY
                                        {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]};
                                end
                                else begin  // holding the previous round KEYs since sbox_done is not high
                                    for(int i=0; i<6; i++)
                                        {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]};
                                    
                                    for(int i=0; i<4; i++)
                                        {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]};
                                end
                            end 
                            2'b10: begin
                                if(sbox_done) begin  // updating the register since sbox_done is high  
                                    for(int i=0; i<6; i++)  // updating current round KEYs so that these can be used in next round as previous round KEYs
                                        {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]};
                                    
                                    for(int i=0; i<4; i++) begin  // adding round KEY
                                        if(i < 2)
                                            {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ {prev_expKey[3][i+4], prev_expKey[2][i+4], prev_expKey[1][i+4], prev_expKey[0][i+4]};
                                        else 
                                            {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ {expKey[3][i-2], expKey[2][i-2], expKey[1][i-2], expKey[0][i-2]};
                                    end
                                end
                                else begin  // holding the previous round KEYs since sbox_done is not high
                                    for(int i=0; i<6; i++)
                                        {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]};
                                    
                                    for(int i=0; i<4; i++)
                                        {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]};
                                end
                            end
                            2'b11: begin  // these rounds don't actually require new expanded KEYs, they use previous KEYs
                                for(int i=0; i<6; i++)  // continues to hold the previous round KEYs since new KEYs are not computed
                                    {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]};

                                for(int i=0; i<4; i++)  // previous KEYs are used as they are sufficient for current round
                                    {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ {prev_expKey[3][i+2], prev_expKey[2][i+2], prev_expKey[1][i+2], prev_expKey[0][i+2]};
                            end
                            default: begin
                                for(int i=0; i<6; i++)
                                    {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]};

                                for(int i=0; i<4; i++)
                                    {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]};
                            end
                        endcase
                    end
                end
                2'b11: begin  // AES-256
                    if(round_num == 0) begin  // first round simply uses master KEY
                        for(int i=0; i<8; i++)  // simply loading maskter KEY into expKey for further usage
                            {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= master_key[(32*i) +: 32];

                        for(int i=0; i<4; i++)  // adding round KEY for round-0
                            {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ master_key[(32*i) +: 32];
                    end
                    else begin  // remianing rounds use expanded KEYs
                        if(sbox_done) begin  // updating the register since sbox_done is high 
                            if(round_num[0] == 1) begin  // odd rounds don't generate new expanded KEYs, so previous batch KEYs are used
                                for(int i=0; i<4; i++) begin  // updating current round KEYs so that these can be used in next round as previous round KEYs
                                    {prev_expKey[3][i+4], prev_expKey[2][i+4], prev_expKey[1][i+4], prev_expKey[0][i+4]} <= {expKey[3][i+4], expKey[2][i+4], expKey[1][i+4], expKey[0][i+4]};
                                    {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ {expKey[3][i+4], expKey[2][i+4], expKey[1][i+4], expKey[0][i+4]};

                                    // explicitly holding values of these registers to avoid linting warning/errors
                                    {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]};
                                end
                            end
                            else begin  // even rounds generate new expanded KEYs which will be sufficient for current and next round, so using current round expanded KEYs
                                for(int i=0; i<4; i++) begin
                                    {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]};
                                    {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]};

                                    // explicitly holding values of these registers to avoid linting warning/errors
                                    {prev_expKey[3][i+4], prev_expKey[2][i+4], prev_expKey[1][i+4], prev_expKey[0][i+4]} <= {prev_expKey[3][i+4], prev_expKey[2][i+4], prev_expKey[1][i+4], prev_expKey[0][i+4]};
                                end
                            end
                        end
                        else begin  // holding the previous round KEYs since sbox_done is not high
                            for(int i=0; i<8; i++)
                                {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]};
                            
                            for(int i=0; i<4; i++)
                                {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]};
                        end
                    end
                end
                default: begin
                    for(int i=0; i<8; i++)
                        {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]};
                    
                    for(int i=0; i<4; i++)
                        {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]};
                end
            endcase
        end
    end
endmodule
