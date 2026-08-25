/**
 * This is an unmasked Cipher which uses the unmasked Sbox that doesn't have any masking scheme and composite field math.
 * This Cipher simply uses byte to subByte mapped Sbox and AddRoundKey module used here only supports key size of 256 bits.
 * As CBC-MAC and CTR-DRBG need encryption with key size of 256 bits, this Cipher is designed to support only 256 bits key size.
**/

import type_defs_pkg::*;

// package that has unmasked Sbox implemented
package unmkased_sbox;
    // S-box as a constant array
    localparam logic [7:0] AES_SBOX[0:255] = '{
        8'h63, 8'h7c, 8'h77, 8'h7b, 8'hf2, 8'h6b, 8'h6f, 8'hc5,
        8'h30, 8'h01, 8'h67, 8'h2b, 8'hfe, 8'hd7, 8'hab, 8'h76,
        8'hca, 8'h82, 8'hc9, 8'h7d, 8'hfa, 8'h59, 8'h47, 8'hf0,
        8'had, 8'hd4, 8'ha2, 8'haf, 8'h9c, 8'ha4, 8'h72, 8'hc0,
        8'hb7, 8'hfd, 8'h93, 8'h26, 8'h36, 8'h3f, 8'hf7, 8'hcc,
        8'h34, 8'ha5, 8'he5, 8'hf1, 8'h71, 8'hd8, 8'h31, 8'h15,
        8'h04, 8'hc7, 8'h23, 8'hc3, 8'h18, 8'h96, 8'h05, 8'h9a,
        8'h07, 8'h12, 8'h80, 8'he2, 8'heb, 8'h27, 8'hb2, 8'h75,
        8'h09, 8'h83, 8'h2c, 8'h1a, 8'h1b, 8'h6e, 8'h5a, 8'ha0,
        8'h52, 8'h3b, 8'hd6, 8'hb3, 8'h29, 8'he3, 8'h2f, 8'h84,
        8'h53, 8'hd1, 8'h00, 8'hed, 8'h20, 8'hfc, 8'hb1, 8'h5b,
        8'h6a, 8'hcb, 8'hbe, 8'h39, 8'h4a, 8'h4c, 8'h58, 8'hcf,
        8'hd0, 8'hef, 8'haa, 8'hfb, 8'h43, 8'h4d, 8'h33, 8'h85,
        8'h45, 8'hf9, 8'h02, 8'h7f, 8'h50, 8'h3c, 8'h9f, 8'ha8,
        8'h51, 8'ha3, 8'h40, 8'h8f, 8'h92, 8'h9d, 8'h38, 8'hf5,
        8'hbc, 8'hb6, 8'hda, 8'h21, 8'h10, 8'hff, 8'hf3, 8'hd2,
        8'hcd, 8'h0c, 8'h13, 8'hec, 8'h5f, 8'h97, 8'h44, 8'h17,
        8'hc4, 8'ha7, 8'h7e, 8'h3d, 8'h64, 8'h5d, 8'h19, 8'h73,
        8'h60, 8'h81, 8'h4f, 8'hdc, 8'h22, 8'h2a, 8'h90, 8'h88,
        8'h46, 8'hee, 8'hb8, 8'h14, 8'hde, 8'h5e, 8'h0b, 8'hdb,
        8'he0, 8'h32, 8'h3a, 8'h0a, 8'h49, 8'h06, 8'h24, 8'h5c,
        8'hc2, 8'hd3, 8'hac, 8'h62, 8'h91, 8'h95, 8'he4, 8'h79,
        8'he7, 8'hc8, 8'h37, 8'h6d, 8'h8d, 8'hd5, 8'h4e, 8'ha9,
        8'h6c, 8'h56, 8'hf4, 8'hea, 8'h65, 8'h7a, 8'hae, 8'h08,
        8'hba, 8'h78, 8'h25, 8'h2e, 8'h1c, 8'ha6, 8'hb4, 8'hc6,
        8'he8, 8'hdd, 8'h74, 8'h1f, 8'h4b, 8'hbd, 8'h8b, 8'h8a,
        8'h70, 8'h3e, 8'hb5, 8'h66, 8'h48, 8'h03, 8'hf6, 8'h0e,
        8'h61, 8'h35, 8'h57, 8'hb9, 8'h86, 8'hc1, 8'h1d, 8'h9e,
        8'he1, 8'hf8, 8'h98, 8'h11, 8'h69, 8'hd9, 8'h8e, 8'h94,
        8'h9b, 8'h1e, 8'h87, 8'he9, 8'hce, 8'h55, 8'h28, 8'hdf,
        8'h8c, 8'ha1, 8'h89, 8'h0d, 8'hbf, 8'he6, 8'h42, 8'h68,
        8'h41, 8'h99, 8'h2d, 8'h0f, 8'hb0, 8'h54, 8'hbb, 8'h16
    };

    function automatic type_defs_pkg::u128_t unmaskedSbox(
        input type_defs_pkg::u128_t in_state,  // input state matrix
        input logic subByte_len);  // indicates whether subByte is required for 4 bytes (subByte_len = 1'b0) or 16 bytes (subByte_len = 1'b1)

        if(subByte_len) begin  // used by Cipher which requires subByte for all 16 bytes
            return {
                AES_SBOX[in_state[127:120]],
                AES_SBOX[in_state[119:112]],
                AES_SBOX[in_state[111:104]],
                AES_SBOX[in_state[103:96]],
                AES_SBOX[in_state[95:88]],
                AES_SBOX[in_state[87:80]],
                AES_SBOX[in_state[79:72]],
                AES_SBOX[in_state[71:64]],
                AES_SBOX[in_state[63:56]],
                AES_SBOX[in_state[55:48]],
                AES_SBOX[in_state[47:40]],
                AES_SBOX[in_state[39:32]],
                AES_SBOX[in_state[31:24]],
                AES_SBOX[in_state[23:16]],
                AES_SBOX[in_state[15:8]],
                AES_SBOX[in_state[7:0]]
            };
        end
        else begin  // used by AddRoundKey which requires subByte for only 4 bytes
            return {
                96'h0000_0000_0000_0000_0000_0000,
                AES_SBOX[in_state[31:24]],
                AES_SBOX[in_state[23:16]],
                AES_SBOX[in_state[15:8]],
                AES_SBOX[in_state[7:0]]
            };
        end
    endfunction
endpackage

/**
 * This block only supports KEY size of 256 bits.
 * This block uses unmasked Sbox which is used in KeyExpansion logic when special conditions are met which are defined in AES standard
 * KeyExpansion logic works based on the equations:
    - if i%8 = 0 then w[i] = w[i-Nk] xor w[i-1]
    - if i%8 != 0 then special transformation is applied, w[i] = w[i-Nk] xor subWord(RotWord(w[i-1])) xor RCON[i/8]
    - AES-256 has one extra rule and that is if i%8 = 4 then w[i] = w[i-Nk] xor subWord(w[i-1])
**/
module addRoundKey_AES256( 
    output state_matrix_t addRoundKeyOut,  // output of addRoundKey
    output logic ark_done,  // indicates that addRoundKey is done with computation
    input state_matrix_t state,  // input state matrix
    input u256_t master_key,  // input master KEY
    input unibble round_num,  // input from CIPHER which indicates number of AES rounds
    input logic enb_n, rst_n, clk);

    import unmkased_sbox::*;

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

    logic gated_clk;  // gated clock to reduce dynamic power consumption
    expKey_matrix_t expKey;  // expanded KEYs by KeyExpansion logic
    expKey_matrix_t prev_expKey;  // these are previous round KEYs which are used in current round
    u128_t rotword_subBytes;  // stores SBox transformation of rotated words
    u128_t subBytes;  // stores sub-bytes of expanded KEY

    // ICG cell to reduce dynamic power consumption
    icg ICG(gated_clk, (~enb_n | ~rst_n), clk); 

    // function to left rotate the bytes in a given word
    function automatic word_t rotWord(input word_t word);
        word_t rot_word;
        rot_word[31:24] = word[23:16];
        rot_word[23:16] = word[15:8];
        rot_word[15:8] = word[7:0];
        rot_word[7:0] = word[31:24];
        return rot_word;
    endfunction

    assign rotword_subBytes = unmaskedSbox({96'd0, rotWord({prev_expKey[3][7], prev_expKey[2][7], prev_expKey[1][7], prev_expKey[0][7]})}, 1'b0);
    assign subBytes = unmaskedSbox({96'd0, {prev_expKey[3][3], prev_expKey[2][3], prev_expKey[1][3], prev_expKey[0][3]}}, 1'b0);

    // core logic of KeyExpansion()
    always_comb begin
        if(round_num == 0) begin  // round-0 uses master KEY so KEY expansion is not required
            for(int i=0; i<8; i++) 
                {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = 32'h0000_0000;
        end
        else begin  // actual KeyExpansion starts from round=1
            if(round_num == 1) begin  // this round doesn't generate any new KEY as upper half of master KEY is consumed
                for(int i=0; i<8; i++) 
                    {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = 32'h0000_0000;
            end
            else begin
                if(round_num[0] == 0) begin  // even rounds require first 4 KEY words
                    for(int i=0; i<4; i++) begin
                        if(i == 0)  // since this index is multiple of 8 it satisfies i%8 = 0. So special transformation is applied
                            {expKey[3][0], expKey[2][0], expKey[1][0], expKey[0][0]} = {prev_expKey[3][0], prev_expKey[2][0], prev_expKey[1][0], prev_expKey[0][0]} ^ rotword_subBytes[31:0] ^ RCON[{1'b0, round_num[3:1]}];
                        else  // remaining all indices in this loop range don't satisfy i%8 = 0 and i%8 = 4. So normal transformation is applied
                            {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} ^ {expKey[3][i-1], expKey[2][i-1], expKey[1][i-1], expKey[0][i-1]};
                    end

                    for(int i=4; i<8; i++)  // explicitly assignment to avoid latches
                        {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = 32'h0000_0000;
                end
                else begin  // odd rounds require last 4 KEY words
                    for(int i=0; i<4; i++)  // explicitly assignment to avoid latches
                        {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = 32'h0000_0000;

                    for(int i=4; i<8; i++) begin
                        if(i == 4)  // since this index satisfies i%8 = 4, special transformation is applied
                            {expKey[3][4], expKey[2][4], expKey[1][4], expKey[0][4]} = {prev_expKey[3][4], prev_expKey[2][4], prev_expKey[1][4], prev_expKey[0][4]} ^ subBytes[31:0];
                        else  // remaining all indices in this loop range don't satisfy i%8 = 0 and i%8 = 4. So normal transformation is applied
                            {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} ^ {expKey[3][i-1], expKey[2][i-1], expKey[1][i-1], expKey[0][i-1]};
                    end
                end
            end
        end
    end

    // core logic of addRoundKey()
    always_ff @(posedge gated_clk) begin
        if(!rst_n) begin
            ark_done <= 0;
            for(int i=0; i<32; i++) prev_expKey[i/8][i%8] <= 8'h00;
            for(int i=0; i<16; i++) addRoundKeyOut[i/4][i%4] <= 8'h00;
        end
        else begin
            // as CIPHER ties ard_done to ark_enb_n when needed this block is required to function only when output is still
            // not computed yet so it helps to avoid execution of this block more than once which corrupts prev_expKey register
            if(!enb_n && !ark_done) begin
                if(round_num == 0) begin  // first round simply uses master KEY
                    for(int i=0; i<8; i++)  // simply loading maskter KEY into expKey for further usage
                        {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= master_key[(32*i) +: 32];

                    for(int i=0; i<4; i++)  // adding round KEY for round-0  
                        {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ master_key[(32*i) +: 32];

                    ark_done <= 1;  // made high since addRoundKey output is available
                end
                else if(round_num == 1) begin  // this round also doesn't need any new KEY as it uses upper half of master KEY which is already available in prev_expKey
                    for(int i=0; i<8; i++)  // continues to hold the previous round KEYs since new KEYs are not computed
                        {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]};

                    for(int i=0; i<4; i++)  // previous KEYs are used as they are sufficient for current round KEY addition 
                        {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ {prev_expKey[3][i+4], prev_expKey[2][i+4], prev_expKey[1][i+4], prev_expKey[0][i+4]};

                    ark_done <= 1;  // made high since addRoundKey output is available
                end
                else begin  // remianing rounds use expanded KEYs   
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

                    ark_done <= 1;  // made high since addRoundKey output is available
                end
            end
            else begin  // holds its state when disabled
                for(int i=0; i<8; i++)
                    {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]};
                
                for(int i=0; i<4; i++)
                    {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]} <= {addRoundKeyOut[3][i], addRoundKeyOut[2][i], addRoundKeyOut[1][i], addRoundKeyOut[0][i]};

                ark_done <= 0;
            end
        end
    end
endmodule

// Cipher module which uses unmasked Sbox and AddRoundKey module to perform AES-256 encryption
module unmasked_cipher(
    output state_matrix_t cipher_state,  // state matrix that has gone through whole CIPHER algorithm
    output logic cipher_done,  // becomes high when CIPHER is done computing transformed state
    input state_matrix_t state,  // input state matrix (plain text)
    input u256_t master_key,  // MASTER KEY required for key expansion
    input logic enb_n, rst_n, clk);
    
    import unmkased_sbox::*;

    localparam unibble Nr = 4'hE;  // number of CIPHER rounds based for AES-256 KEY size as specified in FIPS 197
    logic gated_clk;
    unibble round_cntr;  // keeps track of CIPHER round count
    state_matrix_t temp_state;
    logic ark_enb_n;  // addRoundKey enable signal
    state_matrix_t ark_state;  // input state to addRoundKey
    state_matrix_t addRoundKeyOut;  // output of AddRoundKey module
    logic ark_done;  // indicates that addRoundKey has computed the output
    u128_t sbox_state;  // input state matrix to SBox
    u128_t subBytes;  // output of SBox
    state_matrix_t subBytes_matrix;  // matrix version of subBytes
    state_matrix_t shift_rows;  // stores state that has gone through shiftRows
    state_matrix_t mix_columns;  // stores state that has gone through mixColumns
    cipher_internal_states fsm_state;

    // sub-module instances
    icg ICG(gated_clk, (~enb_n | ~rst_n | cipher_done), clk);  // ICG cell to reduce dynamic power consumption
    shiftRows ShiftRows(shift_rows, subBytes_matrix);
    mixColumns MixColumns(mix_columns, shift_rows);
    addRoundKey_AES256 AddRoundKey(addRoundKeyOut, ark_done, ark_state, master_key, round_cntr, ark_enb_n, rst_n, gated_clk);

    always_comb begin  // rerouting subBytes to subBytes_matrix as both of them are in different formats
        for(int i=0; i<16; i++)  // loading Sbox input with previous addRoundKey's output
            sbox_state[((8*(i%4))+(32*(i/4))) +: 8] = temp_state[i%4][i/4];

        subBytes = unmaskedSbox(sbox_state, 1'b1);  // wiring the output of SBox to subBytes

        for(int i=0; i<16; i++)  // computing subBytes for given state matrix
            subBytes_matrix[i%4][i/4] = subBytes[((8*(i%4))+(32*(i/4))) +: 8];
    end

    /**
        sequential block based on NIST standard CIPHER algorithm:
        procedure CIPHER(in, Nr, w)
            state ← in
            state ← ADDROUNDKEY(state,w[0..3])
            for round from 1 to Nr − 1 do 
                state ← SUBBYTES(state)
                state ← SHIFTROWS(state)
                state ← MIXCOLUMNS(state)
                state ← ADDROUNDKEY(state,w[4 ∗ round..4 ∗ round + 3]) 
            end for 
            state ← SUBBYTES(state) 
            state ← SHIFTROWS(state) 
            state ← ADDROUNDKEY(state,w[4 ∗ Nr..4 ∗ Nr + 3]) 
            return state
        end procedure
    **/
    always_ff @(posedge gated_clk) begin
        if(!rst_n) begin
            round_cntr <= 0;
            ark_enb_n <= 1;
            cipher_done <= 0;
            fsm_state <= PRE_ADDROUNDKEY;

            for(int i=0; i<16; i++) begin
                cipher_state[i%4][i/4] <= 8'h00;
                temp_state[i%4][i/4] <= 8'h00;
                ark_state[i%4][i/4] <= 8'h00;
            end
        end
        else begin  // (for round from 1 to Nr − 1 do ... end for) & last round
            if(!enb_n) begin  // CIPHER operates when enabled
                if(round_cntr == 0) begin  // only AddRoundKey is performed in first cipher round
                    // AddRoundKey is disabled when it has computed the output to protect it from using stale 
                    // previous cycle output when it enters 'if(round_cntr == 0) or PRE_ADDROUNDKEY'
                    // AddRoundKey's enable also depends on cipher_done because new data will be assigned to CIPHER
                    // which is forwarded to AddRoundKey only after CIPHER is done computing encrypted data
                    // this logic helps to avoid AddRoundKey operate on stale data and raise false ark_done
                    ark_enb_n <= ark_done | cipher_done;

                    ark_state <= state;  // loading input of addRoundKey
                    temp_state <= (ark_done) ? addRoundKeyOut : temp_state;
                    round_cntr <= (ark_done) ? 1 : 0;
                    cipher_done <= 0;  // CIPHER is not done computing transformed state yet
                    fsm_state <= PRE_ADDROUNDKEY;
                end
                else begin
                    case(fsm_state)
                        PRE_ADDROUNDKEY: begin
                            ark_enb_n <= 1;
                            cipher_done <= 0;  // CIPHER is not done computing transformed state yet

                            // since SBox is done computing subBytes it will traverse through ShiftRows and MixColumns which are pure combinational giving MixColumn's / ShiftRow's output
                            temp_state <= (round_cntr == Nr) ? shift_rows : mix_columns;
                            fsm_state <= ADDROUNDKEY;
                        end 
                        ADDROUNDKEY: begin
                            // AddRoundKey is disabled when it has computed the output to protect it from using stale 
                            // previous cycle output when it enters 'if(round_cntr == 0) or PRE_ADDROUNDKEY'
                            ark_enb_n <= ark_done;

                            ark_state <= temp_state;  // loading addRoundKey input with MixColumn's / ShiftRow's output
                            temp_state <= (ark_done) ? addRoundKeyOut : temp_state;

                            if(ark_done) begin
                                if(round_cntr == Nr) begin 
                                    cipher_state <= addRoundKeyOut;
                                    cipher_done <= 1;
                                    round_cntr <= 0;  // starting over CIPHER counter as it's reached maximum rounds for this KEY size
                                end
                                else begin 
                                    cipher_done <= 0;  // CIPHER is not done computing transformed state yet
                                    round_cntr <= round_cntr + 1;  // updating CIPHER counter as state has been updated
                                end

                                fsm_state <= PRE_ADDROUNDKEY;
                            end
                            else begin 
                                cipher_done <= 0;  // CIPHER is not done computing transformed state yet
                                round_cntr <= round_cntr;
                                fsm_state <= ADDROUNDKEY;
                            end
                        end
                    endcase
                end
            end
            else begin  // when CIPHER is disabled it holds the state
                round_cntr <= round_cntr;
                ark_enb_n <= 1;
                cipher_done <= 0;
                fsm_state <= fsm_state;
                cipher_state <= cipher_state;
                temp_state <= temp_state;
                ark_state <= ark_state;
            end
        end
    end
endmodule