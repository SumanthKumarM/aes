/**
 * This is CTR-DRBG module which consumes random conditioned SEED from CBC-MAC conditioner and generated IV for AES
 * CTR-DRBG maintains 2 handshakes: one is with CBC-MAC to consume valid conditioned SEED and other is with AES to 
   produce and send valid IV when AES requires it
 * This CTR-DRBG is designed to generate IV using its internal state for 1024 times and for every such 1024 generations
   it requests a SEED from CBC-MAC conditioner and 'reseeds'
**/

import type_defs_pkg::*;

module ctr_drbg(
    output u128_t generated_iv,  // this is the IV required for AES operations
    output logic iv_valid,  // becomes high when CTR-DRBG is done computing IV
    output logic ctr_drbg_ready,  // ready signal to indicate that it is ready to receive conditioned random word
    output logic rst_cbcmac,  // resets CBC-MAC when it encounters error from health tests
    input u384_t seed,  // 384-bit conditioned random word output from CBC-MAC conditioner
    input logic aes_ready,  // READY signal from AES to let CTR-DRBG know that it's ready to consume IV
    input logic health_error,  // becomes high when health tests fail in CBC-MAC conditioner
    input logic cbcmac_valid,  // becomes high when CBC-MAC conditioner has finished producing conditioned random word
    input logic enb_n, rst_n, clk);

    localparam RESEED_LIM = 1024;
    logic gated_clk;  // gated clock to reduce dynamic power consumption
    logic cipher_rst_n;  // active low reset signal to CIPHER
    logic cipher_enb_n;  // active low enable signal for unmasked CIPHER
    u128_t cipher_state;  // encrypted data from unmasked CIPHER
    logic cipher_done;  // becomes high when CIPHER is done computing transformed state
    u128_t cipher_state_in;  // input state matrix (plain text) to unmasked CIPHER
    u256_t master_key;  // MASTER KEY required for key expansion in unmasked CIPHER
    u384_t provided_data;  // used by Update function which is assigned by CTR-DRBG states
    logic update_enb_n;  // active low enable signal for CTR-DRBG Update function
    logic [1:0] update_enc_cntr;  // keeps track of number of encryptions done in Update function
    u256_t update_temp;  // stores intermediate values in CTR-DRBG Update function
    u256_t update_key;  // KEY register in CTR-DRBG Update function
    u128_t update_regV;  // V register in CTR-DRBG Update function
    logic update_done;  // becoomes high when Update function is completed
    logic [$clog2(RESEED_LIM):0] reseed_cntr;  // counter that keeps track of SEED cycles
    u256_t regKEY;  // stores 'Key' value
    u128_t regV;  // stores 'V' value
    // u128_t temp;  // stores intermediate values in CTR-DRBG main loop
    ctr_drbg_update_states update_fsm;
    ctr_drbg_states fsm_state;
    gen_internal_states gen_fsm;

    // when CTR-DRBG goes to RESET_CBCMAC state it resets all registers so CIPHER is
    // also required to begin from start but not just resume its operation
    assign cipher_rst_n = (fsm_state == RESET_CBCMAC) ? 0 : 1;

    // sub-modules
    icg ICG(gated_clk, (~enb_n | ~rst_n), clk);  // ICG cell to reduce dynamic power consumption
    unmasked_cipher CIPHER(cipher_state, cipher_done, cipher_state_in, master_key, cipher_enb_n, (rst_n & cipher_rst_n), gated_clk);
    
    /**
     * this is a sequential block that models CTR-DRBG Update function as per below NIST defined algorithm
       that is tuned to design requirements which are:
        - ctr_len = block_len = 128. this removes 'if(ctr_len < blocklen)' branch in algorithm

     * Algorithm
        1. temp = Null.
        2. While(len(temp) < seedlen) do
            2.1 V = V + 1
            2.2 output_block = Block_Encrypt(Key, V)
            2.3 temp = temp || output_block
        3. temp = temp ⊕ provided_data
        4. Key = temp[383:128]
        5. V = temp[127:0]
        6. Return {Key, V}
    **/
    always_ff @(posedge gated_clk) begin : CTR_DRBG_UPDATE
        if(!rst_n) begin
            update_enc_cntr <= 0;
            update_temp <= 0;
            update_key <= 0;
            update_regV <= 0;
            update_done <= 0;
            update_fsm <= LOAD;
        end
        else begin
            if(!update_enb_n) begin  // performs CTR-DRBG Update function since it's enabled
                case(update_fsm)
                    // this state's only purpose it to avoid Update function operating unnecessary
                    // when Update_done is high this block gets disabled in next cycle when CTR-DRBG
                    // is in GENERATE_IV::CALL_UPDATE state but in this one cycle gap Update function
                    // performs LOAD state which updates the registers unnecessarily.
                    UPD_IDLE: begin
                        update_enc_cntr <= update_enc_cntr;
                        update_temp <= update_temp;
                        update_key <= update_key;
                        update_regV <= update_regV;
                        update_done <= 0;
                        update_fsm <= (health_error) ? RST_CBCMAC : UPD_IDLE;  // waits in this state until Update function gets disabled which then points to LOAD state
                    end
                    LOAD: begin  // this state loads appropriate data into Update function registers based on CTR-DRBG state
                        case(fsm_state)
                            INSTANTIATE: begin 
                                update_regV <= (update_enc_cntr == 0) ? regV + 1 : update_regV + 1;
                                update_key <= 0;
                            end
                            GENERATE_IV: begin 
                                update_regV <= (update_enc_cntr == 0) ? regV + 1 : update_regV + 1;
                                update_key <= regKEY;
                            end
                            RESEED: begin 
                                update_regV <= (update_enc_cntr == 0) ? regV + 1 : update_regV + 1;
                                update_key <= regKEY;
                            end
                            UNINSTANTIATE: begin 
                                update_regV <= 0;
                                update_key <= 0;
                            end
                            default: begin
                                update_regV <= 0;
                                update_key <= 0;
                            end
                        endcase

                        update_done <= 0;
                        update_fsm <= (health_error) ? RST_CBCMAC : UPDATE;
                    end 
                    UPDATE: begin  // this state aquires encrypted data from CIPHER and updates final state of registers
                        update_enc_cntr <= (cipher_done) ? ((update_enc_cntr == 2) ? 0 : update_enc_cntr + 1) : update_enc_cntr;

                        // updating temp register accordingly for 1st 2 encryptions
                        update_temp[127:0] <= (update_enc_cntr == 0 && cipher_done) ? cipher_state : update_temp[127:0];
                        update_temp[255:128] <= (update_enc_cntr == 1 && cipher_done) ? cipher_state : update_temp[255:128];

                        // updating final state of registers after 3rd encryption
                        update_key <= (update_enc_cntr == 2 && cipher_done) ? ({update_temp[127:0], update_temp[255:128]} ^ provided_data[383:128]) : update_key;
                        update_regV <= (update_enc_cntr == 2 && cipher_done) ? (cipher_state ^ provided_data[127:0]) : update_regV;
                        update_done <= (update_enc_cntr == 2 && cipher_done) ? 1 : 0;
                        if(health_error) update_fsm <= RST_CBCMAC;
                        else update_fsm <= (update_enc_cntr == 2 && cipher_done) ? UPD_IDLE : ((cipher_done) ? LOAD : UPDATE);
                    end
                    RST_CBCMAC: begin
                        update_enc_cntr <= 0;
                        update_temp <= 0;
                        update_key <= 0;
                        update_regV <= 0;
                        update_done <= 0;
                        update_fsm <= LOAD;
                    end
                endcase
            end
            else begin  // holds internal state since it's disabled
                update_enc_cntr <= update_enc_cntr;
                update_temp <= update_temp;
                update_key <= update_key;
                update_regV <= update_regV;
                update_done <= 0;
                update_fsm <= LOAD;
            end
        end
    end

    // this sequential block models INSTANTIATE, GENERATE, RESSED and UNINSTANTIATE functions of CTR-DRBG
    always_ff @(posedge gated_clk) begin : CTR_DRBG_FUNCTIONS
        if(!rst_n) begin
            update_enb_n <= 1;
            reseed_cntr <= 0;
            regKEY <= 0;
            regV <= 0;
            generated_iv <= 0;
            ctr_drbg_ready <= 0;
            iv_valid <= 0;
            rst_cbcmac <= 1;
            provided_data <= 0;
            fsm_state <= INSTANTIATE;
            gen_fsm <= INCREMENT;
        end
        else begin
            if(!enb_n) begin
                case(fsm_state)
                    /**
                     * this state calls CTR-DRBG Update function and updates Key and V. logic follows this algorithm:

                        Instantiate(entropy_input):
                            1. seed_material = entropy_input
                               Key = 0
                               V = 0
                            2. (Key, V) = CTR_DRBG_Update(seed_material, Key, V)
                            3. reseed_counter = 1
                            4. return (Key, V, reseed_counter)
                    **/
                    INSTANTIATE: begin
                        ctr_drbg_ready <= (ctr_drbg_ready && cbcmac_valid) ? 0 : 1;  // extracting seed from CBC-MAC conditioner before enabling Update function
                        provided_data <= (ctr_drbg_ready && cbcmac_valid) ? seed : provided_data;

                        // enabling Update function accordingly
                        if(update_enb_n && cbcmac_valid) update_enb_n <= 0;  // enable Update fnction only when CBC-MAC gives valid seed
                        else if(!update_enb_n && update_done) update_enb_n <= 1;  // disabling once Update function is done
                        else update_enb_n <= update_enb_n;
                        
                        regKEY <= (update_done) ? update_key : regKEY;
                        regV <= (update_done) ? update_regV : regV;
                        reseed_cntr <= (update_done) ? 1 : 0;
                        iv_valid <= 0;
                        rst_cbcmac <= 1;
                        gen_fsm <= INCREMENT;
                        fsm_state <= (health_error) ? RESET_CBCMAC : ((update_done) ? GENERATE_IV : INSTANTIATE);
                    end 

                    /**
                     * this state works as per below algorithm which is tuned to design requirements that is 
                       requested number of bits = 128 which is output length of CIPHER or encryption block
                    
                     * Algorithm:
                        1. temp = NULL
                        2. while(len(temp) < requested_number_of_bits) do
                            2.1 V = V + 1
                            2.2 temp = Block_Encrypt(Key, V)
                        3. {Key, V} = CTR_DRBG_Update(0, Key, V)
                    **/
                    GENERATE_IV: begin
                        case(gen_fsm)
                            INCREMENT: begin  // this state just updated register V
                                update_enb_n <= 1;
                                regV <= regV + 1;
                                iv_valid <= 0; 
                                gen_fsm <= ENCRYPT;
                                fsm_state <= (health_error) ? RESET_CBCMAC : GENERATE_IV;
                            end
                            ENCRYPT: begin  // this state performs encryption which gives IV
                                update_enb_n <= 1;
                                generated_iv <= (cipher_done) ? cipher_state : generated_iv;  // this is the actual IV

                                // managing VALID signal
                                if(cipher_done) iv_valid <= 1;  // asserting VALID to let AES know that CTR-DRBG has valid IV
                                else if(iv_valid && aes_ready) iv_valid <= 0;  // deasserting as soon as AES consumes current IV
                                else iv_valid <= iv_valid;

                                // when health tests fail FSM goes back to INCREMENT so that it can start a new
                                gen_fsm <= (iv_valid && aes_ready) ? CALL_UPDATE : ENCRYPT;
                                fsm_state <= (health_error) ? RESET_CBCMAC : GENERATE_IV;
                            end
                            CALL_UPDATE: begin  // invokes CTR-DRBG Update function
                                update_enb_n <= update_done;
                                regKEY <= (update_done) ? update_key : regKEY;
                                regV <= (update_done) ? update_regV : regV;
                                reseed_cntr <= (update_done) ? ((reseed_cntr == RESEED_LIM) ? 0 : reseed_cntr + 1) : reseed_cntr;
                                iv_valid <= 0;
                                gen_fsm <= (update_done) ? INCREMENT : CALL_UPDATE;
                                if(health_error) fsm_state <= RESET_CBCMAC;
                                else fsm_state <= (update_done) ? ((reseed_cntr == RESEED_LIM) ? RESEED : GENERATE_IV) : GENERATE_IV;
                            end
                            default: begin
                                update_enb_n <= 1;
                                regKEY <= regKEY;
                                regV <= regV;
                                generated_iv <= generated_iv;
                                reseed_cntr <= reseed_cntr;
                                iv_valid <= 0;
                                gen_fsm <= INCREMENT;
                                fsm_state <= GENERATE_IV;
                            end
                        endcase

                        provided_data <= 0;
                        rst_cbcmac <= 1;
                        ctr_drbg_ready <= 0;
                    end

                    /**
                     * this state models RESEED function which follows below algorithm

                        Reseed(entropy_input):
                            1. provided_data = entropy_input
                            2. {Key, V} = CTR_DRBG_Update(provided_data, Key, V)
                            3. reseed_counter = 1
                            4. return (Key, V, reseed_counter)
                    **/
                    RESEED: begin
                        ctr_drbg_ready <= (ctr_drbg_ready && cbcmac_valid) ? 0 : 1;  // extracting seed from CBC-MAC conditioner before enabling Update function
                        provided_data <= (ctr_drbg_ready && cbcmac_valid) ? seed : provided_data;

                        // enabling Update function accordingly
                        if(update_enb_n && cbcmac_valid) update_enb_n <= 0;  // enable Update fnction only when CBC-MAC gives valid seed
                        else if(!update_enb_n && update_done) update_enb_n <= 1;  // disabling once Update function is done
                        else update_enb_n <= update_enb_n;

                        regKEY <= (update_done) ? update_key : regKEY;
                        regV <= (update_done) ? update_regV : regV;
                        reseed_cntr <= (update_done) ? 1 : 0;
                        iv_valid <= 0;
                        rst_cbcmac <= 1;
                        gen_fsm <= INCREMENT;
                        fsm_state <= (health_error) ? RESET_CBCMAC : ((update_done) ? GENERATE_IV : RESEED);
                    end
                    UNINSTANTIATE: begin
                        update_enb_n <= 1;
                        provided_data <= 0;
                        reseed_cntr <= 0;
                        regKEY <= 0;
                        regV <= 0;
                        generated_iv <= 0;
                        ctr_drbg_ready <= 0;
                        iv_valid <= 0;
                        rst_cbcmac <= 1;
                        fsm_state <= INSTANTIATE;
                        gen_fsm <= INCREMENT;
                    end
                    RESET_CBCMAC: begin  // resetting CBC-MAC since health tests error has occurred
                        rst_cbcmac <= 0;
                        provided_data <= 0;
                        update_enb_n <= 1;
                        reseed_cntr <= 0;
                        regKEY <= 0;
                        regV <= 0;
                        generated_iv <= 0;
                        ctr_drbg_ready <= 0;
                        iv_valid <= 0;
                        gen_fsm <= INCREMENT;
                        fsm_state <= INSTANTIATE;
                    end
                    default: begin
                        update_enb_n <= 1;
                        provided_data <= 0;
                        reseed_cntr <= 0;
                        regKEY <= 0;
                        regV <= 0;
                        generated_iv <= 0;
                        ctr_drbg_ready <= 0;
                        iv_valid <= 0;
                        rst_cbcmac <= 1;
                        fsm_state <= INSTANTIATE;
                        gen_fsm <= INCREMENT;
                    end
                endcase
            end
            else begin
                iv_valid <= 0;
                provided_data <= provided_data;
                reseed_cntr <= reseed_cntr;
                regKEY <= regKEY;
                regV <= regV;
                generated_iv <= generated_iv;
                ctr_drbg_ready <= 0;
                update_enb_n <= 1;
                rst_cbcmac <= 1;
                gen_fsm <= gen_fsm;
                fsm_state <= fsm_state;
            end
        end
    end

    // this combinational block assigns corresponding regsiters to CIPHER inputs based on CTR-DRBG state
    always_comb begin
        case(fsm_state)
            INSTANTIATE: begin
                // since CIPHER is only required in UPDATE state it's enabled there and
                // gets disabled as soon as it finishes computing encrypted data
                cipher_enb_n = (update_fsm == UPDATE) ? cipher_done : 1;
                master_key = 0;
                cipher_state_in = update_regV;
            end
            GENERATE_IV: begin
                case(gen_fsm)
                    INCREMENT: begin
                        cipher_enb_n = 1;
                        master_key = regKEY;
                        cipher_state_in = regV;
                    end
                    ENCRYPT: begin
                        // CIPHER enable also depends on iv_valid because this states keeps on waiting for READY 
                        // from AES and meanwhile CIPHER has to stay disabled so it can't operate unnecessarily
                        cipher_enb_n = cipher_done | iv_valid;
                        master_key = regKEY;
                        cipher_state_in = regV;
                    end
                    CALL_UPDATE: begin
                        // since CIPHER is only required in UPDATE state it's enabled there and
                        // gets disabled as soon as it finishes computing encrypted data
                        cipher_enb_n = (update_fsm == UPDATE) ? cipher_done : 1;
                        master_key = update_key;
                        cipher_state_in = update_regV;
                    end
                    default: begin
                        cipher_enb_n = 1;
                        master_key = 0;
                        cipher_state_in = 0;
                    end
                endcase
            end
            RESEED: begin
                // since CIPHER is only required in UPDATE state it's enabled there and
                // gets disabled as soon as it finishes computing encrypted data
                cipher_enb_n = (update_fsm == UPDATE) ? cipher_done : 1;
                master_key = update_key;
                cipher_state_in = update_regV;
            end
            UNINSTANTIATE, RESET_CBCMAC: begin
                cipher_enb_n = 1;
                master_key = 0;
                cipher_state_in = 0;
            end
            default: begin
                cipher_enb_n = 1;
                master_key = 0;
                cipher_state_in = 0;
            end
        endcase
    end
endmodule
