/**
 * This is the top AES module that instantiates all other blocks inside it and uses them accordingly as per different AES modes
 * It supports all AES modes ECB, CBC, CFB, OFB and CTR
 * This module maintains a VALID-READY handshake to accept input 128-bit blocks so that sender can know when to send next block
   and when to accept output from AES
**/

import type_defs_pkg::*;

interface aes_interface (
    input logic clk,  // master or main clock signal
    input logic sampling_clk,  // high frequency independent clock on which external noise sources operate
    input logic rst_n,  // active low master or main reset signal
    input logic enb_n);  // active low enable signal

    /**
     * These bits are supplied by external noise sources to AES block which internally assigns them to TRNG and CBC-MAC blocks
     * raw_rand_bit_trng is used by TRNG to generate random numbers and raw_rand_bit_cbc_mac is used by CBC-MAC to generate unpredictable IV
    **/
    logic raw_rand_bit_trng;
    logic raw_rand_bit_cbc_mac;
    
    /** 
     * These are data ports
     * input_block port is used to accept 128-bit plaintext or ciphertext from external device
     * output_block port is used to give 128-bit ciphertext or plaintext to external device
    **/
    u128_t input_block;
    u128_t output_block;

    /**
     * mode port and it's bits specify:
        mode[2:0] = AES modes, mode[3] = encryption / decryption
        - 0000 is the reset value
     * AES modes (mode[2:0]) are encoded as:
        001 - ECB (Electronic Code Book)
        010 - CBC (Cipher Block Chaining)
        011 - CFB (Cipher Feedback)
        100 - OFB (Output Feedback)
        101 - CTR (Counter)
     * Encryption or Decryption is decided by mode[3]
        mode[3] = 0 - Encryption
        mode[3] = 1 - Decryption
    **/
    unibble mode;

    /**
     * master KEY related ports which specify KEY size and KEY
     * key_size port is used to specify AES KEY size
        00 - reset value
        01 - 128-bit KEY size
        10 - 192-bit KEY size
        11 - 256-bit KEY size
     * master_key port is of 256-bits and slice of it stays valid depending on KEY size
    **/
    logic [1:0] key_size;
    u256_t master_key;

    /**
     * These are the handshake signals for input and output channels
     * In input channel, sender has to assert VALID signal if it has valid blocks to send
       and AES accepts the input by asserting READY signal
     * In output channel, AES asserts VALID signal after it's done processing the input blocks
       and then waits for READY signal from other device while holding the final state
    **/
    logic inVALID, inREADY;  // input channel handshake signals
    logic outVALID, outREADY;  // output channel handshake signals

    /**
     * encCntxtIn is input port that accepts IV or Counter value from external device and encCntxtOut gives out internally 
       generated IV when operating in CBC, CFB and OFM modes or gives out counter values when operating in CTR mode.
     * During encryption iv_gen module generates an unpredictable IV internally which is used in CBC, CFB and OFB modes and
       this same IV is given as output to external devices so that they can store this IV. External devices are required to give
       same IV as input when it wants to decrypt the ciphertext that was generated previously.
     * When in CTR mode, AES outputs counter value for the first block so that external device can reuse the same counter value
       when it wants to decrypt previously encrypted text
    **/
    u128_t encCntxtOut;  // internally generated IV or counter value given as output to external device
    u128_t encCntxtIn;  // IV or counter value accepted from external device

    /**
     * This is an input signal from external device which is used to indicate that current incoming block ia the
       first 128-bit block of message so that AES can know when apply initial conditions to start a new in modes
       CBC, CFB, OFB and CTR. This signal is only valid in CBC, CFB, OFB and CTR modes and is ignored in ECB mode
     * External device is required to hold this signal high for first incoming block and then de-assert it for all 
       subsequent blocks of message. External device has to hold this signal high until it receives inREADY from
       AES which is the standard VALID-READY based handshake protocol does and this design works according to that.
    **/
    logic first;

    /**
     * This signal is encoded to indicate number of bits per segment in CFB mode. This signal is only valid
       in CFB mode and is ignored in other modes. The encoding of this signal is as follows:
        000 - reset value
        001 - CFB8 (8-bit per segment)
        010 - CFB16 (16-bit per segment)
        011 - CFB32 (32-bit per segment)
        100 - CFB64 (64-bit per segment)
        101 - CFB128 (128-bit per segment)
    **/
    logic [2:0] cfb_seg_bits;

    /**
     * These signals are used in OFB and CTR mode where AES has to know partial bit count in last message if sent message is partial
     * partial - this signal is set by external device to indicate that current incoming block is a partial block and not a full 128-bit block
     * valid_bits - this signal is set by external device to indicate how many bits are valid in the current incoming block if it's a partial block
     * If last incoming block is not a partial block then external device has to set partial signal to 0 and valid_bits signal is ignored
    **/
    logic partial;
    logic [6:0] valid_bits;

    modport aes_intf (
        output output_block, encCntxtOut, inREADY, outVALID,
        input input_block, encCntxtIn, inVALID, outREADY, cfb_seg_bits, partial, valid_bits, raw_rand_bit_trng, 
              raw_rand_bit_cbc_mac, master_key, key_size, mode, first, enb_n, rst_n, sampling_clk, clk
    );
endinterface

// AES top module
module aes(
    aes_interface.aes_intf aesBus);

    // internal registers and wires connecting sub-modules
    logic gated_clk;  // gated clock to reduce dynamic power consumption
    logic [1679:0] rand_word;  // 1680-bit random packet to Sbox/invSbox block
    logic trng_key_valid;  // tells Sbox/invSbox that random words are ready
    logic trng_ready_in;  // READY signal from Sbox/invSbox to TRNG to acknowledge receiption of random bits
    logic trng_dead_flag;  // asserted by TRNG to signify that it has encountered fatal failure
    logic sbox_ready;  // tells trng that Sbox is ready to accept random bits
    logic sbox_proceed;  // signal to SBox to advance to next state
    logic invSbox_ready;  // tells TRNG that invSbox is ready to accept random bits
    logic sbox_rst_trng;  // Sbox resets TRNG when health test results in fatal failures
    logic invSbox_rst_trng;  // invSbox resets TRNG when health test results in fatal failures
    logic trng_rst_n;  // active low reset signal to TRNG
    logic sbox_done;  // indicates that SBox is done computing subBytes
    u128_t subBytes;  // subByte of each element of state array computed by Sbox
    logic [1:0] sbox_enb_n;  // SBox enable signal
    logic [1:0] cphSBOX_enb_n;  // SBox enable from CIPHER
    logic [1:0] ark_sbox_enb_n;  // AddRoundKey enabling sbox
    u128_t sbox_state_in;  // input state matrix to SBox
    u128_t cphSBOX_state_in;  // SBox input state from CIPHER
    logic ark_enb_n;  // active low enable signal to AddRoundKey
    logic ark_sbox_proceed;  // signal to SBox to advance to next state only when AddRoundKey has aknowledged
    logic cipher_sbox_proceed;  // signal from CIPHER to SBox to advance to next state only when CIPHER has aknowledged
    logic cphARK_enb_n;  // addRoundKey enable signal controlled by CIPHER
    logic invcphARK_enb_n;  // addRoundKey enable signal controlled by invCIPHER
    logic key_only_mode;  // made high when AddRoundKey is only supposed to give expanded KEY
    unibble ark_round_num;  // this counter drives AddRoundKey to give corresponding KEY
    unibble cipher_round;  // keeps track of CIPHER round count
    unibble invcphARK_round;  // this counter drives AddRoundKey to give corresponding KEY for invCIPHER
    state_matrix_t addRoundKeyOut;  // output of addRoundKey
    logic ark_done;  // indicates that addRoundKey is done with computation
    logic cipher_enb_n, invCipher_enb_n;  // active low enable signals to CIPHER and invCIPHER
    word_t ark_sbox_word;  // rotated version of generated KEY is sent to SBox from AddRoundKey
    state_matrix_t ark_state_in;  // input state to addRoundKey
    state_matrix_t cphARK_state_in;  // input state to addRoundKey from CIPHER
    u128_t cipherIn;  // input state matrix (plaintext) to CIPHER
    u128_t cipherOut;  // state matrix that has gone through whole CIPHER algorithm
    logic cipher_done;  // becomes high when CIPHER is done computing transformed state
    u128_t invCipherIn;  // input state matrix (ciphertext) to invCIPHER
    u128_t invCipherOut;  // state matrix that has gone through whole invCIPHER algorithm
    logic invCipher_done;  // becomes high when invCIPHER is done computing transformed state
    logic iv_valid;  // becomes high when CTR-DRBG is done computing IV
    logic aes_iv_ready;  // READY signal from AES to let CTR-DRBG know that it's ready to consume IV
    u128_t generated_IV;  // unpredictable IV generated by IV_gen module

    // internal registers used in AES mode operations
    logic first_q;  // latches 'first' signal in CBC mode
    logic partial_q;  // latches 'partial' signal in OFB and CTR mode
    logic [6:0] valid_bits_q;  // latches 'valid_bits' signal in OFB and CTR mode
    unibble seg_cntr;  // keeps track of number of segments processed in CFB mode
    unibble seg_cntr_lim;  // seg_cntr max limit based on segment size in CFB mode
    u128_t temp, _temp;  // temporary registers to hold intermediate state in different AES modes
    aes_modes_internal_states fsm_state;
    u128_t ctr_mode_cntr;  // 128-bit counter used in CTR mode
    u128_t ctr_sm;  // stores ctr_mode_cntr in state_matrix_t format
    u128_t dctr_sm;  // stores _temp in state_matrix_t format
    u128_t ectx_ctr;   // encCntxtIn is converted back to plain counter order

    assign trng_rst_n = aesBus.rst_n & sbox_rst_trng & invSbox_rst_trng;  // TRNG is reset when either Sbox or invSbox has encountered fatal error or through global reset
    assign trng_ready_in = sbox_ready | invSbox_ready;  // TRNG gives random entropy when either of Sbox or invSbox is ready to accept them
    assign sbox_enb_n = (!cipher_enb_n) ? cphSBOX_enb_n : ark_sbox_enb_n;  // when CIPHER is active it manages SBox enable or else AddRoundKey will enable is directly
    assign sbox_state_in = (!cipher_enb_n) ? cphSBOX_state_in : {96'd0, ark_sbox_word};  
    assign sbox_proceed = ark_sbox_proceed | cipher_sbox_proceed;  // SBox can advance to next state when either AddRoundKey or CIPHER has acknowledged
    assign ark_enb_n = cphARK_enb_n & invcphARK_enb_n;  // AddRoundKey is enabled when either CIPHER or invCIPHER enables it
    assign key_only_mode = cipher_enb_n & ~invCipher_enb_n;  // AddRoundKey is supposed to give expanded KEY only when invCIPHER is enabled
    assign ark_state_in = (!cipher_enb_n) ? cphARK_state_in : 128'd0;
    assign ark_round_num = (!cphARK_enb_n) ? cipher_round : ((!invcphARK_enb_n) ? invcphARK_round : 4'd0);  // AddRoundKey is supposed to give corresponding KEY based on CIPHER or invCIPHER round count
    
    // sub modules
    icg ICG(  // ICG cell to reduce dynamic power consumption
        gated_clk,
        (~aesBus.enb_n | ~aesBus.rst_n),
        aesBus.clk);

    trng TRNG(
        rand_word,
        trng_key_valid,
        trng_dead_flag,
        trng_ready_in,
        aesBus.raw_rand_bit_trng,
        aesBus.sampling_clk,
        gated_clk,
        trng_rst_n);

    sbox SBOX(
        subBytes,
        sbox_ready, 
        sbox_done, 
        sbox_rst_trng,
        trng_dead_flag,
        sbox_state_in,
        rand_word, 
        trng_key_valid, 
        sbox_proceed, 
        sbox_enb_n[1], 
        sbox_enb_n[0], 
        aesBus.rst_n, 
        gated_clk);

    addRoundKey ADDROUNDKEY(
        addRoundKeyOut,
        ark_done, 
        ark_sbox_word, 
        ark_sbox_enb_n, 
        ark_sbox_proceed, 
        ark_state_in, 
        aesBus.master_key, 
        subBytes[31:0], 
        ark_round_num, 
        aesBus.key_size, 
        key_only_mode, 
        sbox_done, 
        ark_enb_n, 
        aesBus.rst_n, 
        gated_clk);

    cipher CIPHER(
        cipherOut, 
        cipher_round, 
        cipher_done, 
        cphARK_state_in, 
        cphSBOX_state_in, 
        cphSBOX_enb_n, 
        cipher_sbox_proceed, 
        cphARK_enb_n, 
        cipherIn, 
        aesBus.master_key, 
        subBytes, 
        addRoundKeyOut, 
        ark_sbox_word, 
        ark_sbox_enb_n, 
        aesBus.key_size, 
        sbox_done, 
        ark_done, 
        cipher_enb_n, 
        aesBus.rst_n, 
        gated_clk);

    invCipher INVCIPHER(
        invCipherOut, 
        invCipher_done, 
        invcphARK_round, 
        invcphARK_enb_n, 
        invSbox_ready, 
        invSbox_rst_trng, 
        invCipherIn, 
        rand_word[1343:0], 
        aesBus.master_key, 
        aesBus.key_size, 
        addRoundKeyOut, 
        ark_done, 
        trng_key_valid, 
        trng_dead_flag, 
        invCipher_enb_n, 
        aesBus.rst_n, 
        gated_clk);

    iv_gen IV_GENERATOR(
        generated_IV,
        iv_valid,
        aes_iv_ready,
        aesBus.raw_rand_bit_cbc_mac, 
        aesBus.enb_n, 
        aesBus.rst_n, 
        gated_clk);

    always_comb begin
        // no. of segments per 128-bit block based on segment size
        case(aesBus.cfb_seg_bits)
            3'b001: seg_cntr_lim = 4'hF;  // CFB8
            3'b010: seg_cntr_lim = 4'h7;  // CFB16
            3'b011: seg_cntr_lim = 4'h3;  // CFB32
            3'b100: seg_cntr_lim = 4'h1;  // CFB64
            // since in CFB128 a segment is a whole AES block itself it doesn't need a counter to keep track of segments
            default: seg_cntr_lim = 4'h0;
        endcase

        // data format conversions which are required only in CTR mode
        for(int i=0; i<16; i++) begin
            ctr_sm[(8*i) +: 8] = (aesBus.mode[2:0] == 3'b101) ? ctr_mode_cntr[(8*((12+(i/4))-(4*(i%4)))) +: 8] : 8'h00;
            dctr_sm[(8*i) +: 8] = (aesBus.mode == 4'b1101) ? _temp[(8*((12+(i/4))-(4*(i%4)))) +: 8] : 8'h00;
            ectx_ctr[(8*((12+(i/4))-(4*(i%4)))) +: 8] = (aesBus.mode == 4'b1101) ? aesBus.encCntxtIn[(8*i) +: 8] : 0;
        end
    end

    // this is the sequential block that implements AES modes
    always_ff @(posedge gated_clk) begin
        if(!aesBus.rst_n) begin
            cipher_enb_n <= 1;
            invCipher_enb_n <= 1;
            cipherIn <= 0;
            invCipherIn <= 0;
            aesBus.output_block <= 0;
            aes_iv_ready <= 0;
            first_q <= 0;
            partial_q <= 0;
            valid_bits_q <= 0;
            aesBus.encCntxtOut <= 0;
            aesBus.inREADY <= 0;
            aesBus.outVALID <= 0;
            seg_cntr <= 0;
            temp <= 0;
            _temp <= 0;
            ctr_mode_cntr <= 0;
            fsm_state <= ARM;
        end
        else begin
            if(!aesBus.enb_n) begin
                case(aesBus.mode[2:0])
                    /**
                     * ECB mode works by simply invoking CIPHER block to give ciphertext for given plaintext in ENCRYPTION mode
                     * It invokes invCIPHER block to give plaintext for given ciphertext in DECRYPTION mode
                            Cn = CIPHER(Pn, KEY);  - Encryption
                            Pn = invCIPHER(Cn, KEY);  - Decryption
                     * ECB mode doesn't require IV and doesn't use feedback path
                    **/
                    3'b001: begin
                        if(!aesBus.mode[3]) begin  // Encryption in ECB mode
                            case(fsm_state)
                                ARM: begin  // this states loads input block to CIPHER and enables it to start computing
                                    aesBus.inREADY <= 1;  // AES is READY to accept input block
                                    cipher_enb_n <= (aesBus.inVALID) ? 0 : 1;  // CIPHER is enabled when input block is valid
                                    cipherIn <= (aesBus.inVALID) ? aesBus.input_block : cipherIn;
                                    aesBus.outVALID <= 0;  // AES is not READY to give output block yet
                                    fsm_state <= (aesBus.inVALID) ? SHOOT : ARM;
                                end
                                SHOOT: begin  // this state lets CIPHER compute the transformed state and waits for it to finish
                                    aesBus.inREADY <= 0;
                                    cipher_enb_n <= cipher_done | aesBus.outVALID;  // CIPHER gets disabled when it's done computing the transformed state
                                    aesBus.output_block <= (cipher_done) ? cipherOut : aesBus.output_block;  // AES gives output block when CIPHER is done

                                    // asserting outVALID signal accordingly
                                    if(!aesBus.outVALID && cipher_done) aesBus.outVALID <= 1;
                                    else if(aesBus.outVALID && aesBus.outREADY) aesBus.outVALID <= 0;
                                    else aesBus.outVALID <= aesBus.outVALID;

                                    fsm_state <= (aesBus.outVALID && aesBus.outREADY) ? ARM : SHOOT; 
                                end
                            endcase

                            // invCIPHER is disabled in encryption mode
                            invCipherIn <= 0;
                            invCipher_enb_n <= 1;
                        end
                        else begin  // Decryption in ECB mode
                            case(fsm_state)
                                ARM: begin
                                    aesBus.inREADY <= 1;  // AES is READY to accept input block
                                    invCipher_enb_n <= (aesBus.inVALID) ? 0 : 1;  // invCIPHER is enabled when input block is valid
                                    invCipherIn <= (aesBus.inVALID) ? aesBus.input_block : invCipherIn;
                                    aesBus.outVALID <= 0;  // AES is not READY to give output block yet
                                    fsm_state <= (aesBus.inVALID) ? SHOOT : ARM;
                                end
                                SHOOT: begin
                                    aesBus.inREADY <= 0;
                                    invCipher_enb_n <= invCipher_done | aesBus.outVALID;  // invCIPHER gets disabled when it's done computing the transformed state
                                    aesBus.output_block <= (invCipher_done) ? invCipherOut : aesBus.output_block;  // AES gives output block when invCIPHER is done

                                    // asserting outVALID signal accordingly
                                    if(!aesBus.outVALID && invCipher_done) aesBus.outVALID <= 1;
                                    else if(aesBus.outVALID && aesBus.outREADY) aesBus.outVALID <= 0;
                                    else aesBus.outVALID <= aesBus.outVALID;

                                    fsm_state <= (aesBus.outVALID && aesBus.outREADY) ? ARM : SHOOT; 
                                end
                            endcase

                            // CIPHER is disabled in decryption mode
                            cipherIn <= 0;
                            cipher_enb_n <= 1;
                        end

                        aes_iv_ready <= 0;  // AES doesn't require IV in ECB mode
                        temp <= 0;  // temp register is not used in ECB mode
                        _temp <= 0;  // _temp register is not used in ECB mode
                        seg_cntr <= 0;  // this counter has no relevance in this mode
                        aesBus.encCntxtOut <= 0;
                        first_q <= 0;
                        partial_q <= 0;
                        valid_bits_q <= 0;
                    end

                    /**
                     * CBC mode is implemented as per below algorithm:
                        - Encryption:
                            C0 = CIPHER(P0 xor IV, KEY);
                            Cn = CIPHER(Pn xor Cn-1, KEY);
                        - Decryption:
                            P0 = invCIPHER(C0, KEY) xor IV;
                            Pn = invCIPHER(Cn, KEY) xor Cn-1;
                     * CBC mode requires IV and uses feedback path
                    **/
                    3'b010: begin  // CBC mode
                        if(!aesBus.mode[3]) begin  // Encryption in CBC mode
                            case(fsm_state)
                                ARM: begin
                                    aesBus.inREADY <= (aesBus.first) ? iv_valid : 1;  // AES doesn't accept input block until it has valid IV for first block and for subsequent blocks it accepts input block
                                    aes_iv_ready <= (aesBus.first) ? aesBus.inVALID : 0;  // AES doesn't accept IV until it has valid input block for first block and for subsequent blocks it doesn't require IV
                                    
                                    // setting up CIPHER inputs
                                    if(aesBus.first) begin
                                        cipher_enb_n <= (aesBus.inVALID && iv_valid) ? 0 : 1;  // CIPHER is enabled when input block and IV are provided
                                        cipherIn <= (aesBus.inVALID && iv_valid) ? (aesBus.input_block ^ generated_IV) : cipherIn;  // input block is XORed with IV for first block
                                        aesBus.encCntxtOut <= (aesBus.inVALID && iv_valid) ? generated_IV : aesBus.encCntxtOut;
                                    end
                                    else begin
                                        cipher_enb_n <= (aesBus.inVALID) ? 0 : 1;  // CIPHER is enabled when input block is provided
                                        cipherIn <= (aesBus.inVALID) ? (aesBus.input_block ^ aesBus.output_block) : cipherIn;  // input block is XORed with previous ciphertext for subsequent blocks 
                                    end

                                    aesBus.outVALID <= 0;  // AES is not READY to give output block yet
                                    fsm_state <= (aesBus.first) ? ((aesBus.inVALID && iv_valid) ? SHOOT : ARM) : ((aesBus.inVALID) ? SHOOT : ARM);
                                end
                                SHOOT: begin
                                    aesBus.inREADY <= 0;
                                    aes_iv_ready <= 0;
                                    cipher_enb_n <= cipher_done | aesBus.outVALID;  // CIPHER gets disabled when it's done computing the transformed state
                                    aesBus.output_block <= (cipher_done) ? cipherOut : aesBus.output_block;  // AES gives output block when CIPHER is done

                                    // asserting outVALID signal accordingly
                                    if(!aesBus.outVALID && cipher_done) aesBus.outVALID <= 1;
                                    else if(aesBus.outVALID && aesBus.outREADY) aesBus.outVALID <= 0;
                                    else aesBus.outVALID <= aesBus.outVALID;

                                    fsm_state <= (aesBus.outVALID && aesBus.outREADY) ? ARM : SHOOT;
                                end
                            endcase

                            // invCIPHER is disabled in encryption mode
                            invCipherIn <= 0;
                            invCipher_enb_n <= 1;
                        end
                        else begin  // Decryption in CBC mode
                            case(fsm_state)
                                ARM: begin
                                    // SHOOT state requires first signal but as per handshake protocol external device may deassert
                                    // 'first' signal as soon as AES accepts inputs. So SHOOT state will never be able to see if current
                                    // incoming block is the 1st one or not which is why 'first' is latched into 'first_q' and is made
                                    // 0 in SHOOT state
                                    first_q <= (aesBus.first) ? 1 : first_q;

                                    aesBus.inREADY <= 1;  // AES is READY to accept input block
                                    invCipher_enb_n <= (aesBus.inVALID) ? 0 : 1;  // invCIPHER is enabled when input block is provided
                                    invCipherIn <= (aesBus.inVALID) ? aesBus.input_block : invCipherIn;  // input block is given to invCIPHER for subsequent blocks
                                    _temp <= (aesBus.inVALID) ? aesBus.encCntxtIn : _temp;  // capturing IV from external device for first block
                                    aesBus.outVALID <= 0;  // AES is not READY to give output block yet
                                    fsm_state <= (aesBus.inVALID) ? SHOOT : ARM;
                                end
                                SHOOT: begin
                                    aesBus.inREADY <= 0;
                                    invCipher_enb_n <= invCipher_done | aesBus.outVALID;  // invCIPHER gets disabled when it's done computing the transformed state
                                    temp <= (invCipher_done) ? invCipherIn : temp;  // stores previous ciphertext for subsequent blocks
                                    first_q <= (invCipher_done && first_q) ? 0 : first_q;  // making it 0 so it won't unnecessarily stay high for subsequent incoming blocks

                                    // XORing with IV or previous ciphertext depending on whether it's first block or subsequent blocks
                                    if(first_q) aesBus.output_block <= (invCipher_done) ? (invCipherOut ^ _temp) : aesBus.output_block;
                                    else aesBus.output_block <= (invCipher_done) ? (invCipherOut ^ temp) : aesBus.output_block;

                                    // asserting outVALID signal accordingly
                                    if(!aesBus.outVALID && invCipher_done) aesBus.outVALID <= 1;
                                    else if(aesBus.outVALID && aesBus.outREADY) aesBus.outVALID <= 0;
                                    else aesBus.outVALID <= aesBus.outVALID;

                                    fsm_state <= (aesBus.outVALID && aesBus.outREADY) ? ARM : SHOOT;
                                end
                            endcase

                            // CIPHER is disabled in decryption mode
                            cipherIn <= 0;
                            cipher_enb_n <= 1;
                            aes_iv_ready <= 0;  // IV is not generated internally in CBC-dec but given by external device
                            aesBus.encCntxtOut <= 0;
                        end
                        
                        seg_cntr <= 0;  // this counter has no relevance in this mode
                    end

                    /**
                     * CFB mode is implemented as per below algorithm:
                        - Encryption:
                            I0 = IV;
                            Ij = LSBb-s(Ij-1) | Cj-1  for j = 1 … n;
                            Oj = CIPHER(Ij, KEY)      for j = 0, 1 … n;
                            Cj = Pj xor MSBs(Oj)      for j = 0, 1 … n;
                        - Decryption:
                            I0 = IV;
                            Ij = LSBb-s(Ij-1) | Cj-1  for j = 1 … n;
                            Oj = CIPHER(Ij, KEY)      for j = 0, 1 … n;
                            Pj = Cj xor MSBs(Oj)      for j = 0, 1 … n;
                     * CFB mode requires IV and uses feedback path
                    **/
                    3'b011: begin  // CFB mode
                        case(fsm_state)
                            ARM: begin
                                // seg_cntr wraps to 0 after every input block is processed. So AES is required to raise READY at this time.
                                // When AES receives first block of current message it has to wait for IV_gen to generate valid IV and only then can it
                                // accept input block. For subsequent blocks it can accept input block without waiting for IV_gen to generate valid IV.
                                aesBus.inREADY <= (aesBus.first || seg_cntr == 0) ? ((aesBus.first) ? iv_valid : 1) : 0;

                                aes_iv_ready <= (aesBus.first) ? aesBus.inVALID : 0;  // AES doesn't accept IV until it has valid 1st segment in 1stt block and for subsequent blocks it doesn't require IV
                                temp <= (aesBus.inREADY && aesBus.inVALID) ? aesBus.input_block : temp;  // capturing incoming 128-bit block
                                aesBus.encCntxtOut <= (!aesBus.mode[3]) ? ((aesBus.first && aesBus.inVALID && aesBus.inREADY) ? generated_IV : aesBus.encCntxtOut) : 0;
                                aesBus.outVALID <= 0;

                                // setting up CIPHER inputs
                                if(aesBus.first) begin
                                    cipher_enb_n <= (aesBus.inVALID && aesBus.inREADY) ? 0 : 1;
                                    seg_cntr <= 0;  // resetting it so that if previous message is dropped mid operation then current new message can get proper initial state

                                    if(!aesBus.mode[3] && iv_valid) cipherIn <= generated_IV;  // during Encryption AES generates IV internally
                                    else if(aesBus.mode[3] && aesBus.inVALID && aesBus.inREADY) cipherIn <= aesBus.encCntxtIn;  // during Decryption AES accepts IV from external device
                                    else cipherIn <= cipherIn;
                                end
                                else begin
                                    if(seg_cntr != 0 || (aesBus.inVALID && aesBus.inREADY)) begin
                                        case(aesBus.cfb_seg_bits)  // slicing and concatenating based on bits per segment
                                            // since output_block is getting accumulated from MSB side, computed segments always sit at MSB side
                                            3'b001: cipherIn <= (!aesBus.mode[3]) ? {cipherIn[119:0], aesBus.output_block[127:120]} : {cipherIn[119:0], _temp[127:120]};  // CFB8 
                                            3'b010: cipherIn <= (!aesBus.mode[3]) ? {cipherIn[111:0], aesBus.output_block[127:112]} : {cipherIn[111:0], _temp[127:112]};  // CFB16
                                            3'b011: cipherIn <= (!aesBus.mode[3]) ? {cipherIn[95:0], aesBus.output_block[127:96]} : {cipherIn[95:0], _temp[127:96]};  // CFB32
                                            3'b100: cipherIn <= (!aesBus.mode[3]) ? {cipherIn[63:0], aesBus.output_block[127:64]} : {cipherIn[63:0], _temp[127:64]};  // CFB64
                                            3'b101: cipherIn <= (!aesBus.mode[3]) ? aesBus.output_block : _temp;  // CFB128
                                            default: cipherIn <= 0; 
                                        endcase

                                        cipher_enb_n <= 0;
                                        seg_cntr <= seg_cntr;
                                    end
                                    else begin
                                        cipher_enb_n <= 1;
                                        cipherIn <= cipherIn;
                                        seg_cntr <= seg_cntr;
                                    end
                                end

                                if(aesBus.first || seg_cntr == 0) fsm_state <= (aesBus.inVALID && aesBus.inREADY) ? SHOOT : ARM;
                                else fsm_state <= SHOOT;  // takes only 1 cycle to update CIPHER input while operating within 128-bit block
                            end
                            SHOOT: begin
                                aesBus.inREADY <= 0;
                                aes_iv_ready <= 0;
                                cipher_enb_n <= cipher_done | aesBus.outVALID;
                                seg_cntr <= (cipher_done && seg_cntr != seg_cntr_lim) ? seg_cntr + 1 : ((aesBus.outVALID && aesBus.outREADY) ? 0 : seg_cntr);
                                
                                case(aesBus.cfb_seg_bits)  // updating output segment
                                    3'b001: begin 
                                        aesBus.output_block <= (cipher_done) ? (aesBus.output_block >> 8) | {(temp[(7'(seg_cntr) << 3) +: 8] ^ cipherOut[127:120]), 120'd0} : aesBus.output_block;
                                        _temp <= (aesBus.mode[3]) ? ((cipher_done) ? (_temp >> 8) | {temp[(7'(seg_cntr) << 3) +: 8], 120'd0} : _temp) : 0;  // latching current input into _temp so that it can be used as previous ciphertext in decryption mode
                                    end
                                    3'b010: begin
                                        aesBus.output_block <= (cipher_done) ? (aesBus.output_block >> 16) | {(temp[(7'(seg_cntr) << 4) +: 16] ^ cipherOut[127:112]), 112'd0} : aesBus.output_block;
                                        _temp <= (aesBus.mode[3]) ? ((cipher_done) ? (_temp >> 16) | {temp[(7'(seg_cntr) << 4) +: 16], 112'd0} : _temp) : 0;
                                    end
                                    3'b011: begin
                                        aesBus.output_block <= (cipher_done) ? (aesBus.output_block >> 32) | {(temp[(7'(seg_cntr) << 5) +: 32] ^ cipherOut[127:96]), 96'd0} : aesBus.output_block;
                                        _temp <= (aesBus.mode[3]) ? ((cipher_done) ? (_temp >> 32) | {temp[(7'(seg_cntr) << 5) +: 32], 96'd0} : _temp) : 0;
                                    end
                                    3'b100: begin
                                        aesBus.output_block <= (cipher_done) ? (aesBus.output_block >> 64) | {(temp[(7'(seg_cntr) << 6) +: 64] ^ cipherOut[127:64]), 64'd0} : aesBus.output_block;
                                        _temp <= (aesBus.mode[3]) ? ((cipher_done) ? (_temp >> 64) | {temp[(7'(seg_cntr) << 6) +: 64], 64'd0} : _temp) : 0;
                                    end
                                    3'b101: begin
                                        aesBus.output_block <= (cipher_done) ? (temp ^ cipherOut) : aesBus.output_block;
                                        _temp <= (aesBus.mode[3]) ? ((cipher_done) ? temp : _temp) : 0;
                                    end
                                    default: begin
                                        aesBus.output_block <= 0;
                                        _temp <= 0;
                                    end
                                endcase

                                // asserting outVALID signal accordingly
                                if(cipher_done && seg_cntr == seg_cntr_lim) aesBus.outVALID <= 1;  // VALID is asserted after all output segments are accumulated into output_block
                                else if(aesBus.outVALID && aesBus.outREADY) aesBus.outVALID <= 0;
                                else aesBus.outVALID <= aesBus.outVALID;

                                fsm_state <= (seg_cntr == seg_cntr_lim) ? ((aesBus.outVALID && aesBus.outREADY) ? ARM : SHOOT) : ((cipher_done) ? ARM : SHOOT);
                            end
                        endcase

                        // invCIPHER is not used in CFB mode
                        invCipher_enb_n <= 1;
                        invCipherIn <= 0;
                        first_q <= 0;
                        partial_q <= 0;
                        valid_bits_q <= 0;
                    end

                    /**
                     * OFB mode is implemented as per below algorithm:
                        - Encryption:
                            I0 = IV;
                            Ij = Oj-1             for j = 1 … n;
                            Oj = CIPHER(Ij, KEY)  for j = 0, 1 … n;
                            Cj = Pj xor Oj        for j = 0, 1 … n;
                            C* = P* xor MSBu(O)   this is the last block which is partial
                        - Decryption:
                            I0 = IV;
                            Ij = Oj-1             for j = 1 … n;
                            Oj = CIPHER(Ij, KEY)  for j = 0, 1 … n;
                            Pj = Cj xor Oj        for j = 0, 1 … n;
                            P* = C* xor MSBu(O)   this is the last block which is partial
                     * OFB mode requires IV and uses feedback path
                    **/
                    3'b100: begin
                        case(fsm_state)
                            ARM: begin
                                aesBus.inREADY <= (aesBus.first) ? iv_valid : 1;  // AES doesn't accept input block until it has valid IV for first block and for subsequent blocks it accepts input block
                                aes_iv_ready <= (aesBus.first) ? aesBus.inVALID : 0;  // AES doesn't accept IV until it has valid input block for first block and for subsequent blocks it doesn't require IV
                                temp <= (aesBus.inVALID) ? aesBus.input_block : temp;  // capturing input block so that it can be used in SHOOT state
                                partial_q <= (aesBus.partial) ? 1 : partial_q;
                                valid_bits_q <= (aesBus.partial) ? aesBus.valid_bits : valid_bits_q;
                                aesBus.encCntxtOut <= (!aesBus.mode[3]) ? ((aesBus.first && aesBus.inVALID && iv_valid) ? generated_IV : aesBus.encCntxtOut) : 0;

                                // setting up CIPHER inputs
                                if(aesBus.first) begin
                                    cipher_enb_n <= (aesBus.inVALID && iv_valid) ? 0 : 1;  // CIPHER is enabled when input block and IV are provided
                                    
                                    if(!aesBus.mode[3] && iv_valid) cipherIn <= generated_IV;  // during Encryption AES generates IV internally
                                    else if(aesBus.mode[3] && aesBus.inVALID) cipherIn <= aesBus.encCntxtIn;  // during Decryption AES accepts IV from external device
                                    else cipherIn <= cipherIn;
                                end
                                else begin
                                    cipher_enb_n <= (aesBus.inVALID) ? 0 : 1;  // CIPHER is enabled when input block is provided
                                    cipherIn <= (aesBus.inVALID) ? cipherOut : cipherIn;  // feedback path where previous output is taken as input
                                end

                                aesBus.outVALID <= 0;  // AES is not READY to give output block yet
                                fsm_state <= (aesBus.first) ? ((aesBus.inVALID && iv_valid) ? SHOOT : ARM) : ((aesBus.inVALID) ? SHOOT : ARM);
                            end 
                            SHOOT: begin
                                aesBus.inREADY <= 0;
                                aes_iv_ready <= 0;
                                cipher_enb_n <= cipher_done | aesBus.outVALID;  // CIPHER gets disabled when it's done computing the transformed state
                                partial_q <= (cipher_done && partial_q) ? 0 : partial_q;
                                valid_bits_q <= (cipher_done && partial_q) ? 0 : valid_bits_q;

                                if(!partial_q) aesBus.output_block <= (cipher_done) ? (temp ^ cipherOut) : aesBus.output_block;
                                else aesBus.output_block <= (cipher_done) ? ((temp ^ cipherOut) & ({128{1'b1}} << (~valid_bits_q + 7'd1))) : aesBus.output_block;

                                // asserting outVALID signal accordingly
                                if(!aesBus.outVALID && cipher_done) aesBus.outVALID <= 1;
                                else if(aesBus.outVALID && aesBus.outREADY) aesBus.outVALID <= 0;
                                else aesBus.outVALID <= aesBus.outVALID;

                                fsm_state <= (aesBus.outVALID && aesBus.outREADY) ? ARM : SHOOT;
                            end 
                        endcase

                        // invCIPHER isn't required in this mode
                        invCipherIn <= 0;
                        invCipher_enb_n <= 1;
                        _temp <= 0;  // this register is of no use in this mode
                        seg_cntr <= 0;  // this counter has no relavance in this mode
                        first_q <= 0;
                    end

                    /**
                     * CTR mode is implemented as per below algorithm:
                        - Encryption:
                            Oj = CIPHER(Ij, CNTR)  for j = 0, 1 … n;
                            Cj = Pj xor Oj         for j = 0, 1 … n;
                            C* = P* xor MSBu(O)    this is the last block which is partial
                        - Decryption:
                            Oj = CIPHER(Ij, CNTR)  for j = 0, 1 … n;
                            Pj = Cj xor Oj         for j = 0, 1 … n;
                            P* = C* xor MSBu(O)    this is the last block which is partial
                    **/
                    3'b101: begin
                        case(fsm_state)
                            ARM: begin
                                aesBus.inREADY <= 1;  // AES is READY to accept input block
                                temp <= (aesBus.inVALID) ? aesBus.input_block : temp;
                                _temp <= (aesBus.mode[3] && aesBus.first) ? ectx_ctr : _temp;
                                partial_q <= (aesBus.partial) ? 1 : partial_q;
                                valid_bits_q <= (aesBus.partial) ? aesBus.valid_bits : valid_bits_q;
                                cipher_enb_n <= (aesBus.inVALID) ? 0 : 1;  // CIPHER is enabled when input block is valid
                                cipherIn <= (!aesBus.mode[3]) ? ctr_sm : ((aesBus.first) ? aesBus.encCntxtIn : dctr_sm);
                                aesBus.outVALID <= 0;  // AES is not READY to give output block yet
                                aesBus.encCntxtOut <= (!aesBus.mode[3]) ? ((aesBus.first && aesBus.inVALID) ? ctr_sm : aesBus.encCntxtOut) : 0;
                                fsm_state <= (aesBus.inVALID) ? SHOOT : ARM;
                            end 
                            SHOOT: begin
                                aesBus.inREADY <= 0;
                                cipher_enb_n <= cipher_done | aesBus.outVALID;  // CIPHER gets disabled when it's done computing the transformed state
                                ctr_mode_cntr <= (!aesBus.mode[3] && cipher_done) ? ctr_mode_cntr + 1 : ctr_mode_cntr;
                                _temp <= (aesBus.mode[3] && cipher_done) ? _temp + 1 : _temp;
                                partial_q <= (cipher_done && partial_q) ? 0 : partial_q;
                                valid_bits_q <= (cipher_done && partial_q) ? 0 : valid_bits_q;
                                
                                if(!partial_q) aesBus.output_block <= (cipher_done) ? (temp ^ cipherOut) : aesBus.output_block;
                                else aesBus.output_block <= (cipher_done) ? ((temp ^ cipherOut) & ({128{1'b1}} << (~valid_bits_q + 7'd1))) : aesBus.output_block;

                                // asserting outVALID signal accordingly
                                if(!aesBus.outVALID && cipher_done) aesBus.outVALID <= 1;
                                else if(aesBus.outVALID && aesBus.outREADY) aesBus.outVALID <= 0;
                                else aesBus.outVALID <= aesBus.outVALID;

                                fsm_state <= (aesBus.outVALID && aesBus.outREADY) ? ARM : SHOOT; 
                            end 
                        endcase

                        // invCIPHER isn't required in this mode
                        invCipherIn <= 0;
                        invCipher_enb_n <= 1;
                        aes_iv_ready <= 0;  // IV is not required in this mode
                        seg_cntr <= 0;  // this counter has no relavance in this mode
                        first_q <= 0;
                    end

                    default: begin
                        cipher_enb_n <= 1;
                        invCipher_enb_n <= 1;
                        cipherIn <= 0;
                        invCipherIn <= 0;
                        aesBus.output_block <= 0;
                        aesBus.encCntxtOut <= 0;
                        first_q <= 0;
                        partial_q <= 0;
                        valid_bits_q <= 0;
                        aes_iv_ready <= 0;
                        aesBus.inREADY <= 0;
                        aesBus.outVALID <= 0;
                        seg_cntr <= 0;
                        temp <= 0;
                        _temp <= 0;
                        fsm_state <= ARM;
                    end
                endcase
            end
            else begin
                cipher_enb_n <= 1;
                invCipher_enb_n <= 1;
                cipherIn <= cipherIn;
                invCipherIn <= invCipherIn;
                aesBus.output_block <= aesBus.output_block;
                aesBus.encCntxtOut <= aesBus.encCntxtOut;
                aes_iv_ready <= 0;
                aesBus.inREADY <= 0;
                aesBus.outVALID <= 0;
                seg_cntr <= seg_cntr;
                first_q <= 0;
                partial_q <= 0;
                valid_bits_q <= 0;
                temp <= temp;
                _temp <= _temp;
                ctr_mode_cntr <= ctr_mode_cntr;
                fsm_state <= fsm_state;
            end
        end
    end
endmodule