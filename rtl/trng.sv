/**
 * This TRNG block is designed to output 1680 random bits so that CIPHER block can consume it.
 * CIPHER block internally has 2 Sbox's, one Sbox converts whole state matrix and produces subBytes for each element in state matrix. 
   This Sbox consumes 448 random bits (28 random bits per byte).
 * Another Sbox is used in AddRoundKey for keyExpansion logic where Sbox converts a word (32-bits) and produces subBytes for them. This Sbox consumes 112 random bits.
 * Each round in CIPHER invokes Sbox twice when KEY size is either 128 or 256 bits but CIPHER invokes Sbox only once per round only when (i%6=0) is met. 
   So the CIPHER consumes 560 random bits per round at max.
 * This TRNG can output 1680 random bits so it can accommodate 3 CIPHER rounds. While CIPHER works for 3 rounds, TRNG meanwhile computes next batch of 1680 random bits. 
 * So using this mechanism both TRNG and CIPHER work in a pipelined fashion to ensure maximum through-put is acheieved using this design implementation .
**/

import trng_param_pkg::*;
import type_defs_pkg::*;

module trng(
    output logic [1679:0] rand_word,  // 1680-bit random packet to CIPHER block
    output logic trng_key_valid,  // tells S-box that random words are ready
    output logic dead_flag,  // tells SBox that TRNG has failed
    input logic sbox_ready,  // SBox acknowledges receiption of random bits
    input logic raw_rand_bit,  // noise source bit which is driven by noise source model
    input logic sampling_clk,  // high frequency independent clock for noise source
    input logic clk, ext_rst_n);

    logic rand_bit_sync1, rand_bit;  // CDC synchronized rand_bit (clk domain)

    // entropy collector - keccak handshake
    logic [63:0] entropy_word;
    logic valid, ready;

    logic key_ready;  // keccak to control unit
    logic health_error;  // health tests to control unit

    // control unit outputs
    logic noise_src_enb_n;
    logic enb_health_tests_n;
    logic get_raw_entropy;
    logic local_rst_n;

    // since noise source has high frequency independant clock, the output random bit of this 
    // module has to be synchronized with clock frequency of other modules
    // so 2-flop synchronizer is used for clock domain crossing
    // random bit synchronizer, sampling_clk to clk domain
    always_ff @(posedge clk) begin
        if(!ext_rst_n) begin
            rand_bit_sync1 <= 0;
            rand_bit <= 0;
        end
        else begin
            rand_bit_sync1 <= raw_rand_bit;  // first flip-flop
            rand_bit <= rand_bit_sync1;  // second flip-flop
        end
    end

    // entropy collector (clk domain)    
    entropy_clctr ENTROPY_COLLECTOR(entropy_word, valid, rand_bit, ready, clk, local_rst_n);

    // health tests (clk domain)
    health_tests HEALTH_TESTS(health_error, rand_bit, enb_health_tests_n, clk, ext_rst_n);

    // keccak conditioning block (clk domain)
    keccak_cond KECCAK_COND(rand_word, ready, trng_key_valid, entropy_word, get_raw_entropy, sbox_ready, valid, clk, local_rst_n);

    // control unit (clk domain)
    control_unit CONTROL_UNIT(noise_src_enb_n, enb_health_tests_n, get_raw_entropy, local_rst_n, dead_flag, health_error, trng_key_valid, clk, ext_rst_n);
endmodule

// entropy collector
module entropy_clctr(
    output logic [63:0] entropy_word,
    output logic valid,
    input logic rand_bit, ready, clk, rst_n);

    logic [5:0] sipo_fill_cntr; 

    always_ff @(posedge clk) begin
        if(!rst_n) begin
            entropy_word <= 0;
            valid <= 0;
            sipo_fill_cntr <= 0;
        end
        // serial-in parallel-out shift register behavior
        else begin
            if(valid && !ready) begin  // when valid data is available that data should not be changed until receiver is ready
                entropy_word <= entropy_word;
                sipo_fill_cntr <= sipo_fill_cntr;
            end
            else begin
                entropy_word <= (entropy_word << 1) | {63'd0, rand_bit};
                sipo_fill_cntr <= sipo_fill_cntr + 1;  // increments when register gets accumulated with rand_bit
            end
            
            // asserting valid signal 
            if(valid && ready) valid <= 0;  // deasserting valid as the transaction has completed
            else if(sipo_fill_cntr == 63) valid <= valid | 1'b1;  // sticky valid that stays high until ready = 1
            else valid <= valid;
        end
    end
endmodule

// Keccak conditioning block
module keccak_cond (
    output logic [1679:0] rand_word,  // 1680 random bits needed for CIPHER
    output logic ready,  // indicates entropy collector that this block is ready to accecpt raw entropy
    output logic key_ready_req,  // indicates S-Box() that this block has valid key to send
    input logic [63:0] raw_entropy,  // raw entropy from entropy collector 
    input logic get_raw_entropy,  // if high then accepts raw entropy or else uses DRBG feedback
    input logic sbox_ready,  // signal from Sbox that it received random bits
    input logic valid,  // from entropy collector indicating that it's ready to send the data
    input logic clk, rst_n);
    
    keccak_state_t state;  // state matrix for Keccak conditioning block
    logic [191:0] temp_entropy;  // to store raw entropy bits
    logic [4:0] round_cntr;  // keeps track of number of rounds
    logic [1:0] rx_cntr;  // keeps track of handshakes
    Keccak_states fsm_state;  
    logic [1599:0] squeeze_buff;  // stores data temporarily until SQUEEZE enters 2nd cycle
    logic squeeze_done;  // used to extend SQUEEZE state by another cycle

    // flattening state matrix to access slices of it
    logic [1599:0] state_flat;
    assign state_flat = {>>{state}};

    // computing theta for state matrix
    function automatic keccak_state_t theta(input keccak_state_t s);
        logic [4:0][63:0] c;  // column parity bits
        logic [4:0][63:0] d, c_rot;  // theta diffusion term, left rotation of c
        int m, n;
        keccak_state_t diff_state;

        for(int i=0; i<5; i++) begin
            // computing column parity
            c[i] = s[0][i] ^ s[1][i] ^ s[2][i] ^ s[3][i] ^ s[4][i]; 

            // computing theta diffusion term : D[x] = C[x−1] ⊕ ROT(C[x+1],1)
            m = (i == 0) ? 4 : (i-1);
            n = (i == 4) ? 0 : (i+1);
            c_rot[i] = {c[i][62:0], c[i][63]};  // left rotation
            d[i] = c[m] ^ c_rot[n];
        end

        // applying diffusion
        for(int i=0; i<25; i++) begin
            diff_state[i/5][i%5] = s[i/5][i%5] ^ d[i%5];
        end

        return diff_state;
    endfunction

    // computing rho for state matrix
    function automatic keccak_state_t rho(input keccak_state_t s);
        int n;
        logic [63:0] lane;
        keccak_state_t rot_s;

        for(int i=0; i<25; i++) begin
            n = RHO_OFFSETS[i/5][i%5];
            lane = s[i/5][i%5];
            rot_s[i/5][i%5] = (n == 0) ? lane : ((lane << n) | (lane >> (64 - n)));
        end
        return rot_s;
    endfunction

    // computing pi for state matrix
    function automatic keccak_state_t pi(input keccak_state_t s);
        keccak_state_t temp;
        
        for(int i=0; i<25; i++) 
            temp[i/5][i%5] = s[((i/5) + (3*(i%5))) % 5][i/5];
        return temp;
    endfunction

    // computing chi which is non-linear
    function automatic keccak_state_t chi(input keccak_state_t s);
        keccak_state_t temp;
        for(int i=0; i<25; i++) 
            temp[i/5][i%5] = s[i/5][i%5] ^ (~s[i/5][((i%5)+1)%5] & s[i/5][((i%5)+2)%5]);
        return temp;
    endfunction

    // computing iota for state matrix
    function automatic keccak_state_t iota(input keccak_state_t s, logic [63:0] round_const);
        keccak_state_t iota_s;

        for(int i=0; i<25; i++) 
            iota_s[i/5][i%5] = ((i/5 == 0) && (i%5 == 0)) ? (s[0][0] ^ round_const) : s[i/5][i%5];
        return iota_s;
    endfunction

    always_ff @(posedge clk) begin
        if(!rst_n) begin
            fsm_state <= ABSORB;
            rand_word <= 0;
            state <= 0;
            temp_entropy <= 0;
            squeeze_buff <= 0;
            squeeze_done <= 0;
            round_cntr <= 0;
            rx_cntr <= 0;
            ready <= 0;
            key_ready_req <= 0;
        end
        else begin
            case(fsm_state)
                ABSORB: begin
                    key_ready_req <= 0;
                    round_cntr <= 0;

                    // initial stage: round-0
                    // state[191:0]     = true noise source entropy / feedback
                    // state[192]       = 1 (pad start)
                    // state[1342:193]  = 0 (zero padding)
                    // state[1343]      = 1 (pad end)
                    // state[1599:1344] = 0 (capacity, initialized to zero)
                    if(get_raw_entropy) begin  // gets raw entropy bits from entropy collector
                        ready <= 1;
                        if(valid) begin
                            if(rx_cntr == 3) temp_entropy <= temp_entropy; 
                            else temp_entropy[(8'(rx_cntr) << 6) +: 64] <= temp_entropy[(8'(rx_cntr) << 6) +: 64] ^ raw_entropy;
                            rx_cntr <= rx_cntr + 1;
                        end
                        else begin
                            temp_entropy <= temp_entropy;
                            rx_cntr <= rx_cntr;
                        end
                        if(rx_cntr == 3) begin
                            state <= state ^ {256'd0, 1'd1, 1150'd0, 1'd1, temp_entropy};
                            fsm_state <= PERMUTE;
                        end 
                        else begin
                            state <= state;
                            fsm_state <= ABSORB;
                        end
                    end
                    else begin  // DRBG (deterministic random bit generator) feedback path
                        state <= state ^ {256'd0, 1'd1, 1150'd0, 1'd1, state[0][2:0]};  // gets same bits from previous computation
                        fsm_state <= PERMUTE;
                    end
                end 
                PERMUTE: begin
                    state <= iota(chi(pi(rho(theta(state)))), KECCAK_RC[round_cntr]);
                    round_cntr <= (round_cntr == 23) ? 0 : round_cntr + 1;  // updating round_cntr
                    // since "absorb" completed, resetting these registers for next iteration
                    ready <= 0;
                    rx_cntr <= 0;
                    key_ready_req <= 0;
                    fsm_state <= (round_cntr == 23) ? SQUEEZE : PERMUTE;
                end
                SQUEEZE: begin
                    ready <= 0;
                    rx_cntr <= 0;

                    if(!squeeze_done) begin
                        squeeze_buff <= state_flat;
                        squeeze_done <= 1;
                        temp_entropy <= state[0][2:0];  // capturing slice of state that went through all 24 permutation rounds

                        // re-computing Keccak state by running single round so to get unique and fresh random bits
                        // which gets concatenated with 1600 random bits to give final 1680 random bits
                        state <= iota(chi(pi(rho(theta(state)))), KECCAK_RC[0]);
                        fsm_state <= SQUEEZE;
                    end 
                    else begin
                        key_ready_req <= 1;  // key_ready_req has become high since required random bits computed

                        if(sbox_ready) begin
                            rand_word <= {state_flat[79:0], squeeze_buff};
                            fsm_state <= ABSORB;  // goes back to ABSORB state to compute another batch of random bits
                            squeeze_done <= 0;  // resetting it again for next batch
                        end
                        else fsm_state <= SQUEEZE;
                    end 
                end
                default: fsm_state <= ABSORB;
            endcase
        end
    end
endmodule

// NIST standard health tests 
module health_tests (
    output logic error,
    input logic rand_bit, enable_health_test_n,
    input logic clk, rst_n);

    localparam APT_CNTR_WIDTH = $clog2(APT_BIT_WINDOW);
    localparam RCT_CNTR_WIDTH = $clog2(RCT_THRESHOLD + 1);

    logic [RCT_CNTR_WIDTH-1:0] rct_counter;
    logic rct_prev_bit;
    logic [APT_CNTR_WIDTH-1 : 0] apt_window_cntr, apt_counter;
    wire rct_error, apt_error;

    // Repetetion Count Test (RCT)
    always_ff @(posedge clk) begin
        if(!rst_n) begin
            rct_counter <= 0;
            rct_prev_bit <= 0;
        end 
        else begin
            if(!enable_health_test_n) begin
                if(rct_prev_bit == rand_bit) rct_counter <= rct_counter + 1; // counter increases only when consecutive bits appear
                else rct_counter <= 0;
                rct_prev_bit <= rand_bit;  // updating rct_prev_bit so that it can be used in next cycle for comparison
            end
            else begin
                rct_counter <= rct_counter;
                rct_prev_bit <= rct_prev_bit;
            end
        end
    end

    // Adaptive Proportion Test (APT)
    always_ff @(posedge clk) begin
        if(!rst_n) begin
            apt_window_cntr <= 0;
            apt_counter <= 0;
        end
        else begin
            if(!enable_health_test_n) begin
                if(apt_window_cntr == (APT_CNTR_WIDTH)'(APT_BIT_WINDOW-1)) begin
                    apt_counter <= (rand_bit) ? 1 : 0; // if when 1024th bit is 1 then it is counted or else the registers gets reset
                    apt_window_cntr <= 0; // explicit window counter reset to keep both registers in sync
                end
                else begin 
                    apt_counter <= apt_counter + type(apt_counter)'(rand_bit); 
                    apt_window_cntr <= apt_window_cntr + 1; // this counter keeps track of 1024-bit window
                end
            end
            else begin
                apt_window_cntr <= apt_window_cntr;
                apt_counter <= apt_counter;
            end
        end
    end

    assign rct_error = (rct_counter >= (RCT_CNTR_WIDTH)'(RCT_THRESHOLD)) ? 1 : 0;  // if a bit repeats more than the threshold then it errors out
    assign apt_error = (apt_counter > (APT_CNTR_WIDTH)'(APT_THRESHOLD)) ? 1 : 0;
    assign error = rct_error | apt_error;  // final error output
endmodule

// control unit
module control_unit(
    output logic noise_src_enb_n,  // enables noise source (active-low)
    output logic enb_health_tests_n,  // enables health tests module
    output logic get_raw_entropy,  // indicates when to use raw entropy instead of DRBG feedback
    output logic local_rst_n,  // local rst_n given by control unit to all other modules
    output logic dead_flag,  // indicates total failure occurred
    input logic health_error,  // input from health tests when APT or RCT occurs
    input logic Keccak_ready,  // input from Keccak conditioning module indicating that Key is ready
    input logic clk, ext_rst_n);

    localparam DRBG_CNTR_WIDTH = $clog2(DRBG_CYCLES);

    cu_states fsm_state;
    logic [DRBG_CNTR_WIDTH-1 : 0] drbg_cntr;  // determines for how many cycles state matrix should get raw entropy

    always_ff @(posedge clk) begin
        if(!ext_rst_n) begin
            fsm_state <= IDLE;
            noise_src_enb_n <= 1;
            enb_health_tests_n <= 1;
            get_raw_entropy <= 0;
            dead_flag <= 0;
            drbg_cntr <= 0;
            local_rst_n <= 0;
        end
        else begin
            case(fsm_state)
                IDLE: begin  // this state provides the TRNG to stabilize and maintain its states before performing actual operations
                    noise_src_enb_n <= 1;  // making oscilattor stable
                    enb_health_tests_n <= 1;  // disabling health tests module
                    get_raw_entropy <= 0;  // disables raw entropy as default
                    dead_flag <= 0;
                    drbg_cntr <= drbg_cntr;
                    local_rst_n <= 0; 
                    fsm_state <= BIST;  // unconditionally transitions to BIST state 
                end 
                BIST: begin
                    local_rst_n <= 1;
                    dead_flag <= 0;

                    // enabling blocks
                    noise_src_enb_n <= 0;
                    enb_health_tests_n <= 0;

                    // setting get_raw_entropy, for every (DRBG_CYCLES) cycles Keccak block uses
                    // actual raw entropy or else it uses DRBG feedback path
                    get_raw_entropy <= (drbg_cntr == 0) ? 1 : 0;

                    fsm_state <= (health_error) ? DEAD : ((Keccak_ready) ? WAIT_FOR_XFER : BIST);
                end
                WAIT_FOR_XFER: begin
                    get_raw_entropy <= 0;  // no entropy collection when waiting for acknowledgement
                    dead_flag <= 0;

                    // Increment exactly once per completed key transfer
                    if(!Keccak_ready) drbg_cntr <= (drbg_cntr == (DRBG_CNTR_WIDTH)'(DRBG_CYCLES-1)) ? 0 : drbg_cntr + 1;
                    else drbg_cntr <= drbg_cntr; 

                    fsm_state <= (health_error) ? DEAD : ((!Keccak_ready) ? BIST : WAIT_FOR_XFER);
                end
                DEAD: begin
                    // deasserting signals as total failure occurred
                    noise_src_enb_n <= 1;
                    enb_health_tests_n <= 1;
                    get_raw_entropy <= 0;
                    drbg_cntr <= 0;
                    dead_flag <= 1;  // indicates that whole TRNG block need reset to boot
                    fsm_state <= DEAD;  // waits in this state until ext_rst_n is asserted which inturn asserts local_rst_n to reset all blocks
                end
            endcase
        end
    end
endmodule
