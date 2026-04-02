import ro_param_pkg::*;

typedef logic [4:0][4:0][63:0] state_t;

module trng(
    output logic [447:0] rand_word,  // 448-bit random packet to S-box
    output logic key_ready_req,  // tells S-box that random words are ready
    output logic dead_flag,  // tells AES_GCM that TRNG has failed
    input logic s_box_ack,  // S-box acknowledges receipt of random words
    input logic raw_rand_bit,  // noise source bit which is driven by noise source model
    input logic sampling_clk,  // high frequency independent clock for noise source
    input logic clk, ext_rst_n);

    logic rand_bit_sync1, rand_bit;  // CDC synchronized rand_bit (clk domain)

    // CDC synchronized control signals (sampling_clk domain)
    logic noise_enb_sync1, noise_enb_n;
    logic noise_rst_sync1, noise_rst_n;

    // entropy collector - keccak handshake
    logic [63:0] entropy_word;
    logic valid, ready;

    logic key_ready;  // keccak to control unit
    logic health_error, total_failure;  // health tests to control unit

    // control unit outputs
    logic noise_src_enb_n;
    logic enb_health_tests;
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

    // noise source enable synchronizer, clk domain to sampling_clk domain
    always_ff @(posedge sampling_clk) begin
        if(!local_rst_n) begin
            noise_enb_sync1 <= 1;   // active low — disabled by default
            noise_enb_n <= 1;
        end
        else begin
            noise_enb_sync1 <= noise_src_enb_n;
            noise_enb_n <= noise_enb_sync1;
        end
    end

    // noise source reset synchronizer, clk domain to sampling_clk domain
    always_ff @(posedge sampling_clk) begin
        if(!local_rst_n) begin
            noise_rst_sync1 <= 0;
            noise_rst_n <= 0;
        end
        else begin
            noise_rst_sync1 <= 1;
            noise_rst_n <= noise_rst_sync1;
        end
    end

    // entropy collector (clk domain)    
    entropy_clctr entropy_col(entropy_word, valid, rand_bit, ready, clk, local_rst_n);

    // health tests (clk domain)
    health_tests hlth_tst(health_error, total_failure, rand_bit, enb_health_tests, clk, ext_rst_n);

    // keccak conditioning block (clk domain)
    keccak_cond keccak(rand_word, ready, key_ready_req, entropy_word, 
    get_raw_entropy, s_box_ack, valid, clk, local_rst_n);

    // control unit (clk domain)
    control_unit cu (noise_src_enb_n, enb_health_tests, get_raw_entropy, local_rst_n, dead_flag, 
    health_error, total_failure, key_ready_req, clk, ext_rst_n);
endmodule

// entropy collector
module entropy_clctr(
    output logic [63:0] entropy_word,
    output logic valid,
    input logic rand_bit, ready, clk, rst_n);

    logic [5:0] sipo_fill_cntr; 

    always_ff@(posedge clk) begin
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
typedef enum logic [1:0] {ABSORB, PERMUTE, SQUEEZ} Keccak_states;

module keccak_cond (
    output logic [447:0] rand_word,  // 112 4-bit random words needed for S-Box()
    output logic ready,  // indicates entropy collector that this block isi ready to accecpt raw entropy
    output logic key_ready_req,  // indicates S-Box() that this block has valid key to send
    input logic [63:0] raw_entropy,  // raw entropy from entropy collector 
    input logic get_raw_entropy,  // if high then accepts raw entropy or else uses DRBG feedback
    input logic s_box_ack,  // acknowledgement from S-Box() that it received 64 random words
    input logic valid,  // from entropy collector indicating that it's ready to send the data
    input logic clk, rst_n);
    
    state_t state;  // state matrix for Keccak conditioning block
    logic [191:0] temp_entropy;  // to store raw entropy bits
    logic [4:0] round_cntr;  // keeps track of number of rounds
    logic [1:0] rx_cntr;  // keeps track of handshakes
    logic [1:0] word_tx_cntr;  // keeps track of random 448-bit packets that are being sent to AES_GCM
    Keccak_states fsm_state;  

    // flattening state matrix to access slices of it
    logic [1599:0] state_flat;
    assign state_flat = {>>{state}};

    // computing theta for state matrix
    function automatic state_t theta(input state_t s);
        logic [4:0][63:0] c;  // column parity bits
        logic [4:0][63:0] d, c_rot;  // theta diffusion term, left rotation of c
        int m, n;
        state_t diff_state;

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
    function automatic state_t rho(input state_t s);
        int n;
        logic [63:0] lane;

        for(int i=0; i<25; i++) begin
            n = RHO_OFFSETS[i/5][i%5];
            lane = s[i/5][i%5];
            s[i/5][i%5] = (n == 0) ? lane : ((lane << n) | (lane >> (64 - n)));
        end
        return s;
    endfunction

    // computing pi for state matrix
    function automatic state_t pi(input state_t s);
        state_t temp;
        int x, y;
        for(int i=0; i<25; i++) begin
            x = i/5;  // rows
            y = i%5;  // columns
            temp[x][y] = s[(x + (3*y)) % 5][x];
        end
        return temp;
    endfunction

    // computing chi which is non-linear
    function automatic state_t chi(input state_t s);
        state_t temp;
        for(int i=0; i<25; i++) begin
            temp[i/5][i%5] = s[i/5][i%5] ^ (~s[i/5][((i%5)+1)%5] & s[i/5][((i%5)+2)%5]);
        end
        return temp;
    endfunction

    // computing iota for state matrix
    function automatic state_t iota(input state_t s, logic [63:0] round_const);
        s[0][0] = s[0][0] ^ round_const;
        return s;
    endfunction

    always_ff@(posedge clk) begin
        if(!rst_n) begin
            fsm_state <= ABSORB;
            rand_word <= 0;
            state <= 0;
            temp_entropy <= 0;
            round_cntr <= 0;
            rx_cntr <= 0;
            word_tx_cntr <= 0;
            ready <= 0;
            key_ready_req <= 0;
        end
        else begin
            case(fsm_state)
                ABSORB: begin
                    key_ready_req <= 0;
                    word_tx_cntr <= 0;
                    round_cntr <= 0;
                    rand_word <= rand_word;

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
                    word_tx_cntr <= 0;
                    fsm_state <= (round_cntr == 23) ? SQUEEZ : PERMUTE;
                end
                SQUEEZ: begin
                    temp_entropy <= state[0][2:0];
                    ready <= 0;
                    rx_cntr <= 0;

                    if(word_tx_cntr < 3 && s_box_ack) word_tx_cntr <= word_tx_cntr + 1;
                    else if(word_tx_cntr == 3) word_tx_cntr <= 0;
                    else word_tx_cntr <= word_tx_cntr;

                    // PISO logic to send 448-bit random packets to AES_GCM block 
                    case (word_tx_cntr)
                        2'b00: rand_word <= state_flat[447:0];
                        2'b01: rand_word <= state_flat[895:448];
                        2'b10: rand_word <= state_flat[1343:896]; 
                        default: rand_word <= 0;
                    endcase

                    // when random key is available key_ready_req becomes high and when all data is sent it becomes low
                    key_ready_req <= (word_tx_cntr != 3) ? 1'b1 : 0;
                    
                    fsm_state <= (word_tx_cntr == 3) ? ABSORB : SQUEEZ;  
                end
                default: fsm_state <= ABSORB;
            endcase
        end
    end
endmodule

// NIST standard health tests 
module health_tests (
    output logic error, total_failure,
    input logic rand_bit, enable_health_test,
    input logic clk, rst_n);

    localparam APT_CNTR_WIDTH = $clog2(APT_BIT_WINDOW);

    logic [3:0] rct_counter;
    logic [1:0] err_cntr;
    logic rct_prev_bit, prev_err;
    logic [APT_CNTR_WIDTH-1 : 0] apt_window_cntr, apt_counter;
    wire rct_error, apt_error;

    // Repetetion Count Test (RCT)
    always_ff@(posedge clk) begin
        if(!rst_n || !enable_health_test) begin
            rct_counter <= 0;
            rct_prev_bit <= 0;
        end 
        else begin
            if(rct_prev_bit  ==  rand_bit) rct_counter <= rct_counter + 1; // counter increases only when consecutive bits appear
            else rct_counter <= 0;
            // updating rct_prev_bit so that it can be used in next cycle for comparison
            rct_prev_bit <= rand_bit;
        end
    end

    // if a bit repeats more than the threshold then it errors out
    assign rct_error = (rct_counter >= 4'(RCT_THRESHOLD)) ? 1 : 0;

    // Adaptive Proportion Test (APT)
    always_ff@(posedge clk) begin
        if(!rst_n || !enable_health_test) begin
            apt_window_cntr <= 0;
            apt_counter <= 0;
        end
        else begin
            if(apt_window_cntr  ==  (APT_CNTR_WIDTH)'(APT_BIT_WINDOW-1)) begin
                apt_counter <= (rand_bit == 1) ? 1 : 0; // if when 1024th bit is 1 then it is counted or else the registers gets reset
                apt_window_cntr <= 0; // explicit window counter reset to keep both registers in sync
            end
            else begin 
                apt_counter <= apt_counter + type(apt_counter)'(rand_bit); 
                apt_window_cntr <= apt_window_cntr + 1; // this counter keeps track of 1024-bit window
            end
        end
    end

    assign apt_error = (apt_counter > (APT_CNTR_WIDTH)'(APT_THRESHOLD)) ? 1 : 0;

    // final error output
    assign error = rct_error | apt_error;

    // total failure occurs when consecutive error occur
    always_ff@(posedge clk) begin
        if(!rst_n) begin
            err_cntr <= 0;
            prev_err <= 0;
            total_failure <= 0;
        end 
        else begin
            if(prev_err == error && error == 1) err_cntr <= err_cntr + 1; // increments when consecutive errors occur
            else err_cntr <= 0;
            //updating prev_err so that it can be used in next cycle for comparison
            prev_err <= error;

            // updating total_failure bit which is a sticky bit
            total_failure <= total_failure | (err_cntr >= 2'(CONSECUTIVE_ERRORS));
        end
    end
endmodule

// control unit
typedef enum logic [2:0] {IDLE, BIST, WAIT_FOR_XFER, 
    ERROR_RECOVERY, DEAD
} cu_states;

module control_unit(
    output logic noise_src_enb_n,  // enables noise source (active-low)
    output logic enb_health_tests,  // enables health tests module
    output logic get_raw_entropy,  // indicates when to use raw entropy instead of DRBG feedback
    output logic local_rst_n,  // local rst_n given by control unit to all other modules
    output logic dead_flag,  // indicates total failure occurred
    input logic health_error,  // input from health tests when APT or RCT occurs 
    input logic total_failure,  // input from health tests module when consecutive health errors occur
    input logic Keccak_ready,  // input from Keccak conditioning module indicating that Key is ready
    input logic clk, ext_rst_n);

    localparam DRBG_CNTR_WIDTH = $clog2(DRBG_CYCLES);

    cu_states fsm_state;
    logic [DRBG_CNTR_WIDTH-1 : 0] drbg_cntr;  // determines for how many cycles state matrix should get raw entropy
    logic err_state_delay;

    always_ff@(posedge clk) begin
        if(!ext_rst_n) begin
            fsm_state <= IDLE;
            noise_src_enb_n <= 1;
            enb_health_tests <= 0;
            get_raw_entropy <= 0;
            dead_flag <= 0;
            drbg_cntr <= 0;
            local_rst_n <= 0;
            err_state_delay <= 0;
        end
        else begin
            case(fsm_state)
                IDLE: begin
                    // this state provides the TRNG to stabilize and maintain its states before performing actual operations
                    noise_src_enb_n <= 1;  // making oscilattor stable
                    enb_health_tests <= 0;  // disabling health tests module
                    get_raw_entropy <= 0;  // disables raw entropy as default
                    dead_flag <= 0;  // indicates that whole TRNG block need reset to boot
                    drbg_cntr <= drbg_cntr;
                    local_rst_n <= 1; 
                    // unconditionally transitions to BIST state
                    fsm_state <= BIST; 
                end 
                BIST: begin
                    local_rst_n <= 1;
                    drbg_cntr <= drbg_cntr;

                    // enabling blocks
                    noise_src_enb_n <= 0;
                    enb_health_tests <= 1;

                    // setting get_raw_entropy, for every (DRBG_CYCLES) cycles Keccak block uses
                    // actual raw entropy or else it uses DRBG feedback path
                    get_raw_entropy <= (drbg_cntr == 0) ? 1 : 0;

                    // state transition
                    case({total_failure, health_error})
                        2'b00: fsm_state <= (Keccak_ready == 1) ? WAIT_FOR_XFER : BIST;
                        2'b01: fsm_state <= ERROR_RECOVERY;  // since an error has occurred, goes to error recovery state
                        2'b10, 2'b11: fsm_state <= DEAD;  // since both cases have total_failure = 1, goes to DEAD state waiting for external reset 
                        default: fsm_state <= BIST; 
                    endcase
                end
                WAIT_FOR_XFER: begin
                    // holding their previous state
                    noise_src_enb_n <= noise_src_enb_n;
                    enb_health_tests <= enb_health_tests;
                    local_rst_n <= local_rst_n;
                    dead_flag <= dead_flag;
                    err_state_delay <= err_state_delay;
                    get_raw_entropy <= 0;  // no entropy collection when waiting for acknowledgement

                    // Increment exactly once per completed key transfer
                    if(!Keccak_ready) drbg_cntr <= (drbg_cntr == (DRBG_CNTR_WIDTH)'(DRBG_CYCLES-1)) ? 0 : drbg_cntr + 1;
                    else drbg_cntr <= drbg_cntr; 

                    // state transition
                    case({total_failure, health_error})
                        // keeps on waiting until keccak ready becomes low which indicates all requests from AES_GCM have been acknowledged
                        2'b00: fsm_state <= (!Keccak_ready) ? BIST : WAIT_FOR_XFER;  
                        2'b01: fsm_state <= ERROR_RECOVERY;  // since an error has occurred, goes to error recovery state
                        2'b10, 2'b11: fsm_state <= DEAD;  // since both cases have total_failure = 1, goes to DEAD state waiting for external reset 
                        default: fsm_state <= WAIT_FOR_XFER; 
                    endcase
                end
                ERROR_RECOVERY: begin
                    // resets noise source, entropy collector and Keccak conditioning block 
                    // since they gave psuedo randomness instead of true randomness
                    local_rst_n <= 0;

                    // holding their previous state
                    noise_src_enb_n <= noise_src_enb_n;
                    enb_health_tests <= enb_health_tests;
                    get_raw_entropy <= get_raw_entropy;
                    dead_flag <= dead_flag;
                    drbg_cntr <= 0;  // resetting this so that Keccak block can start using raw entropy instead of DRBG feedback

                    err_state_delay <= err_state_delay + 1;  // gives 1 cycle delay so that reset values settle in
                    fsm_state <= (err_state_delay) ? BIST : ERROR_RECOVERY;
                end
                DEAD: begin
                    // deasserting signals as total failure occurred
                    noise_src_enb_n <= 1;
                    enb_health_tests <= 0;
                    get_raw_entropy <= 0;
                    drbg_cntr <= 0;

                    // asseting dead_flag and waiting for external reset
                    dead_flag <= 1;
                    local_rst_n <= (ext_rst_n == 0) ? 0 : 1;  // restting other blocks

                    err_state_delay <= err_state_delay + 1;  // gives 1 cycle delay so that reset values settle in
                    fsm_state <= (err_state_delay) ? IDLE : DEAD;
                end
                default: fsm_state <= IDLE;
            endcase
        end
    end
endmodule
