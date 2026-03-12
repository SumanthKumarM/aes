import ro_param_pkg::*;

typedef logic [4:0][4:0][63:0] state_t;

// top level module - True Random Number Generator
module trng(
    output logic [3:0] rand_word,
    output logic
);
endmodule

// noise source
module ring_osc_array (
    output var logic rand_bit,
    input sampling_clk, enb_n, rst_n);

    genvar i, j;
    wire logic [N_RO-1 : 0][N_INV-1 : 0] inv;
    logic [N_RO-1 : 0] q;

    // creating ring oscillator arrays
    generate
        for(i=0; i<N_RO; i++) begin // ring scillator arrays
            for(j=0; j<N_INV-1; j++) begin // ring oscillators - cascaded inverters
                assign #(INV_DELAY[i][j]) inv[i][j+1] = ~inv[i][j];
            end
            // enable is active low because when high the oscillator goes into stable mode
            // and when it's low then actual oscillation happen
            assign #(INV_DELAY[i][N_INV-1]) inv[i][0] = ~(enb_n | inv[i][N_INV-1]);
        end
    endgenerate

    // sampling each ring oscillator's output with resepct to sampling clock
    always_ff @(posedge sampling_clk) begin 
        if(!rst_n) begin 
            q <= 0;
            rand_bit <= 0;
        end
        else begin
            for(int i=0; i<N_RO; i++) q[i] <= inv[i][N_INV-1];
            rand_bit <= ^q;
        end
    end
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
    output state_t rand_state,
    output logic ready, key_ready,
    input logic [63:0] raw_entropy,
    input logic get_raw_entropy,  // if high then accepts raw entropy or else uses DRBG feedback
    input logic valid, cont_permute, clk, rst_n);
    
    state_t state;  // state matrix for Keccak conditioning block
    logic [191:0] temp_entropy;  // to store raw entropy bits
    logic [4:0] round_cntr;  // keeps track of number of rounds
    logic [1:0] rx_cntr; 
    Keccak_states fsm_state;  

    // computing theta for state matrix
    function automatic state_t theta(input state_t s);
        logic [4:0][63:0] c;  // column parity bits
        logic [4:0][63:0] d, c_rot;  // theta diffusion term, left rotation of c

        for(int i=0; i<5; i++) begin
            // computing column parity
            c[i] = s[0][i] ^ s[1][i] ^ s[2][i] ^ s[3][i] ^ s[4][i]; 

            // computing theta diffusion term : D[x] = C[x−1] ⊕ ROT(C[x+1],1)
            int m = (i == 0) ? 4 : (i-1);
            int n = (i == 4) ? 0 : (i+1);
            c_rot[i] = {c[i][62:0], c[i][63]};  // left rotation
            d[i] = c[m] ^ c_rot[n];
        end

        // applying diffusion
        state_t diff_state;
        for(int i=0; i<25; i++) begin
            diff_state[i/5][i%5] = s[i/5][i%5] ^ d[i%5];
        end

        return diff_state;
    endfunction

    // computing rho for state matrix
    function automatic state_t rho(input state_t s);
        for(int i=0; i<25; i++) begin
            if(i == 0) s[0][0] = s[0][0];
            else s[i/5][i%5] = {s[i/5][i%5][63-RHO_OFFSETS[i/5][i%5] : 0], s[i/5][i%5][63 : 64-RHO_OFFSETS[i/5][i%5]]};
        end
        return s;
    endfunction

    // computing pi for state matrix
    function automatic state_t pi(input state_t s);
        state_t temp;
        for(int i=0; i<25; i++) begin
            int x = i/5;  // rows
            int y = i%5;  // columns
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
            rand_state <= 0;
            state <= 0;
            temp_entropy <= 0;
            round_cntr <= 0;
            rx_cntr <= 0;
            ready <= 0;
            key_ready <= 0;
        end
        else begin
            case(fsm_state)
                ABSORB: begin
                    key_ready <= 0;
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
                            else temp_entropy[(rx_cntr * 64) +: 64] <= temp_entropy[(rx_cntr * 64) +: 64] ^ raw_entropy;
                            rx_cntr <= rx_cntr + 1;
                        end
                        else begin
                            temp_entropy <= temp_entropy;
                            rx_cntr <= rx_cntr;
                        end
                        if(rx_cntr == 3) begin
                            state <= state ^ {256'd0, 1'd1, 1150'd0, 1'd1, temp_entropy};
                            fsm_state <= PERMUTE
                        end 
                        else begin
                            state <= state;
                            fsm_state <= ABSORB;
                        end
                    end
                    else begin  // DRBG (deterministic random bit generator) feedback path
                        state <= state ^ {256'd0, 1'd1, 1150'd0, 1'd1, state[191:0]};  // gets same bits from previous computation
                        fsm_state <= PERMUTE;
                    end
                end 
                PERMUTE: begin
                    state <= iota(chi(pi(rho(theta(state)))), KECCAK_RC[round_cntr]);
                    round_cntr <= (round_cntr == 23) ? 0 : round_cntr + 1;  // updating round_cntr
                    // since "absorb" completed, resetting these registers for next iteration
                    ready <= 0;
                    rx_cntr <= 0;
                    key_ready <= 0;
                    fsm_state <= (round_cntr == 23) ? SQUEEZ : PERMUTE;
                end
                SQUEEZ: begin
                    temp_entropy <= state[191:0];
                    rand_state <= state;
                    ready <= 0;
                    rx_cntr <= 0;
                    key_ready <= 1;  // indicates that random key is eady for consumption
                    // if cont_permute is high then this block can continue permutating or else it 
                    // has to hold its output key and wait
                    fsm_state <= (cont_permute == 1) ? ABSORB : SQUEEZ;  
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
    wire logic rct_error, apt_error;

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
    assign rct_error = (rct_counter >= RCT_THRESHOLD) ? 1 : 0;

    // Adaptive Proportion Test (APT)
    always_ff@(posedge clk) begin
        if(!rst_n || !enable_health_test) begin
            apt_window_cntr <= 0;
            apt_counter <= 0;
        end
        else begin
            if(apt_window_cntr  ==  APT_BIT_WINDOW-1) begin
                apt_counter <= (rand_bit == 1) ? 1 : 0; // if when 1024th bit is 1 then it is counted or else the registers gets reset
                apt_window_cntr <= 0; // explicit window counter reset to keep both registers in sync
            end
            else begin 
                apt_counter <= apt_counter + rand_bit; 
                apt_window_cntr <= apt_window_cntr + 1; // this counter keeps track of 1024-bit window
            end
        end
    end

    assign apt_error = (apt_counter > APT_THRESHOLD) ? 1 : 0;

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
            total_failure <= total_failure | (err_cntr >= CONSECUTIVE_ERRORS);
        end
    end
endmodule

// control unit
typedef enum logic [2:0] {IDLE, BIST, WAIT_FOR_ACK, 
    ERROR_RECOVERY, DEAD
} cu_states;

module control_unit(
    output logic noise_src_enb_n, enb_health_tests, get_raw_entropy,
    send_req, local_rst_n, dead_flag, cont_permute,
    input logic ext_enable, health_error, total_failure, get_ack, 
    Keccak_ready, clk, ext_rst_n);

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
            send_req <= 0;
            dead_flag <= 0;
            drbg_cntr <= 0;
            local_rst_n <= 1;
            cont_permute <= 0;
            err_state_delay <= 0;
        end
        else begin
            case(fsm_state)
                IDLE: begin
                    noise_src_enb_n <= 1;  // making oscilattor stable
                    enb_health_tests <= 0;  // disabling health tests module
                    get_raw_entropy <= 0;  // disables raw entropy as default
                    send_req <= 0;  // indicates that there's no valid random Key to send yet
                    dead_flag <= 0;  // indicates that whole TRNG block need reset to boot
                    drbg_cntr <= drbg_cntr;
                    local_rst_n <= 1; 
                    cont_permute <= 1;
                    // transitions to BIST when it receives external enable or else keeps on waiting
                    // in IDLE state until external enable arrives
                    fsm_state <= (ext_enable == 1) ? BIST : IDLE; 
                end 
                BIST: begin
                    send_req <=0;
                    local_rst_n <= 1;

                    // enabling blocks
                    noise_src_enb_n <= 0;
                    enb_health_tests <= 1;

                    // updating DRBG counter based on Keccak_ready
                    if(drbg_cntr == DRBG_CYCLES-1) drbg_cntr <= 0;
                    else if(Keccak_ready == 1) drbg_cntr <= drbg_cntr + 1;
                    else drbg_cntr <= drbg_cntr; 

                    // setting get_raw_entropy, for every (DRBG_CYCLES) cycles Keccak block uses
                    // actual raw entropy or else it uses DRBG feedback path
                    get_raw_entropy <= (drbg_cntr == 0) ? 1 : 0;

                    // once Keccak conditioning block computes random Key cont_permute is made low
                    // so that it stops Keccak conditioning block from computing 
                    cont_permute <= (Keccak_ready == 1) ? 0 : 1;

                    // state transition
                    case({total_failure, health_error})
                        2'b00: fsm_state <= (Keccak_ready == 1) ? WAIT_FOR_ACK : BIST;
                        2'b01: fsm_state <= ERROR_RECOVERY;  // since an error has occurred, goes to error recovery state
                        2'b10, 2'b11: fsm_state <= DEAD;  // since both cases have total_failure = 1, goes to DEAD state waiting for external reset 
                        default: fsm_state <= BIST; 
                    endcase
                end
                WAIT_FOR_ACK: begin
                    send_req <= 1;  // sends request and waits for acknowledgement from AES_GCM block

                    // holding their previous state
                    noise_src_enb_n <= noise_src_enb_n;
                    enb_health_tests <= enb_health_tests;
                    local_rst_n <= local_rst_n;
                    dead_flag <= dead_flag;
                    drbg_cntr <= drbg_cntr;
                    get_raw_entropy <= 0;  // no entropy collection when waiting for acknowledgement

                    // only after receiving acknowledgement from AES_GCM block it will let Keccak conditioning
                    // block to continue permuatate while AES_GCM block consumes random words parallely
                    cont_permute <= (get_ack) ? 1 : 0;  

                    fsm_state <= (get_ack) ? BIST : WAIT_FOR_ACK;  // keeps on waiting for acknowledgement
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
                    cont_permute <= 0;  // holding Keccak conditioning block from continuing further

                    err_state_delay <= err_state_delay + 1;  // gives 1 cycle delay so that reset values settle in
                    if(err_state_delay == 1) begin
                        fsm_state <= BIST;
                        err_state_delay <= 0;  // resetting it for next iteration
                    end
                    else begin
                        fsm_state <= ERROR_RECOVERY;
                        err_state_delay <= err_state_delay;
                    end
                end
                DEAD: begin
                    // holding their previous state
                    noise_src_enb_n <= noise_src_enb_n;
                    enb_health_tests <= enb_health_tests;
                    get_raw_entropy <= get_raw_entropy;
                    send_req <= send_req;
                    drbg_cntr <= drbg_cntr;
                    local_rst_n <= local_rst_n;
                    err_state_delay <= err_state_delay;

                    cont_permute <= 0;  // holding Keccak conditioning block from continuing further

                    // asseting dead_flag and waiting for external reset
                    dead_flag <= 1;
                    fsm_state <= (ext_rst_n == 0) ? IDLE : DEAD;
                end
                default: fsm_state <= IDLE;
            endcase
        end
    end
endmodule
