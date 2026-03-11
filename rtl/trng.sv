import ro_param_pkg::*;

typedef logic [4:0][4:0][63:0] state_t;

// noise source
module ring_osc_array (
    output var logic rand_bit,
    input sampling_clk, enb, rst_n);

    genvar i, j;
    wire logic [N_RO-1 : 0][N_INV-1 : 0] inv;
    logic [N_RO-1 : 0] q;

    // creating ring oscillator arrays
    generate
        for(i=0; i<N_RO; i++) begin // ring scillator arrays
            for(j=0; j<N_INV-1; j++) begin // ring oscillators - cascaded inverters
                assign #(INV_DELAY[i][j]) inv[i][j+1] = ~inv[i][j];
            end
            assign #(INV_DELAY[i][N_INV-1]) inv[i][0] = ~(enb | inv[i][N_INV-1]);
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
    output logic [1:0] tx_cntr,
    output logic valid,
    input logic rand_bit, ready, clk, rst_n);

    logic [5:0] sipo_fill_cntr; 

    always_ff@(posedge clk) begin
        if(!rst_n) begin
            entropy_word <= 0;
            valid <= 0;
            tx_cntr <= 0;
            sipo_fill_cntr <= 0;
        end
        // serial-in parallel-out shift register behavior
        else begin
            if(valid && !ready) begin  // when valid data is available that data should not be changed until receiver is ready
                entropy_word <= entropy_word;
                sipo_fill_cntr <= sipo_fill_cntr;
                tx_cntr <= tx_cntr;
            end
            else begin
                entropy_word <= (entropy_word << 1) | {63'd0, rand_bit};
                sipo_fill_cntr <= sipo_fill_cntr + 1;  // increments when register gets accumulated with rand_bit
            end
            
            // asserting valid signal 
            if(valid && ready) valid <= 0;  // deasserting valid as the transaction has completed
            else if(sipo_fill_cntr==63) valid <= valid | 1'b1;  // sticky valid that stays high until ready = 1
            else valid <= valid;

            // incrementing tx_counter 
            if(valid && ready) tx_cntr <= (tx_cntr==2) ? 0 : tx_cntr + 1;  // when all 3 64-bit words are sent this counter resets
            else tx_cntr <= tx_cntr;
        end
    end
endmodule

// Keccak conditioning block
module keccak_cond (
    output state_t rand_state,
    output logic [1:0] rx_cntr,
    output logic ready,
    input logic [63:0] raw_entropy,
    input logic get_raw_entropy,  // if high then accepts raw entropy or else uses DRBG feedback
    input logic valid, clk, rst_n);
    
    state_t state;  // state matrix for Keccak conditioning block
    logic [191:0] temp_entropy;  // to store raw entropy bits
    logic [4:0] round_cntr;  // keeps track of number of rounds

    // computing theta for state matrix
    function automatic state_t theta(input state_t s);
        logic [4:0][63:0] c;  // column parity bits
        logic [4:0][63:0] d, c_rot;  // theta diffusion term, left rotation of c

        for(int i=0; i<5; i++) begin
            // computing column parity
            c[i] = s[0][i] ^ s[1][i] ^ s[2][i] ^ s[3][i] ^ s[4][i]; 

            // computing theta diffusion term : D[x] = C[x−1] ⊕ ROT(C[x+1],1)
            int m = (i==0) ? 4 : (i-1);
            int n = (i==4) ? 0 : (i+1);
            c_rot[i] = {c[3:0], c[4]};  // left rotation
            d[i] = c[m] ^ c_rot[n];
        end

        // applying diffusion
        state_t diff_state;
        for(int i=0; i<25; i++) begin
            diff_state[i/5][i%5] = diff_state[i/5][i%5] ^ d[i%5];
        end

        return diff_state;
    endfunction

    // computing rho for state matrix
    function automatic state_t rho(input state_t s);
        for(int i=0; i<25; i++) begin
            if(i==0) s[0][0] = s[0][0];
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
            temp[i/5][i%5] = s[i/5][i%5] ^ (~s[i/5][(i%5)+1] & s[i/5][(i%5)+2]);
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
            rand_state <= 0;
            temp_entropy <= 0;
            round_cntr <= 0;
            rx_cntr <= 0;
            ready <= 0;
        end
        else begin
            // initial stage: round-0
            // state[191:0]     = true noise source entropy / feedback
            // state[192]       = 1         (pad start)
            // state[1342:193]  = 0         (zero padding)
            // state[1343]      = 1         (pad end)
            // state[1599:1344] = 0        (capacity, initialized to zero)
            if(round_cntr==0) begin
                if(get_raw_entropy) begin  // gets raw entropy bits from entropy collector
                    ready <= 1;
                    if(valid==1 && ready==1) begin
                        temp_entropy[((rx_cntr * 64) + 63) : (rx_cntr * 64)] = temp_entropy[((rx_cntr * 64) + 63) : (rx_cntr * 64)] ^ raw_entropy;
                        rx_cntr <= (rx_cntr==2) ? 0 : rx_cntr + 1;
                    end
                    else begin
                        rand_state <= rand_state;
                        rx_cntr <= rx_cntr;
                    end
                    if(rx_cntr==2) rand_state <= rand_state ^ {256'd0, 1'd1, 1250'd0, 1'd1, temp_entropy};
                end
                else begin  // DRBG (deterministic random bit generator) feedback path
                    rand_state <= rand_state ^ {256'd0, 1'd1, 1250'd0, 1'd1, rand_state[191:0]};  // gets same bits from previous computation
                end
            end
            else begin  // rounds 1-23
                
            end

            round_cntr <= (round_cntr==23) ? 0 : round_cntr + 1;  // updating round_cntr
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
            if(rct_prev_bit == rand_bit) rct_counter <= rct_counter + 1; // counter increases only when consecutive bits appear
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
            if(apt_window_cntr == APT_BIT_WINDOW-1) begin
                apt_counter <= (rand_bit==1) ? 1 : 0; // if when 1024th bit is 1 then it is counted or else the registers gets reset
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
            if(prev_err==error && error==1) err_cntr <= err_cntr + 1; // increments when consecutive errors occur
            else err_cntr <= 0;
            //updating prev_err so that it can be used in next cycle for comparison
            prev_err <= error;

            // updating total_failure bit which is a sticky bit
            total_failure <= total_failure | (err_cntr >= CONSECUTIVE_ERRORS);
        end
    end
endmodule
