import ro_param_pkg::*;

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