import trng_param_pkg::RCT_THRESHOLD;
import trng_param_pkg::APT_BIT_WINDOW;
import trng_param_pkg::APT_THRESHOLD;

// entropy collector
module entropy_clctr #(
    parameter WIDTH = 64) (
    output logic [WIDTH-1:0] entropy_word,
    output logic valid,
    input logic rand_bit, ready, clk, rst_n);

    localparam SIPO_CNTR_WIDTH = $clog2(WIDTH);
    logic [SIPO_CNTR_WIDTH-1:0] sipo_fill_cntr; 

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
                entropy_word <= (entropy_word << 1) | {(WIDTH-1)'(0), rand_bit};
                sipo_fill_cntr <= sipo_fill_cntr + 1;  // increments when register gets accumulated with rand_bit
            end
            
            // asserting valid signal 
            if(valid && ready) valid <= 0;  // deasserting valid as the transaction has completed
            else if(sipo_fill_cntr == (SIPO_CNTR_WIDTH)'(WIDTH-1)) valid <= valid | 1'b1;  // sticky valid that stays high until ready = 1
            else valid <= valid;
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
