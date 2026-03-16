# Directory paths
RTL_DIR = ../rtl
TB_DIR  = ../tb
SIM_DIR = .

# Cocotb setup
TOPLEVEL = trng
MODULE   = trng_tb
SIM      = verilator

# Verilator specific flags
EXTRA_ARGS += --trace --trace-structs --binary
COMPILE_ARGS += -I$(RTL_DIR)

# RTL sources
VERILOG_SOURCES = $(RTL_DIR)/ro_param_pkg.sv $(RTL_DIR)/trng.sv

# Logic to skip parameter generation
skip_gen ?= 0

# Waveform generation
WAVES ?= 0
ifeq ($(WAVES), 1)
    EXTRA_ARGS += --trace
endif

# Handle specific test selection
ifeq ($(test),)
    # Run all tests
else
    export TESTCASE = $(test)
endif

# --- Custom Targets ---

# Use 'make run' as your default starting point
all: run

.PHONY: gen_param
gen_param:
ifeq ($(skip_gen), 0)
	@echo ">>> Generating randomized jitter parameters..."
	python $(SIM_DIR)/gen_param.py
else
	@echo ">>> Skipping parameter generation, using existing package."
endif

.PHONY: run
run: gen_param
	$(MAKE) sim

.PHONY: run_test
run_test: gen_param
	@echo ">>> Running specific test: $(test)"
	$(MAKE) sim

# --- Cocotb Inclusion ---
# This file provides the 'sim' target
include $(shell cocotb-config --makefiles)/Makefile.sim

# --- Clean up ---
.PHONY: clean_all
clean_all: clean
	rm -f $(RTL_DIR)/ro_param_pkg.sv
	rm -f *.vcd
	rm -rf __pycache__
