# Directory paths
RTL_DIR = ../rtl
TB_DIR = ../tb
SIM_DIR = .

PARAM_FILE = $(RTL_DIR)/ro_param_pkg.sv

export PYTHONPYCACHEPREFIX := $(CURDIR)/.cache  # Redirect __pycache__ to the current simulation directory
$(shell mkdir -p $(PYTHONPYCACHEPREFIX))  # Create the cache directory if it doesn't exist
export PYTHONPATH := $(TB_DIR):$(SIM_DIR):$(PYTHONPATH)

# Cocotb setup
TOPLEVEL = trng
COCOTB_TEST_MODULES = trng_tb
SIM = verilator

# Verilator specific flags
EXTRA_ARGS += --trace --trace-structs 
COMPILE_ARGS += -I$(RTL_DIR) --timescale 1ps/1ps --timing --x-initial unique --x-assign 0

# RTL sources
VERILOG_SOURCES = $(PARAM_FILE) $(RTL_DIR)/trng.sv

# handle specific test selection
ifneq ($(test),)
  COCOTB_TEST_FILTER = $(test)
  export COCOTB_TEST_FILTER
endif

# generate parameter package file if it misses
$(PARAM_FILE): 
	@echo "Geberating RTL parameters..."
	python $(SIM_DIR)/gen_param.py

# Use 'make run' as your default starting point
all: run

.PHONY: gen_param
gen_param:
	@echo "Generating RTL parameters..."
	python $(SIM_DIR)/gen_param.py

.PHONY: run
run: $(PARAM_FILE)
	$(MAKE) sim 2>&1 | tee sim.log

.PHONY: run_tests
run_tests: $(PARAM_FILE)
	@echo "Running specific test: $(test)"
	$(MAKE) sim 2>&1 | tee sim.log

# cocotb inclusion -
# This file provides the 'sim' target
include $(shell cocotb-config --makefiles)/Makefile.sim

.PHONY: clean_all
clean_all: clean
	rm -f *.vcd *.fst
	rm -rf sim_build
	rm -f sim.log results.xml
	rm -rf .cache*
