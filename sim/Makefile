# Directory paths
RTL_DIR = ../rtl
TB_DIR = ../tb
SIM_DIR = .
SYNTH_DIR = ../synth
SYNTH_SCRIPT = $(SYNTH_DIR)/block_lvl_synth.ys

PARAM_FILE = $(RTL_DIR)/ro_param_pkg.sv

export PYTHONPYCACHEPREFIX := $(CURDIR)/.cache  # Redirect __pycache__ to the current simulation directory
$(shell mkdir -p $(PYTHONPYCACHEPREFIX))  # Create the cache directory if it doesn't exist
export PYTHONPATH := $(TB_DIR):$(SIM_DIR):$(PYTHONPATH)

# Cocotb setup
TOPLEVEL = trng
COCOTB_TEST_MODULES = trng_tb
SIM = verilator

# Linting Tools 
VERIBLE_LINT = verible-verilog-lint
SLANG = slang
YOSYS = yosys

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

# simulates all tests
all: run_all

.PHONY: gen_param
gen_param:
	@echo "Generating RTL parameters..."
	python $(SIM_DIR)/gen_param.py

.PHONY: run_all
run_all: $(PARAM_FILE)
	$(MAKE) sim 2>&1 | tee sim.log

.PHONY: run_test
run_test: $(PARAM_FILE)
	@echo "Running specific test: $(test)"
	$(MAKE) sim 2>&1 | tee sim.log

# cocotb inclusion -
# This file provides the 'sim' target
include $(shell cocotb-config --makefiles)/Makefile.sim

# Linting Targets 
.PHONY: lint-style
lint-style: $(PARAM_FILE)
	@echo "Running Verible Style Lint..."
	$(VERIBLE_LINT) $(VERILOG_SOURCES) --rules_config_search

.PHONY: lint-syntax
lint-syntax: $(PARAM_FILE)
	@echo "Running Slang Syntax Check..."
	$(SLANG) $(VERILOG_SOURCES) -I$(RTL_DIR) --top $(TOPLEVEL)

.PHONY: lint-synth
lint-synth: $(PARAM_FILE)
	@echo "Running Yosys Synthesis Lint (Slang Parser)..."
	$(YOSYS) -p "plugin -i slang; \
				read_slang $(VERILOG_SOURCES); \
				hierarchy -check -top $(TOPLEVEL); \
				proc; \
				check; \
				stat"

# A master lint target to run everything
.PHONY: lint
lint: lint-style lint-syntax lint-synth

.PHONY: synth
synth: $(PARAM_FILE)
	@echo "Running Yosys Synthesis Script for $(block)..."
	cd $(SYNTH_DIR) && BLOCK=$(block) python block_lvl_synth_gen.py 2>&1 | tee synth.log

.PHONY: clean_all
clean_all: clean
	rm -f *.vcd *.fst
	rm -rf sim_build
	rm -f sim.log results.xml
	rm -rf .cache*
	rm -rf $(SYNTH_DIR)/*.log $(SYNTH_DIR)/*.dot $(SYNTH_DIR)/*.json
