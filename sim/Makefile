# Directory paths
RTL_DIR = ../rtl
TB_DIR = ../tb
SIM_DIR = .
SYNTH_DIR = ../synth
LINT_DIR = ../lint
SYNTH_SCRIPT = $(SYNTH_DIR)/block_lvl_synth.ys

PARAM_FILE = $(RTL_DIR)/ro_param_pkg.sv

export PYTHONPYCACHEPREFIX := $(CURDIR)/.cache  # Redirect __pycache__ to the current simulation directory
$(shell mkdir -p $(PYTHONPYCACHEPREFIX))  # Create the cache directory if it doesn't exist
export PYTHONPATH := $(TB_DIR):$(SIM_DIR):$(PYTHONPATH)

# Cocotb setup
COCOTB_TEST_MODULES = trng_tb
SIM = verilator

# Linting Tools 
VERIBLE_LINT = verible-verilog-lint
SLANG = slang
YOSYS = yosys

# tool selection
tool ?= vivado  # default tool
SELECTED_TOOL = $(strip $(tool))

# vivado paths
VIVADO = vivado -mode batch -notrace
VIVADO_LINT  = vivado -mode batch -notrace -journal $(LINT_DIR)/vivado.jou -log $(LINT_DIR)/vivado.log
VIVADO_SYNTH = vivado -mode batch -notrace -journal $(SYNTH_DIR)/vivado.jou -log $(SYNTH_DIR)/vivado.log

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
	$(SLANG) $(VERILOG_SOURCES) -I$(RTL_DIR) --top $(block)

.PHONY: lint-synth
lint-synth: $(PARAM_FILE)
	@echo "Running Yosys Synthesis Lint (Slang Parser)..."
	$(YOSYS) -p "plugin -i slang; \
				read_slang $(VERILOG_SOURCES); \
				hierarchy -check -top $(block); \
				proc; \
				check; \
				stat"

.PHONY: lint-vivado
lint-vivado: $(PARAM_FILE)
	@echo "Running Vivado Elaborated Design Lint for $(block)..."
	cd $(LINT_DIR) && $(VIVADO_LINT) -source block_lvl_lint.tcl -tclargs $(block)

# A master lint target to run everything
.PHONY: lint
lint: 
	@if [ "$(SELECTED_TOOL)" = "vivado" ]; then \
		$(MAKE) lint-vivado block=$(block) 2>&1 | tee $(LINT_DIR)/vivado_lint.log; \
	else \
		@echo "Running multi-tool lint (Verible/Slang/Yosys)..."; \
		$(MAKE) lint-style lint-syntax lint-synth 2>&1 | tee $(LINT_DIR)/yosys_slang_lint.log; \
	fi

.PHONY: synth
synth: $(PARAM_FILE)
	@echo "Running synthesis for $(block) using $(tool)..."
	@if [ "$(SELECTED_TOOL)" = "vivado" ]; then \
		cd $(SYNTH_DIR) && $(VIVADO_SYNTH) -source block_lvl_synth.tcl -tclargs $(block) 2>&1 | tee $(SYNTH_DIR)/vivado_synth.log; \
	elif [ "$(SELECTED_TOOL)" = "yosys" ]; then \
		cd $(SYNTH_DIR) && BLOCK=$(block) python3 block_lvl_synth_gen.py 2>&1 | tee $(SYNTH_DIR)/yosys_synth.log; \
	else \
		echo "Error: Unknown tool '$(tool)'. Use 'vivado' or 'yosys'."; exit 1; \
	fi

.PHONY: clean_all
clean_all: clean
	rm -f ./*.vcd ./*.fst ./*.log ./*.xml 
	rm -rf sim_build ./.cache*
	rm -rf $(SYNTH_DIR)/*.log $(SYNTH_DIR)/*.dot $(SYNTH_DIR)/*.json $(SYNTH_DIR)/*.v
	rm -rf $(SYNTH_DIR)/*.jou $(SYNTH_DIR)/*.rpt $(SYNTH_DIR)/*.dcp $(SYNTH_DIR)/*.svg.new 
	rm -rf $(SYNTH_DIR)/*.pdf $(SYNTH_DIR)/*.backup.*
	rm -rf $(LINT_DIR)/*.log $(LINT_DIR)/*.jou $(LINT_DIR)/*.rpt $(LINT_DIR)/*.backup.*
