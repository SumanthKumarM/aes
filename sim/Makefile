# Directory paths
RTL_DIR = ../rtl
TB_DIR = ../tb
SIM_DIR = .
SYNTH_DIR = ../synth
LINT_DIR = ../lint
SYNTH_SCRIPT = $(SYNTH_DIR)/block_lvl_synth.ys
TRNG_PARAM_FILE = $(RTL_DIR)/trng_param_pkg.sv
TYPEDEF_PKG = $(RTL_DIR)/type_defs_pkg.sv

export PYTHONPYCACHEPREFIX := $(CURDIR)/.cache  # Redirect __pycache__ to the current simulation directory
export PYTHONDONTWRITEBYTECODE := 1  # Prevent __pycache__ creation in source directories 
$(shell mkdir -p $(PYTHONPYCACHEPREFIX))  # Create the cache directory if it doesn't exist
export PYTHONPATH := $(TB_DIR):$(SIM_DIR):$(PYTHONPATH)

# Cocotb setup
COCOTB_TEST_MODULES = addRoundKey_tb
SIM = verilator

# Linting Tools 
VERIBLE_LINT = verible-verilog-lint
SLANG = slang
YOSYS = yosys

# tool selection
tool ?= vivado  # default tool
SELECTED_TOOL := $(strip $(tool))

# vivado paths
VIVADO = vivado -mode batch -notrace
VIVADO_LINT  = vivado -mode batch -notrace -journal $(LINT_DIR)/vivado.jou -log $(LINT_DIR)/vivado.log
VIVADO_SYNTH = vivado -mode batch -notrace -journal $(SYNTH_DIR)/vivado.jou -log $(SYNTH_DIR)/vivado.log

# Verilator specific flags
EXTRA_ARGS += --trace --trace-structs 
COMPILE_ARGS += -I$(RTL_DIR) --timescale 1ps/1ps --timing --x-initial unique --x-assign 0

# generate parameter package file if it misses
$(TRNG_PARAM_FILE): gen_param

# RTL sources
BLOCK_DEPS =
VERILOG_SOURCES = $(TYPEDEF_PKG)

ifneq ($(filter $(block),trng trng_sbox_top),)
    BLOCK_DEPS += $(TRNG_PARAM_FILE)
    VERILOG_SOURCES += $(TRNG_PARAM_FILE) 
endif

ifeq ($(block),trng_sbox_top)
	VERILOG_SOURCES += $(RTL_DIR)/trng.sv $(RTL_DIR)/sbox.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),addRoundKey)
    VERILOG_SOURCES += $(RTL_DIR)/sbox.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),cipher)
	VERILOG_SOURCES += $(RTL_DIR)/sbox.sv $(RTL_DIR)/shiftRows.sv $(RTL_DIR)/mixColumns.sv $(RTL_DIR)/addRoundKey.sv $(RTL_DIR)/$(block).sv
else
	VERILOG_SOURCES += $(RTL_DIR)/$(block).sv
endif

# handle specific test selection
ifneq ($(test),)
  COCOTB_TEST_FILTER = $(test)
  export COCOTB_TEST_FILTER
endif

# simulates all tests
all: run_all

.PHONY: gen_param
gen_param:
	@echo "Generating RTL parameters..."
	python $(SIM_DIR)/gen_param.py

# RTL compilation marker - indicates RTL has been compiled
RTL_COMPILED_MARKER = sim_build/.rtl_compiled

# RTL compilation (generates C++ files and binaries)
.PHONY: compile_rtl
compile_rtl: $(BLOCK_DEPS)
	@echo "Compiling RTL for $(block) with Verilator..."
	verilator --cc $(COMPILE_ARGS) $(EXTRA_ARGS) -I$(RTL_DIR) $(VERILOG_SOURCES) --top $(block) 2>&1 | tee compile.log
	@mkdir -p sim_build && touch $(RTL_COMPILED_MARKER)
	@echo "RTL compilation complete. Compiled artifacts in obj_dir/"

# Dependency: Only compile RTL if not already compiled
$(RTL_COMPILED_MARKER): $(BLOCK_DEPS)
	$(MAKE) compile_rtl

.PHONY: run_all
run_all: $(RTL_COMPILED_MARKER)
	@echo "Running all tests (using pre-compiled RTL)..."
	$(MAKE) sim 2>&1 | tee sim.log

.PHONY: run_test
run_test: $(RTL_COMPILED_MARKER)
	@echo "Running specific test: $(test) (using pre-compiled RTL)"
	$(MAKE) sim 2>&1 | tee sim.log

# cocotb inclusion -
# This file provides the 'sim' target
include $(shell cocotb-config --makefiles)/Makefile.sim

# Linting Targets 
.PHONY: lint-style
lint-style: $(BLOCK_DEPS)
	@echo "Running Verible Style Lint..."
	$(VERIBLE_LINT) $(VERILOG_SOURCES) --rules_config_search

.PHONY: lint-syntax
lint-syntax: $(BLOCK_DEPS)
	@echo "Running Slang Syntax Check..."
	$(SLANG) $(VERILOG_SOURCES) -I$(RTL_DIR) --top $(block)

.PHONY: lint-synth
lint-synth: $(BLOCK_DEPS)
	@echo "Running Yosys Synthesis Lint (Slang Parser)..."
	$(YOSYS) -p "plugin -i slang; \
				read_slang $(VERILOG_SOURCES); \
				hierarchy -check -top $(block); \
				proc; \
				check; \
				stat"

.PHONY: lint-vivado
lint-vivado: $(BLOCK_DEPS)
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
synth: $(BLOCK_DEPS)
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
	rm -rf sim_build ./.cache* obj_dir
	rm -rf $(TB_DIR)/__pycache__  # Remove any Python cache from source directory
	rm -rf $(SYNTH_DIR)/*.log $(SYNTH_DIR)/*.dot $(SYNTH_DIR)/*.json $(SYNTH_DIR)/*.v
	rm -rf $(SYNTH_DIR)/*.jou $(SYNTH_DIR)/*.rpt $(SYNTH_DIR)/*.dcp $(SYNTH_DIR)/*.svg.new
	rm -rf $(SYNTH_DIR)/*.pdf $(SYNTH_DIR)/*.backup.*
	rm -rf $(LINT_DIR)/*.log $(LINT_DIR)/*.jou $(LINT_DIR)/*.rpt $(LINT_DIR)/*.backup.*
