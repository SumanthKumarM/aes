# Directory paths
RTL_DIR = ../rtl
TB_DIR = ../tb
SIM_DIR = .
SYNTH_DIR = ../synth
LINT_DIR = ../lint
SYNTH_REPORT_DIR := $(SYNTH_DIR)/synth_reports
STA_REPORT_DIR := $(SYNTH_DIR)/sta_reports
LINT_REPORT_DIR := $(LINT_DIR)/reports
SYNTH_SCRIPT = $(SYNTH_DIR)/block_lvl_synth.ys
TRNG_PARAM_FILE = $(RTL_DIR)/trng_param_pkg.sv
TYPEDEF_PKG = $(RTL_DIR)/type_defs_pkg.sv
COMPOSITE_MATH_PKG = $(RTL_DIR)/composite_field_math.sv
DRBG_UTILS = $(RTL_DIR)/drbg_utilities.sv

export PYTHONPYCACHEPREFIX := $(CURDIR)/.cache  # Redirect __pycache__ to the current simulation directory
export PYTHONDONTWRITEBYTECODE := 1  # Prevent __pycache__ creation in source directories 
$(shell mkdir -p $(PYTHONPYCACHEPREFIX))  # Create the cache directory if it doesn't exist
export PYTHONPATH := $(TB_DIR):$(SIM_DIR):$(PYTHONPATH)
SHELL := /bin/bash

# Cocotb setup
SIM = verilator

# Per-block build directory. cocotb's Makefile.sim keys its incremental rebuild
# on source mtimes, not on the elaborated top module, so a single shared
# sim_build/ silently reuses the previous block's binary when $(block) changes
# and cocotb then aborts with "Can not find root handle '<block>'". Giving each
# block its own directory keeps the incremental rebuild while making a block
# switch a different build.
SIM_BUILD := sim_build/$(block)

# Tools 
VERIBLE_LINT = verible-verilog-lint
SLANG = slang
YOSYS = yosys
OPENSTA = sta

# Synthesis defaults.  Override with, for example:
#   make synth tool=vivado block=cipher freq=200
#   make synth tool=yosys  block=cipher freq=200
# The Yosys flow uses the library for standard-cell mapping; its ABC mapping
# does not consume a clock constraint, while Vivado uses freq for STA.
NANGATE45_LIB ?= /opt/pdks/nangate45/lib/NangateOpenCellLibrary_typical.lib
freq ?= 100

# tool selection
tool ?= vivado  # default tool
SELECTED_TOOL := $(strip $(tool))

# vivado paths
VIVADO = vivado -mode batch -notrace
VIVADO_LINT  = vivado -mode batch -notrace -journal $(LINT_REPORT_DIR)/vivado_lint.jou -log $(LINT_REPORT_DIR)/vivado_lint.log

# schematic ?= (unset) -- pass `schematic=1` to `make synth` to additionally
# generate a schematic PDF. That needs GUI context (start_gui), so it switches
# Vivado into `-mode tcl` instead of the default headless `-mode batch`; a
# real Vivado window will pop up on screen for that step. Without it, synth
# stays batch-mode: fast, headless, memory-safe, area/power/timing reports only.
schematic ?=
ifeq ($(strip $(schematic)),)
    VIVADO_SYNTH_MODE = batch
else
    VIVADO_SYNTH_MODE = tcl
endif
VIVADO_SYNTH = vivado -mode $(VIVADO_SYNTH_MODE) -notrace -journal $(SYNTH_REPORT_DIR)/vivado_synth.jou -log $(SYNTH_REPORT_DIR)/vivado_synth.log

# Verilator specific flags
EXTRA_ARGS += --trace --trace-structs 
COMPILE_ARGS += -I$(RTL_DIR) --timescale 1ps/1ps --timing --x-initial unique --x-assign 0

# generate parameter package file only when missing or stale -- a real file
# rule (not PHONY) so nested $(MAKE) invocations don't regenerate it repeatedly
$(TRNG_PARAM_FILE): $(SIM_DIR)/gen_param.py
	@echo "Generating RTL parameters..."
	python3 $(SIM_DIR)/gen_param.py

# Verification-only top wrappers, generated on demand by gen_top.py; never
# committed to git, and never used by lint/synth/standalone RTL compilation --
# those only ever see the real design files referenced below.
#
# Two kinds, both existing only so cocotb has an elaborable DUT to drive:
#   * entropy wrappers  -- bind a TRNG-consuming block to a real trng instance
#   * aes_top           -- flattens aes.sv's aes_interface port into ordinary
#                          ports, which Verilator requires of a simulation top
#                          (see INTERFACE_TOP_BLOCKS below)
GENERATED_TOP_BLOCKS := sbox_top addRoundKey_top cipher_top invSbox_top invCipher_top invAddRoundKey_top aes_top

# RTL sources
# composite_field_math_pkg is a foundational package (imports only type_defs_pkg)
# used by sbox.sv and invSbox.sv, and transitively by every block that embeds an
# S-Box (sbox_top, addRoundKey(_top), cipher(_top)). It is listed in the base
# sources -- right after the typedef package it depends on -- so any block that
# imports it elaborates; blocks that don't just compile an unused package.
BLOCK_DEPS =
VERILOG_SOURCES = $(TYPEDEF_PKG) $(COMPOSITE_MATH_PKG) $(RTL_DIR)/icg.sv

# aes.sv is the full-chip top: it instantiates TRNG, SBOX, ADDROUNDKEY, CIPHER,
# INVCIPHER and IV_GEN directly, so its dependency set is the union of every
# other block's. Two things this list must not lose:
#   * invCipher.sv instantiates invAddRoundKey, and iv_gen.sv pulls in
#     cbc_mac/ctr_drbg (each embedding its own unmasked_cipher, which in turn
#     holds the addRoundKey_AES256 module and needs shiftRows/mixColumns).
#   * Order matters. Verilator elaborates these as one compilation unit, and
#     while -I$(RTL_DIR) lets it auto-find a *module* by filename, package
#     imports do not resolve that way -- listing aes.sv alone made sbox.sv's
#     composite_field_math functions ("Can't find definition of task/function:
#     'masked_denominator'") unresolvable. Leaf modules are therefore listed
#     ahead of the blocks that instantiate them, after the base packages above.
AES_RTL_SOURCES = $(RTL_DIR)/shiftRows.sv $(RTL_DIR)/mixColumns.sv $(RTL_DIR)/invShiftRows.sv \
                  $(RTL_DIR)/invMixColumns.sv $(RTL_DIR)/unmasked_cipher.sv $(RTL_DIR)/cbc_mac.sv \
                  $(RTL_DIR)/ctr_drbg.sv $(RTL_DIR)/iv_gen.sv $(RTL_DIR)/trng.sv $(RTL_DIR)/sbox.sv \
                  $(RTL_DIR)/invSbox.sv $(RTL_DIR)/addRoundKey.sv $(RTL_DIR)/invAddRoundKey.sv \
                  $(RTL_DIR)/cipher.sv $(RTL_DIR)/invCipher.sv

# drbg_utilities.sv holds the entropy collector and the SP 800-90B health tests,
# shared by trng.sv and cbc_mac.sv (and pulled in transitively by every _top
# wrapper that embeds a real TRNG). health_tests reads RCT_THRESHOLD /
# APT_BIT_WINDOW / APT_THRESHOLD, so the blocks needing drbg_utilities.sv are
# exactly the blocks needing trng_param_pkg.sv -- both are added together, with
# the parameter package first so its imports resolve.
ifneq ($(filter $(block),trng cbc_mac iv_gen aes aes_top sbox_top addRoundKey_top cipher_top invSbox_top invCipher_top invAddRoundKey_top),)
    BLOCK_DEPS += $(TRNG_PARAM_FILE)
    VERILOG_SOURCES += $(TRNG_PARAM_FILE) $(DRBG_UTILS)
endif

ifeq ($(block),sbox_top)
	VERILOG_SOURCES += $(RTL_DIR)/trng.sv $(RTL_DIR)/sbox.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),addRoundKey_top)
	VERILOG_SOURCES += $(RTL_DIR)/trng.sv $(RTL_DIR)/sbox.sv $(RTL_DIR)/addRoundKey.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),addRoundKey)
    VERILOG_SOURCES += $(RTL_DIR)/sbox.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),cipher_top)
	VERILOG_SOURCES += $(RTL_DIR)/trng.sv $(RTL_DIR)/sbox.sv $(RTL_DIR)/shiftRows.sv $(RTL_DIR)/mixColumns.sv $(RTL_DIR)/addRoundKey.sv $(RTL_DIR)/cipher.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),cipher)
	VERILOG_SOURCES += $(RTL_DIR)/sbox.sv $(RTL_DIR)/shiftRows.sv $(RTL_DIR)/mixColumns.sv $(RTL_DIR)/addRoundKey.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),unmasked_cipher)
	VERILOG_SOURCES += $(RTL_DIR)/shiftRows.sv $(RTL_DIR)/mixColumns.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),cbc_mac)
	VERILOG_SOURCES += $(RTL_DIR)/shiftRows.sv $(RTL_DIR)/mixColumns.sv $(RTL_DIR)/unmasked_cipher.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),ctr_drbg)
	# ctr_drbg embeds one unmasked_cipher; no health tests or entropy collector,
	# so drbg_utilities.sv/trng_param_pkg.sv are deliberately not pulled in.
	VERILOG_SOURCES += $(RTL_DIR)/shiftRows.sv $(RTL_DIR)/mixColumns.sv $(RTL_DIR)/unmasked_cipher.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),iv_gen)
	# Full entropy pipeline: cbc_mac (conditioner + health tests + collector)
	# and ctr_drbg, each with its own unmasked_cipher instance.
	VERILOG_SOURCES += $(RTL_DIR)/shiftRows.sv $(RTL_DIR)/mixColumns.sv $(RTL_DIR)/unmasked_cipher.sv $(RTL_DIR)/cbc_mac.sv $(RTL_DIR)/ctr_drbg.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),invSbox_top)
	VERILOG_SOURCES += $(RTL_DIR)/trng.sv $(RTL_DIR)/invSbox.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),invCipher_top)
	VERILOG_SOURCES += $(RTL_DIR)/trng.sv $(RTL_DIR)/sbox.sv $(RTL_DIR)/invSbox.sv $(RTL_DIR)/invShiftRows.sv $(RTL_DIR)/invMixColumns.sv $(RTL_DIR)/addRoundKey.sv $(RTL_DIR)/invCipher.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),invCipher)
	VERILOG_SOURCES += $(RTL_DIR)/invSbox.sv $(RTL_DIR)/invShiftRows.sv $(RTL_DIR)/invMixColumns.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),invAddRoundKey_top)
	VERILOG_SOURCES += $(RTL_DIR)/trng.sv $(RTL_DIR)/sbox.sv $(RTL_DIR)/addRoundKey.sv $(RTL_DIR)/invAddRoundKey.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),invAddRoundKey)
	VERILOG_SOURCES += $(RTL_DIR)/sbox.sv $(RTL_DIR)/addRoundKey.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),aes)
	VERILOG_SOURCES += $(AES_RTL_SOURCES) $(RTL_DIR)/$(block).sv
else ifeq ($(block),aes_top)
	# Simulation flavour of the block above: same sources plus the flat-port
	# wrapper that makes aes.sv drivable by cocotb (see INTERFACE_TOP_BLOCKS).
	VERILOG_SOURCES += $(AES_RTL_SOURCES) $(RTL_DIR)/aes.sv $(RTL_DIR)/$(block).sv
else ifeq ($(block),icg)
	# icg.sv is already in base VERILOG_SOURCES, so not needed here
else
	VERILOG_SOURCES += $(RTL_DIR)/$(block).sv
endif

# Default TOPLEVEL to the block under test; override with TOPLEVEL=... if needed
TOPLEVEL ?= $(block)

# Map each block to its cocotb test module. Testbenches are named after the
# design block under test, not the generated verification wrapper, so strip a
# trailing "_top" when deriving the module name (sbox_top -> sbox_tb,
# addRoundKey_top -> addRoundKey_tb, cipher_top -> cipher_tb).
#
# Blocks whose testbench is shared with another block, or simply not named after
# the block, override that default via TB_MODULE_<block>.
#
# unmasked_cipher.sv implements the same FIPS 197 CIPHER procedure as cipher.sv
# (LUT S-Box, no TRNG, AES-256 only), so cipher_tb.py verifies both: it
# auto-detects the DUT flavor from COCOTB_TOPLEVEL and skips the AES-128/192
# known-answer tests when the DUT is AES-256 only.
#
# aes_top's suite is split across three modules rather than one monolith --
# aes_sequence.py (the @cocotb.test bodies), aes_testbench.py (driver, monitor,
# protocol checker, noise) and aes_ref_model.py (the SP 800-38A golden model).
# Only the module holding the tests is named here; the other two are ordinary
# imports found via PYTHONPATH.
TB_MODULE_unmasked_cipher := cipher_tb
TB_MODULE_aes_top := aes_sequence

COCOTB_TEST_MODULES ?= $(or $(TB_MODULE_$(block)),$(patsubst %_top,%,$(block))_tb)

# handle specific test selection
#
# The value is single-quoted because cocotb's Makefile.verilator interpolates it
# straight into the shell command line as
#   COCOTB_TEST_FILTER=$(COCOTB_TEST_FILTER) ... $(SIM_BUILD)/Vtop
# with no quoting of its own. COCOTB_TEST_FILTER is a REGEX, so a perfectly
# ordinary selection like `test='ecb_.*|cbc_.*'` otherwise has its `|` eaten by
# the shell as a pipe and the run dies with "Error 127". The quotes are stripped
# by the shell before the variable reaches the simulator, and that inline
# assignment overrides the exported copy below, so the regex arrives intact.
ifneq ($(test),)
  COCOTB_TEST_FILTER = '$(test)'
  export COCOTB_TEST_FILTER
endif

# simulates all tests
all: run_test_suite

.PHONY: gen_param
gen_param: $(TRNG_PARAM_FILE)

# Generates the verification-only top wrapper for $(block), when $(block) is
# one of GENERATED_TOP_BLOCKS. A no-op otherwise -- lint/synth/compile_rtl
# never depend on this target, so base block names are unaffected either way.
.PHONY: gen_top
gen_top:
ifneq ($(filter $(block),$(GENERATED_TOP_BLOCKS)),)
	@echo "Generating verification top module '$(block).sv'..."
	python3 $(RTL_DIR)/gen_top.py $(block)
endif

# Blocks whose top-level port list is a SystemVerilog interface rather than flat
# ports. aes.sv is one: `module aes(aes_interface.aes_intf aesBus)`. Verilator
# cannot build a model for such a top --
#   %Error-UNSUPPORTED: ../rtl/aes.sv:121: Interfaced port on top level module
# -- and adding $(EXTRA_ARGS)' --trace on top of that trips an internal error in
# V3TraceDecl ("Expected an interface scope name to have at least one dot"), so
# the trace flags have to come off too. Elaboration itself is fine, so
# compile_rtl runs these through a trace-free `--lint-only` instead: same full
# hierarchy elaboration, same width/connectivity/lint diagnostics, just no
# obj_dir/ C++ model at the end.
#
# To *simulate* such a block, use its flat-port wrapper instead: aes_top.sv
# instantiates aes_interface internally and re-exposes every member as an
# ordinary port, so `block=aes_top` builds and runs aes_sequence.py against the
# real aes.sv. That wrapper is produced by gen_top.py like every other
# *_top.sv here, so it is in GENERATED_TOP_BLOCKS above and the `gen_top`
# prerequisite regenerates it before each build.
INTERFACE_TOP_BLOCKS := aes
ifneq ($(filter $(block),$(INTERFACE_TOP_BLOCKS)),)
    VERILATOR_ELAB_ARGS = --lint-only $(COMPILE_ARGS)
    VERILATOR_ELAB_NOTE = (elaboration only -- interface top, no C++ model)
    VERILATOR_ELAB_DONE = Elaboration check passed; no obj_dir/ model is produced for an interface top.
else
    VERILATOR_ELAB_ARGS = --cc $(COMPILE_ARGS) $(EXTRA_ARGS)
    VERILATOR_ELAB_NOTE =
    VERILATOR_ELAB_DONE = Compiled artifacts in obj_dir/
endif

# Refuses a cocotb run for a block Verilator cannot build a model for, instead of
# letting it fail several hundred lines into an internal-error dump.
.PHONY: check_sim_top
check_sim_top:
	@if [ -n "$(filter $(block),$(INTERFACE_TOP_BLOCKS))" ]; then \
		echo "Error: block '$(block)' exposes a SystemVerilog interface on its top-level ports,"; \
		echo "       which Verilator cannot elaborate as a simulation top."; \
		echo "       Run the simulation against its flat-port wrapper instead:"; \
		echo "           make run_test_suite block=$(block)_top"; \
		echo "       or use 'make compile_rtl block=$(block)' for an elaboration check."; \
		exit 1; \
	fi

# Standalone RTL elaboration check (Verilator only, no cocotb linkage). This is
# independent of run_test/run_test_suite: cocotb's own `sim` target (pulled in below)
# already compiles incrementally via Make's normal file-mtime tracking, so
# nothing here needs to duplicate that compile.
# gen_top is a prerequisite so that _top wrapper blocks are (re)generated
# before elaboration; it is a no-op for base block names.
#
# `set -o pipefail` is load-bearing: piping verilator into tee otherwise hands
# make tee's exit status, so a failed compile still reported success.
.PHONY: compile_rtl
compile_rtl: gen_top $(BLOCK_DEPS)
	@echo "Compiling RTL for $(block) with Verilator...$(if $(VERILATOR_ELAB_NOTE), $(VERILATOR_ELAB_NOTE))"
	@set -o pipefail; verilator $(VERILATOR_ELAB_ARGS) $(VERILOG_SOURCES) --top $(block) 2>&1 | tee compile.log
	@echo "RTL compilation complete. $(VERILATOR_ELAB_DONE)"

.PHONY: run_test_suite
run_test_suite: check_sim_top gen_top $(BLOCK_DEPS)
	@echo "Running all tests..."
	@set -o pipefail; $(MAKE) sim 2>&1 | tee sim.log

.PHONY: run_test
run_test: check_sim_top gen_top $(BLOCK_DEPS)
	@echo "Running specific test: $(test)"
	@set -o pipefail; $(MAKE) sim 2>&1 | tee sim.log

# cocotb inclusion -
# This file provides the 'sim' target
COCOTB_CONFIG := $(shell command -v cocotb-config 2>/dev/null)
ifneq ($(strip $(COCOTB_CONFIG)),)
include $(shell cocotb-config --makefiles)/Makefile.sim
else
.PHONY: sim
sim:
	@echo "Error: cocotb-config not found; simulation targets are unavailable."
	@exit 1
endif

# Linting Targets 
.PHONY: lint-style
lint-style: $(BLOCK_DEPS)
	@mkdir -p $(LINT_REPORT_DIR)
	@echo "Running Verible Style Lint..."
	$(VERIBLE_LINT) $(VERILOG_SOURCES) --rules_config_search 2>&1 | tee $(LINT_REPORT_DIR)/verible_lint.log

.PHONY: lint-syntax
lint-syntax: $(BLOCK_DEPS)
	@mkdir -p $(LINT_REPORT_DIR)
	@echo "Running Slang Syntax Check..."
	$(SLANG) $(VERILOG_SOURCES) -I$(RTL_DIR) --top $(block) 2>&1 | tee $(LINT_REPORT_DIR)/slang_lint.log

.PHONY: lint-synth
lint-synth: $(BLOCK_DEPS)
	@mkdir -p $(LINT_REPORT_DIR)
	@echo "Running Yosys Synthesis Lint (Slang Parser)..."
	$(YOSYS) -p "plugin -i slang; \
				read_slang $(VERILOG_SOURCES); \
				hierarchy -check -top $(block); \
				proc; \
				check; \
				tee -o $(LINT_REPORT_DIR)/yosys_lint.rpt stat"

.PHONY: lint-vivado
lint-vivado: $(BLOCK_DEPS)
	@mkdir -p $(LINT_REPORT_DIR)
	@echo "Running Vivado Elaborated Design Lint for $(block)..."
	cd $(LINT_DIR) && $(VIVADO_LINT) -source block_lvl_lint.tcl -tclargs $(block) 2>&1 | tee $(LINT_REPORT_DIR)/vivado_lint_console.log

# A master lint target to run everything
.PHONY: lint
lint: 
	@mkdir -p $(LINT_REPORT_DIR)
	@if [ "$(SELECTED_TOOL)" = "vivado" ]; then \
		$(MAKE) lint-vivado block=$(block) 2>&1 | tee $(LINT_REPORT_DIR)/vivado_lint_make.log; \
	else \
		echo "Running multi-tool lint (Verible/Slang/Yosys)..."; \
		$(MAKE) lint-style lint-syntax lint-synth 2>&1 | tee $(LINT_REPORT_DIR)/yosys_slang_lint.log; \
	fi

.PHONY: synth
synth: $(BLOCK_DEPS)
	@mkdir -p $(SYNTH_REPORT_DIR)
	@echo "Running synthesis for $(block) using $(tool)..."
	@if [ "$(SELECTED_TOOL)" = "vivado" ]; then \
		cd $(SYNTH_DIR) && SYNTH_REPORT_DIR=$(SYNTH_REPORT_DIR) $(VIVADO_SYNTH) -source block_lvl_synth.tcl -tclargs $(block) $(freq) $(if $(schematic),schematic,) 2>&1 | tee $(SYNTH_REPORT_DIR)/vivado_synth_console.log; \
	elif [ "$(SELECTED_TOOL)" = "yosys" ]; then \
		cd $(SYNTH_DIR) && BLOCK=$(block) LIBERTY=$(NANGATE45_LIB) REPORT_DIR=$(SYNTH_REPORT_DIR) SCHEMATIC=$(if $(schematic),1,0) python3 block_lvl_synth_gen.py 2>&1 | tee $(SYNTH_REPORT_DIR)/yosys_synth.log; \
	else \
		echo "Error: Unknown tool '$(tool)'. Use 'vivado' or 'yosys'."; exit 1; \
	fi

.PHONY: sta
sta:
	@if [ -z "$(block)" ]; then \
		echo "Error: pass block=<block_name>, for example: make sta block=cipher"; exit 1; \
	fi
	@mkdir -p $(STA_REPORT_DIR)
	@if [ ! -f "$(SYNTH_REPORT_DIR)/$(block)_netlist.v" ]; then \
		echo "No mapped netlist found; running Yosys synthesis for $(block)..."; \
		$(MAKE) synth tool=yosys block=$(block) freq=$(freq); \
	fi
	@set -o pipefail; \
	LIBERTY=$(NANGATE45_LIB) TOP=$(block) NETLIST=$(SYNTH_REPORT_DIR)/$(block)_netlist.v \
	OUT_DIR=$(STA_REPORT_DIR)/$(block) FREQ_MHZ=$(freq) \
	$(OPENSTA) -no_init -exit $(SYNTH_DIR)/block_lvl_sta.tcl \
	2>&1 | tee $(STA_REPORT_DIR)/$(block)_sta.log

# Full-tree cleanup, hooked onto cocotb's own `clean`.
#
# cocotb's Makefile.inc declares clean as a DOUBLE-COLON rule (`clean::`), which
# is its documented extension point: every `clean::` rule in the build runs, in
# the order the files were read. So the rule below appends to cocotb's cleanup
# rather than replacing it -- `make clean` first runs cocotb's own (removes
# $(SIM_BUILD), $(COCOTB_RESULTS_FILE), and the Verilator dump.vcd/dump.fst),
# then everything here.
#
# Keep the double colon. GNU Make refuses to mix `:` and `::` rules for one
# target ("target file 'clean' has both : and :: entries"), so a single-colon
# `clean:` here would be a hard error whenever cocotb-config is on PATH.
.PHONY: clean
clean::
	rm -f ./*.vcd ./*.fst ./*.log ./*.xml
	rm -rf sim_build ./.cache* obj_dir
	rm -rf $(TB_DIR)/__pycache__
	rm -rf $(SYNTH_REPORT_DIR)/
	rm -rf $(STA_REPORT_DIR)/
	rm -rf $(LINT_REPORT_DIR)/
	rm -rf $(SYNTH_DIR)/*.log $(SYNTH_DIR)/*.dot $(SYNTH_DIR)/*.json $(SYNTH_DIR)/*.v
	rm -rf $(SYNTH_DIR)/*.jou $(SYNTH_DIR)/*.rpt $(SYNTH_DIR)/*.dcp $(SYNTH_DIR)/*.svg.new
	rm -rf $(SYNTH_DIR)/*.pdf $(SYNTH_DIR)/*.backup.*
	rm -rf $(LINT_DIR)/*.log $(LINT_DIR)/*.jou $(LINT_DIR)/*.rpt $(LINT_DIR)/*.backup.*
