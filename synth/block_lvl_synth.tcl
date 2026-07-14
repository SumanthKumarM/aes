# Args
if {$argc < 1 || $argc > 2} {
    puts "Error: Usage: vivado -source block_lvl_synth.tcl -tclargs <block_name> \[schematic\]"
    exit 1
}
set block [lindex $argv 0]
set gen_schematic [expr {$argc == 2 && [lindex $argv 1] eq "schematic"}]
set RTL_DIR [file normalize "../rtl"]

# Define block dependencies
proc get_block_dependencies { block } {
    set deps [list]

    switch -exact -- $block {
        "cipher" {
            lappend deps "sbox.sv" "shiftRows.sv" "mixColumns.sv" "addRoundKey.sv" "icg.sv"
        }
        "addRoundKey" {
            lappend deps "icg.sv"
        }
        "sbox" {
            lappend deps "icg.sv"
        }
        "trng_sbox_top" {
            lappend deps "trng.sv" "sbox.sv" "icg.sv"
        }
        default {
            # No external dependencies for this block
        }
    }
    return $deps
}

# Auto-discover source files needed for $block
# Parses "import <pkg_name>::" from the block's
# .sv and pulls in matching *_pkg.sv files first.
proc discover_sources { rtl_dir block } {
    set main_file [file join $rtl_dir "${block}.sv"]
    if {![file exists $main_file]} {
        puts "Error: RTL file not found: $main_file"
        exit 1
    }

    # Read the block's source
    set fh [open $main_file r]
    set content [read $fh]
    close $fh

    set sources [list]

    # Step 1: Add type definitions package (always needed)
    set pkg_file [file join $rtl_dir "type_defs_pkg.sv"]
    if {[file exists $pkg_file]} {
        lappend sources $pkg_file
        puts "  \[auto\] including package: $pkg_file"
    }

    # Step 2: Add module dependencies based on block type
    set dependencies [get_block_dependencies $block]
    foreach dep $dependencies {
        set dep_file [file join $rtl_dir $dep]
        if {[file exists $dep_file] && [lsearch -exact $sources $dep_file] == -1} {
            lappend sources $dep_file
            puts "  \[auto\] including module:  $dep_file"
        }
    }

    # Step 3: Add any additional packages imported by the main block
    set pos 0
    while {[regexp -start $pos -indices {import\s+([A-Za-z_][A-Za-z0-9_]*)\s*::} $content fullm pkgm]} {

        set pkg_name [string range $content [lindex $pkgm 0] [lindex $pkgm 1]]
        set pkg_file [file join $rtl_dir "${pkg_name}.sv"]

        # Add package file once, before the main file
        if {[file exists $pkg_file] && [lsearch -exact $sources $pkg_file] == -1} {
            lappend sources $pkg_file
            puts "  \[auto\] including package: $pkg_file"
        }
        set pos [expr {[lindex $fullm 1] + 1 }]
    }

    # Main block file goes last (packages must be read first)
    lappend sources $main_file
    puts "  \[auto\] including block:   $main_file"
    return $sources
}

# Cap synth_design's internal multithreading. Default is (nproc - 1), which on
# an 8-core/7.4GB machine oversubscribes memory during the heavier optimization
# phases (Cross Boundary and Area Optimization in particular) and gets the main
# process OOM-killed. Lower peak memory at the cost of longer wall-clock time.
set_param general.maxThreads 2

# Project + RTL
create_project -in_memory -part xc7a35tcsg324-1

set source_files [discover_sources $RTL_DIR $block]
foreach f $source_files {
    read_verilog -sv $f
}

# Synthesize. -flatten_hierarchy none (vs. rebuilt) skips fully collapsing the
# module hierarchy before optimizing -- cheaper in memory, and fine here since
# icg.sv is just a clock-gate leaf cell, not something on sbox's data-path
# critical path, so keeping it as a separate hierarchical instance doesn't
# affect the timing numbers we care about.
synth_design -top $block -part xc7a35tcsg324-1 -flatten_hierarchy none

set design_name [get_designs]
current_design $design_name

# Clock constraint — required for Vivado's STA engine to analyze any reg-to-reg
# path at all, and for report_power's dynamic-power estimate to mean anything
# (it scales with frequency). 100MHz/10ns is a placeholder target, not a claim
# about what this design can hit -- tune it once you have a real target. Either
# way, "Data Path Delay" in the detailed timing report below is the raw cell+net
# propagation delay and is independent of this period value, so it reflects the
# true critical path regardless of what you set here.
create_clock -period 10.000 -name clk [get_ports clk]

# Reports: area, power, timing
report_utilization -file "${block}_utilization.rpt"
report_power -file "${block}_power.rpt"
report_timing_summary -file "${block}_timing.rpt"
report_timing -delay_type max -sort_by group -path_type full -nworst 10 -file "${block}_timing_detail.rpt"
write_checkpoint -force "${block}_synth.dcp"

# Schematic — opt-in only (pass `schematic=1` to `make synth`), since it needs
# an active GUI context: show_schematic/write_schematic are silent no-ops
# without it (confirmed empirically -- no error, just no file). start_gui
# requires this process to be launched with `-mode tcl` (or `-mode gui`),
# never `-mode batch` -- the Makefile picks the mode based on `schematic=`.
if {$gen_schematic} {
    if {[catch {
        start_gui
        show_schematic [get_cells -hierarchical]
        write_schematic -format pdf -force -orientation landscape "${block}_schematic.pdf"
        stop_gui
    } err]} {
        puts "Warning: schematic generation failed: $err"
    }
} else {
    puts "Skipping schematic (pass schematic=1 to 'make synth' to enable)."
}

puts "--- Synthesis complete for $block ---"
exit