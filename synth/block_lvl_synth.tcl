# Args
if {$argc != 1} {
    puts "Error: Usage: vivado -source block_lvl_synth.tcl -tclargs <block_name>"
    exit 1
}
set block [lindex $argv 0]
set RTL_DIR [file normalize "../rtl"]

# Define block dependencies
proc get_block_dependencies { block } {
    set deps [list]

    switch -exact -- $block {
        "cipher" {
            lappend deps "sbox.sv" "shiftRows.sv" "mixColumns.sv" "addRoundKey.sv"
        }
        "addRoundKey" {
            lappend deps "sbox.sv"
        }
        "trng_sbox_top" {
            lappend deps "trng.sv" "sbox.sv"
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

# Project + RTL
create_project -in_memory -part xc7a35tcsg324-1

set source_files [discover_sources $RTL_DIR $block]
foreach f $source_files {
    read_verilog -sv $f
}

# Synthesize
synth_design -top $block -part xc7a35tcsg324-1 -flatten_hierarchy rebuilt

set design_name [get_designs]
current_design $design_name

# Reports
report_utilization -file "${block}_utilization.rpt"
report_timing_summary -file "${block}_timing.rpt"
write_checkpoint -force "${block}_synth.dcp"

# Schematic — requires GUI context to render
start_gui
show_schematic [get_cells -hierarchical]
write_schematic -format pdf -force -orientation landscape "${block}_schematic.pdf"
stop_gui

puts "--- Synthesis complete for $block ---"
exit