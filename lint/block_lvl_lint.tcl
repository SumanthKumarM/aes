# Args
if { $argc != 1 } {
    puts "Error: Usage: vivado -source block_lvl_lint.tcl -tclargs <block_name>"
    exit 1
}
set block [lindex $argv 0]
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

# Auto-discover sources (same logic as synth)
proc discover_sources { rtl_dir block } {
    set main_file [file join $rtl_dir "${block}.sv"]
    if {![file exists $main_file]} {
        puts "Error: RTL file not found: $main_file"
        exit 1
    }

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

        if {[file exists $pkg_file] && [lsearch -exact $sources $pkg_file] == -1} {
            lappend sources $pkg_file
            puts "  \[auto\] including package: $pkg_file"
        }
        set pos [expr { [lindex $fullm 1] + 1 }]
    }

    # Step 4: Add main block file
    lappend sources $main_file
    puts "  \[auto\] including block:   $main_file"
    return $sources
}

# Read only what this block needs
set source_files [discover_sources $RTL_DIR $block]
foreach f $source_files {
    read_verilog -sv $f
}

# Elaborate (RTL lint — no full synthesis)
synth_design -top $block -rtl -rtl_skip_mlo -name lint_1

# Check results
set cw_count [get_msg_config -count -severity {CRITICAL WARNING}]
set er_count [get_msg_config -count -severity {ERROR}]

if {$er_count > 0} {
    puts "ERROR:  Lint finished with $er_count Error(s)."
} elseif {$cw_count > 0} {
    puts "WARNING:  Lint finished with $cw_count Critical Warning(s)."
} else {
    puts "INFO:  Lint clean for $block — no Critical Warnings or Errors."
}

exit