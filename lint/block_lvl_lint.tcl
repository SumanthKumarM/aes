# Args
if { $argc != 1 } {
    puts "Error: Usage: vivado -source block_lvl_lint.tcl -tclargs <block_name>"
    exit 1
}
set block [lindex $argv 0]
set RTL_DIR [file normalize "../rtl"]

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