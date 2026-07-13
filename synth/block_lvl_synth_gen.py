import subprocess
import os
import sys
import re
import tempfile


def get_block_dependencies(block: str) -> list[str]:
    """
    Submodule .sv files instantiated by `block` that Yosys needs on top of
    whatever `block`.sv itself imports. Mirrors get_block_dependencies() in
    block_lvl_lint.tcl / block_lvl_synth.tcl -- keep these three in sync.
    """
    deps = {
        "cipher": ["sbox.sv", "shiftRows.sv", "mixColumns.sv", "addRoundKey.sv", "icg.sv"],
        "addRoundKey": ["icg.sv"],
        "sbox": ["icg.sv"],
        "trng_sbox_top": ["trng.sv", "sbox.sv", "icg.sv"],
    }
    return deps.get(block, [])


def discover_sources(rtl_dir: str, block: str) -> list[str]:
    """
    Return an ordered list of .sv files needed for `block`.
    Parses 'import <pkg>::' lines from the block file and
    prepends any matching *pkg*.sv found in rtl_dir, then adds
    this block's known submodule dependencies.
    """
    main_file = os.path.join(rtl_dir, f"{block}.sv")
    if not os.path.exists(main_file):
        print(f"Error: RTL file not found: {main_file}")
        sys.exit(1)

    with open(main_file, "r") as fh:
        content = fh.read()

    sources = []

    # Match every "import <identifier>::" in the file
    for pkg_name in re.findall(r'\bimport\s+([A-Za-z_]\w*)\s*::', content):
        pkg_file = os.path.join(rtl_dir, f"{pkg_name}.sv")
        if os.path.exists(pkg_file) and pkg_file not in sources:
            print(f"  [auto] including package: {pkg_file}")
            sources.append(pkg_file)

    # Submodule dependencies (instantiated modules, not packages)
    for dep in get_block_dependencies(block):
        dep_file = os.path.join(rtl_dir, dep)
        if os.path.exists(dep_file) and dep_file not in sources:
            print(f"  [auto] including module:  {dep_file}")
            sources.append(dep_file)

    print(f"  [auto] including block:   {main_file}")
    sources.append(main_file)
    return sources


def build_yosys_script(template: str, block: str, sources: list[str]) -> str:
    """
    Replace ${BLOCK} in the template and inject the discovered sources as a
    single read_slang argument list (read_slang takes all files in one call,
    unlike read_verilog which is invoked once per file).
    """
    read_sources = " ".join(sources)
    script = template.replace("${READ_SOURCES}", read_sources)
    script = script.replace("${BLOCK}", block)
    return script


def dot_to_pdf(dot_file: str, pdf_file: str) -> None:
    if os.path.exists(dot_file):
        print(f"--- Converting schematic → PDF: {pdf_file} ---")
        subprocess.run(["dot", "-Tpdf", dot_file, "-o", pdf_file], check=True)
    else:
        print("Warning: .dot file not found — skipping PDF conversion.")


def run_yosys() -> None:
    block = os.environ.get("BLOCK", "").strip()
    if not block:
        print("Error: BLOCK environment variable not set.")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    rtl_dir = os.path.normpath(os.path.join(script_dir, "../rtl"))

    # Discover only the files this block needs
    sources = discover_sources(rtl_dir, block)

    # Load the .ys template
    template_path = os.path.join(script_dir, "block_lvl_synth.ys")
    with open(template_path, "r") as fh:
        template = fh.read()

    script_content = build_yosys_script(template, block, sources)

    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".ys", dir=script_dir)
        with os.fdopen(fd, "w") as tmp:
            tmp.write(script_content)

        print(f"--- Launching Yosys for: {block} ---")
        result = subprocess.run(["yosys", "-s", tmp_path], cwd=script_dir)
        if result.returncode != 0:
            print(f"Error: Yosys exited with code {result.returncode}.")
            sys.exit(result.returncode)

        # Convert schematic
        dot_to_pdf(
            os.path.join(script_dir, f"{block}_schematic.dot"),
            os.path.join(script_dir, f"{block}_schematic.pdf"),
        )

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


if __name__ == "__main__":
    run_yosys()