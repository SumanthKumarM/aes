import subprocess
import os
import sys
import re
import tempfile


def discover_sources(rtl_dir: str, block: str) -> list[str]:
    """
    Return an ordered list of .sv files needed for `block`.
    Parses 'import <pkg>::' lines from the block file and
    prepends any matching *pkg*.sv found in rtl_dir.
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

    print(f"  [auto] including block:   {main_file}")
    sources.append(main_file)
    return sources


def build_yosys_script(template: str, block: str, sources: list[str]) -> str:
    """
    Replace ${BLOCK} in the template and inject the correct
    read_verilog lines for only the discovered sources.
    """
    read_lines = "\n".join(
        f"read_verilog -sv {src}" for src in sources
    )
    script = template.replace("${READ_SOURCES}", read_lines)
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