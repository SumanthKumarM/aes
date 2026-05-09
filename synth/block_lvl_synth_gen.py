import subprocess
import os
import sys
import tempfile

def run_yosys():
    block_name = os.environ.get("BLOCK")
    if not block_name:
        print("Error: No BLOCK environment variable found.")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(script_dir, "block_lvl_synth.ys")

    with open(template_path, "r") as f:
        script_content = f.read().replace("${BLOCK}", block_name)

    tmp_path = None
    try:
        # mkstemp gives us more explicit control than NamedTemporaryFile
        fd, tmp_path = tempfile.mkstemp(suffix=".ys", dir=script_dir)
        with os.fdopen(fd, "w") as tmp:
            tmp.write(script_content)

        print(f"--- Launching Yosys for: {block_name} ---")
        print(f"--- Resolved script: {tmp_path} ---", flush=True)

        result = subprocess.run(["yosys", "-s", tmp_path], cwd=script_dir)

        if result.returncode != 0:
            print(f"Error: Yosys exited with code {result.returncode}.")
            sys.exit(result.returncode)

        # Convert .dot to PDF
        dot_file = os.path.join(script_dir, f"{block_name}_schematic.dot")
        pdf_file = os.path.join(script_dir, f"{block_name}_schematic.pdf")
        if os.path.exists(dot_file):
            print(f"--- Converting schematic to PDF: {pdf_file} ---")
            subprocess.run(["dot", "-Tpdf", dot_file, "-o", pdf_file], check=True)
        else:
            print("Warning: .dot file not found, skipping PDF conversion.")

    finally:
        # Safe cleanup — don't crash if file is already gone
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

if __name__ == "__main__":
    run_yosys()