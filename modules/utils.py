import subprocess


def emit(line, output_file=None):
    """Print a line and mirror it to the output file, if one is open."""
    print(line)
    if output_file:
        output_file.write(line + "\n")


def run_tool(cmd, timeout):
    """Run an external tool, returning its stdout or '' if it fails."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except FileNotFoundError:
        print(f"[ERR] {cmd[0]} not found — is it installed and on PATH?")
    except subprocess.TimeoutExpired:
        print(f"[ERR] {cmd[0]} timed out after {timeout}s")
    return ""
