import tempfile

from modules.utils import emit, run_tool


def filter_alive_hosts(subdomains, config, output_file=None):
    print(f"[INF] Probing {len(subdomains)} hosts for alive status")

    if not config["tools"]["httpx"]:
        print("[INF] httpx disabled in config, skipping")
        return subdomains

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(subdomains))
        subs_path = f.name

    cmd = ["httpx-toolkit", "-l", subs_path, "-silent", "-nc", "-status-code",
           "-threads", str(config["tools"]["httpx_threads"])]
    stdout = run_tool(cmd, config["scanning"]["timeout"])

    alive = [line.strip() for line in stdout.splitlines() if line.strip()]

    for host in alive:
        emit(f"[ALV] {host}", output_file)

    print(f"[INF] {len(alive)} hosts alive")
    return alive
