import tempfile

from modules.utils import emit, run_tool


def probe_web_services(alive_hosts, config, output_file=None):
    print(f"[INF] Probing web services on {len(alive_hosts)} hosts")

    if not config["tools"]["httpx"]:
        print("[INF] httpx disabled in config, skipping")
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(h.split()[0] for h in alive_hosts))
        alive_path = f.name

    cmd = ["httpx-toolkit", "-l", alive_path, "-silent", "-nc", "-status-code",
           "-title", "-tech-detect", "-threads", str(config["tools"]["httpx_threads"])]
    stdout = run_tool(cmd, config["scanning"]["timeout"])

    services = []
    for line in stdout.splitlines():
        if line.strip():
            emit(f"[WEB] {line.strip()}", output_file)
            services.append(line.strip())

    print(f"[INF] Found {len(services)} web services")
    return services
