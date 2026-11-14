from urllib.parse import urlparse

from modules.utils import emit, run_tool


def scan_ports(alive_hosts, config, output_file=None):
    print(f"[INF] Scanning ports on {len(alive_hosts)} hosts")

    if not config["tools"]["nmap"]:
        print("[INF] nmap disabled in config, skipping")
        return {}

    ports = config["tools"]["nmap_ports"]
    rate = config["scanning"]["rate_limit"]
    timeout = config["scanning"]["timeout"]

    # httpx returns both http:// and https:// variants of the same host —
    # dedupe by hostname so it isn't scanned twice.
    hostnames = []
    seen = set()
    for host in alive_hosts:
        hostname = urlparse(host.split()[0]).hostname or host.split()[0]
        if hostname not in seen:
            seen.add(hostname)
            hostnames.append(hostname)

    results = {}
    for hostname in hostnames:
        cmd = ["nmap", "-sV", "--open", "-p", ports, "--max-rate", str(rate), hostname, "-T4"]
        stdout = run_tool(cmd, timeout)

        open_ports = []
        for line in stdout.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port = int(parts[0].split("/")[0])
                service = parts[2] if len(parts) > 2 else "unknown"
                version = " ".join(parts[3:]) if len(parts) > 3 else ""
                emit(f"[PORT] {hostname}:{port} {service} {version}".strip(), output_file)
                open_ports.append(port)

        results[hostname] = open_ports

    print(f"[INF] Port scanning completed")
    return results
