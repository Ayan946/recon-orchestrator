import subprocess
import re


def scan_ports(alive_hosts, config, output_file=None):
    print(f"[INF] Scanning ports on {len(alive_hosts)} hosts")

    results = {}
    ports = config["tools"]["nmap_ports"]

    for host in alive_hosts:
        clean_host = re.sub(r"https?://", "", host.split()[0])
        cmd = ["nmap", "-sV", "--open", "-p", ports, clean_host, "-T4"]
        result = subprocess.run(cmd, capture_output=True, text=True)

        open_ports = []
        for line in result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port = parts[0].split("/")[0]
                service = parts[2] if len(parts) > 2 else "unknown"
                version = " ".join(parts[3:]) if len(parts) > 3 else ""
                entry = f"[PORT] {clean_host}:{port} {service} {version}".strip()
                print(entry)
                if output_file:
                    output_file.write(entry + "\n")
                open_ports.append(int(port))

        results[clean_host] = open_ports

    print(f"[INF] Port scanning completed")
    return results
