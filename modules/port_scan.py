import subprocess

def scan_ports(alive_hosts, config):
    if not alive_hosts:
        return {}

    output_file = config["output"]["port_scan"]
    ports = config["tools"]["nmap_ports"]

    scan_results = {}

    for host in alive_hosts:
        cmd = [
            "nmap",
            "-T4",
            "-p", ports,
            "--open",
            host
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        scan_results[host] = result.stdout

    with open(output_file, "w") as f:
        for host, data in scan_results.items():
            f.write(f"\n### {host} ###\n")
            f.write(data)

    print(f"[+] Port scanning completed on {len(alive_hosts)} hosts")
    return scan_results
