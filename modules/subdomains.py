import subprocess
from pathlib import Path


def enumerate_subdomains(domain, config, output_file=None):
    print(f"[INF] Starting subdomain enumeration on {domain}")

    cmd = ["subfinder", "-d", domain, "-silent"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

    subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]

    for sub in subdomains:
        line = f"[SUB] {sub}"
        print(line)
        if output_file:
            output_file.write(line + "\n")

    print(f"[INF] Found {len(subdomains)} subdomains")
    return subdomains if subdomains else [domain]
