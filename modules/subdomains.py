from modules.utils import emit, run_tool


def enumerate_subdomains(domain, config, output_file=None):
    print(f"[INF] Starting subdomain enumeration on {domain}")

    if not config["tools"]["subfinder"]:
        print("[INF] subfinder disabled in config, skipping")
        return [domain]

    cmd = ["subfinder", "-d", domain, "-silent"]
    stdout = run_tool(cmd, config["scanning"]["timeout"])

    subdomains = [line.strip() for line in stdout.splitlines() if line.strip()]

    for sub in subdomains:
        emit(f"[SUB] {sub}", output_file)

    print(f"[INF] Found {len(subdomains)} subdomains")
    return subdomains if subdomains else [domain]
