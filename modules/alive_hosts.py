import subprocess


def filter_alive_hosts(subdomains, config, output_file=None):
    print(f"[INF] Probing {len(subdomains)} hosts for alive status")

    with open("/tmp/subs.txt", "w") as f:
        f.write("\n".join(subdomains))

    cmd = ["httpx-toolkit", "-l", "/tmp/subs.txt", "-silent", "-status-code",
           "-threads", str(config["tools"]["httpx_threads"])]
    result = subprocess.run(cmd, capture_output=True, text=True)

    alive = [line.strip() for line in result.stdout.splitlines() if line.strip()]

    for host in alive:
        line = f"[ALV] {host}"
        print(line)
        if output_file:
            output_file.write(line + "\n")

    print(f"[INF] {len(alive)} hosts alive")
    return alive
