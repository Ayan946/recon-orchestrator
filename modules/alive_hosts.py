import subprocess

def filter_alive_hosts(subdomains, config):
    if not subdomains:
        return []

    output_file = config["output"]["alive_hosts"]
    threads = config["tools"]["httpx_threads"]

    with open("/tmp/subs.txt", "w") as f:
        for sub in subdomains:
            f.write(f"http://{sub}\n")
            f.write(f"http://{sub}\n")
    cmd = [
        "/usr/bin/httpx-toolkit",
        "-l", "/tmp/subs.txt",
        "-silent",
        "-threads", str(threads)
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    alive_hosts = result.stdout.strip().splitlines()

    with open(output_file, "w") as f:
        for host in alive_hosts:
            f.write(host + "\n")

    print(f"[+] Alive hosts found: {len(alive_hosts)}")
    return alive_hosts
