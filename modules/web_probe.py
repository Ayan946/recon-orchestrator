import subprocess

def probe_web_services(alive_hosts, config):
    if not alive_hosts:
        return []

    output_file = config["output"]["web_services"]
    threads = config["tools"]["httpx_threads"]

    with open("/tmp/alive.txt", "w") as f:
        for host in alive_hosts:
            f.write(host + "\n")

    cmd = [
        "httpx-toolkit",
        "-l", "/tmp/alive.txt",
        "-silent",
        "-status-code",
        "-title",
        "-threads", str(threads)
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    web_services = result.stdout.strip().splitlines()

    with open(output_file, "w") as f:
        for service in web_services:
            f.write(service + "\n")

    print(f"[+] Web services identified: {len(web_services)}")
    return web_services
