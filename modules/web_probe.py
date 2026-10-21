import subprocess
import re


def probe_web_services(alive_hosts, config, output_file=None):
    print(f"[INF] Probing web services on {len(alive_hosts)} hosts")

    with open("/tmp/alive.txt", "w") as f:
        f.write("\n".join([h.split()[0] for h in alive_hosts]))

    cmd = ["httpx-toolkit", "-l", "/tmp/alive.txt", "-silent",
           "-status-code", "-title", "-tech-detect", "-threads",
           str(config["tools"]["httpx_threads"])]

    result = subprocess.run(cmd, capture_output=True, text=True)

    services = []
    for line in result.stdout.splitlines():
        if line.strip():
            entry = f"[WEB] {line.strip()}"
            print(entry)
            if output_file:
                output_file.write(entry + "\n")
            services.append(line.strip())

    print(f"[INF] Found {len(services)} web services")
    return services
