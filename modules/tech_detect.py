import subprocess

def detect_tech(web_services, config):
    if not web_services:
        return {}

    output_file = config["output"]["tech_detect"]
    tech_results = {}

    with open("/tmp/web.txt", "w") as f:
        for service in web_services:
            f.write(service.split(" ")[0] + "\n")

    cmd = [
        "httpx-toolkit",
        "-l", "/tmp/web.txt",
        "-silent",
        "-tech-detect"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    for line in result.stdout.strip().splitlines():
        parts = line.split(" ")
        tech_results[parts[0]] = line

    with open(output_file, "w") as f:
        for host, data in tech_results.items():
            f.write(data + "\n")

    print(f"[+] Technology detection completed")
    return tech_results
