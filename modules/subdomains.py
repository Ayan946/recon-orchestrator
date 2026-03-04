import subprocess
from pathlib import Path


def enumerate_subdomains(domain, config):
    print("[*] Enumerating subdomains (passive)...")

    output_dir = Path(config["output"]["base_dir"])
    output_dir.mkdir(exist_ok=True)

    raw_output = output_dir / "amass_raw.txt"

    cmd = [
        "amass",
        "enum",
        "-passive",
        "-d",
        domain
    ]

    try:
        with open(raw_output, "w") as f:
            subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.DEVNULL,
                check=True
            )
    except subprocess.CalledProcessError:
        print("[!] Amass failed during enumeration")
        return []

    subdomains = set()
    with open(raw_output, "r") as f:
        for line in f:
            sub = line.strip()
            if sub.endswith(domain):
                subdomains.add(sub)

    cleaned = sorted(subdomains)

    cleaned_output = output_dir / "subdomains.txt"
    with open(cleaned_output, "w") as f:
        for sub in cleaned:
            f.write(sub + "\n")

    print(f"[+] Found {len(cleaned)} unique subdomains")
    return cleaned
