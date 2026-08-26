import subprocess
from pathlib import Path
from rich.console import Console

console = Console()

def enumerate_subdomains(domain, config):
    console.print("[*] Enumerating subdomains (passive)...")

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
                check=True,
                timeout=60
            )
    except subprocess.TimeoutExpired:
        console.print("[yellow][!] Amass timed out after 60s — using partial results[/yellow]")
    except subprocess.CalledProcessError:
        console.print("[red][!] Amass failed during enumeration[/red]")
        return []

    subdomains = set()
    try:
        with open(raw_output, "r") as f:
            for line in f:
                sub = line.strip()
                if sub.endswith(domain):
                    subdomains.add(sub)
    except FileNotFoundError:
        return [domain]

    cleaned = sorted(subdomains)

    cleaned_output = output_dir / "subdomains.txt"
    with open(cleaned_output, "w") as f:
        for sub in cleaned:
            f.write(sub + "\n")

    console.print(f"[green][+] Found {len(cleaned)} unique subdomains[/green]")
    return cleaned if cleaned else [domain]