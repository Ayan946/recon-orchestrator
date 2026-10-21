import argparse
import sys
from modules.subdomains import enumerate_subdomains
from modules.alive_hosts import filter_alive_hosts
from modules.port_scan import scan_ports
from modules.web_probe import probe_web_services
from modules.tech_detect import detect_tech
from modules.risk_engine import tag_risks
from modules.signal_filter import filter_signals
from modules.prioritizer import prioritize_findings

BANNER = """
\033[92m
____                      _  __
|  _ \ ___  ___ ___  _ __ \ \/ /
| |_) / _ \/ __/ _ \| '_ \ \  / 
|  _ <  __/ (_| (_) | | | |/  \ 
|_| \_\___|\___\___/|_| |_/_/\_\ 
\033[0m
\033[90m Recon Orchestrator v2.0 — Automated Recon Pipeline\033[0m
"""

def parse_args():
    parser = argparse.ArgumentParser(
        prog="recon-orchestrator",
        description="Automated Reconnaissance Pipeline"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target", help="Single target domain")
    group.add_argument("-l", "--list", help="File with list of targets")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range (default: 1-1000)")
    parser.add_argument("-o", "--output", help="Save output to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    return parser.parse_args()


def get_targets(args):
    if args.target:
        return [args.target]
    with open(args.list, "r") as f:
        return [line.strip() for line in f if line.strip()]


def print_summary(risk_findings, signal_findings, prioritized, output_file=None):
    high = len([f for f in risk_findings if f["severity"] == "HIGH"])
    med = len([f for f in risk_findings if f["severity"] == "MEDIUM"])
    low = len([f for f in risk_findings if f["severity"] == "LOW"])
    sigs = len(signal_findings)

    lines = [
        "",
        "[INF] ─────────────────────────────────────",
        f"[INF] Recon completed",
        f"[INF] Risk findings  → HIGH: {high} | MED: {med} | LOW: {low}",
        f"[INF] Signals found  → {sigs}",
        f"[INF] Total findings → {len(prioritized)}",
        "[INF] ─────────────────────────────────────",
    ]

    for line in lines:
        print(line)
        if output_file:
            output_file.write(line + "\n")


def run_recon(target, config, output_file=None):
    print(f"\n[INF] Target: {target}")
    print(f"[INF] Ports : {config['tools']['nmap_ports']}\n")

    subdomains = enumerate_subdomains(target, config, output_file)
    alive = filter_alive_hosts(subdomains, config, output_file)
    ports = scan_ports(alive, config, output_file)
    web = probe_web_services(alive, config, output_file)
    tech = detect_tech(web, config, output_file)

    scan_data = {"ports": ports, "web_services": web, "tech_stack": tech}

    risks = tag_risks(scan_data, output_file)
    signals = filter_signals(scan_data, output_file)
    prioritized = prioritize_findings(risks, signals)

    print_summary(risks, signals, prioritized, output_file)


def main():
    print(BANNER)
    args = parse_args()

    try:
        from yaml import safe_load
        with open("config.yaml") as f:
            config = safe_load(f)
    except Exception as e:
        print(f"[ERR] Failed to load config: {e}")
        sys.exit(1)

    config["tools"]["nmap_ports"] = args.ports

    targets = get_targets(args)
    print(f"[INF] Loaded {len(targets)} target(s)")

    output_file = open(args.output, "w") if args.output else None

    try:
        for target in targets:
            run_recon(target, config, output_file)
    finally:
        if output_file:
            print(f"\n[INF] Output saved to {args.output}")
            output_file.close()


if __name__ == "__main__":
    main()
