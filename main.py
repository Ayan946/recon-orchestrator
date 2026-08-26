import yaml
import sys
import argparse
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from modules.subdomains import enumerate_subdomains
from modules.alive_hosts import filter_alive_hosts
from modules.port_scan import scan_ports
from modules.web_probe import probe_web_services
from modules.tech_detect import detect_tech
from modules.report import generate_summary
from modules.risk_engine import tag_risks
from modules.signal_filter import filter_signals
from modules.prioritizer import prioritize_findings
from modules.reporter import generate_reports

console = Console()

def load_config():
    try:
        with open("config.yaml", "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        console.print(f"[red][!] Failed to load config: {e}[/red]")
        sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Recon Orchestrator - Automated Reconnaissance Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target", help="Single target domain (e.g. example.com)")
    group.add_argument("-l", "--list", help="File containing list of targets (one per line)")
    parser.add_argument("-o", "--output", help="Output directory (default: output)", default="output")
    parser.add_argument("-p", "--ports", help="Port range to scan (default: 1-1000)", default="1-1000")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def get_targets(args):
    if args.target:
        return [args.target]
    elif args.list:
        path = Path(args.list)
        if not path.exists():
            console.print(f"[red][!] Target file not found: {args.list}[/red]")
            sys.exit(1)
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    return []

def print_banner():
    console.print(Panel.fit(
        "[cyan]Recon Orchestrator[/cyan]\n[dim]Automated Reconnaissance Tool[/dim]",
        border_style="cyan"
    ))

def print_findings_table(risk_findings, signal_findings, prioritized):
    if risk_findings:
        table = Table(title="Risk Findings", box=box.SIMPLE_HEAVY, border_style="red")
        table.add_column("Severity", style="bold")
        table.add_column("Message")
        for f in risk_findings:
            sev = f["severity"]
            color = "red" if sev == "HIGH" else "yellow" if sev == "MEDIUM" else "green"
            table.add_row(f"[{color}]{sev}[/{color}]", f["message"])
        console.print(table)

    if signal_findings:
        table = Table(title="Signal Findings", box=box.SIMPLE_HEAVY, border_style="yellow")
        table.add_column("Type", style="bold")
        table.add_column("Details")
        for f in signal_findings:
            if f["type"] == "interesting_port":
                table.add_row("PORT", f"{f['host']}:{f['port']} → {f['note']}")
            elif f["type"] == "auth_surface":
                table.add_row("AUTH", f"{f['url']} → {f['note']}")
        console.print(table)

    if prioritized:
        table = Table(title="Prioritized Findings", box=box.SIMPLE_HEAVY, border_style="cyan")
        table.add_column("Score", style="bold cyan")
        table.add_column("Category")
        table.add_column("Details")
        for item in prioritized:
            if item["category"] == "risk":
                sev = item["details"]["severity"]
                msg = item["details"]["message"]
                table.add_row(str(item["score"]), f"[red]{sev}[/red]", msg)
            elif item["category"] == "signal":
                detail = item["details"]
                if detail["type"] == "interesting_port":
                    table.add_row(str(item["score"]), "PORT", f"{detail['host']}:{detail['port']}")
                elif detail["type"] == "auth_surface":
                    table.add_row(str(item["score"]), "AUTH", detail["url"])
        console.print(table)

def run_recon(domain, config):
    console.print(f"\n[cyan][+] Starting recon on:[/cyan] [bold]{domain}[/bold]\n")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task("Enumerating subdomains...", total=None)
        subdomains = enumerate_subdomains(domain, config)
        if not subdomains:
            subdomains = [domain]
        progress.update(task, description=f"[green]Found {len(subdomains)} subdomains[/green]")

        progress.update(task, description="Filtering alive hosts...")
        alive_hosts = filter_alive_hosts(subdomains, config)

        progress.update(task, description="Scanning ports...")
        scan_results = scan_ports(alive_hosts, config)

        progress.update(task, description="Probing web services...")
        web_services = probe_web_services(alive_hosts, config)

        progress.update(task, description="Detecting technologies...")
        tech_stack = detect_tech(web_services, config)

    scan_data = {
        "ports": scan_results,
        "web_services": web_services,
        "tech_stack": tech_stack
    }

    risk_findings = tag_risks(scan_data)
    signal_findings = filter_signals(scan_data)
    prioritized = prioritize_findings(risk_findings, signal_findings)

    print_findings_table(risk_findings, signal_findings, prioritized)

    json_path, html_path = generate_reports(
        domain, scan_data, risk_findings, signal_findings, prioritized
    )

    console.print(f"\n[green][+] JSON report:[/green] {json_path}")
    console.print(f"[green][+] HTML report:[/green] {html_path}")

    generate_summary(domain, subdomains, alive_hosts, scan_results, web_services, tech_stack, config)
    console.print(f"\n[green][+] Recon completed on {domain}[/green]\n")

def main():
    print_banner()
    args = parse_args()
    config = load_config()

    config["output"]["base_dir"] = args.output
    config["tools"]["nmap_ports"] = args.ports
    config["behavior"]["verbose"] = args.verbose

    targets = get_targets(args)
    console.print(f"[dim]Targets loaded: {len(targets)}[/dim]\n")

    for target in targets:
        config["target"]["domain"] = target
        run_recon(target, config)

if __name__ == "__main__":
    main()
