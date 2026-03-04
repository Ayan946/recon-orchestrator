import yaml
import sys

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

def load_config():
    try:
        with open("config.yaml", "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"[!] Failed to load config: {e}")
        sys.exit(1)


def main():
    config = load_config()
    domain = config["target"]["domain"]

    print(f"\n[+] Starting recon on target: {domain}\n")

    subdomains = enumerate_subdomains(domain, config)
    if not subdomains: subdomains = [domain]
    alive_hosts = filter_alive_hosts(subdomains, config)

    scan_results = scan_ports(alive_hosts, config)
    web_services = probe_web_services(alive_hosts, config)

    tech_stack = detect_tech(web_services, config)

    scan_data = {
     "ports":scan_results,
     "web_services":web_services,
     "tech_stack":tech_stack
}

    risk_findings = tag_risks(scan_data)
    signal_findings = filter_signals(scan_data)
    prioritized = prioritize_findings(risk_findings, signal_findings)

    print("\n=== Risk Summary ===")

    for finding in risk_findings:
       print(f"[{finding['severity']}] {finding['message']}")

    print("\n=== Signal Summary ===")

    for finding in signal_findings:
       if finding["type"] == "interesting_port":
          print(f"[PORT]{finding['host']}:{finding['port']}->{finding['note']}")

       elif finding["type"] == "auth_surface":
          print(f"[AUTH]{finding['url']}->{finding['note']}")

    print("\n=== Prioritized Findings ===")

    for item in prioritized:
       score = item["score"]
       category = item["category"]

       if category == "risk":
          sev = item["details"]["severity"]
          msg = item["details"]["message"]
          print(f"[{score}] ({sev}) {msg}")

       elif category == "signal":
         detail = item["details"]

         if detail["type"] == "interesting_port":
            print(f"[{score}] PORT {detail['host']}:{detail['port']}")

         elif detail["type"] == "auth_surface":
            print(f"[{score}] AUTH {detail['url']}")

    json_path, html_path = generate_reports(
         domain,
         scan_data,
         risk_findings,
         signal_findings,
         prioritized
    )

    print(f"\n[+] JSON report saved to: {json_path}")
    print(f"[+] HTML report saved to:{html_path}")

    generate_summary(
        domain,
        subdomains,
        alive_hosts,
        scan_results,
        web_services,
        tech_stack,
        config
    )

    print("\n[+] Recon completed successfully.\n")


if __name__ == "__main__":
    main()
