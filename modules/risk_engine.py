HIGH_RISK_PORTS = {21, 22, 23, 3306, 5432, 6379, 27017, 9200, 2375}
MEDIUM_RISK_PORTS = {8080, 8000, 8443, 8888, 9090}


def tag_risks(scan_data, output_file=None):
    print("[INF] Running risk engine")
    findings = []

    for host, ports in scan_data.get("ports", {}).items():
        for port in ports:
            if port in HIGH_RISK_PORTS:
                entry = f"[HIGH] {host}:{port} sensitive service exposed publicly"
                findings.append({"severity": "HIGH", "message": entry})
                print(entry)
                if output_file:
                    output_file.write(entry + "\n")

            elif port in MEDIUM_RISK_PORTS:
                entry = f"[MED] {host}:{port} web service on uncommon port"
                findings.append({"severity": "MEDIUM", "message": entry})
                print(entry)
                if output_file:
                    output_file.write(entry + "\n")

    for service in scan_data.get("web_services", []):
        url = service.split()[0]
        if url.startswith("http://"):
            entry = f"[LOW] {url} does not enforce HTTPS"
            findings.append({"severity": "LOW", "message": entry})
            print(entry)
            if output_file:
                output_file.write(entry + "\n")

    return findings
