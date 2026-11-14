from modules.utils import emit

CRITICAL_RISK_PORTS = {2375, 6379, 27017}  # Docker API, Redis, MongoDB — commonly unauthenticated by default
HIGH_RISK_PORTS = {21, 22, 23, 3306, 5432, 9200}
MEDIUM_RISK_PORTS = {8080, 8000, 8443, 8888, 9090}


def tag_risks(scan_data, output_file=None):
    print("[INF] Running risk engine")
    findings = []

    for host, ports in scan_data.get("ports", {}).items():
        for port in ports:
            if port in CRITICAL_RISK_PORTS:
                entry = f"[CRIT] {host}:{port} commonly unauthenticated service exposed publicly"
                findings.append({"severity": "CRITICAL", "message": entry})
                emit(entry, output_file)

            elif port in HIGH_RISK_PORTS:
                entry = f"[HIGH] {host}:{port} sensitive service exposed publicly"
                findings.append({"severity": "HIGH", "message": entry})
                emit(entry, output_file)

            elif port in MEDIUM_RISK_PORTS:
                entry = f"[MED] {host}:{port} web service on uncommon port"
                findings.append({"severity": "MEDIUM", "message": entry})
                emit(entry, output_file)

    for service in scan_data.get("web_services", []):
        url = service.split()[0]
        if url.startswith("http://"):
            entry = f"[LOW] {url} does not enforce HTTPS"
            findings.append({"severity": "LOW", "message": entry})
            emit(entry, output_file)

    return findings
