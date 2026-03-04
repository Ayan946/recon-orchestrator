def filter_signals(scan_data):
    findings = []

    # ---- Interesting Ports ----
    interesting_ports = [21, 22, 23, 25, 53, 110, 139, 445, 3306, 3389, 5432, 6379, 8080, 8443]

    for host, ports in scan_data.get("ports", {}).items():
        for port in ports:
            if port in interesting_ports:
                findings.append({
                    "type": "interesting_port",
                    "host": host,
                    "port": port,
                    "note": "Uncommon or potentially sensitive service"
                })

    # ---- Admin / Login detection ----
    for service in scan_data.get("web_services", []):
        url = service.split()[0]

        keywords = ["admin", "login", "dashboard", "panel"]

        for word in keywords:
            if word in url.lower():
                findings.append({
                    "type": "auth_surface",
                    "url": url,
                    "note": "Potential authentication surface"
                })

    return findings
