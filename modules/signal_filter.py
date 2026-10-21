AUTH_KEYWORDS = ["login", "signin", "auth", "admin", "dashboard", "portal", "account"]
INTERESTING_PORTS = {8080, 8443, 9090, 9200, 2375, 4848, 7001, 7002}


def filter_signals(scan_data, output_file=None):
    print("[INF] Running signal filter")
    findings = []

    for host, ports in scan_data.get("ports", {}).items():
        for port in ports:
            if port in INTERESTING_PORTS:
                entry = f"[SIG] {host}:{port} interesting port worth investigating"
                findings.append({"type": "interesting_port", "host": host, "port": port, "note": entry})
                print(entry)
                if output_file:
                    output_file.write(entry + "\n")

    for service in scan_data.get("web_services", []):
        url = service.split()[0]
        for keyword in AUTH_KEYWORDS:
            if keyword in url.lower():
                entry = f"[SIG] {url} authentication surface detected"
                findings.append({"type": "auth_surface", "url": url, "note": entry})
                print(entry)
                if output_file:
                    output_file.write(entry + "\n")
                break

    print(f"[INF] Found {len(findings)} signals")
    return findings
