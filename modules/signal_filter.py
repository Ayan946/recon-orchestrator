import re

from modules.utils import emit

# Admin ports with no severity in risk_engine — kept separate so a port
# is never counted as both a risk finding and a signal finding.
INTERESTING_PORTS = {4848, 7001, 7002}
AUTH_KEYWORDS = ["login", "signin", "auth", "admin", "dashboard", "portal", "account"]


def filter_signals(scan_data, output_file=None):
    print("[INF] Running signal filter")
    findings = []

    for host, ports in scan_data.get("ports", {}).items():
        for port in ports:
            if port in INTERESTING_PORTS:
                entry = f"[SIG] {host}:{port} interesting port worth investigating"
                findings.append({"type": "interesting_port", "host": host, "port": port, "note": entry})
                emit(entry, output_file)

    for service in scan_data.get("web_services", []):
        url = service.split()[0]
        for keyword in AUTH_KEYWORDS:
            # Whole-word match against the full line (url + status + title + tech),
            # so "author.example.com" doesn't match "auth" and a page titled
            # "Admin Login" is caught even if the URL itself isn't.
            if re.search(rf"\b{keyword}\b", service, re.IGNORECASE):
                entry = f"[SIG] {url} authentication surface detected"
                findings.append({"type": "auth_surface", "url": url, "note": entry})
                emit(entry, output_file)
                break

    print(f"[INF] Found {len(findings)} signals")
    return findings
