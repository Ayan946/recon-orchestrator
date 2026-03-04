def tag_risks(scan_data):
    """
    scan_data expects:
    {
        "ports": {"host": [port1, port2]},
        "web_services": ["http://host:port"],
        "tech_stack": {"host": ["Apache", "PHP"]}
    }
    """

    findings = []

    # 🔥 HIGH RISK PORTS
    high_risk_ports = {21, 22, 23, 3306, 6379, 27017}

    for host, ports in scan_data.get("ports", {}).items():
        for port in ports:
            if port in high_risk_ports:
                findings.append({
                    "severity": "HIGH",
                    "message": f"{host} has sensitive port {port} exposed"
                })

    # ⚠️ MEDIUM – Alt web ports
    medium_ports = {8080, 8000, 8443, 8888}

    for host, ports in scan_data.get("ports", {}).items():
        for port in ports:
            if port in medium_ports:
                findings.append({
                    "severity": "MEDIUM",
                    "message": f"{host} running web service on uncommon port {port}"
                })

    # LOW – HTTP without HTTPS
    for service in scan_data.get("web_services", []):
       url = service.split()[0] #takes only URL part
       if url.startswith("http://"):
          findings.append({
	     "severity":"LOW",
             "message":f"{url} does not enforce HTTPS"
            })

    return findings
