import os
import json
from datetime import datetime


def generate_reports(target, scan_data, risk_findings, signal_findings, prioritized):

    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ---------------- JSON REPORT ----------------
    json_report = {
        "target": target,
        "timestamp": timestamp,
        "summary": {
            "total_risks": len(risk_findings),
            "total_signals": len(signal_findings),
            "total_prioritized": len(prioritized)
        },
        "risk_findings": risk_findings,
        "signal_findings": signal_findings,
        "prioritized_findings": prioritized
    }

    json_path = f"reports/{target}.json"

    with open(json_path, "w") as f:
        json.dump(json_report, f, indent=4)

    # ---------------- HTML REPORT ----------------
    html_path = f"reports/{target}.html"

    with open(html_path, "w") as f:
        f.write(f"""
        <html>
        <head>
            <title>Recon Report - {target}</title>
            <style>
                body {{ font-family: Arial; background: #111; color: #eee; padding: 20px; }}
                h1 {{ color: #00ffcc; }}
                .section {{ margin-bottom: 30px; }}
                .critical {{ color: red; }}
                .high {{ color: orange; }}
                .medium {{ color: yellow; }}
                .low {{ color: lightgreen; }}
                .card {{
                    background: #1e1e1e;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 5px;
                }}
            </style>
        </head>
        <body>
            <h1>Recon Report</h1>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Generated:</strong> {timestamp}</p>

            <div class="section">
                <h2>Summary</h2>
                <p>Total Risks: {len(risk_findings)}</p>
                <p>Total Signals: {len(signal_findings)}</p>
                <p>Total Prioritized Findings: {len(prioritized)}</p>
            </div>

            <div class="section">
                <h2>Prioritized Findings</h2>
        """)

        for item in prioritized:
            if item["category"] == "risk":
                sev = item["details"]["severity"].lower()
                msg = item["details"]["message"]

                f.write(f"""
                <div class="card {sev}">
                    <strong>{item['details']['severity']}</strong><br>
                    {msg}
                </div>
                """)

            elif item["category"] == "signal":
                detail = item["details"]

                if detail["type"] == "interesting_port":
                    content = f"Port {detail['port']} exposed on {detail['host']}"

                elif detail["type"] == "auth_surface":
                    content = f"Authentication surface detected: {detail['url']}"

                else:
                    content = "Signal detected"

                f.write(f"""
                <div class="card medium">
                    <strong>SIGNAL</strong><br>
                    {content}
                </div>
                """)

        f.write("""
            </div>
        </body>
        </html>
        """)

    return json_path, html_path
