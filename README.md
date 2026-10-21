# ReconX

A fast, automated reconnaissance pipeline for penetration testers and bug bounty hunters. Chains subdomain enumeration, alive host detection, port scanning, and risk tagging into a single CLI command — nuclei-style output, zero config editing.

## Features

- Passive subdomain enumeration via Subfinder
- Alive host detection with status codes via httpx
- Port scanning with service/version detection via Nmap
- Technology stack fingerprinting
- Risk engine tagging HIGH/MEDIUM/LOW findings
- Signal filter flagging interesting attack surfaces
- Clean, progressive nuclei-style terminal output
- Optional output file saving

## Installation

```bash
git clone https://github.com/Ayan946/recon-orchestrator.git
cd recon-orchestrator
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Requires `subfinder`, `httpx-toolkit`, and `nmap` installed on your system.

## Usage

```bash
reconx -t target.com
```

Scan multiple targets:
```bash
reconx -l targets.txt
```

Save output to a file:
```bash
reconx -t target.com -o results.txt
```

Custom port range:
```bash
reconx -t target.com -p 1-65535
```

## Help

```bash
reconx --help
```

```
usage: reconx [-h] (-t TARGET | -l LIST) [-p PORTS] [-o OUTPUT] [-v]

Automated Reconnaissance Pipeline

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Single target domain
  -l LIST, --list LIST  File with list of targets
  -p PORTS, --ports PORTS
                        Port range (default: 1-1000)
  -o OUTPUT, --output OUTPUT
                        Save output to file
  -v, --verbose         Verbose mode
```

## Disclaimer

For authorized security testing and bug bounty programs only.
