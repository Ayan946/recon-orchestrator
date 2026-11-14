# ReconX

A fast, automated reconnaissance pipeline for penetration testers and bug bounty hunters. Chains subdomain enumeration, alive-host detection, port scanning, tech fingerprinting, and risk/signal tagging into a single CLI command — nuclei-style output, config-driven, works out of the box even with no config file.

## Features

- Passive subdomain enumeration via Subfinder
- Alive host detection with status codes via httpx
- Port scanning with service/version detection via Nmap
- Technology stack fingerprinting from httpx's `-tech-detect`
- Risk engine tagging CRITICAL/HIGH/MEDIUM/LOW findings
- Signal filter flagging interesting attack surfaces (admin ports, auth pages)
- Findings are prioritized and the top ones printed in the final summary
- Per-target error isolation — one target failing doesn't kill a multi-target run
- Falls back to sane defaults if `config.yaml` is missing or incomplete
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

Requires `subfinder`, `httpx-toolkit`, and `nmap` installed and on your `PATH`.

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

Verbose mode (prints the resolved config before each target runs):
```bash
reconx -t target.com -v
```

## Help

```bash
reconx --help
```
usage: reconx [-h] (-t TARGET | -l LIST) [-p PORTS] [-o OUTPUT] [-v]

Automated Reconnaissance Pipeline

options:
-h, --help show this help message and exit
-t TARGET, --target TARGET
Single target domain
-l LIST, --list LIST File with list of targets
-p PORTS, --ports PORTS
Port range (default: 1-1000)
-o OUTPUT, --output OUTPUT
Save output to file
-v, --verbose Verbose mode


## Configuration

`config.yaml` in the current directory is optional — if it's missing, or missing individual keys, built-in defaults are used, so `reconx` works from any directory after `pip install -e .`.

```yaml
tools:
  subfinder: true       # set false to skip this stage
  nmap: true             # set false to skip this stage
  nmap_ports: "1-1000"   # overridden by -p
  httpx: true             # set false to skip alive-host/web-probe stages
  httpx_threads: 50

scanning:
  rate_limit: 150   # passed to nmap as --max-rate
  timeout: 10        # per-tool subprocess timeout, in seconds

behavior:
  verbose: false
  stop_on_error: false   # true = abort the whole run on a target's failure
```

`-v` on the command line always forces verbose mode on, regardless of `config.yaml`.

## Risk tiers

| Severity | Ports | Notes |
|---|---|---|
| CRITICAL | 2375, 6379, 27017 | Docker API, Redis, MongoDB — commonly unauthenticated by default |
| HIGH | 21, 22, 23, 3306, 5432, 9200 | |
| MEDIUM | 8080, 8000, 8443, 8888, 9090 | |
| LOW | any `http://` URL | no HTTPS enforced |

Signals (admin ports 4848/7001/7002, and pages whose URL, title, or detected tech match an auth-related keyword) are tracked separately from risk findings, so nothing is double-counted.

## Architecture

main.py CLI, config loading, pipeline orchestration
modules/
utils.py shared print+log helper, subprocess wrapper with timeout/error handling
subdomains.py subfinder
alive_hosts.py httpx (status codes)
port_scan.py nmap -sV
web_probe.py httpx (title + tech-detect)
tech_detect.py parses tech stack out of web_probe’s output
risk_engine.py severity tagging
signal_filter.py interesting-surface tagging
prioritizer.py merges and sorts all findings


## Disclaimer

For authorized security testing and bug bounty programs only.
