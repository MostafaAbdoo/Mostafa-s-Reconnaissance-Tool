![Recon Tool Banner](https://i.postimg.cc/9fsSGWCs/Gh-WXDt5bc-AAt-Qld.jpg)

# 🛠️ Custom Reconnaissance Tool

A lightweight, modular reconnaissance tool developed in Python to automate information gathering for penetration testing engagements.

## 🚀 Features

### 🔎 Passive Recon
- **WHOIS Lookup**  
  Uses the `whois` module to fetch domain registration info.
  
- **DNS Enumeration**  
  Supports `A`, `NS`, `TXT`, and `MX` records using `dnspython`.

- **Subdomain Enumeration**  
  Queries:
  - [crt.sh](https://crt.sh/)
  - [AlienVault OTX](https://otx.alienvault.com/)

---

### 🎯 Active Recon
- **Port Scanning**  
  Uses `nmap` (via `python-nmap`) to scan common ports.

- **Banner Grabbing**  
  Connects to specific IP/port combos and fetches service banners.

- **Technology Detection**  
  Uses [`whatweb`](https://tools.kali.org/web-applications/whatweb) (must be installed) to fingerprint web technologies.

---

### 📄 Reporting
- Generates a report in `.txt` format
- Includes timestamps, IP info, and modular scan results
- Automatically saved as `report_<domain>_<timestamp>.txt`

---

## 🧩 Modularity

Each module is **independent and callable via CLI flags**:

| Feature            | Flag              |
|--------------------|-------------------|
| WHOIS              | `--whois`         |
| DNS Enumeration    | `--dns`           |
| Subdomain Scan     | `--subdomains`    |
| Port Scan          | `--scan`          |
| Technology Detect  | `--tech`          |
| Banner Grabbing    | `--banner IP PORT`|
| Report Generation  | `--report`        |
| Verbose Logging    | `--verbose`       |

---

## 🧪 Example Usage

```bash
python recon.py --domain example.com --whois --dns --subdomains --scan --tech --report
```

```bash
python recon.py --banner 192.168.1.1 80
```
```bash
python recon.py --domain example.com --dns --verbose
```

## ⚙️ Requirements

Install required packages:
```bash
pip install whois dnspython python-nmap requests
```

Install whatweb for tech detection (Kali/Ubuntu):
```bash
sudo apt install whatweb
```
