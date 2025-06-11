import whois
import dns.resolver
import json
import argparse
import logging
from datetime import datetime
import requests
import nmap
import socket
import subprocess
from socket import gethostbyname

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def do_whois(domain):
    res = whois.whois(domain)
    print(res)
    return str(res)

def do_dns(domain):
    output = ""
    types = ['A', 'NS', 'TXT', 'MX']
    for record_type in types:
        try:
            res = dns.resolver.resolve(domain, record_type)
            section = f"\n{record_type} Records\n" + "-"*20 + "\n"
            for server in res:
                section += server.to_text() + "\n"
            print(section)
            output += section
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            print('Domain does not exist')
            return "Domain does not exist"
        except KeyboardInterrupt:
            print('Program has been aborted')
            quit()
        except Exception as e:
            print(f"Error while resolving {record_type}: {e}")
    return output

def find_subdomains(domain):
    subdomains = set()
    output = f"\n[+] Scanning {domain} via APIs...\n"
    try:
        print("- Querying crt.sh...")
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = json.loads(response.text)
            for entry in data:
                if 'name_value' in entry:
                    for sub in entry["name_value"].split("\n"):
                        if domain in sub:
                            subdomains.add(sub.strip().lower())
    except Exception as e:
        print(f"[!] crt.sh error: {e}")

    try:
        print("- Querying AlienVault OTX...")
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if "passive_dns" in data:
                for entry in data["passive_dns"]:
                    if domain in entry["hostname"]:
                        subdomains.add(entry["hostname"].strip().lower())
    except Exception as e:
        print(f"[!] AlienVault error : {e}")

    print("\n[+] Discovered Subdomains:")
    if not subdomains:
        print("No subdomains found.")
        return "No subdomains found."
    else:
        output += "\n".join(sorted(subdomains))
        for i, sub in enumerate(sorted(subdomains), 1):
            print(f"{i}. {sub}")
    output += f"\nTotal found: {len(subdomains)}"
    return output

def scan_port(domain):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
                    8443, 8888, 9000, 10000]
    result = ""
    try:
        ip = gethostbyname(domain)
        result += f"Target IP: {ip}\n\n[+] Starting Nmap scan...\n"
        print(result)
        nm = nmap.PortScanner()
        nm.scan(ip, arguments=f"-p {','.join(map(str, common_ports))}")
        for port in common_ports:
            try:
                state = nm[ip]['tcp'][port]['state']
                line = f"Port {port} is {state}\n"
                print(line, end="")
                result += line
            except KeyError:
                line = f"Port {port} not available in scan results\n"
                print(line, end="")
                result += line
    except Exception as e:
        error = f"[!] Error during scan: {e}"
        print(error)
        result += error
    return result

def banner_grabbing(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((ip, int(port)))
        banner = sock.recv(1024).decode(errors="ignore").strip()
        result = f"[+] Banner for {ip}:{port} → {banner}"
        print(result)
        sock.close()
        return result
    except socket.timeout:
        result = f"[-] Timeout on {ip}:{port}"
        print(result)
        return result
    except Exception as e:
        result = f"[!] Error grabbing banner from {ip}:{port} → {e}"
        print(result)
        return result

def detect_technologies(domain):
    if not domain.startswith(('http://', 'https://')):
        url = f"http://{domain}"
    else:
        url = domain
    print(f"\n[+] Technology Detection for {domain}")
    print("-" * 60)
    print("\n[+] Running WhatWeb Scan...")
    try:
        result = subprocess.run(
            ['whatweb', '-a', '3', '--color=never', url],
            capture_output=True,
            text=True,
            timeout=30
        )
        clean_output = result.stdout.replace('\x1b[0m', '').replace('\x1b[1m', '')
        print(clean_output if clean_output else "No technologies detected")
        return clean_output if clean_output else "No technologies detected"
    except FileNotFoundError:
        error = "WhatWeb not found. Install with: sudo apt install whatweb"
        print(error)
        return error
    except Exception as e:
        error = f"WhatWeb scan failed: {str(e)}"
        print(error)
        return error

def write_report(result_dict, filename):
    try:
        with open(filename, 'w') as f:
            for section, content in result_dict.items():
                f.write(f"=== {section.upper()} ===\n")
                f.write(f"{content}\n\n")
        print(f"\n[+] Report saved to {filename}")
    except Exception as e:
        print(f"[!] Failed to write report: {e}")

def main():
    parser = argparse.ArgumentParser(description="Recon Tool by Mostafa")
    parser.add_argument('--domain', help="Target domain")
    parser.add_argument('--whois', action='store_true', help="Perform WHOIS lookup")
    parser.add_argument('--dns', action='store_true', help="DNS enumeration")
    parser.add_argument('--subdomains', action='store_true', help="Find subdomains")
    parser.add_argument('--scan', action='store_true', help="Port scanning and banner grabbing")
    parser.add_argument('--tech', action='store_true', help="Technology detection")
    parser.add_argument('--verbose', action='store_true', help="Enable debug output")
    parser.add_argument('--report', action='store_true', help="Generate report file")
    parser.add_argument("--banner", nargs=2, metavar=('IP', 'PORT'), help="Grab banner from IP and port")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    target = args.domain
    result = {}

    if not target and not args.banner:
        print("[!] Please provide at least --domain or --banner option.")
        return

    if target:
        if args.whois:
            result['whois'] = do_whois(target)
        if args.dns:
            result['dns'] = do_dns(target)
        if args.subdomains:
            result['subdomains'] = find_subdomains(target)
        if args.scan:
            result['scan'] = scan_port(target)
        if args.tech:
            result['tech'] = detect_technologies(target)

    if args.banner:
        ip, port = args.banner
        result['banner'] = banner_grabbing(ip, port)

    if args.report and result:
        filename = f"report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        write_report(result, filename)

if __name__ == "__main__":
    main()
