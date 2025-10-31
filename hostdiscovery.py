import subprocess
import platform
import ipaddress
import argparse
from concurrent.futures import ThreadPoolExecutor
import socket

def ping_host(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    result = subprocess.run(["ping", param, "1", str(ip)],
                            stdout=subprocess.DEVNULL)
    if result.returncode == 0:
        print(f"[+] Host {ip} is online")

def resolve_domain(domain):
    try:
        ips = socket.gethostbyname_ex(domain)[2]
        print(f"[i] Domain resolved to: {ips}")
        return ips
    except socket.gaierror:
        print(f"[!] Could not resolve domain: {domain}")
        return []

def scan_range(cidr, threads=100):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        print(f"[i] Scanning {cidr} with {threads} threads...\n")
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for ip in network.hosts():
                executor.submit(ping_host, ip)
    except ValueError:
        print(f"[!] Invalid CIDR range: {cidr}")

def main():
    parser = argparse.ArgumentParser(description="Remote Ping Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--range", help="Target IP range (e.g., 10.0.0.0/24)")
    group.add_argument("--domain", help="Target domain (e.g., google.com)")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    args = parser.parse_args()

    if args.range:
        scan_range(args.range, args.threads)
    elif args.domain:
        ips = resolve_domain(args.domain)
        for ip in ips:
            ping_host(ip)

if __name__ == "__main__":
    main()
