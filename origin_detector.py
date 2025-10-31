import requests
import json
import socket
import sys
import dns.resolver
from bs4 import BeautifulSoup
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Use local custom IP intelligence API
API_URL = "http://localhost:8000/lookup?ip={ip}"
VIEWDNS_HISTORY_URL = "https://viewdns.info/iphistory/?domain={domain}"
HEADERS = {"User-Agent": "Mozilla/5.0"}

def get_historical_dns(domain):
    try:
        print("[*] Getting historical DNS records from ViewDNS...")
        url = VIEWDNS_HISTORY_URL.format(domain=domain)
        r = requests.get(url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        table = soup.find_all("table")[3] if len(soup.find_all("table")) >= 4 else None
        if not table:
            return [], "No records found"
        rows = table.find_all("tr")[1:]  # Skip header
        ips = []
        for row in rows:
            cols = row.find_all("td")
            if len(cols) >= 2:
                ip = cols[1].text.strip()
                if ip not in ips:
                    ips.append(ip)
        return ips, url
    except Exception as e:
        return [], f"Error fetching DNS history: {e}"

def brute_force_subdomains(domain, wordlist=None, max_threads=40):
    if wordlist is None:
        # Expanded wordlist for better coverage
        wordlist = [
            "www", "mail", "ftp", "ns1", "ns2", "blog", "dev", "api", "cdn", "m", "shop", "support", "help", "video",
            "test", "portal", "admin", "webmail", "smtp", "imap", "pop", "vpn", "cpanel", "web", "beta", "old", "new", "secure",
            "server", "gw", "gateway", "intranet", "extranet", "db", "mysql", "sql", "staging", "prod", "production", "demo", "docs",
            "static", "assets", "images", "img", "files", "download", "uploads", "user", "users", "auth", "login", "logout", "register"
        ]
    found = []
    lock = threading.Lock()
    def worker(sub):
        try:
            ip = socket.gethostbyname(f"{sub}.{domain}")
            with lock:
                found.append(f"{sub}.{domain}")
        except:
            pass
    threads = []
    for sub in wordlist:
        t = threading.Thread(target=worker, args=(sub,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return found

def get_subdomains(domain):
    print("[*] Getting subdomains from crt.sh, DNS brute-force, BufferOver API, and DNS zone transfer attempts...")
    subdomains = set()
    # crt.sh
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        data = r.json()
        for entry in data:
            for name in entry['name_value'].split('\n'):
                if domain in name:
                    subdomains.add(name.strip())
    except:
        pass
    # BufferOver API (free, public)
    try:
        r = requests.get(f"https://dns.bufferover.run/dns?q=.\u0025.{domain}", timeout=10)
        data = r.json()
        for item in data.get('FDNS_A', []) + data.get('RDNS', []):
            parts = item.split(',')
            if len(parts) == 2:
                sub = parts[1].strip()
                if sub.endswith(domain):
                    subdomains.add(sub)
    except:
        pass
    # DNS brute-force (now with more threads and larger wordlist)
    try:
        brute = brute_force_subdomains(domain, max_threads=40)
        subdomains.update(brute)
    except:
        pass
    # Attempt DNS zone transfer (AXFR) on common nameservers
    try:
        ns_records = dns.resolver.resolve(domain, 'NS', lifetime=5)
        for ns in ns_records:
            ns_addr = str(ns.target).rstrip('.')
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_addr, domain, timeout=5))
                for name, node in zone.nodes.items():
                    fqdn = f"{name}.{domain}" if str(name) != '@' else domain
                    subdomains.add(fqdn)
            except Exception:
                continue
    except Exception:
        pass
    return sorted(subdomains)

def resolve_subdomain(sub):
    try:
        ip = socket.gethostbyname(sub)
        return ip
    except:
        return None

def get_ip_info(ip):
    try:
        info = requests.get(API_URL.format(ip=ip), timeout=10).json()
        # Try all possible fields for country name
        country = (
            info.get("geo", {}).get("country") or
            info.get("geo", {}).get("country_name") or
            info.get("country") or
            "Unknown"
        )
        return {
            "ip": ip,
            "org": info.get("asn", {}).get("name"),
            "country": country,
            "asn": info.get("asn", {}).get("asn", "Unknown"),
        }
    except:
        return {}

def main(domain):
    results = {
        "domain": domain,
        "cdn_org": None,
        "dns_history": {},
        "subdomains": []
    }

    # Resolve main domain and get org info
    try:
        answers = dns.resolver.resolve(domain, 'A', lifetime=5)
        main_ip = str(answers[0])
        main_ip_info = get_ip_info(main_ip)
        results["cdn_org"] = main_ip_info.get("org", "Unknown")
        results["main_ip"] = main_ip
        results["main_ip_info"] = main_ip_info
    except Exception as e:
        results["cdn_org"] = f"Error: {e}"
        results["main_ip"] = None
        results["main_ip_info"] = {}

    historical_ips, dns_status = get_historical_dns(domain)
    results["dns_history"] = {
        "ips": historical_ips,
        "status": dns_status
    }

    subdomains = get_subdomains(domain)
    # Parallelize subdomain info lookups
    def subdomain_info(sub):
        ip = resolve_subdomain(sub)
        if ip:
            ip_info = get_ip_info(ip)
            return {
                "subdomain": sub,
                "ip": ip,
                "info": ip_info
            }
        return None
    subdomain_results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(subdomain_info, sub) for sub in subdomains]
        for future in as_completed(futures):
            res = future.result()
            if res:
                subdomain_results.append(res)
    results["subdomains"] = subdomain_results

    print("\n[+] Final Output:\n")
    print(json.dumps(results, indent=2))

    with open(f"{domain}_report.json", "w") as f:
        json.dump(results, f, indent=2)
        print(f"\n✅ Report saved to {domain}_report.json")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <domain>")
    else:
        main(sys.argv[1])