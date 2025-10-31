import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict
import time
import ssl

COMMON_PORTS = [
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    53,   # DNS
    80,   # HTTP
    110,  # POP3
    135,  # MSRPC
    139,  # NetBIOS
    143,  # IMAP
    443,  # HTTPS
    445,  # SMB
    993,  # IMAPS
    995,  # POP3S
    3306, # MySQL
    3389, # RDP
    5900, # VNC
    8080, # HTTP-Proxy
    8443, # HTTPS-Alt
    4444, # Metasploit
    23,   # Telnet (repeat for emphasis, can be removed)
    53,   # DNS (repeat for emphasis, can be removed)
    1723, # PPTP
    6379, # Redis
    27017 # MongoDB
]

SERVICE_MAP: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5900: "vnc",
    8080: "http-proxy",
    8443: "https-alt",
    4444: "metasploit",
    1723: "pptp",
    6379: "redis",
    27017: "mongodb"
}

def scan_port(ip: str, port: int, service: str):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        sock.connect((ip, port))
        try:
            sock.send(b"\r\n")
            banner = sock.recv(1024).decode(errors="ignore").strip().replace("\r", "").replace("\n", " ")
        except:
            banner = "-"
        finally:
            sock.close()
        print(f"{port}/tcp   open    {service:<12} {banner}")
    except:
        pass

def scan_common_ports(ip: str):
    print(f"{'PORT':<9} {'STATE':<7} {'SERVICE':<12} VERSION")
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in COMMON_PORTS:
            service = SERVICE_MAP.get(port, "unknown")
            executor.submit(scan_port, ip, port, service)

def scan_common_ports_json(ip: str):
    """Scan common ports and return results as a list of dicts, with improved banner grabbing for HTTP/HTTPS."""
    results = []
    import http.client
    def scan_port_result(ip: str, port: int, service: str):
        # Try to connect first
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)
        try:
            sock.connect((ip, port))
        except socket.timeout:
            results.append({
                "port": port,
                "state": "filtered",
                "service": service,
                "banner": "timeout/no response"
            })
            sock.close()
            return
        except (ConnectionRefusedError, OSError):
            results.append({
                "port": port,
                "state": "closed",
                "service": service,
                "banner": "connection refused"
            })
            sock.close()
            return
        except Exception as e:
            results.append({
                "port": port,
                "state": "error",
                "service": service,
                "banner": f"connect error: {e}"
            })
            sock.close()
            return
        # If connect succeeds, try to grab banner
        banner = "-"
        import http.client
        if port in (80, 8080):
            try:
                conn = http.client.HTTPConnection(ip, port, timeout=1)
                conn.request("GET", "/", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"})
                resp = conn.getresponse()
                headers = "\n".join(f"{k}: {v}" for k, v in resp.getheaders())
                banner = f"HTTP {resp.status} {resp.reason}\\n{headers}"
                conn.close()
            except Exception as e:
                banner = f"HTTP probe error: {e}"
        elif port == 443:
            try:
                conn = http.client.HTTPSConnection(ip, port, timeout=1, context=ssl._create_unverified_context())
                conn.request("GET", "/", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"})
                resp = conn.getresponse()
                headers = "\n".join(f"{k}: {v}" for k, v in resp.getheaders())
                banner = f"HTTPS {resp.status} {resp.reason}\\n{headers}"
                conn.close()
            except Exception as e:
                banner = f"HTTPS probe error: {e}"
        elif port == 22:
            try:
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except Exception as e:
                banner = f"SSH probe error: {e}"
        elif port == 21:
            try:
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except Exception as e:
                banner = f"FTP probe error: {e}"
        elif port == 3306:
            try:
                handshake = sock.recv(1024)
                if handshake:
                    if handshake[0] == 10:
                        server_version = handshake[1:].split(b'\x00')[0].decode(errors="ignore")
                        banner = f"MySQL Server version: {server_version}"
                    else:
                        banner = f"MySQL handshake: {handshake[:20].hex()}..."
            except Exception as e:
                banner = f"MySQL probe error: {e}"
        else:
            try:
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode(errors="ignore").strip().replace("\r", "").replace("\n", " ")
            except Exception as e:
                banner = f"Generic probe error: {e}"
        sock.close()
        results.append({
            "port": port,
            "state": "open",
            "service": service,
            "banner": banner
        })
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in COMMON_PORTS:
            service = SERVICE_MAP.get(port, "unknown")
            executor.submit(scan_port_result, ip, port, service)
    executor.shutdown(wait=True)
    return results

# Example usage
if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Change this to target IP
    scan_common_ports(target_ip)
