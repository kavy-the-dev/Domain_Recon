# ipinfo_api_custom.py

import os
import geoip2.database
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import subprocess
import sys
import json
from PortScan import scan_common_ports_json
from xss_scanner import scan_for_xss
from web_tech_detector import detect_web_technologies
from dir_enumerator import enumerate_directories
from fastapi import Query

# Paths to GeoLite2 databases (downloaded from MaxMind)
GEO_DB = "C:\\Users\\kavy\\OneDrive\\Desktop\\sgp7\\GeoLite2-City_20250701\\GeoLite2-City_20250701\\GeoLite2-City.mmdb"
ASN_DB = "C:\\Users\\kavy\\OneDrive\\Desktop\\sgp7\\GeoLite2-ASN_20250703\\GeoLite2-ASN_20250703\\GeoLite2-ASN.mmdb"



app = FastAPI(title="Custom IP Intelligence API")

# Serve static files (CSS, JS, etc.)
app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/", response_class=FileResponse)
def index():
    return FileResponse("index.html")

# IPInfoResponse class definition (restored)
class IPInfoResponse(BaseModel):
    ip: str
    geo: dict
    asn: dict




@app.get("/lookup", response_model=IPInfoResponse)
def lookup(ip: str):
    if not os.path.exists(GEO_DB) or not os.path.exists(ASN_DB):
        raise HTTPException(status_code=500, detail="GeoIP databases not found.")

    try:
        geo_reader = geoip2.database.Reader(GEO_DB)
        asn_reader = geoip2.database.Reader(ASN_DB)

        geo_data = geo_reader.city(ip)
        asn_data = asn_reader.asn(ip)

        # Robust country fallback for geo_info
        country = (
            geo_data.country.name or
            getattr(geo_data.country, 'names', {}).get('en') or
            getattr(geo_data.country, 'iso_code', None) or
            "Unknown"
        )
        region = (
            geo_data.subdivisions.most_specific.name or
            getattr(geo_data.subdivisions.most_specific, 'names', {}).get('en') or
            getattr(geo_data.subdivisions.most_specific, 'iso_code', None) or
            "Unknown"
        )
        city = geo_data.city.name or getattr(geo_data.city, 'names', {}).get('en') or "Unknown"
        geo_info = {
            "city": city,
            "region": region,
            "country": country,
            "postal_code": geo_data.postal.code or "Unknown",
            "accuracy_radius": geo_data.location.accuracy_radius or "Unknown",
        }


        asn_info = {
            "asn": asn_data.autonomous_system_number,
            "name": asn_data.autonomous_system_organization
        }

        return IPInfoResponse(
            ip=ip,
            geo=geo_info,
            asn=asn_info
        )

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing IP: {e}")

@app.get("/scan")
def scan(domain: str):
    # Run the origin_detector.py script as a subprocess and capture output
    try:
        result = subprocess.run([
            sys.executable, "origin_detector.py", domain
        ], capture_output=True, text=True, timeout=60)
        import os
        report_file = f"{domain}_report.json"
        if os.path.exists(report_file):
            with open(report_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Try to get the main IP from the report and run port scan
            main_ip = data.get("main_ip")
            portscan_result = None
            if main_ip:
                try:
                    portscan_result = scan_common_ports_json(main_ip)
                except Exception as e:
                    portscan_result = {"error": str(e)}
            data["portscan"] = {
                "ip": main_ip,
                "results": portscan_result
            }
            
            # Add Technology and XSS scanning
            try:
                # Try HTTPS first, then fallback to HTTP
                target_url = f"https://{domain}"
                try:
                    # First detect web technologies
                    tech_results = detect_web_technologies(target_url)
                    data["technology_scan"] = tech_results
                    
                    # Then perform directory enumeration
                    dir_results = enumerate_directories(target_url)
                    data["directory_scan"] = dir_results
                    
                    # Finally perform XSS scan
                    xss_results = scan_for_xss(target_url)
                except Exception as first_error:
                    print(f"HTTPS scan failed: {str(first_error)}")
                    # If HTTPS fails, try HTTP
                    target_url = f"http://{domain}"
                    try:
                        tech_results = detect_web_technologies(target_url)
                        data["technology_scan"] = tech_results
                        
                        dir_results = enumerate_directories(target_url)
                        data["directory_scan"] = dir_results
                        
                        xss_results = scan_for_xss(target_url)
                    except Exception as second_error:
                        raise Exception(f"Both HTTPS and HTTP scans failed. HTTPS error: {str(first_error)}, HTTP error: {str(second_error)}")
                
                data["xss_scan"] = {
                    "url_tested": target_url,
                    "vulnerable_params": xss_results.get("vulnerable_params", []),
                    "vulnerable_forms": xss_results.get("vulnerable_forms", []),
                    "errors": xss_results.get("errors", []),
                    "debug_info": xss_results.get("debug_info", {})
                }
            except Exception as e:
                data["xss_scan"] = {
                    "error": str(e),
                    "debug_info": {
                        "error_type": type(e).__name__,
                        "error_details": str(e)
                    }
                }
                data["technology_scan"] = {
                    "error": str(e),
                    "debug_info": {
                        "error_type": type(e).__name__,
                        "error_details": str(e)
                    }
                }
                
            return JSONResponse(content=data)
        else:
            return JSONResponse(content={"error": "No report generated", "stdout": result.stdout, "stderr": result.stderr})
    except Exception as e:
        return JSONResponse(content={"error": str(e)})

@app.get("/xss")
def xss_scan(domain: str = Query(..., description="Domain to scan for XSS vulnerabilities")):
    """Scan a domain for XSS vulnerabilities"""
    try:
        # Try HTTPS first
        target_url = f"https://{domain}"
        try:
            xss_results = scan_for_xss(target_url)
        except Exception as e:
            # If HTTPS fails, try HTTP
            target_url = f"http://{domain}"
            xss_results = scan_for_xss(target_url)
        return JSONResponse(content=xss_results)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.get("/portscan")
def portscan(ip: str = Query(..., description="Target IP address to scan")):
    """Scan common ports on the given IP and return open ports and banners."""
    # Basic input validation
    import re
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
        return JSONResponse(content={"error": "Invalid IP address"}, status_code=400)
    try:
        results = scan_common_ports_json(ip)
        return JSONResponse(content={"ip": ip, "results": results})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
