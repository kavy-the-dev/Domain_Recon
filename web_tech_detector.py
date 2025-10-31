import requests
from bs4 import BeautifulSoup
import re
import json
import socket
import ssl

class WebTechnologyDetector:
    def __init__(self):
        self.results = {
            "url": "",
            "server_info": {
                "server": "",
                "operating_system": None,
                "server_version": None
            },
            "frameworks": [],
            "waf": [],
            "cms": None,
            "languages": [],
            "technologies": [],
            "headers": {},
            "javascript_libs": [],
            "meta_info": {},
            "security_headers": {},
            "ssl_info": {},
            "errors": []
        }
        
        # Framework fingerprints
        self.framework_patterns = {
            'Laravel': ['laravel', 'XSRF-TOKEN'],
            'Django': ['csrftoken', 'dsessionid'],
            'Ruby on Rails': ['rails', '_rails_admin_session'],
            'ASP.NET': ['asp.net', '__VIEWSTATE', '__ASPXAUTH'],
            'CakePHP': ['cakephp', 'CAKEPHP'],
            'CherryPy': ['cherrypy.session'],
            'Flask': ['flask'],
            'Express.js': ['express', 'connect.sid'],
            'Spring': ['jsessionid', 'spring.session'],
            'Symfony': ['symfony', '_symfony_'],
            'CodeIgniter': ['ci_session'],
            'Zend': ['zend'],
            'Yii': ['_csrf-frontend', '_csrf-backend']
        }
        
        # WAF fingerprints
        self.waf_patterns = {
            'Cloudflare': ['cloudflare', '__cfduid', 'cf-ray'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'Imperva': ['incapsula', 'visid_incap'],
            'F5 BIG-IP': ['BIG-IP', 'F5'],
            'Akamai': ['akamai', 'aka'],
            'AWS WAF': ['aws-waf', 'awselb'],
            'Sucuri': ['sucuri', 'sucuriiframe'],
            'Barracuda': ['barracuda', 'barra'],
            'Fortinet': ['fortigate', 'fortiweb'],
            'Palo Alto': ['panos', 'pan-user-id']
        }
        
        # Operating System fingerprints
        self.os_patterns = {
            'Windows': ['windows', 'win32', 'iis'],
            'Linux': ['linux', 'ubuntu', 'debian', 'centos', 'fedora', 'redhat'],
            'Unix': ['unix', 'freebsd', 'openbsd', 'netbsd'],
            'macOS': ['darwin', 'macos', 'mac os x']
        }
        
        # Language fingerprints
        self.language_patterns = {
            'PHP': ['.php', 'php', 'PHPSESSID', 'X-Powered-By: PHP'],
            'Python': ['.py', 'python', 'wsgi', 'django', 'flask'],
            'Ruby': ['.rb', 'ruby', 'rails', 'rack'],
            'Java': ['.jsp', '.java', 'jsessionid', 'servlet'],
            'Node.js': ['node', 'express', 'npm'],
            'ASP.NET': ['.aspx', '.asp', 'asp.net', 'iis'],
            'Perl': ['.pl', '.cgi', 'perl'],
            'Go': ['golang', 'go server'],
            'Scala': ['scala', 'play framework']
        }
        
        # CMS fingerprints (expanded)
        self.cms_patterns = {
            'WordPress': [
                'wp-content',
                'wp-includes',
                'wp-admin',
                'WordPress',
                'WooCommerce'
            ],
            'Joomla': [
                'joomla',
                '/components/com_',
                'Joomla!'
            ],
            'Drupal': [
                'drupal',
                'Drupal.settings',
                '/sites/all/themes/',
                '/sites/default/'
            ],
            'Magento': [
                'magento',
                'Mage.Cookies',
                '/skin/frontend/'
            ],
            'PrestaShop': [
                'prestashop',
                'PrestaShop',
                '/modules/ps_'
            ],
            'MODX': [
                'modx',
                '/core/cache/',
                'MODX.config'
            ],
            'Bitrix': [
                'bitrix',
                '/bitrix/js/',
                'BX.ready'
            ],
            'Shopify': [
                'shopify',
                '.myshopify.com',
                'Shopify.theme'
            ],
            'Ghost': [
                'ghost',
                'ghost-blog',
                'Ghost.org'
            ],
            'WooCommerce': [
                'woocommerce',
                'WooCommerce',
                '/wp-content/plugins/woocommerce/'
            ]
        }

    def detect_technologies(self, url):
        """Main detection function"""
        self.results["url"] = url
        
        try:
            # Get the initial response with browser-like headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            response = requests.get(url, verify=False, timeout=10, headers=headers)
            self.results["headers"] = dict(response.headers)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            html_content = response.text.lower()
            headers_str = str(response.headers).lower()
            
            # Server and OS Detection
            self._detect_server_info(response.headers, html_content)
            
            # Framework Detection
            self._detect_frameworks(headers_str, html_content, soup)
            
            # WAF Detection
            self._detect_waf(headers_str, response.headers)
            
            # CMS Detection
            self._detect_cms(soup, html_content)
            
            # Language Detection
            self._detect_languages(headers_str, html_content)
            
            # JavaScript libraries
            self._detect_js_libs(soup)
            
            # Meta information
            self._get_meta_info(soup)
            
            # Security headers
            self._check_security_headers(response.headers)
            
            # SSL/TLS
            self._check_ssl(url)
            
            # Additional technologies
            self._detect_common_tech(soup, html_content)
            
        except Exception as e:
            self.results["errors"].append(str(e))
            
    def _detect_server_info(self, headers, html_content):
        """Detect server and operating system information"""
        # Server detection
        server_header = headers.get('Server', '')
        self.results["server_info"]["server"] = server_header
        
        # Try to extract server version if present
        if server_header:
            version_match = re.search(r'[\d\.]+', server_header)
            if version_match:
                self.results["server_info"]["server_version"] = version_match.group(0)
        
        # OS detection
        for os_name, patterns in self.os_patterns.items():
            for pattern in patterns:
                if pattern in html_content or pattern in str(headers).lower():
                    self.results["server_info"]["operating_system"] = os_name
                    break
            if self.results["server_info"]["operating_system"]:
                break
                
    def _detect_frameworks(self, headers_str, html_content, soup):
        """Detect web frameworks"""
        # Check headers and cookies
        for framework, patterns in self.framework_patterns.items():
            for pattern in patterns:
                if pattern.lower() in headers_str or pattern.lower() in html_content:
                    if framework not in self.results["frameworks"]:
                        self.results["frameworks"].append(framework)
                        
        # Check meta tags and generator info
        for meta in soup.find_all('meta'):
            content = meta.get('content', '').lower()
            name = meta.get('name', '').lower()
            if 'generator' in name:
                for framework, patterns in self.framework_patterns.items():
                    if any(pattern.lower() in content for pattern in patterns):
                        if framework not in self.results["frameworks"]:
                            self.results["frameworks"].append(framework)
                            
    def _detect_waf(self, headers_str, headers):
        """Detect Web Application Firewall"""
        # Check WAF-specific headers and cookies
        for waf, patterns in self.waf_patterns.items():
            for pattern in patterns:
                if pattern.lower() in headers_str:
                    if waf not in self.results["waf"]:
                        self.results["waf"].append(waf)
        
        # Check for specific WAF response headers
        if 'x-sucuri-id' in headers_str:
            self.results["waf"].append('Sucuri')
        if 'x-fw-hash' in headers_str:
            self.results["waf"].append('Fortinet FortiWeb')
            
    def _detect_languages(self, headers_str, html_content):
        """Detect programming languages"""
        for lang, patterns in self.language_patterns.items():
            for pattern in patterns:
                if pattern.lower() in headers_str or pattern.lower() in html_content:
                    if lang not in self.results["languages"]:
                        self.results["languages"].append(lang)

    def _detect_cms(self, soup, html):
        """Detect Content Management System"""
        cms_patterns = {
            'WordPress': [
                'wp-content',
                'wp-includes',
                '<meta name="generator" content="WordPress'
            ],
            'Joomla': [
                'joomla!',
                '/components/com_',
                '<meta name="generator" content="Joomla'
            ],
            'Drupal': [
                'Drupal.settings',
                'jquery.once.js?v=',
                '/sites/all/themes/'
            ],
            'Magento': [
                'Mage.Cookies',
                '/skin/frontend/',
                'Magento/js/prototype'
            ]
        }

        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if pattern.lower() in html.lower():
                    self.results["cms"] = cms
                    return

    def _detect_js_libs(self, soup):
        """Detect JavaScript libraries"""
        scripts = soup.find_all('script', src=True)
        
        common_libs = {
            'jQuery': r'jquery[.-]',
            'React': r'react[.-]',
            'Angular': r'angular[.-]',
            'Vue.js': r'vue[.-]',
            'Bootstrap': r'bootstrap[.-]',
            'Modernizr': r'modernizr[.-]',
            'Lodash': r'lodash[.-]'
        }

        for script in scripts:
            src = script['src'].lower()
            for lib, pattern in common_libs.items():
                if re.search(pattern, src):
                    if lib not in self.results["javascript_libs"]:
                        self.results["javascript_libs"].append(lib)

    def _get_meta_info(self, soup):
        """Get meta information from HTML"""
        meta_tags = soup.find_all('meta')
        
        for tag in meta_tags:
            name = tag.get('name', tag.get('property', '')).lower()
            content = tag.get('content', '')
            
            if name and content:
                self.results["meta_info"][name] = content

    def _check_security_headers(self, headers):
        """Check for security headers"""
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'X-Frame',
            'X-XSS-Protection': 'XSS Protection',
            'X-Content-Type-Options': 'Content Type Options',
            'Referrer-Policy': 'Referrer Policy'
        }

        for header, desc in security_headers.items():
            if header in headers:
                self.results["security_headers"][desc] = headers[header]

    def _check_ssl(self, url):
        """Check SSL/TLS information"""
        if not url.startswith('https'):
            return

        try:
            domain = url.split('https://')[1].split('/')[0]
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
                
                self.results["ssl_info"] = {
                    "version": s.version(),
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "expires": cert['notAfter'],
                    "subject": dict(x[0] for x in cert['subject'])
                }
        except Exception as e:
            self.results["errors"].append(f"SSL Error: {str(e)}")

    def _detect_common_tech(self, soup, html):
        """Detect common web technologies"""
        tech_patterns = {
            'PHP': ['.php', 'PHPSESSID'],
            'ASP.NET': ['.aspx', '__VIEWSTATE'],
            'Java': ['.jsp', 'jsessionid'],
            'Python': ['.py', 'wsgi'],
            'Ruby': ['.rb', 'ruby-on-rails'],
            'Apache': ['apache'],
            'Nginx': ['nginx'],
            'IIS': ['IIS'],
            'OpenSSL': ['openssl'],
            'CloudFlare': ['cloudflare']
        }

        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if pattern.lower() in html.lower() or \
                   pattern.lower() in str(self.results["headers"]).lower():
                    if tech not in self.results["technologies"]:
                        self.results["technologies"].append(tech)

def detect_web_technologies(target_url):
    """Main function to detect web technologies"""
    detector = WebTechnologyDetector()
    detector.detect_technologies(target_url)
    return detector.results