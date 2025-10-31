import requests
from urllib.parse import urljoin
import threading
import queue
import json

class DirectoryEnumerator:
    def __init__(self):
        self.common_dirs = [
            "admin", "wp-admin", "administrator", "login", "wp-content",
            "admin/login", "admin/admin", "admin/index", "users", "password",
            "log", "logs", "backup", "backups", "config", "dashboard",
            "home", "file", "files", "upload", "uploads", "api", "script",
            "scripts", "setup", "test", "testing", "dev", "development",
            ".git", ".env", "database", "db", "admin/db", "admin/backup",
            "admin/upload", "images", "img", "css", "js", "javascript",
            "bin", "cgi-bin", "cgi", "webservices", "web-services"
        ]
        self.common_files = [
            "index.html", "index.php", "index.asp", "index.aspx",
            "config.php", "configuration.php", "config.inc.php",
            "wp-config.php", ".htaccess", "robots.txt", "sitemap.xml",
            "readme.html", "readme.txt", "README.md", "LICENSE",
            "phpinfo.php", "test.php", "info.php", ".env",
            "web.config", "crossdomain.xml", "composer.json",
            "package.json", ".gitignore", "error_log"
        ]
        self.results = {
            "accessible_dirs": [],
            "accessible_files": [],
            "errors": []
        }
        self.queue = queue.Queue()
        self.found_urls = set()

    def enumerate(self, base_url, num_threads=5):
        """Main enumeration function"""
        # Initialize the queue with paths to check
        for dir_name in self.common_dirs:
            self.queue.put(dir_name + "/")
        for file_name in self.common_files:
            self.queue.put(file_name)

        # Create and start threads
        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=self._worker, args=(base_url,))
            t.daemon = True
            t.start()
            threads.append(t)

        # Wait for all threads to complete
        self.queue.join()
        for t in threads:
            t.join()

        return self.results

    def _worker(self, base_url):
        """Worker function for threads"""
        while True:
            try:
                # Get path from queue with timeout
                path = self.queue.get(timeout=1)
            except queue.Empty:
                break

            try:
                url = urljoin(base_url, path)
                response = requests.get(
                    url, 
                    allow_redirects=False,
                    timeout=10,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Connection': 'keep-alive',
                    }
                )
                
                # Check if the URL was found
                if response.status_code in [200, 301, 302, 403]:
                    if url not in self.found_urls:
                        self.found_urls.add(url)
                        
                        # Categorize the finding
                        if path.endswith('/'):
                            self.results["accessible_dirs"].append({
                                "url": url,
                                "status_code": response.status_code,
                                "content_length": len(response.content),
                                "content_type": response.headers.get('Content-Type', '')
                            })
                        else:
                            self.results["accessible_files"].append({
                                "url": url,
                                "status_code": response.status_code,
                                "content_length": len(response.content),
                                "content_type": response.headers.get('Content-Type', '')
                            })

            except Exception as e:
                self.results["errors"].append(f"Error checking {url}: {str(e)}")
            
            finally:
                self.queue.task_done()

def enumerate_directories(target_url, num_threads=5):
    """Main function to enumerate directories and files"""
    enumerator = DirectoryEnumerator()
    results = enumerator.enumerate(target_url, num_threads)
    return results