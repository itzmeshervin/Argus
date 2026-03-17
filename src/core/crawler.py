"""
Web Crawler Engine.
Discovers attack surfaces by crawling target websites.
"""

import re
import time
import logging
from urllib.parse import urljoin, urlparse, parse_qsl, urlunparse
from typing import Set, List, Dict, Optional, Tuple
from collections import deque

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import FeatureNotFound
from bs4 import BeautifulSoup

from src.models.scan_context import (
    AttackSurface, Form, FormField, URLParameter, 
    Cookie, APIEndpoint, FileUploadEndpoint, ScanContext
)


logger = logging.getLogger(__name__)


class WebCrawler:
    """
    Comprehensive web crawler for attack surface discovery.
    Extracts URLs, forms, parameters, cookies, headers, and API endpoints.
    """
    
    SENSITIVE_FILES = [
        "robots.txt", ".htaccess", ".git/config", ".env", 
        "wp-config.php", "config.php", "web.config", ".svn/entries",
        "backup.sql", "database.sql", ".DS_Store", "phpinfo.php",
        "server-status", "info.php", "test.php", "admin/", "login/",
        ".well-known/security.txt", "sitemap.xml", "crossdomain.xml"
    ]
    
    API_PATTERNS = [
        r'/api/', r'/v\d+/', r'/rest/', r'/graphql', r'/json',
        r'\.json$', r'/ws/', r'/rpc/'
    ]
    
    STATIC_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico',
        '.css',
        '.pdf', '.zip', '.rar', '.7z', '.tar', '.gz',
        '.mp4', '.mp3', '.wav', '.avi', '.mov', '.mkv',
        '.woff', '.woff2', '.ttf', '.eot'
    }
    
    def __init__(self, target_url: str, max_depth: int = 3, 
                 max_urls: int = 500, rate_limit: float = 0.5,
                 timeout: int = 10, user_agent: str = "VulnScanner/1.0"):
        self.target_url = target_url.rstrip('/')
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.user_agent = user_agent
        
        parsed = urlparse(target_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        retry = Retry(
            total=3,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"]
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        self.html_parser = self._select_html_parser()
        
        self.visited: Set[str] = set()
        self.attack_surface = AttackSurface()
        self.response_headers: Dict[str, Dict[str, str]] = {}
        
    def crawl(self, progress_callback=None, url_callback=None) -> AttackSurface:
        """
        Perform full website crawl and return attack surface.
        """
        logger.info(f"Starting crawl of {self.target_url}")
        
        queue = deque([(self.target_url, 0)])
        
        for url in self._check_sensitive_files(progress_callback, url_callback):
            queue.append((url, 0))
        
        while queue and len(self.visited) < self.max_urls:
            url, depth = queue.popleft()
            
            if url in self.visited or depth > self.max_depth:
                continue
            
            if not self._is_same_domain(url):
                continue
            
            self.visited.add(url)
            self.attack_surface.urls.add(url)
            if url_callback: url_callback(url)
            
            if progress_callback:
                progress_callback(f"Crawling: {url[:60]}...")
            
            try:
                response = self._fetch_url(url)
                if response is None:
                    continue
                
                final_url = self._canonicalize_url(response.url)
                if final_url and final_url not in self.visited:
                    self.visited.add(final_url)
                    self.attack_surface.urls.add(final_url)
                    if url_callback: url_callback(final_url)
                
                self.response_headers[url] = dict(response.headers)
                
                self._extract_cookies(response)
                
                if 'text/html' in response.headers.get('Content-Type', ''):
                    soup = BeautifulSoup(response.text, self.html_parser)
                    
                    links = self._extract_links(soup, url)
                    for link in links:
                        if link not in self.visited:
                            queue.append((link, depth + 1))
                    
                    self._extract_forms(soup, url)
                elif self._is_javascript_response(url, response):
                    for js_url in self._extract_js_urls(response.text, base_url=url):
                        if self._is_same_domain(js_url) and js_url not in self.visited:
                            queue.append((js_url, depth + 1))
                    
                if self._is_probable_sitemap(url, response):
                    for sitemap_url in self._parse_sitemap(response.text):
                        if self._is_same_domain(sitemap_url) and sitemap_url not in self.visited:
                            queue.append((sitemap_url, depth + 1))
                
                if self._is_probable_robots(url, response):
                    for robots_url in self._parse_robots(response.text, base_url=url):
                        if self._is_same_domain(robots_url) and robots_url not in self.visited:
                            queue.append((robots_url, depth + 1))
                
                self._extract_url_parameters(url)
                
                self._detect_api_endpoints(url, response)
                
                time.sleep(self.rate_limit)
                
            except Exception as e:
                logger.warning(f"Error crawling {url}: {e}")
                continue
        
        logger.info(f"Crawl complete. Found {len(self.attack_surface.urls)} URLs, "
                   f"{len(self.attack_surface.forms)} forms, "
                   f"{len(self.attack_surface.url_parameters)} parameters")
        
        return self.attack_surface
    
    def _fetch_url(self, url: str) -> Optional[requests.Response]:
        """Fetch URL with error handling."""
        try:
            response = self.session.get(
                url, 
                timeout=self.timeout,
                allow_redirects=True,
                verify=True
            )
            return response
        except requests.RequestException as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            return None
    
    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the target domain."""
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc == ""
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract all internal links from page."""
        links = []
        
        for tag in soup.find_all(['a', 'link', 'area']):
            href = tag.get('href')
            if href:
                full_url = self._normalize_url(href, base_url)
                if full_url and self._is_same_domain(full_url) and not self._is_static_asset(full_url):
                    links.append(full_url)
        
        for tag in soup.find_all(['script', 'img', 'iframe', 'embed', 'source']):
            src = tag.get('src')
            if src:
                full_url = self._normalize_url(src, base_url)
                if full_url and self._is_same_domain(full_url) and not self._is_static_asset(full_url):
                    links.append(full_url)
        
        for tag in soup.find_all('form'):
            action = tag.get('action')
            if action:
                full_url = self._normalize_url(action, base_url)
                if full_url and self._is_same_domain(full_url):
                    links.append(full_url)
        
        return list(set(links))
    
    def _select_html_parser(self) -> str:
        """Select the best available HTML parser for BeautifulSoup."""
        try:
            BeautifulSoup("", "lxml")
            return "lxml"
        except FeatureNotFound:
            return "html.parser"
    
    def _normalize_url(self, url: str, base_url: str) -> Optional[str]:
        """Normalize URL and filter out non-HTTP URLs."""
        if not url:
            return None
        
        url = url.strip()
        
        if url.startswith(('javascript:', 'mailto:', 'tel:', 'data:', '#')):
            return None
        
        full_url = urljoin(base_url, url)
        
        parsed = urlparse(full_url)
        if parsed.scheme not in ('http', 'https'):
            return None
        
        return self._canonicalize_url(full_url)

    def _canonicalize_url(self, url: str) -> Optional[str]:
        """Canonicalize URL by stripping fragments and normalizing default ports."""
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return None
        
        netloc = parsed.netloc
        if parsed.scheme == 'http' and netloc.endswith(':80'):
            netloc = netloc[:-3]
        elif parsed.scheme == 'https' and netloc.endswith(':443'):
            netloc = netloc[:-4]
        
        clean = parsed._replace(netloc=netloc, fragment='')
        return urlunparse(clean)
    
    def _is_static_asset(self, url: str) -> bool:
        """Check if URL looks like a static asset by extension."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        for ext in self.STATIC_EXTENSIONS:
            if path.endswith(ext):
                return True
        return False
    
    def _is_javascript_response(self, url: str, response: requests.Response) -> bool:
        content_type = response.headers.get('Content-Type', '').lower()
        if 'javascript' in content_type:
            return True
        return urlparse(url).path.lower().endswith('.js')
    
    def _extract_forms(self, soup: BeautifulSoup, source_url: str):
        """Extract all forms from page."""
        for form_tag in soup.find_all('form'):
            action = form_tag.get('action', '')
            method = form_tag.get('method', 'GET').upper()
            enctype = form_tag.get('enctype', 'application/x-www-form-urlencoded')
            
            action_url = urljoin(source_url, action) if action else source_url
            
            fields = []
            has_file_upload = False
            file_field_name = ""
            accepted_types = []
            
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                field_name = input_tag.get('name', '')
                field_type = input_tag.get('type', 'text')
                field_value = input_tag.get('value', '')
                required = input_tag.has_attr('required')
                
                if field_name:
                    fields.append(FormField(
                        name=field_name,
                        field_type=field_type,
                        value=field_value,
                        required=required
                    ))
                    
                    if field_type == 'file':
                        has_file_upload = True
                        file_field_name = field_name
                        accept = input_tag.get('accept', '')
                        accepted_types = [t.strip() for t in accept.split(',') if t.strip()]
            
            form = Form(
                action=action_url,
                method=method,
                fields=fields,
                enctype=enctype,
                source_url=source_url
            )
            self.attack_surface.forms.append(form)
            
            if has_file_upload:
                self.attack_surface.file_upload_endpoints.append(
                    FileUploadEndpoint(
                        url=action_url,
                        method=method,
                        field_name=file_field_name,
                        accepted_types=accepted_types
                    )
                )
    
    def _extract_url_parameters(self, url: str):
        """Extract URL query parameters."""
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        
        for name, value in params:
            param = URLParameter(
                name=name,
                value=value,
                source_url=url
            )
            existing = [p for p in self.attack_surface.url_parameters 
                       if p.name == name and p.source_url == url and p.value == value]
            if not existing:
                self.attack_surface.url_parameters.append(param)
    
    def _extract_cookies(self, response: requests.Response):
        """Extract cookies from response."""
        for cookie in self.session.cookies:
            existing = [c for c in self.attack_surface.cookies 
                       if c.name == cookie.name]
            if not existing:
                self.attack_surface.cookies.append(Cookie(
                    name=cookie.name,
                    value=cookie.value,
                    domain=cookie.domain,
                    path=cookie.path,
                    secure=cookie.secure,
                    httponly=cookie.has_nonstandard_attr('HttpOnly'),
                    samesite=cookie.get_nonstandard_attr('SameSite', '')
                ))
    
    def _detect_api_endpoints(self, url: str, response: requests.Response):
        """Detect API endpoints from URL patterns and response type."""
        is_api = False
        
        for pattern in self.API_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                is_api = True
                break
        
        content_type = response.headers.get('Content-Type', '')
        if 'application/json' in content_type or 'application/xml' in content_type:
            is_api = True
        
        if is_api:
            existing = [e for e in self.attack_surface.api_endpoints if e.url == url]
            if not existing:
                self.attack_surface.api_endpoints.append(APIEndpoint(
                    url=url,
                    method="GET",
                    content_type=content_type
                ))
    
    def _check_sensitive_files(self, progress_callback=None, url_callback=None):
        """Check for common sensitive files."""
        discovered = []
        for file_path in self.SENSITIVE_FILES:
            url = f"{self.target_url}/{file_path}"
            
            if progress_callback:
                progress_callback(f"Checking: {file_path}")
            
            try:
                response = self.session.head(url, timeout=self.timeout, allow_redirects=False)
                if response.status_code in (200, 301, 302, 307, 308):
                    self.attack_surface.urls.add(url)
                    if url_callback: url_callback(url)
                    discovered.append(url)
                    logger.info(f"Found sensitive file: {url}")
                elif response.status_code in (403, 405):
                    get_resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                    if get_resp.status_code in (200, 301, 302, 307, 308):
                        self.attack_surface.urls.add(url)
                        if url_callback: url_callback(url)
                        discovered.append(url)
                        logger.info(f"Found sensitive file (GET): {url}")
            except:
                pass
            
            time.sleep(self.rate_limit / 2)
        return discovered
    
    def _is_probable_sitemap(self, url: str, response: requests.Response) -> bool:
        content_type = response.headers.get('Content-Type', '')
        return url.lower().endswith('sitemap.xml') or 'xml' in content_type
    
    def _is_probable_robots(self, url: str, response: requests.Response) -> bool:
        content_type = response.headers.get('Content-Type', '')
        if url.lower().endswith('robots.txt'):
            return True
        if 'text/plain' in content_type and 'user-agent' in response.text.lower():
            return True
        return False
    
    def _parse_sitemap(self, xml_text: str) -> List[str]:
        urls = re.findall(r'<loc>\s*([^<]+)\s*</loc>', xml_text, flags=re.IGNORECASE)
        return [self._canonicalize_url(u) for u in urls if self._canonicalize_url(u)]
    
    def _parse_robots(self, text: str, base_url: str) -> List[str]:
        urls = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.lower().startswith('sitemap:'):
                sitemap_url = line.split(':', 1)[1].strip()
                canon = self._canonicalize_url(sitemap_url)
                if canon:
                    urls.append(canon)
                continue
            if line.lower().startswith(('allow:', 'disallow:')):
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    full = self._normalize_url(path, base_url)
                    if full:
                        urls.append(full)
        return urls
    
    def _extract_js_urls(self, js_text: str, base_url: str) -> List[str]:
        if not js_text:
            return []
        if len(js_text) > 2_000_000:
            return []
        
        candidates = set()
        for match in re.findall(r'https?://[^\s"\'<>]+', js_text):
            canon = self._canonicalize_url(match)
            if canon:
                candidates.add(canon)
        
        for match in re.findall(r'["\'](/[^"\']+)["\']', js_text):
            norm = self._normalize_url(match, base_url)
            if norm:
                candidates.add(norm)
        
        return list(candidates)
    
    def get_response_headers(self) -> Dict[str, Dict[str, str]]:
        """Get collected response headers by URL."""
        return self.response_headers
    
    def create_scan_context(self, scan_level: str = "medium", 
                           allow_intrusive: bool = False) -> ScanContext:
        """Create ScanContext from crawl results."""
        return ScanContext(
            target_url=self.target_url,
            attack_surface=self.attack_surface,
            scan_level=scan_level,
            allow_intrusive=allow_intrusive,
            rate_limit=self.rate_limit,
            timeout=self.timeout,
            user_agent=self.user_agent
        )
