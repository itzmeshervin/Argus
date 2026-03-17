"""
SSRF (Server-Side Request Forgery) Detection Plugin.
Uses safe indicator-based detection.
"""

import time
import requests
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class SSRFPlugin(PluginBase):
    """Detects SSRF indicators using safe detection methods."""
    
    def __init__(self):
        super().__init__()
        params = list(self.URL_PARAMS)
        seen = set()
        self._ssrf_params = []
        for p in params:
            if p and p not in seen:
                seen.add(p)
                self._ssrf_params.append(p)
        
        targets = self.load_wordlist("ssrf.txt")
        if not targets:
            targets = [f"http://{h}/" for h in self.INTERNAL_HOSTS]
        seen = set()
        deduped = []
        for t in targets:
            if t and t not in seen:
                seen.add(t)
                deduped.append(t)
        self.set_payloads(deduped)
        self.set_payload_limits(low=5, medium=20, high=50)
    
    URL_PARAMS = [
        "url", "uri", "path", "dest", "destination", "redirect", "return",
        "next", "target", "rurl", "link", "src", "source", "request",
        "fetch", "load", "file", "document", "page", "callback", "api",
        "proxy", "forward", "host", "endpoint"
    ]
    
    INTERNAL_HOSTS = [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "169.254.169.254",
        "metadata.google.internal",
        "[::1]",
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1"
    ]
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Server-Side Request Forgery (SSRF)",
            id="ssrf",
            severity_hint="high",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects SSRF indicators"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        ssrf_indicators = []
        targets = self.get_payloads_for_level(context.scan_level)
        
        for param in context.attack_surface.url_parameters:
            if param.name.lower() in [p.lower() for p in self._ssrf_params]:
                result = self._test_ssrf_param(param, context, targets)
                if result:
                    ssrf_indicators.append(result)
        
        for url in list(context.attack_surface.urls)[:20]:
            parsed = urlparse(url)
            existing_params = list(parse_qs(parsed.query).keys())
            
            for url_param in self._ssrf_params[:5]:
                if url_param.lower() not in [p.lower() for p in existing_params]:
                    result = self._test_new_param(url, url_param, context, targets)
                    if result:
                        ssrf_indicators.append(result)
        
        if ssrf_indicators:
            finding = self.create_finding(
                vuln_name="Server-Side Request Forgery (SSRF)",
                short_intro=f"Found {len(ssrf_indicators)} potential SSRF vulnerabilities. "
                           "Attackers could access internal services or perform port scanning.",
                description=(
                    "The application appears to make server-side requests based on user input "
                    "without proper validation. This could allow attackers to access internal "
                    "services, read cloud metadata (leading to credential theft), perform port "
                    "scanning, or bypass firewalls. SSRF is particularly dangerous in cloud "
                    "environments where metadata services are accessible."
                ),
                affected_endpoints=[i["url"] for i in ssrf_indicators],
                impact=[
                    f"Parameter '{i['param']}': {i['indicator']}"
                    for i in ssrf_indicators
                ] + [
                    "Access to internal services and APIs",
                    "Cloud metadata endpoint access (credential theft)",
                    "Internal network port scanning",
                    "Firewall bypass for internal attacks",
                    "Potential for further exploitation"
                ],
                proof_of_concept=[
                    f"1. Access endpoint with URL parameter",
                    f"2. Set parameter to internal address (e.g., http://127.0.0.1/)",
                    "3. Observe server behavior indicating request was made",
                    "4. NOTE: Only safe detection payloads used"
                ],
                evidence=[{
                    "request": f"GET {i['test_url'][:100]}",
                    "response": i.get("response_snippet", "SSRF indicator detected")[:200],
                    "description": i["indicator"]
                } for i in ssrf_indicators[:5]],
                remediation=[
                    "Validate and sanitize all URL inputs",
                    "Use allowlists for permitted domains/IPs",
                    "Block requests to internal IP ranges (10.x, 172.16-31.x, 192.168.x)",
                    "Block requests to localhost and cloud metadata endpoints",
                    "Disable HTTP redirects or validate redirect destinations",
                    "Implement network segmentation",
                    "Use a proxy for outbound requests with strict filtering"
                ],
                references=[
                    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                    "https://portswigger.net/web-security/ssrf"
                ],
                confidence="Medium",
                suggested_cvss={
                    "AV": "N",
                    "AC": "L",
                    "PR": "N",
                    "UI": "N",
                    "S": "C",
                    "C": "H",
                    "I": "L",
                    "A": "L"
                }
            )
            finding.target_url = context.target_url
            findings.append(finding)
        
        return findings
    
    def _test_ssrf_param(self, param, context, targets: List[str]) -> dict:
        """Test a URL-like parameter for SSRF indicators."""
        parsed = urlparse(param.source_url)
        
        try:
            params = parse_qs(parsed.query)
            indicators = [
                "connection refused",
                "couldn't connect",
                "failed to connect",
                "connection timed out",
                "no route to host",
                "network unreachable",
                "name or service not known",
                "invalid url",
                "connection reset",
                "econnrefused",
                "timeout",
            ]
            
            for target in targets:
                params[param.name] = [target]
                
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(params, doseq=True), parsed.fragment
                ))
                
                response = requests.get(
                    test_url,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
                
                response_lower = response.text.lower()
                
                for indicator in indicators:
                    if indicator.lower() in response_lower:
                        return {
                            "url": param.source_url,
                            "param": param.name,
                            "test_url": test_url,
                            "indicator": f"Server attempted to connect to internal address (error: {indicator})",
                            "response_snippet": response.text[:300]
                        }
                
                if any(k in response_lower for k in ["ami-id", "instance-id", "computeMetadata", "metadata"]):
                    return {
                        "url": param.source_url,
                        "param": param.name,
                        "test_url": test_url,
                        "indicator": "Potential metadata service response",
                        "response_snippet": response.text[:300]
                    }
                
                time.sleep(context.rate_limit)
            
        except Exception as e:
            self.log_debug(f"Error testing SSRF param {param.name}: {e}")
        
        return None
    
    def _test_new_param(self, url: str, param_name: str, context, targets: List[str]) -> dict:
        """Test adding a URL parameter that might trigger SSRF."""
        parsed = urlparse(url)
        
        try:
            params = parse_qs(parsed.query)
            for target in targets[:5]:
                params[param_name] = [target]
                
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(params, doseq=True), parsed.fragment
                ))
                
                response = requests.get(
                    test_url,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
                
                if any(k in response.text.lower() for k in ["ami-id", "instance-id", "computeMetadata", "metadata"]):
                    return {
                        "url": url,
                        "param": param_name,
                        "test_url": test_url,
                        "indicator": "Metadata endpoint accessible",
                        "response_snippet": response.text[:300]
                    }
                
                time.sleep(context.rate_limit)
            
        except Exception as e:
            pass
        
        return None
