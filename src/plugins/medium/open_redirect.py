"""
Open Redirect Detection Plugin.
Detects URL redirection vulnerabilities.
"""

import time
import requests
from urllib.parse import urljoin, urlencode, parse_qs, urlparse, urlunparse
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class OpenRedirectPlugin(PluginBase):
    """Detects open redirect vulnerabilities."""
    
    def __init__(self):
        super().__init__()
        payloads = list(self.REDIRECT_PARAMS)
        payloads += self.load_wordlist("open_redirect.txt")
        seen = set()
        deduped = []
        for p in payloads:
            if p and p not in seen:
                seen.add(p)
                deduped.append(p)
        self.set_payloads(deduped)
        self.set_payload_limits(low=10, medium=30, high=80)
    
    REDIRECT_PARAMS = [
        "url", "redirect", "redirect_url", "redirect_uri", "return",
        "return_url", "returnTo", "next", "goto", "destination", "dest",
        "target", "rurl", "continue", "forward", "location", "out", "view",
        "ref", "site", "callback", "path", "link"
    ]
    
    TEST_URL = "https://evil.example.com"
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Open Redirect",
            id="open-redirect",
            severity_hint="medium",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects open redirect vulnerabilities"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        vulnerable_params = []
        params_to_test = self.get_payloads_for_level(context.scan_level)
        
        for param in context.attack_surface.url_parameters:
            if param.name.lower() in [p.lower() for p in params_to_test]:
                try:
                    parsed = urlparse(param.source_url)
                    params = parse_qs(parsed.query)
                    params[param.name] = [self.TEST_URL]
                    
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(params, doseq=True), parsed.fragment
                    ))
                    
                    response = requests.get(
                        test_url,
                        timeout=context.timeout,
                        headers={"User-Agent": context.user_agent},
                        verify=True,
                        allow_redirects=False
                    )
                    
                    location = response.headers.get("Location", "")
                    
                    if response.status_code in (301, 302, 303, 307, 308):
                        if location.startswith("http") and (self.TEST_URL in location or "evil.example.com" in location):
                            vulnerable_params.append({
                                "param": param.name,
                                "source_url": param.source_url,
                                "test_url": test_url,
                                "redirect_location": location,
                                "status_code": response.status_code
                            })
                    
                    time.sleep(context.rate_limit)
                    
                except Exception as e:
                    self.log_debug(f"Error testing {param.name}: {e}")
                    continue
        
        for url in list(context.attack_surface.urls)[:30]:
            parsed = urlparse(url)
            existing_params = parse_qs(parsed.query)
            
            for redirect_param in params_to_test:
                if redirect_param.lower() in [p.lower() for p in existing_params.keys()]:
                    continue
                
                try:
                    params = dict(existing_params)
                    params[redirect_param] = [self.TEST_URL]
                    
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(params, doseq=True), parsed.fragment
                    ))
                    
                    response = requests.get(
                        test_url,
                        timeout=context.timeout,
                        headers={"User-Agent": context.user_agent},
                        verify=True,
                        allow_redirects=False
                    )
                    
                    location = response.headers.get("Location", "")
                    
                    if response.status_code in (301, 302, 303, 307, 308):
                        if location.startswith("http") and (self.TEST_URL in location or "evil.example.com" in location):
                            vulnerable_params.append({
                                "param": redirect_param,
                                "source_url": url,
                                "test_url": test_url,
                                "redirect_location": location,
                                "status_code": response.status_code
                            })
                    
                    time.sleep(context.rate_limit)
                    
                except Exception as e:
                    continue
        
        if vulnerable_params:
            finding = self.create_finding(
                vuln_name="Open Redirect Vulnerability",
                short_intro=f"Found {len(vulnerable_params)} URL parameters that redirect to external domains. "
                           "This can be exploited for phishing attacks.",
                description=(
                    "The application redirects users to URLs specified in request parameters "
                    "without validating that the destination is a trusted domain. Attackers can "
                    "craft malicious links that appear to come from the trusted site but redirect "
                    "victims to phishing pages, malware downloads, or other malicious content."
                ),
                affected_endpoints=[p["source_url"] for p in vulnerable_params],
                impact=[
                    f"Parameter '{p['param']}' redirects to: {p['redirect_location'][:50]}"
                    for p in vulnerable_params
                ] + [
                    "Attackers can craft convincing phishing links",
                    "Malware could be distributed via trusted domain",
                    "OAuth tokens could be stolen via redirect manipulation",
                    "Brand reputation damage from association with malicious content"
                ],
                proof_of_concept=[
                    f"1. Access: {vulnerable_params[0]['test_url'][:100]}",
                    f"2. Observe redirect to external domain (Status: {vulnerable_params[0]['status_code']})",
                    f"3. Location header contains: {vulnerable_params[0]['redirect_location'][:50]}",
                    "4. User would be redirected to attacker-controlled site"
                ],
                evidence=[{
                    "request": f"GET {p['test_url'][:100]}",
                    "response": f"HTTP {p['status_code']}\nLocation: {p['redirect_location']}",
                    "description": f"Parameter: {p['param']}"
                } for p in vulnerable_params[:5]],
                remediation=[
                    "Implement a whitelist of allowed redirect destinations",
                    "Use relative paths instead of full URLs for internal redirects",
                    "Validate that redirect URLs belong to trusted domains",
                    "Add warning pages before external redirects",
                    "Use indirect reference maps (e.g., redirect?id=1 maps to specific URL)",
                    "Never use user input directly in redirect headers"
                ],
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
                ],
                confidence="High",
                suggested_cvss={
                    "AV": "N",
                    "AC": "L",
                    "PR": "N",
                    "UI": "R",
                    "S": "C",
                    "C": "L",
                    "I": "L",
                    "A": "N"
                }
            )
            finding.target_url = context.target_url
            findings.append(finding)
        
        return findings
