"""
Reflected XSS Detection Plugin.
Uses safe token reflection checks.
"""

import re
import time
import uuid
import requests
from urllib.parse import urljoin, urlencode, parse_qs, urlparse
from typing import List, Dict

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class ReflectedXSSPlugin(PluginBase):
    """Detects reflected XSS using safe token reflection."""
    
    def __init__(self):
        super().__init__()
        payloads = []
        payloads += self.load_wordlist("xss.txt")
        if not payloads:
            payloads = []
        # Dedupe while preserving order
        seen = set()
        deduped = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                deduped.append(p)
        self.set_payloads(deduped)
        self.set_payload_limits(low=20, medium=100, high=300)
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Reflected XSS",
            id="reflected-xss",
            severity_hint="medium",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects reflected XSS using safe token reflection"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        vulnerable_params = []
        
        test_token = f"XSS{uuid.uuid4().hex[:8]}TEST"
        payloads = self.get_payloads_for_level(context.scan_level)
        
        for param in context.attack_surface.url_parameters[:20]:
            try:
                parsed = urlparse(param.source_url)
                params = parse_qs(parsed.query)
                payload = test_token
                if payloads:
                    payload = payloads[0]
                
                params[param.name] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                
                response = requests.get(
                    test_url,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
                
                if payload in response.text:
                    context_info = self._analyze_reflection_context(response.text, payload)
                    vulnerable_params.append({
                        "param": param.name,
                        "url": param.source_url,
                        "test_url": test_url,
                        "context": context_info
                    })
                
                time.sleep(context.rate_limit)
                
            except Exception as e:
                self.log_debug(f"Error testing param {param.name}: {e}")
                continue
        
        for form in context.attack_surface.forms[:15]:
            if form.method.upper() != "GET":
                continue
                
            for field in form.fields:
                if field.field_type in ["hidden", "submit", "button"]:
                    continue
                    
                try:
                    test_token = f"XSS{uuid.uuid4().hex[:8]}TEST"
                    payload = test_token
                    if payloads:
                        payload = payloads[0]
                    
                    params = {f.name: f.value or "test" for f in form.fields}
                    params[field.name] = payload
                    
                    test_url = f"{form.action}?{urlencode(params)}"
                    
                    response = requests.get(
                        test_url,
                        timeout=context.timeout,
                        headers={"User-Agent": context.user_agent},
                        verify=True
                    )
                    
                    if payload in response.text:
                        context_info = self._analyze_reflection_context(response.text, payload)
                        vulnerable_params.append({
                            "param": field.name,
                            "url": form.action,
                            "test_url": test_url,
                            "context": context_info,
                            "form": True
                        })
                    
                    time.sleep(context.rate_limit)
                    
                except Exception as e:
                    self.log_debug(f"Error testing form field {field.name}: {e}")
                    continue
        
        if vulnerable_params:
            finding = self.create_finding(
                vuln_name="Reflected Cross-Site Scripting (XSS)",
                short_intro=f"Found {len(vulnerable_params)} parameters that reflect input in responses. "
                           "This could allow XSS attacks if output is not properly encoded.",
                description=(
                    "The application reflects user input in responses without proper encoding. "
                    "While this test used a safe token, real attackers could inject malicious "
                    "JavaScript code that executes in victims' browsers. XSS can lead to session "
                    "hijacking, credential theft, and malicious actions performed as the user."
                ),
                affected_endpoints=[p["url"] for p in vulnerable_params],
                impact=[
                    f"Parameter '{p['param']}' reflects in {p['context']} context"
                    for p in vulnerable_params
                ] + [
                    "Attackers could steal session cookies",
                    "Malicious JavaScript could be executed in user browsers",
                    "Users could be redirected to phishing sites",
                    "Keyloggers or credential stealers could be injected"
                ],
                proof_of_concept=[
                    f"1. Navigate to {vulnerable_params[0]['test_url']}",
                    f"2. Observe that the token appears in the response",
                    "3. The reflection context determines exploitability",
                    "4. NOTE: This test used safe tokens, not actual XSS payloads"
                ],
                evidence=[{
                    "request": f"GET {p['test_url']}",
                    "response": f"Token reflected in {p['context']} context",
                    "description": f"Parameter: {p['param']}"
                } for p in vulnerable_params[:5]],
                remediation=[
                    "Implement context-aware output encoding",
                    "Use HTML entity encoding for HTML context",
                    "Use JavaScript encoding for JS context",
                    "Use URL encoding for URL context",
                    "Implement Content-Security-Policy header",
                    "Consider using auto-escaping template engines"
                ],
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                ],
                confidence="Medium",
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
    
    def _analyze_reflection_context(self, html: str, token: str) -> str:
        """Analyze the context where the token is reflected."""
        idx = html.find(token)
        if idx == -1:
            return "unknown"
        
        before = html[max(0, idx-100):idx]
        after = html[idx:idx+100]
        
        if re.search(r'<script[^>]*>', before, re.IGNORECASE):
            return "JavaScript"
        elif re.search(r'on\w+\s*=\s*["\']?$', before, re.IGNORECASE):
            return "Event Handler"
        elif re.search(r'<[^>]+\s+\w+\s*=\s*["\']?$', before):
            return "HTML Attribute"
        elif re.search(r'<style[^>]*>', before, re.IGNORECASE):
            return "CSS"
        elif re.search(r'href\s*=\s*["\']?$', before, re.IGNORECASE):
            return "URL/href"
        else:
            return "HTML Body"
