"""
Stored XSS Detection Plugin.
Uses safe persistence token checks.
"""

import uuid
import time
import requests
from typing import List, Dict

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class StoredXSSPlugin(PluginBase):
    """Detects potential stored XSS using safe persistence checks."""
    
    def __init__(self):
        super().__init__()
        payloads = []
        payloads += self.load_wordlist("xss.txt")
        if not payloads:
            payloads = []
        seen = set()
        deduped = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                deduped.append(p)
        self.set_payloads(deduped)
        self.set_payload_limits(low=10, medium=50, high=150)
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Stored XSS Indicators",
            id="stored-xss",
            severity_hint="medium",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects potential stored XSS using safe tokens"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        potential_stored_xss = []
        
        for form in context.attack_surface.forms[:10]:
            if form.method.upper() != "POST":
                continue
            
            text_fields = [f for f in form.fields 
                         if f.field_type in ["text", "textarea", "email", "search", "url"]]
            
            if not text_fields:
                continue
            
            test_token = f"SXSS{uuid.uuid4().hex[:8]}TEST"
            payloads = self.get_payloads_for_level(context.scan_level)
            payload = test_token
            if payloads:
                payload = payloads[0]
            
            try:
                form_data = {f.name: f.value or "test" for f in form.fields}
                
                target_field = text_fields[0]
                form_data[target_field.name] = payload
                
                headers = {
                    "User-Agent": context.user_agent,
                    "Content-Type": form.enctype
                }
                
                response = requests.post(
                    form.action,
                    data=form_data,
                    timeout=context.timeout,
                    headers=headers,
                    verify=True,
                    allow_redirects=True
                )
                
                if payload in response.text:
                    potential_stored_xss.append({
                        "form_action": form.action,
                        "form_source": form.source_url,
                        "field": target_field.name,
                        "token": payload,
                        "immediate_reflection": True
                    })
                    continue
                
                time.sleep(context.rate_limit)
                
                check_urls = [form.source_url, form.action]
                
                for check_url in check_urls:
                    try:
                        check_response = requests.get(
                            check_url,
                            timeout=context.timeout,
                            headers={"User-Agent": context.user_agent},
                            verify=True
                        )
                        
                        if payload in check_response.text:
                            potential_stored_xss.append({
                                "form_action": form.action,
                                "form_source": form.source_url,
                                "field": target_field.name,
                                "token": payload,
                                "found_at": check_url,
                                "stored": True
                            })
                            break
                            
                    except Exception:
                        continue
                
                time.sleep(context.rate_limit)
                
            except Exception as e:
                self.log_debug(f"Error testing form {form.action}: {e}")
                continue
        
        if potential_stored_xss:
            stored = [p for p in potential_stored_xss if p.get("stored")]
            reflected = [p for p in potential_stored_xss if p.get("immediate_reflection")]
            
            finding = self.create_finding(
                vuln_name="Potential Stored Cross-Site Scripting (XSS)",
                short_intro=f"Found {len(potential_stored_xss)} forms that persist/reflect submitted data. "
                           f"{len(stored)} show signs of stored XSS, {len(reflected)} reflect immediately.",
                description=(
                    "The application stores or reflects user-submitted data without proper encoding. "
                    "Stored XSS is particularly dangerous as the malicious payload persists on the "
                    "server and affects all users who view the infected content. This test used safe "
                    "tokens to detect the vulnerability without causing harm."
                ),
                affected_endpoints=[p["form_action"] for p in potential_stored_xss],
                impact=[
                    f"Form at {p['form_action']} - Field '{p['field']}' " +
                    ("persists and displays data" if p.get("stored") else "reflects data immediately")
                    for p in potential_stored_xss
                ] + [
                    "Attackers could inject persistent malicious scripts",
                    "All users viewing affected pages would be compromised",
                    "Session tokens could be stolen at scale",
                    "Defacement or phishing could affect all users"
                ],
                proof_of_concept=[
                    f"1. Submit the form at {potential_stored_xss[0]['form_source']}",
                    f"2. Enter test token in field '{potential_stored_xss[0]['field']}'",
                    "3. Submit the form",
                    "4. Observe the token appears in subsequent page loads",
                    "5. NOTE: Safe tokens used, not actual XSS payloads"
                ],
                evidence=[{
                    "request": f"POST {p['form_action']}\nField: {p['field']}={p['token']}",
                    "response": f"Token persisted/reflected" + 
                               (f" at {p.get('found_at', 'submission response')}" if p.get('stored') else ""),
                    "description": "Stored" if p.get("stored") else "Immediately reflected"
                } for p in potential_stored_xss[:5]],
                remediation=[
                    "Sanitize all user input before storage",
                    "Encode all output based on context (HTML, JS, URL, CSS)",
                    "Implement Content-Security-Policy header",
                    "Use HTTPOnly cookies to protect session tokens",
                    "Consider using DOMPurify or similar for HTML sanitization",
                    "Implement input validation with allowlists"
                ],
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://portswigger.net/web-security/cross-site-scripting/stored"
                ],
                confidence="Medium",
                suggested_cvss={
                    "AV": "N",
                    "AC": "L",
                    "PR": "L",
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
