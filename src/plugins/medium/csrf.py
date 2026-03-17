"""
CSRF Token Absence Detection Plugin.
Detects missing CSRF protections.
"""

import re
import requests
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class CSRFPlugin(PluginBase):
    """Detects missing CSRF token protection."""
    
    CSRF_TOKEN_PATTERNS = [
        r'csrf',
        r'xsrf',
        r'_token',
        r'authenticity_token',
        r'__RequestVerificationToken',
        r'csrfmiddlewaretoken',
        r'_csrf_token',
        r'anti-csrf',
        r'anticsrf',
    ]
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="CSRF Token Absence",
            id="csrf-absence",
            severity_hint="medium",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects missing CSRF token protection"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        vulnerable_forms = []
        
        for form in context.attack_surface.forms:
            if form.method.upper() != "POST":
                continue
            
            has_csrf_token = False
            
            for field in form.fields:
                field_name = field.name.lower()
                for pattern in self.CSRF_TOKEN_PATTERNS:
                    if re.search(pattern, field_name, re.IGNORECASE):
                        has_csrf_token = True
                        break
                if has_csrf_token:
                    break
            
            if not has_csrf_token:
                try:
                    response = requests.get(
                        form.source_url,
                        timeout=context.timeout,
                        headers={"User-Agent": context.user_agent},
                        verify=True
                    )
                    
                    has_meta_csrf = False
                    for pattern in self.CSRF_TOKEN_PATTERNS:
                        if re.search(rf'<meta[^>]*{pattern}[^>]*>', response.text, re.IGNORECASE):
                            has_meta_csrf = True
                            break
                    
                    if not has_meta_csrf:
                        is_state_changing = any(
                            f.field_type in ["password", "email", "file"] or
                            f.name.lower() in ["password", "email", "amount", "quantity", "delete", "update"]
                            for f in form.fields
                        )
                        
                        vulnerable_forms.append({
                            "action": form.action,
                            "source": form.source_url,
                            "method": form.method,
                            "fields": [f.name for f in form.fields],
                            "state_changing": is_state_changing
                        })
                        
                except Exception as e:
                    self.log_debug(f"Error checking form at {form.source_url}: {e}")
        
        if vulnerable_forms:
            state_changing = [f for f in vulnerable_forms if f["state_changing"]]
            
            finding = self.create_finding(
                vuln_name="Missing CSRF Protection",
                short_intro=f"Found {len(vulnerable_forms)} POST forms without CSRF tokens. "
                           f"{len(state_changing)} appear to perform state-changing actions.",
                description=(
                    "The application has forms that submit data via POST but lack CSRF "
                    "(Cross-Site Request Forgery) token protection. This allows attackers "
                    "to craft malicious pages that submit requests on behalf of authenticated "
                    "users, potentially leading to unauthorized actions like password changes, "
                    "fund transfers, or data modifications."
                ),
                affected_endpoints=[f["action"] for f in vulnerable_forms],
                impact=[
                    f"Form at {f['source']} → {f['action']} (Fields: {', '.join(f['fields'][:3])})"
                    + (" [STATE-CHANGING]" if f["state_changing"] else "")
                    for f in vulnerable_forms[:10]
                ] + [
                    "Attackers could perform actions as authenticated users",
                    "Password/email changes could be forced",
                    "Financial transactions could be initiated",
                    "Data could be created/modified/deleted without consent"
                ],
                proof_of_concept=[
                    "1. Examine the form source code",
                    "2. Note the absence of CSRF token fields",
                    "3. A malicious page could submit this form with attacker-controlled data",
                    "4. Victim's browser would include session cookies automatically",
                    "5. Server would process the forged request as legitimate"
                ],
                evidence=[{
                    "request": f"Form: {f['action']}\nMethod: {f['method']}\nFields: {', '.join(f['fields'])}",
                    "response": "No CSRF token found in form or page meta tags",
                    "description": f"Form from {f['source']}"
                } for f in vulnerable_forms[:5]],
                remediation=[
                    "Implement CSRF tokens for all state-changing forms",
                    "Use framework-provided CSRF protection (Django, Rails, etc.)",
                    "Validate CSRF tokens server-side on every POST request",
                    "Consider using SameSite cookie attribute",
                    "Implement double-submit cookie pattern if needed",
                    "Add custom request headers for AJAX requests"
                ],
                references=[
                    "https://owasp.org/www-community/attacks/csrf",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
                ],
                confidence="High" if state_changing else "Medium",
                suggested_cvss={
                    "AV": "N",
                    "AC": "L",
                    "PR": "N",
                    "UI": "R",
                    "S": "U",
                    "C": "N",
                    "I": "L" if not state_changing else "H",
                    "A": "N"
                }
            )
            finding.target_url = context.target_url
            findings.append(finding)
        
        return findings
