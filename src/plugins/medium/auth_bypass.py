"""
Authentication Bypass Indicators Detection Plugin.
Detects potential authentication bypass vulnerabilities.
"""

import requests
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class AuthBypassPlugin(PluginBase):
    """Detects potential authentication bypass indicators."""
    
    def __init__(self):
        super().__init__()
        payloads = list(self.PROTECTED_PATHS)
        payloads += self.load_wordlist("auth_bypass.txt")
        seen = set()
        deduped = []
        for p in payloads:
            if p and p not in seen:
                seen.add(p)
                deduped.append(p)
        self.set_payloads(deduped)
        self.set_payload_limits(low=20, medium=60, high=120)
    
    PROTECTED_PATHS = [
        "/admin", "/admin/", "/administrator", "/dashboard", "/panel",
        "/manage", "/management", "/control", "/config", "/settings",
        "/user/profile", "/account", "/my-account", "/users",
        "/api/admin", "/api/users", "/api/config", "/private",
        "/internal", "/staff", "/moderator", "/console"
    ]
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Authentication Bypass Indicators",
            id="auth-bypass",
            severity_hint="medium",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects potential authentication bypass vulnerabilities"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        bypass_indicators = []
        paths = self.get_payloads_for_level(context.scan_level)
        
        for path in paths:
            try:
                url = f"{context.target_url.rstrip('/')}{path}"
                
                response = requests.get(
                    url,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True,
                    allow_redirects=False
                )
                
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    if any(kw in content for kw in ["login", "sign in", "password", "authenticate"]):
                        continue
                    
                    if any(kw in content for kw in ["dashboard", "admin panel", "settings", 
                                                     "configuration", "users list", "management"]):
                        bypass_indicators.append({
                            "path": path,
                            "url": url,
                            "status": response.status_code,
                            "type": "Direct Access",
                            "snippet": response.text[:300]
                        })
                
                elif response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get("Location", "")
                    
                    follow_response = requests.get(
                        url,
                        timeout=context.timeout,
                        headers={"User-Agent": context.user_agent},
                        verify=True,
                        allow_redirects=True
                    )
                    
                    if follow_response.status_code == 200:
                        if "login" not in follow_response.url.lower():
                            content = follow_response.text.lower()
                            if any(kw in content for kw in ["dashboard", "admin", "settings"]):
                                bypass_indicators.append({
                                    "path": path,
                                    "url": url,
                                    "status": f"{response.status_code} → 200",
                                    "type": "Redirect Bypass",
                                    "snippet": follow_response.text[:300]
                                })
                
            except Exception as e:
                self.log_debug(f"Error checking {path}: {e}")
                continue
        
        discovered_admin_pages = [u for u in context.attack_surface.urls 
                                  if any(p in u.lower() for p in 
                                        ["admin", "dashboard", "panel", "manage", "config"])]
        
        for url in discovered_admin_pages[:10]:
            try:
                response = requests.get(
                    url,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
                
                if response.status_code == 200:
                    content = response.text.lower()
                    if not any(kw in content for kw in ["login", "sign in", "password"]):
                        if any(kw in content for kw in ["edit", "delete", "create", "modify", "save"]):
                            bypass_indicators.append({
                                "path": url.replace(context.target_url, ""),
                                "url": url,
                                "status": 200,
                                "type": "Discovered Admin Page",
                                "snippet": response.text[:300]
                            })
                            
            except Exception as e:
                continue
        
        if bypass_indicators:
            finding = self.create_finding(
                vuln_name="Potential Authentication Bypass",
                short_intro=f"Found {len(bypass_indicators)} protected pages accessible without authentication. "
                           "Administrative functions may be exposed.",
                description=(
                    "Several pages that appear to require authentication are accessible without "
                    "proper credentials. This could indicate missing access controls, broken "
                    "authentication, or misconfigured security settings. Administrative pages "
                    "and sensitive functions should never be accessible to unauthenticated users."
                ),
                affected_endpoints=[b["url"] for b in bypass_indicators],
                impact=[
                    f"{b['path']}: {b['type']} (Status: {b['status']})"
                    for b in bypass_indicators
                ] + [
                    "Unauthorized access to administrative functions",
                    "User data may be exposed or modifiable",
                    "System configuration could be changed",
                    "Complete application compromise possible"
                ],
                proof_of_concept=[
                    "1. Clear all cookies and session data",
                    f"2. Navigate directly to {bypass_indicators[0]['url']}",
                    "3. Observe that the page loads without authentication",
                    "4. Verify administrative content is visible"
                ],
                evidence=[{
                    "request": f"GET {b['url']}",
                    "response": f"Status: {b['status']}\n{b['snippet'][:150]}...",
                    "description": b["type"]
                } for b in bypass_indicators[:5]],
                remediation=[
                    "Implement proper authentication checks on all protected pages",
                    "Use authentication middleware/decorators consistently",
                    "Implement role-based access control (RBAC)",
                    "Verify authentication server-side, not just client-side",
                    "Audit all routes for proper access controls",
                    "Use secure session management"
                ],
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema",
                    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
                ],
                confidence="Medium",
                suggested_cvss={
                    "AV": "N",
                    "AC": "L",
                    "PR": "N",
                    "UI": "N",
                    "S": "U",
                    "C": "L",
                    "I": "L",
                    "A": "N"
                }
            )
            finding.target_url = context.target_url
            findings.append(finding)
        
        return findings
