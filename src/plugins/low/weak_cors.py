"""
Weak CORS Configuration Detection Plugin.
Detects permissive CORS configurations.
"""

import requests
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class WeakCORSPlugin(PluginBase):
    """Detects weak CORS configurations."""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Weak CORS Configuration",
            id="weak-cors",
            severity_hint="low",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects permissive CORS configurations"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        cors_issues = []
        
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null"
        ]
        
        urls_to_check = [context.target_url]
        
        for endpoint in context.attack_surface.api_endpoints[:5]:
            urls_to_check.append(endpoint.url)
        
        for url in urls_to_check[:10]:
            for origin in test_origins:
                try:
                    response = requests.get(
                        url,
                        timeout=context.timeout,
                        headers={
                            "User-Agent": context.user_agent,
                            "Origin": origin
                        },
                        verify=True
                    )
                    
                    acao = response.headers.get("Access-Control-Allow-Origin", "")
                    acac = response.headers.get("Access-Control-Allow-Credentials", "")
                    vary = response.headers.get("Vary", "")
                    
                    if acao == "*":
                        cors_issues.append({
                            "url": url,
                            "issue": "Wildcard origin allowed",
                            "acao": acao,
                            "acac": acac,
                            "origin_tested": origin,
                            "vary": vary
                        })
                    elif acao == origin:
                        if origin == "null":
                            cors_issues.append({
                                "url": url,
                                "issue": "Null origin reflected",
                                "acao": acao,
                                "acac": acac,
                                "origin_tested": origin,
                                "vary": vary
                            })
                        else:
                            cors_issues.append({
                                "url": url,
                                "issue": "Arbitrary origin reflected",
                                "acao": acao,
                                "acac": acac,
                                "origin_tested": origin,
                                "vary": vary
                            })
                    
                    if acao and acac.lower() == "true":
                        if acao == "*" or acao == origin:
                            cors_issues.append({
                                "url": url,
                                "issue": "Credentials allowed with permissive origin",
                                "acao": acao,
                                "acac": acac,
                                "origin_tested": origin,
                                "vary": vary
                            })
                            
                except Exception as e:
                    self.log_debug(f"Error checking CORS for {url}: {e}")
                    continue
        
        unique_issues = []
        seen = set()
        for issue in cors_issues:
            key = f"{issue['url']}:{issue['issue']}"
            if key not in seen:
                seen.add(key)
                unique_issues.append(issue)
        
        if unique_issues:
            finding = self.create_finding(
                vuln_name="Weak CORS Configuration",
                short_intro=f"Found {len(unique_issues)} CORS misconfigurations. "
                           "Attackers could steal data via cross-origin requests.",
                description=(
                    "The application has permissive Cross-Origin Resource Sharing (CORS) "
                    "configuration that could allow malicious websites to read responses "
                    "from the application. This is especially dangerous when combined with "
                    "Access-Control-Allow-Credentials: true, as it allows attackers to "
                    "steal authenticated user data."
                ),
                affected_endpoints=[i["url"] for i in unique_issues],
                impact=[
                    f"{i['url']}: {i['issue']} (ACAO: {i['acao']}, ACAC: {i['acac']})"
                    for i in unique_issues
                ] + [
                    "Attackers can read sensitive data via cross-origin requests",
                    "Authenticated user sessions could be hijacked",
                    "API data could be stolen by malicious websites"
                ],
                proof_of_concept=[
                    "1. Create a malicious HTML page with JavaScript",
                    "2. Use fetch() or XMLHttpRequest to request target URL",
                    "3. Set Origin header to attacker-controlled domain",
                    "4. Observe that response data is accessible cross-origin",
                    f"5. Tested origins: {', '.join(test_origins)}"
                ],
                evidence=[{
                    "request": f"GET {i['url']}\nOrigin: {i['origin_tested']}",
                    "response": f"Access-Control-Allow-Origin: {i['acao']}\n"
                               f"Access-Control-Allow-Credentials: {i['acac']}\n"
                               f"Vary: {i.get('vary', '')}",
                    "description": i["issue"]
                } for i in unique_issues[:5]],
                remediation=[
                    "Implement a strict whitelist of allowed origins",
                    "Never use Access-Control-Allow-Origin: *",
                    "Never reflect arbitrary Origin headers",
                    "Be careful with Access-Control-Allow-Credentials: true",
                    "Validate Origin header against whitelist on server side",
                    "Consider using same-site cookies for additional protection"
                ],
                references=[
                    "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                    "https://portswigger.net/web-security/cors"
                ],
                confidence="High",
                suggested_cvss={
                    "AV": "N",
                    "AC": "L",
                    "PR": "N",
                    "UI": "R",
                    "S": "U",
                    "C": "L",
                    "I": "N",
                    "A": "N"
                }
            )
            finding.target_url = context.target_url
            findings.append(finding)
        
        return findings
