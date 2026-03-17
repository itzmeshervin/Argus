"""
API Misconfiguration Detection Plugin.
Detects common API security issues.
"""

import json
import requests
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class APIMisconfigPlugin(PluginBase):
    """Detects API misconfigurations."""
    
    def __init__(self):
        super().__init__()
        payloads = self.load_wordlist("api_misconfig.txt")
        seen = set()
        deduped = []
        for p in payloads:
            if p and p not in seen:
                seen.add(p)
                deduped.append(p)
        self.set_payloads(deduped)
        self.set_payload_limits(low=10, medium=30, high=80)
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="API Misconfiguration",
            id="api-misconfig",
            severity_hint="medium",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects common API security misconfigurations"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        api_issues = []
        
        for endpoint in context.attack_surface.api_endpoints[:20]:
            issues = self._check_api_endpoint(endpoint, context)
            api_issues.extend(issues)
        
        extra_paths = self.get_payloads_for_level(context.scan_level)
        for path in extra_paths:
            url = f"{context.target_url.rstrip('/')}{path}"
            issues = self._check_url(url, context)
            api_issues.extend(issues)
        
        if api_issues:
            finding = self.create_finding(
                vuln_name="API Security Misconfiguration",
                short_intro=f"Found {len(api_issues)} API security issues. "
                           "APIs may expose sensitive data or lack proper security controls.",
                description=(
                    "The application's API endpoints show signs of security misconfiguration. "
                    "This includes issues like missing authentication, verbose error messages, "
                    "exposed debug endpoints, or improper HTTP method handling. APIs are common "
                    "attack targets and should implement defense in depth."
                ),
                affected_endpoints=[i["url"] for i in api_issues],
                impact=[f"{i['url']}: {i['issue']}" for i in api_issues] + [
                    "Sensitive data exposure through APIs",
                    "Unauthorized access to API functions",
                    "Information disclosure via error messages",
                    "Potential for injection attacks"
                ],
                proof_of_concept=[
                    "1. Send requests to the identified API endpoints",
                    "2. Observe responses for security issues",
                    "3. Check for missing authentication, verbose errors, etc."
                ],
                evidence=[{
                    "request": f"{i.get('method', 'GET')} {i['url']}",
                    "response": i.get("evidence", "Security issue detected"),
                    "description": i["issue"]
                } for i in api_issues[:5]],
                remediation=[
                    "Implement authentication for all API endpoints",
                    "Use proper authorization checks",
                    "Disable verbose error messages in production",
                    "Implement rate limiting",
                    "Validate all input data",
                    "Use HTTPS for all API communication",
                    "Implement proper CORS policies"
                ],
                references=[
                    "https://owasp.org/www-project-api-security/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"
                ],
                confidence="Medium",
                suggested_cvss={
                    "AV": "N",
                    "AC": "L",
                    "PR": "N",
                    "UI": "N",
                    "S": "U",
                    "C": "L",
                    "I": "N",
                    "A": "N"
                }
            )
            finding.target_url = context.target_url
            findings.append(finding)
        
        return findings
    
    def _check_url(self, url: str, context) -> List[dict]:
        """Check a URL for API-like misconfig issues."""
        issues = []
        try:
            response = requests.get(
                url,
                timeout=context.timeout,
                headers={"User-Agent": context.user_agent},
                verify=True
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    if isinstance(data, dict):
                        sensitive_keys = ["password", "secret", "token", "key", "credential", 
                                         "ssn", "credit_card", "private"]
                        for key in data.keys():
                            if any(s in key.lower() for s in sensitive_keys):
                                issues.append({
                                    "url": url,
                                    "issue": f"Sensitive field '{key}' exposed in API response",
                                    "method": "GET",
                                    "evidence": f"Field: {key}"
                                })
                                break
                        
                        if "error" in data or "exception" in data or "traceback" in data:
                            issues.append({
                                "url": url,
                                "issue": "Verbose error information in response",
                                "method": "GET",
                                "evidence": str(data)[:200]
                            })
                            
                except json.JSONDecodeError:
                    pass
            
            options_response = requests.options(
                url,
                timeout=context.timeout,
                verify=True
            )
            
            allow_header = options_response.headers.get("Allow", "")
            if allow_header:
                dangerous_methods = ["PUT", "DELETE", "PATCH"]
                for method in dangerous_methods:
                    if method in allow_header:
                        issues.append({
                            "url": url,
                            "issue": f"Potentially dangerous HTTP method {method} allowed",
                            "method": "OPTIONS",
                            "evidence": f"Allow: {allow_header}"
                        })
                        break
                        
        except Exception as e:
            self.log_debug(f"Error checking API endpoint {url}: {e}")
        
        return issues
    
    def _check_api_endpoint(self, endpoint, context) -> List[dict]:
        """Check an API endpoint for security issues."""
        issues = []
        
        try:
            response = requests.get(
                endpoint.url,
                timeout=context.timeout,
                headers={"User-Agent": context.user_agent},
                verify=True
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    if isinstance(data, dict):
                        sensitive_keys = ["password", "secret", "token", "key", "credential", 
                                         "ssn", "credit_card", "private"]
                        for key in data.keys():
                            if any(s in key.lower() for s in sensitive_keys):
                                issues.append({
                                    "url": endpoint.url,
                                    "issue": f"Sensitive field '{key}' exposed in API response",
                                    "method": "GET",
                                    "evidence": f"Field: {key}"
                                })
                                break
                        
                        if "error" in data or "exception" in data or "traceback" in data:
                            issues.append({
                                "url": endpoint.url,
                                "issue": "Verbose error information in response",
                                "method": "GET",
                                "evidence": str(data)[:200]
                            })
                            
                except json.JSONDecodeError:
                    pass
            
            options_response = requests.options(
                endpoint.url,
                timeout=context.timeout,
                verify=True
            )
            
            allow_header = options_response.headers.get("Allow", "")
            if allow_header:
                dangerous_methods = ["PUT", "DELETE", "PATCH"]
                for method in dangerous_methods:
                    if method in allow_header:
                        issues.append({
                            "url": endpoint.url,
                            "issue": f"Potentially dangerous HTTP method {method} allowed",
                            "method": "OPTIONS",
                            "evidence": f"Allow: {allow_header}"
                        })
                        break
                        
        except Exception as e:
            self.log_debug(f"Error checking API endpoint {endpoint.url}: {e}")
        
        return issues
