"""
Remote Code Execution (RCE) Indicators Detection Plugin.
Non-destructive detection of RCE vulnerabilities.
"""

import re
import requests
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class RCEIndicatorsPlugin(PluginBase):
    """Detects RCE indicators through non-destructive means."""
    
    DANGEROUS_FUNCTIONS = {
        "PHP": [
            r"eval\s*\(",
            r"assert\s*\(",
            r"preg_replace\s*\([^,]*['\"]/.*/e",
            r"create_function\s*\(",
            r"call_user_func\s*\(",
            r"system\s*\(",
            r"exec\s*\(",
            r"shell_exec\s*\(",
            r"passthru\s*\(",
            r"popen\s*\(",
            r"proc_open\s*\(",
            r"\$\{.*\}",
        ],
        "JavaScript/Node": [
            r"eval\s*\(",
            r"Function\s*\(",
            r"setTimeout\s*\(['\"]",
            r"setInterval\s*\(['\"]",
            r"child_process",
        ],
        "Python": [
            r"eval\s*\(",
            r"exec\s*\(",
            r"os\.system\s*\(",
            r"subprocess\.",
            r"__import__\s*\(",
        ]
    }
    
    TEMPLATE_INJECTION_PATTERNS = [
        r"\{\{.*\}\}",
        r"\$\{.*\}",
        r"<%.*%>",
        r"\[\[.*\]\]",
    ]
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="RCE Indicators",
            id="rce-indicators",
            severity_hint="high",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects RCE indicators non-destructively"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        rce_indicators = []
        
        for url in list(context.attack_surface.urls)[:30]:
            try:
                response = requests.get(
                    url,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
                
                for lang, patterns in self.DANGEROUS_FUNCTIONS.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, response.text)
                        if matches:
                            if "application" in response.headers.get("Content-Type", "").lower():
                                rce_indicators.append({
                                    "url": url,
                                    "type": f"{lang} dangerous function",
                                    "pattern": pattern,
                                    "match": matches[0][:50] if matches else ""
                                })
                                break
                
                for pattern in self.TEMPLATE_INJECTION_PATTERNS:
                    if re.search(pattern, response.text):
                        test_payloads = ["{{7*7}}", "${7*7}", "<%=7*7%>"]
                        for payload in test_payloads[:1]:
                            if payload in response.text:
                                continue
                            
                            for param in context.attack_surface.url_parameters:
                                if param.source_url == url:
                                    test_result = self._test_template_injection(
                                        url, param.name, payload, context
                                    )
                                    if test_result:
                                        rce_indicators.append(test_result)
                                        break
                                        
            except Exception as e:
                self.log_debug(f"Error checking {url}: {e}")
        
        if rce_indicators:
            finding = self.create_finding(
                vuln_name="Remote Code Execution Indicators",
                short_intro=f"Found {len(rce_indicators)} potential RCE vectors. "
                           "Critical - could allow complete server takeover.",
                description=(
                    "The application shows indicators of potential Remote Code Execution "
                    "vulnerabilities. This includes template injection, dangerous function "
                    "calls visible in responses, or code evaluation endpoints. RCE allows "
                    "attackers to execute arbitrary code on the server, leading to complete "
                    "system compromise."
                ),
                affected_endpoints=[i["url"] for i in rce_indicators],
                impact=[
                    f"{i['type']} at {i['url'][:50]}"
                    for i in rce_indicators
                ] + [
                    "Complete server takeover",
                    "Data exfiltration",
                    "Backdoor installation",
                    "Cryptocurrency mining",
                    "Pivot to internal network"
                ],
                proof_of_concept=[
                    "1. Identified dangerous patterns in responses",
                    "2. Code execution functions or template syntax detected",
                    "3. Further manual testing recommended",
                    "4. NOTE: Only non-destructive detection performed"
                ],
                evidence=[{
                    "request": f"GET {i['url'][:80]}",
                    "response": f"Type: {i['type']}\nMatch: {i.get('match', 'Pattern detected')[:100]}",
                    "description": "RCE indicator detected"
                } for i in rce_indicators[:5]],
                remediation=[
                    "Never use eval() or similar functions with user input",
                    "Implement strict input validation",
                    "Use sandboxed template engines",
                    "Apply principle of least privilege",
                    "Use WAF to detect code injection attempts",
                    "Keep all frameworks and libraries updated",
                    "Implement code review processes"
                ],
                references=[
                    "https://owasp.org/www-community/attacks/Code_Injection",
                    "https://portswigger.net/web-security/server-side-template-injection"
                ],
                confidence="Medium",
                suggested_cvss={
                    "AV": "N",
                    "AC": "L",
                    "PR": "N",
                    "UI": "N",
                    "S": "C",
                    "C": "H",
                    "I": "H",
                    "A": "H"
                }
            )
            finding.target_url = context.target_url
            findings.append(finding)
        
        return findings
    
    def _test_template_injection(self, url: str, param: str, payload: str, context) -> dict:
        """Test for template injection."""
        from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [payload]
            
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
            
            if "49" in response.text and payload not in response.text:
                return {
                    "url": url,
                    "type": "Template Injection",
                    "pattern": payload,
                    "match": "7*7 evaluated to 49"
                }
                
        except Exception:
            pass
        
        return None
