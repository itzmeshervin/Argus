"""
Command Injection Detection Plugin.
Uses safe indicator-based detection.
"""

import re
import time
import requests
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class CommandInjectionPlugin(PluginBase):
    """Detects command injection indicators."""
    
    def __init__(self):
        super().__init__()
        payloads = []
        payloads += self.load_wordlist("command_injection.txt")
        if not payloads:
            payloads = list(self.SAFE_PAYLOADS)
        seen = set()
        deduped = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                deduped.append(p)
        self.set_payloads(deduped)
        self.set_payload_limits(low=20, medium=100, high=300)
    
    CMD_PARAMS = [
        "cmd", "command", "exec", "execute", "run", "ping", "query",
        "host", "hostname", "ip", "domain", "file", "path", "dir",
        "target", "daemon", "upload", "action", "log", "process"
    ]
    
    SAFE_PAYLOADS = [
        "; echo CMDTEST123",
        "| echo CMDTEST123",
        "` echo CMDTEST123 `",
        "$(echo CMDTEST123)",
        "&& echo CMDTEST123",
        "|| echo CMDTEST123",
    ]
    
    ERROR_PATTERNS = [
        r"sh: .+: not found",
        r"bash: .+: command not found",
        r"'.*' is not recognized as an internal or external command",
        r"The system cannot find the path specified",
        r"No such file or directory",
        r"/bin/sh:",
        r"/bin/bash:",
        r"cmd\.exe",
        r"syntax error near unexpected token",
    ]
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Command Injection",
            id="command-injection",
            severity_hint="high",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects command injection indicators"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        vulnerable_params = []
        payloads = self.get_payloads_for_level(context.scan_level)
        
        for param in context.attack_surface.url_parameters[:20]:
            if param.name.lower() in [p.lower() for p in self.CMD_PARAMS]:
                result = self._test_cmd_param(param, context, payloads)
                if result:
                    vulnerable_params.append(result)
        
        for form in context.attack_surface.forms[:10]:
            for field in form.fields:
                if field.name.lower() in [p.lower() for p in self.CMD_PARAMS]:
                    result = self._test_form_field(form, field, context, payloads)
                    if result:
                        vulnerable_params.append(result)
        
        if vulnerable_params:
            finding = self.create_finding(
                vuln_name="Command Injection",
                short_intro=f"Found {len(vulnerable_params)} potential command injection points. "
                           "Attackers could execute arbitrary system commands.",
                description=(
                    "The application appears to pass user input to system commands without "
                    "proper sanitization. This could allow attackers to execute arbitrary "
                    "commands on the server, potentially leading to complete system compromise. "
                    "Command injection is one of the most severe web vulnerabilities."
                ),
                affected_endpoints=[p["url"] for p in vulnerable_params],
                impact=[
                    f"Parameter '{p['param']}': {p['indicator']}"
                    for p in vulnerable_params
                ] + [
                    "Complete server compromise",
                    "Data theft or destruction",
                    "Lateral movement in network",
                    "Installation of backdoors",
                    "Cryptocurrency mining",
                    "Use as bot in attacks"
                ],
                proof_of_concept=[
                    f"1. Access endpoint with vulnerable parameter",
                    f"2. Inject command separator (e.g., ; or |)",
                    "3. Observe shell error or command output in response",
                    "4. NOTE: Only safe detection payloads used"
                ],
                evidence=[{
                    "request": f"{p.get('method', 'GET')} {p['url'][:100]}\nPayload: {p['payload']}",
                    "response": p.get("response_snippet", "Command injection indicator detected")[:200],
                    "description": p["indicator"]
                } for p in vulnerable_params[:5]],
                remediation=[
                    "Avoid system command execution with user input",
                    "Use language-native functions instead of shell commands",
                    "If commands necessary, use strict allowlists for input",
                    "Never concatenate user input into command strings",
                    "Use parameterized APIs when available",
                    "Implement least privilege for application processes",
                    "Use sandboxing and containerization"
                ],
                references=[
                    "https://owasp.org/www-community/attacks/Command_Injection",
                    "https://portswigger.net/web-security/os-command-injection"
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
    
    def _test_cmd_param(self, param, context, payloads: List[str]) -> dict:
        """Test a parameter for command injection indicators."""
        parsed = urlparse(param.source_url)
        baseline = self._get_baseline(param.source_url, context)
        
        for payload in payloads:
            try:
                params = parse_qs(parsed.query)
                original_value = params.get(param.name, ["test"])[0]
                params[param.name] = [original_value + payload]
                
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
                
                if "CMDTEST123" in response.text and "CMDTEST123" not in baseline.get("text", ""):
                    return {
                        "url": param.source_url,
                        "param": param.name,
                        "payload": payload,
                        "indicator": "Command output reflected in response",
                        "response_snippet": response.text[:300],
                        "method": "GET"
                    }
                
                for pattern in self.ERROR_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE) and not re.search(pattern, baseline.get("text", ""), re.IGNORECASE):
                        return {
                            "url": param.source_url,
                            "param": param.name,
                            "payload": payload,
                            "indicator": "Shell error message detected",
                            "response_snippet": response.text[:300],
                            "method": "GET"
                        }
                
                time.sleep(context.rate_limit)
                
            except Exception as e:
                self.log_debug(f"Error testing cmd param {param.name}: {e}")
        
        return None
    
    def _test_form_field(self, form, field, context, payloads: List[str]) -> dict:
        """Test a form field for command injection."""
        baseline = self._get_baseline(form.action, context, method=form.method)
        for payload in payloads:
            try:
                data = {f.name: f.value or "test" for f in form.fields}
                data[field.name] = data.get(field.name, "test") + payload
                
                if form.method.upper() == "GET":
                    test_url = f"{form.action}?{urlencode(data)}"
                    response = requests.get(
                        test_url,
                        timeout=context.timeout,
                        headers={"User-Agent": context.user_agent},
                        verify=True
                    )
                else:
                    response = requests.post(
                        form.action,
                        data=data,
                        timeout=context.timeout,
                        headers={"User-Agent": context.user_agent},
                        verify=True
                    )
                
                if "CMDTEST123" in response.text and "CMDTEST123" not in baseline.get("text", ""):
                    return {
                        "url": form.action,
                        "param": field.name,
                        "payload": payload,
                        "indicator": "Command output reflected",
                        "response_snippet": response.text[:300],
                        "method": form.method
                    }
                
                for pattern in self.ERROR_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE) and not re.search(pattern, baseline.get("text", ""), re.IGNORECASE):
                        return {
                            "url": form.action,
                            "param": field.name,
                            "payload": payload,
                            "indicator": "Shell error detected",
                            "response_snippet": response.text[:300],
                            "method": form.method
                        }
                
                time.sleep(context.rate_limit)
                
            except Exception:
                continue
        
        return None
    
    def _get_baseline(self, url: str, context, method: str = "GET") -> dict:
        """Fetch baseline response for comparison."""
        try:
            if method.upper() == "POST":
                response = requests.post(
                    url,
                    data={},
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
            else:
                response = requests.get(
                    url,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
            return {"text": response.text, "status": response.status_code}
        except Exception:
            return {"text": "", "status": 0}
