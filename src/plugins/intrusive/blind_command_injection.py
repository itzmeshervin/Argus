"""
Blind Command Injection Detection Plugin.
INTRUSIVE - Uses time delays, requires explicit consent.
"""

import time
import requests
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class BlindCommandInjectionPlugin(PluginBase):
    """
    Blind command injection detection using time delays.
    INTRUSIVE: Uses sleep commands that may affect server performance.
    """
    
    TIME_PAYLOADS = [
        "; sleep 5",
        "| sleep 5",
        "& sleep 5",
        "&& sleep 5",
        "|| sleep 5",
        "` sleep 5 `",
        "$(sleep 5)",
        "; ping -c 5 127.0.0.1",
        "| ping -c 5 127.0.0.1",
    ]
    
    CMD_PARAMS = [
        "cmd", "command", "exec", "execute", "run", "ping", "host",
        "ip", "domain", "target", "process", "action"
    ]
    
    DELAY_THRESHOLD = 4
    BASELINE_SAMPLES = 2
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Blind Command Injection",
            id="blind-command-injection",
            severity_hint="high",
            intrusive=True,
            author="VulnScanner Team",
            description="Blind command injection using timing (INTRUSIVE)"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        if not context.allow_intrusive:
            self.log_info("Intrusive checks not allowed, skipping blind command injection")
            return []
        
        findings = []
        vulnerable_params = []
        
        for param in context.attack_surface.url_parameters[:15]:
            if param.name.lower() in [p.lower() for p in self.CMD_PARAMS]:
                result = self._test_time_based(param, context)
                if result:
                    vulnerable_params.append(result)
        
        for form in context.attack_surface.forms[:10]:
            for field in form.fields:
                if field.name.lower() in [p.lower() for p in self.CMD_PARAMS]:
                    result = self._test_form_time_based(form, field, context)
                    if result:
                        vulnerable_params.append(result)
        
        if vulnerable_params:
            finding = self.create_finding(
                vuln_name="Blind Command Injection",
                short_intro=f"CONFIRMED: {len(vulnerable_params)} parameters execute system commands. "
                           "Server responded with delays matching sleep payload.",
                description=(
                    "The application is confirmed vulnerable to blind command injection. "
                    "Time-based payloads caused measurable response delays, indicating that "
                    "system commands are being executed. This is a critical vulnerability "
                    "that allows complete server takeover."
                ),
                affected_endpoints=[p["url"] for p in vulnerable_params],
                impact=[
                    f"Parameter '{p['param']}': {p['delay']:.1f}s delay with {p['payload'][:20]}"
                    for p in vulnerable_params
                ] + [
                    "Complete server takeover possible",
                    "Data exfiltration",
                    "Backdoor installation",
                    "Lateral movement in network"
                ],
                proof_of_concept=[
                    f"1. Injected sleep command into {vulnerable_params[0]['param']}",
                    f"2. Payload: {vulnerable_params[0]['payload']}",
                    f"3. Response delayed by {vulnerable_params[0]['delay']:.1f} seconds",
                    "4. Delay confirms command execution"
                ],
                evidence=[{
                    "request": f"{p['method']} {p['url'][:80]}\nPayload: {p['payload']}",
                    "response": f"Response time: {p['delay']:.1f}s (expected ~5s delay)",
                    "description": "Blind command injection confirmed via timing"
                } for p in vulnerable_params[:5]],
                remediation=[
                    "Never pass user input to system commands",
                    "This is a critical vulnerability requiring immediate fix",
                    "Use language-native functions instead of shell commands",
                    "If commands necessary, use strict allowlists",
                    "Implement sandboxing and least privilege"
                ],
                references=[
                    "https://owasp.org/www-community/attacks/Command_Injection",
                    "https://portswigger.net/web-security/os-command-injection/blind"
                ],
                confidence="High",
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
    
    def _test_time_based(self, param, context) -> dict:
        """Test a URL parameter for blind command injection."""
        parsed = urlparse(param.source_url)
        baseline = self._measure_baseline(param.source_url, context)
        
        for payload in self.TIME_PAYLOADS[:4]:
            try:
                params = parse_qs(parsed.query)
                original_value = params.get(param.name, ["test"])[0]
                params[param.name] = [original_value + payload]
                
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(params, doseq=True), parsed.fragment
                ))
                
                start_time = time.time()
                response = requests.get(
                    test_url,
                    timeout=15,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
                elapsed = time.time() - start_time
                
                if self._is_delayed(elapsed, baseline):
                    if not self._confirm_delay(test_url, context, baseline):
                        continue
                    return {
                        "url": param.source_url,
                        "param": param.name,
                        "payload": payload,
                        "delay": elapsed,
                        "method": "GET"
                    }
                
                time.sleep(context.rate_limit)
                
            except requests.Timeout:
                if self._is_delayed(15.0, baseline):
                    if not self._confirm_delay(test_url, context, baseline):
                        continue
                    return {
                        "url": param.source_url,
                        "param": param.name,
                        "payload": payload,
                        "delay": 15.0,
                        "method": "GET"
                    }
            except Exception as e:
                self.log_debug(f"Error testing {param.name}: {e}")
        
        return None
    
    def _test_form_time_based(self, form, field, context) -> dict:
        """Test a form field for blind command injection."""
        for payload in self.TIME_PAYLOADS[:3]:
            try:
                data_base = {f.name: f.value or "test" for f in form.fields}
                baseline = self._measure_baseline(form.action, context, method="POST", data=data_base)
                
                data = dict(data_base)
                data[field.name] = data.get(field.name, "test") + payload
                
                start_time = time.time()
                if form.method.upper() == "GET":
                    test_url = f"{form.action}?{urlencode(data)}"
                    response = requests.get(
                        test_url,
                        timeout=15,
                        headers={"User-Agent": context.user_agent},
                        verify=True
                    )
                else:
                    response = requests.post(
                        form.action,
                        data=data,
                        timeout=15,
                        headers={"User-Agent": context.user_agent},
                        verify=True
                    )
                elapsed = time.time() - start_time
                
                if self._is_delayed(elapsed, baseline):
                    if not self._confirm_delay(form.action, context, baseline, method=form.method, data=data):
                        continue
                    return {
                        "url": form.action,
                        "param": field.name,
                        "payload": payload,
                        "delay": elapsed,
                        "method": form.method
                    }
                
                time.sleep(context.rate_limit)
                
            except requests.Timeout:
                if self._is_delayed(15.0, baseline):
                    if not self._confirm_delay(form.action, context, baseline, method=form.method, data=data):
                        continue
                    return {
                        "url": form.action,
                        "param": field.name,
                        "payload": payload,
                        "delay": 15.0,
                        "method": form.method
                    }
            except Exception:
                continue
        
        return None
    
    def _measure_baseline(self, url: str, context, method: str = "GET", data: dict = None) -> float:
        """Measure baseline response time."""
        samples = []
        for _ in range(self.BASELINE_SAMPLES):
            try:
                start = time.time()
                if method.upper() == "POST":
                    requests.post(
                        url,
                        data=data or {},
                        timeout=15,
                        headers={"User-Agent": context.user_agent},
                        verify=True
                    )
                else:
                    requests.get(
                        url,
                        timeout=15,
                        headers={"User-Agent": context.user_agent},
                        verify=True
                    )
                samples.append(time.time() - start)
            except Exception:
                continue
        if not samples:
            return 0.0
        return sum(samples) / len(samples)
    
    def _is_delayed(self, elapsed: float, baseline: float) -> bool:
        return elapsed >= max(self.DELAY_THRESHOLD, baseline + 3.0)
    
    def _confirm_delay(self, url: str, context, baseline: float, method: str = "GET", data: dict = None) -> bool:
        """Confirm delay with a second request."""
        try:
            start = time.time()
            if method.upper() == "POST":
                requests.post(
                    url,
                    data=data or {},
                    timeout=15,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
            else:
                requests.get(
                    url,
                    timeout=15,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
            elapsed = time.time() - start
            return self._is_delayed(elapsed, baseline)
        except Exception:
            return False
