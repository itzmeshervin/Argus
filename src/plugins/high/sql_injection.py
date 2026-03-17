"""
SQL Injection Detection Plugin.
Uses safe error-based and reflection-based detection.
"""

import re
import time
import requests
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
from typing import List, Dict

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class SQLInjectionPlugin(PluginBase):
    """Detects SQL injection using safe error-based detection."""
    
    def __init__(self):
        super().__init__()
        payloads = []
        payloads += self.load_wordlist("sql_injection.txt")
        if not payloads:
            payloads = list(self.SAFE_PAYLOADS)
        # Dedupe while preserving order
        seen = set()
        deduped = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                deduped.append(p)
        self.set_payloads(deduped)
        self.set_payload_limits(low=50, medium=200, high=None)
    
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
        r"Unknown column",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"Zend_Db_",
        r"MySqlException",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"Driver.*SQL Server",
        r"OLE DB.*SQL Server",
        r"\bSQL Server\b.*Driver",
        r"Warning.*mssql_",
        r"\bSQL Server\b.*[0-9a-fA-F]{8}",
        r"System\.Data\.SqlClient\.",
        r"Exception.*\WSystem\.Data\.SqlClient\.",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"macabordar/telegramBot",
        r"\bORA-\d{5}",
        r"Oracle.*Driver",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
        r"oracle\.jdbc\.driver",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"Microsoft Access Driver",
        r"JET Database Engine",
        r"Access Database Engine",
        r"ODBC Microsoft Access",
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
        r"SQL error.*message.*driver",
        r"Warning.*sybase",
        r"Sybase message",
        r"Sybase.*Server message",
        r"SybSQLException",
        r"com\.sybase\.jdbc",
        r"DB2 SQL error:",
        r"db2_\w+\(",
        r"SQLSTATE.+SQLCODE",
    ]
    
    SAFE_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "1' AND '1'='1",
        "1 AND 1=1",
        "' OR 1=1--",
        "admin'--",
    ]
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="SQL Injection",
            id="sql-injection",
            severity_hint="high",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects SQL injection using safe error-based detection"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        vulnerable_params = []
        payloads = self.get_payloads_for_level(context.scan_level)
        
        for param in context.attack_surface.url_parameters[:30]:
            result = self._test_parameter(param.source_url, param.name, context, payloads)
            if result:
                vulnerable_params.append(result)
        
        for form in context.attack_surface.forms[:15]:
            for field in form.fields:
                if field.field_type in ["hidden", "submit", "button", "file"]:
                    continue
                
                if form.method.upper() == "GET":
                    result = self._test_get_form(form, field, context, payloads)
                else:
                    result = self._test_post_form(form, field, context, payloads)
                    
                if result:
                    vulnerable_params.append(result)
        
        if vulnerable_params:
            finding = self.create_finding(
                vuln_name="SQL Injection",
                short_intro=f"Found {len(vulnerable_params)} parameters vulnerable to SQL injection. "
                           "Attackers could read, modify, or delete database data.",
                description=(
                    "The application is vulnerable to SQL injection attacks. By inserting "
                    "malicious SQL code into input parameters, attackers can manipulate "
                    "database queries. This can lead to unauthorized data access, data "
                    "modification, authentication bypass, or even command execution on "
                    "the database server. This is one of the most critical web vulnerabilities."
                ),
                affected_endpoints=[p["url"] for p in vulnerable_params],
                impact=[
                    f"Parameter '{p['param']}': {p['error_type']} detected"
                    for p in vulnerable_params
                ] + [
                    "Complete database compromise possible",
                    "Authentication bypass",
                    "Unauthorized data access or theft",
                    "Data modification or deletion",
                    "Potential server takeover via advanced techniques"
                ],
                proof_of_concept=[
                    f"1. Navigate to {vulnerable_params[0]['url'][:80]}",
                    f"2. Inject payload: {vulnerable_params[0]['payload']}",
                    "3. Observe SQL error in response",
                    "4. NOTE: Only detection payloads used, no data extracted"
                ],
                evidence=[{
                    "request": f"{p.get('method', 'GET')} {p['url'][:100]}\nPayload: {p['payload']}",
                    "response": p['error_snippet'][:300],
                    "description": f"Parameter: {p['param']}, Error: {p['error_type']}"
                } for p in vulnerable_params[:5]],
                remediation=[
                    "Use parameterized queries (prepared statements)",
                    "Use ORM frameworks properly",
                    "Implement input validation (allowlist approach)",
                    "Apply least privilege to database accounts",
                    "Use Web Application Firewalls (WAF)",
                    "Regularly test for SQL injection",
                    "Never concatenate user input into SQL queries"
                ],
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    "https://portswigger.net/web-security/sql-injection"
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
    
    def _test_parameter(self, url: str, param_name: str, context, payloads: List[str]) -> Dict:
        """Test a URL parameter for SQL injection."""
        parsed = urlparse(url)
        
        baseline = self._get_baseline(url, context)
        
        for payload in payloads:
            try:
                params = parse_qs(parsed.query)
                params[param_name] = [payload]
                
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
                
                error_type = self._detect_sql_error(response.text)
                if error_type and self._is_new_error(baseline, response.text):
                    return {
                        "url": url,
                        "param": param_name,
                        "payload": payload,
                        "error_type": error_type,
                        "error_snippet": response.text[:500],
                        "method": "GET"
                    }
                
                time.sleep(context.rate_limit)
                
            except Exception as e:
                self.log_debug(f"Error testing {param_name}: {e}")
                continue
        
        return None
    
    def _test_get_form(self, form, field, context, payloads: List[str]) -> Dict:
        """Test a GET form field for SQL injection."""
        baseline = self._get_baseline(form.action, context)
        for payload in payloads:
            try:
                params = {f.name: f.value or "test" for f in form.fields}
                params[field.name] = payload
                
                test_url = f"{form.action}?{urlencode(params)}"
                
                response = requests.get(
                    test_url,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
                
                error_type = self._detect_sql_error(response.text)
                if error_type and self._is_new_error(baseline, response.text):
                    return {
                        "url": form.action,
                        "param": field.name,
                        "payload": payload,
                        "error_type": error_type,
                        "error_snippet": response.text[:500],
                        "method": "GET"
                    }
                
                time.sleep(context.rate_limit)
                
            except Exception:
                continue
        
        return None
    
    def _test_post_form(self, form, field, context, payloads: List[str]) -> Dict:
        """Test a POST form field for SQL injection."""
        baseline = self._get_baseline(form.action, context, method="POST", data={})
        for payload in payloads:
            try:
                data = {f.name: f.value or "test" for f in form.fields}
                data[field.name] = payload
                
                response = requests.post(
                    form.action,
                    data=data,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
                
                error_type = self._detect_sql_error(response.text)
                if error_type and self._is_new_error(baseline, response.text):
                    return {
                        "url": form.action,
                        "param": field.name,
                        "payload": payload,
                        "error_type": error_type,
                        "error_snippet": response.text[:500],
                        "method": "POST"
                    }
                
                time.sleep(context.rate_limit)
                
            except Exception:
                continue
        
        return None
    
    def _get_baseline(self, url: str, context, method: str = "GET", data: Dict = None) -> Dict:
        """Fetch a baseline response for comparison."""
        try:
            if method == "POST":
                response = requests.post(
                    url,
                    data=data or {},
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
            return {
                "text": response.text,
                "length": len(response.text),
                "status": response.status_code
            }
        except Exception:
            return {"text": "", "length": 0, "status": 0}
    
    def _is_new_error(self, baseline: Dict, text: str) -> bool:
        """Check whether error pattern appears only after payload injection."""
        if not baseline or not baseline.get("text"):
            return True
        base_text = baseline.get("text", "")
        if self._detect_sql_error(base_text):
            return False
        return True
    
    def _detect_sql_error(self, text: str) -> str:
        """Detect SQL error patterns in response text."""
        for pattern in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                if "MySQL" in pattern:
                    return "MySQL Error"
                elif "PostgreSQL" in pattern or "pg_" in pattern:
                    return "PostgreSQL Error"
                elif "SQL Server" in pattern or "SqlClient" in pattern:
                    return "SQL Server Error"
                elif "ORA-" in pattern or "oracle" in pattern.lower():
                    return "Oracle Error"
                elif "SQLite" in pattern:
                    return "SQLite Error"
                else:
                    return "SQL Error"
        return None
