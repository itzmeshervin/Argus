"""
Information Leakage Detection Plugin.
Detects sensitive information in responses.
"""

import re
import requests
from typing import List, Dict

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class InformationLeakagePlugin(PluginBase):
    """Detects sensitive information leakage."""
    
    SENSITIVE_PATTERNS = {
        "Internal IP Address": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        "AWS Key": r"AKIA[0-9A-Z]{16}",
        "Private Key": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        "Database Connection String": r"(?:mysql|postgresql|mongodb|redis):\/\/[^\s\"']+",
        "API Key Pattern": r"(?:api[_-]?key|apikey|api_secret)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{20,})[\"']?",
        "Password in URL": r"(?:password|passwd|pwd|pass)[\"']?\s*[:=]\s*[\"']?[^\s\"'&]+",
        "Debug Information": r"(?:stack\s*trace|traceback|exception|error.*line\s*\d+)",
        "SQL Error": r"(?:SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite.*error)",
        "Path Disclosure": r"(?:/var/www/|/home/\w+/|C:\\\\(?:inetpub|Users)\\\\)",
        "Comment with TODO/FIXME": r"(?:TODO|FIXME|HACK|XXX|BUG)[:\s]+[^\n]{10,}",
    }
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Information Leakage",
            id="information-leakage",
            severity_hint="low",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects sensitive information in responses"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        leaks_found: Dict[str, List[Dict]] = {}
        
        urls_to_check = list(context.attack_surface.urls)[:50]
        
        for url in urls_to_check:
            try:
                response = requests.get(
                    url,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
                
                content = response.text
                
                for leak_type, pattern in self.SENSITIVE_PATTERNS.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        if leak_type not in leaks_found:
                            leaks_found[leak_type] = []
                        
                        for match in matches[:3]:
                            match_str = match if isinstance(match, str) else match[0]
                            if len(match_str) > 50:
                                match_str = match_str[:50] + "..."
                            
                            leaks_found[leak_type].append({
                                "url": url,
                                "match": match_str
                            })
                            
            except Exception as e:
                self.log_debug(f"Error checking {url}: {e}")
                continue
        
        if leaks_found:
            all_endpoints = set()
            impact_list = []
            
            for leak_type, leaks in leaks_found.items():
                for leak in leaks:
                    all_endpoints.add(leak["url"])
                impact_list.append(f"{leak_type}: Found {len(leaks)} instance(s)")
            
            finding = self.create_finding(
                vuln_name="Sensitive Information Leakage",
                short_intro=f"Detected {len(leaks_found)} types of sensitive information in responses. "
                           "This could aid attackers in further exploitation.",
                description=(
                    "The application exposes sensitive information in its responses. "
                    "This includes internal IP addresses, error messages, debug information, "
                    "file paths, or credentials. Such information helps attackers understand "
                    "the application's internal structure and identify further attack vectors."
                ),
                affected_endpoints=list(all_endpoints)[:10],
                impact=impact_list + [
                    "Exposure of internal infrastructure details",
                    "Potential credential leakage",
                    "Debug information aiding exploitation"
                ],
                proof_of_concept=[
                    "1. Browse to the affected endpoints",
                    "2. View page source or response body",
                    "3. Search for patterns matching sensitive data",
                    f"4. Found {sum(len(v) for v in leaks_found.values())} instances of sensitive data"
                ],
                evidence=[{
                    "request": f"GET {leaks[0]['url']}",
                    "response": f"Found: {leaks[0]['match']}",
                    "description": f"{leak_type} detected"
                } for leak_type, leaks in list(leaks_found.items())[:5]],
                remediation=[
                    "Remove debug information from production responses",
                    "Configure proper error handling to hide stack traces",
                    "Remove comments containing sensitive information",
                    "Use environment variables for credentials, not hardcoded values",
                    "Implement proper logging that doesn't expose sensitive data"
                ],
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"
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
