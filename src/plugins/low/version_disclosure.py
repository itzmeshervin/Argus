"""
Version Disclosure Detection Plugin.
Detects server and technology version information leakage.
"""

import re
import requests
from typing import List, Dict

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class VersionDisclosurePlugin(PluginBase):
    """Detects version information disclosure."""
    
    VERSION_PATTERNS = {
        "Server": r"(Apache|nginx|IIS|LiteSpeed|Caddy|Tomcat|Jetty)[\s/]*([\d.]+)?",
        "X-Powered-By": r"(PHP|ASP\.NET|Express|Node\.js|Ruby|Python|Java)[\s/]*([\d.]+)?",
        "X-AspNet-Version": r"([\d.]+)",
        "X-AspNetMvc-Version": r"([\d.]+)",
        "X-Generator": r"(.+)",
        "X-Drupal-Cache": r"(.+)",
        "X-Varnish": r"(.+)",
        "Via": r"(.+)"
    }
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Version Disclosure",
            id="version-disclosure",
            severity_hint="low",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects server and technology version disclosure"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        
        try:
            response = requests.get(
                context.target_url,
                timeout=context.timeout,
                headers={"User-Agent": context.user_agent},
                verify=True
            )
            
            disclosed_versions = []
            
            for header, pattern in self.VERSION_PATTERNS.items():
                header_value = response.headers.get(header, "")
                if header_value:
                    match = re.search(pattern, header_value, re.IGNORECASE)
                    if match:
                        disclosed_versions.append({
                            "header": header,
                            "value": header_value,
                            "technology": match.group(1) if match.groups() else header_value
                        })
            
            body_patterns = [
                (r"WordPress\s*([\d.]+)?", "WordPress"),
                (r"Joomla!\s*([\d.]+)?", "Joomla"),
                (r"Drupal\s*([\d.]+)?", "Drupal"),
                (r"jQuery\s*v?([\d.]+)", "jQuery"),
                (r"Bootstrap\s*v?([\d.]+)", "Bootstrap"),
                (r"React\s*v?([\d.]+)", "React"),
                (r"Angular\s*v?([\d.]+)", "Angular"),
                (r"Vue\.js\s*v?([\d.]+)", "Vue.js")
            ]
            
            for pattern, tech in body_patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() and match.group(1) else "detected"
                    disclosed_versions.append({
                        "header": "HTML Body",
                        "value": f"{tech} {version}",
                        "technology": tech
                    })
            
            if disclosed_versions:
                finding = self.create_finding(
                    vuln_name="Technology Version Disclosure",
                    short_intro=f"The server discloses {len(disclosed_versions)} technology versions. "
                               "Attackers can use this to find known vulnerabilities.",
                    description=(
                        "The web server reveals version information about the technologies used. "
                        "This information helps attackers identify known vulnerabilities and exploits "
                        "specific to those versions. Technologies disclosed: " +
                        ", ".join(set([d["technology"] for d in disclosed_versions]))
                    ),
                    affected_endpoints=[context.target_url],
                    impact=[
                        f"{d['header']}: {d['value']}" for d in disclosed_versions
                    ] + [
                        "Attackers can search for CVEs affecting disclosed versions",
                        "Facilitates targeted attacks using version-specific exploits"
                    ],
                    proof_of_concept=[
                        f"1. Send a GET request to {context.target_url}",
                        "2. Examine the response headers and body",
                        "3. Identify version strings in headers like Server, X-Powered-By"
                    ],
                    evidence=[{
                        "request": f"GET {context.target_url}",
                        "response": "\n".join([
                            f"{d['header']}: {d['value']}" for d in disclosed_versions
                        ]),
                        "description": "Disclosed version information"
                    }],
                    remediation=[
                        "Configure web server to suppress version headers",
                        "For Apache: ServerTokens Prod, ServerSignature Off",
                        "For Nginx: server_tokens off;",
                        "Remove X-Powered-By and similar headers",
                        "Remove version strings from HTML comments and meta tags"
                    ],
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
                    ],
                    confidence="High",
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
                
        except Exception as e:
            self.log_warning(f"Error checking version disclosure: {e}")
        
        return findings
