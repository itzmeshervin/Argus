"""
Missing Security Headers Detection Plugin.
Detects missing or misconfigured security headers.
"""

import requests
from typing import List, Dict

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class SecurityHeadersPlugin(PluginBase):
    """Detects missing security headers."""
    
    REQUIRED_HEADERS = {
        "Strict-Transport-Security": {
            "description": "HSTS header prevents protocol downgrade attacks",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header"
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME type sniffing attacks",
            "remediation": "Add 'X-Content-Type-Options: nosniff' header"
        },
        "X-Frame-Options": {
            "description": "Prevents clickjacking attacks",
            "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header"
        },
        "Content-Security-Policy": {
            "description": "CSP prevents XSS and data injection attacks",
            "remediation": "Implement a Content-Security-Policy header with appropriate directives"
        },
        "Referrer-Policy": {
            "description": "Controls referrer information leakage",
            "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header"
        },
        "Permissions-Policy": {
            "description": "Controls browser features and APIs",
            "remediation": "Add Permissions-Policy header to restrict sensitive features"
        }
    }
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Missing Security Headers",
            id="security-headers",
            severity_hint="low",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects missing or misconfigured HTTP security headers"
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
            
            missing_headers = []
            present_headers = []
            
            for header, info in self.REQUIRED_HEADERS.items():
                if header == "Strict-Transport-Security" and not context.target_url.startswith("https://"):
                    continue
                if header.lower() not in [h.lower() for h in response.headers.keys()]:
                    missing_headers.append((header, info))
                else:
                    present_headers.append(header)
            
            if missing_headers:
                header_list = [h[0] for h in missing_headers]
                
                finding = self.create_finding(
                    vuln_name="Missing Security Headers",
                    short_intro=f"The target is missing {len(missing_headers)} security headers. "
                               f"This may expose the application to various attacks.",
                    description=(
                        "HTTP security headers are a critical defense mechanism that help protect "
                        "web applications from various attacks including XSS, clickjacking, MIME type "
                        "confusion, and protocol downgrade attacks. The following headers are missing: "
                        f"{', '.join(header_list)}."
                    ),
                    affected_endpoints=[context.target_url],
                    impact=[
                        f"Missing {h}: {info['description']}" 
                        for h, info in missing_headers
                    ],
                    proof_of_concept=[
                        f"1. Send a GET request to {context.target_url}",
                        "2. Examine the response headers",
                        f"3. Observe that the following headers are missing: {', '.join(header_list)}"
                    ],
                    evidence=[{
                        "request": f"GET {context.target_url} HTTP/1.1\nHost: {context.target_url}",
                        "response": f"HTTP/1.1 {response.status_code}\n" + 
                                   "\n".join([f"{k}: {v}" for k, v in response.headers.items()]),
                        "description": "Response headers from target"
                    }],
                    remediation=[info["remediation"] for _, info in missing_headers],
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
                        "https://securityheaders.com/"
                    ],
                    confidence="High",
                    suggested_cvss={
                        "AV": "N",
                        "AC": "L",
                        "PR": "N",
                        "UI": "N",
                        "S": "U",
                        "C": "N",
                        "I": "L",
                        "A": "N"
                    }
                )
                finding.target_url = context.target_url
                findings.append(finding)
                
        except Exception as e:
            self.log_warning(f"Error checking security headers: {e}")
        
        return findings
