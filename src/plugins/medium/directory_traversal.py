"""
Directory Traversal Detection Plugin.
Detects path traversal vulnerabilities.
"""

import re
import time
import requests
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class DirectoryTraversalPlugin(PluginBase):
    """Detects directory traversal/path traversal vulnerabilities."""
    
    def __init__(self):
        super().__init__()
        payloads = []
        payloads += self.load_wordlist("directory_traversal.txt")
        if not payloads:
            payloads = list(self.TRAVERSAL_PAYLOADS)
        seen = set()
        deduped = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                deduped.append(p)
        self.set_payloads(deduped)
        self.set_payload_limits(low=20, medium=100, high=500)
    
    FILE_PARAMS = [
        "file", "path", "page", "document", "doc", "folder", "root",
        "pg", "style", "pdf", "template", "php_path", "include",
        "dir", "download", "cat", "action", "board", "date", "detail",
        "name", "img", "image", "filename", "filepath"
    ]
    
    TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..\\..\\..\\windows\\win.ini",
    ]
    
    LINUX_SIGNATURES = [
        "root:x:0:0",
        "/bin/bash",
        "/bin/sh",
        "daemon:",
        "nobody:"
    ]
    
    WINDOWS_SIGNATURES = [
        "[fonts]",
        "[extensions]",
        "[mci extensions]",
        "for 16-bit app support"
    ]
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Directory Traversal",
            id="directory-traversal",
            severity_hint="medium",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects path traversal vulnerabilities"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        vulnerable_params = []
        
        for param in context.attack_surface.url_parameters:
            if param.name.lower() not in [p.lower() for p in self.FILE_PARAMS]:
                continue
            
            baseline = self._get_baseline(param.source_url, context)
            
            payloads = self.get_payloads_for_level(context.scan_level)
            for payload in payloads:
                try:
                    parsed = urlparse(param.source_url)
                    params = parse_qs(parsed.query)
                    params[param.name] = [payload]
                    
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
                    
                    is_vulnerable = False
                    detected_os = ""
                    
                    for sig in self.LINUX_SIGNATURES:
                        if sig in response.text:
                            if sig not in baseline.get("text", ""):
                                is_vulnerable = True
                                detected_os = "Linux/Unix"
                                break
                    
                    if not is_vulnerable:
                        for sig in self.WINDOWS_SIGNATURES:
                            if sig in response.text:
                                if sig not in baseline.get("text", ""):
                                    is_vulnerable = True
                                    detected_os = "Windows"
                                    break
                    
                    if is_vulnerable:
                        vulnerable_params.append({
                            "param": param.name,
                            "source_url": param.source_url,
                            "test_url": test_url,
                            "payload": payload,
                            "os": detected_os,
                            "response_snippet": response.text[:500]
                        })
                        break
                    
                    time.sleep(context.rate_limit)
                    
                except Exception as e:
                    self.log_debug(f"Error testing {param.name}: {e}")
                    continue
        
        if vulnerable_params:
            finding = self.create_finding(
                vuln_name="Directory Traversal / Path Traversal",
                short_intro=f"Found {len(vulnerable_params)} parameters vulnerable to path traversal. "
                           "Attackers can read arbitrary files from the server.",
                description=(
                    "The application is vulnerable to directory traversal (also known as path "
                    "traversal or dot-dot-slash) attacks. By manipulating file path parameters "
                    "with sequences like '../', attackers can access files outside the intended "
                    "directory. This can expose sensitive configuration files, source code, "
                    "credentials, or system files."
                ),
                affected_endpoints=[p["source_url"] for p in vulnerable_params],
                impact=[
                    f"Parameter '{p['param']}' allows reading files ({p['os']} detected)"
                    for p in vulnerable_params
                ] + [
                    "Attackers can read /etc/passwd, /etc/shadow",
                    "Configuration files with credentials may be exposed",
                    "Source code could be stolen",
                    "This could lead to full system compromise"
                ],
                proof_of_concept=[
                    f"1. Access: {vulnerable_params[0]['test_url'][:100]}",
                    f"2. Payload used: {vulnerable_params[0]['payload']}",
                    f"3. System file content detected ({vulnerable_params[0]['os']})",
                    "4. NOTE: Only detection payloads used, not exploitation"
                ],
                evidence=[{
                    "request": f"GET {p['test_url'][:100]}",
                    "response": p["response_snippet"][:200] + "...",
                    "description": f"Parameter: {p['param']}, OS: {p['os']}"
                } for p in vulnerable_params[:3]],
                remediation=[
                    "Never use user input directly in file paths",
                    "Implement strict input validation (whitelist approach)",
                    "Use chroot or similar containment",
                    "Canonicalize paths and verify they're within allowed directories",
                    "Use indirect file references (map IDs to files)",
                    "Implement proper access controls on the file system"
                ],
                references=[
                    "https://owasp.org/www-community/attacks/Path_Traversal",
                    "https://portswigger.net/web-security/file-path-traversal"
                ],
                confidence="High",
                suggested_cvss={
                    "AV": "N",
                    "AC": "L",
                    "PR": "N",
                    "UI": "N",
                    "S": "U",
                    "C": "H",
                    "I": "N",
                    "A": "N"
                }
            )
            finding.target_url = context.target_url
            findings.append(finding)
        
        return findings
    
    def _get_baseline(self, url: str, context) -> dict:
        """Fetch baseline response for comparison."""
        try:
            response = requests.get(
                url,
                timeout=context.timeout,
                headers={"User-Agent": context.user_agent},
                verify=True
            )
            return {"text": response.text, "status": response.status_code}
        except Exception:
            return {"text": "", "status": 0}
