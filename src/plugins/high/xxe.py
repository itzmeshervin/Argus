"""
XXE (XML External Entity) Detection Plugin.
Detects XXE indicators non-destructively.
"""

import re
import requests
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class XXEPlugin(PluginBase):
    """Detects XXE indicators."""
    
    XML_CONTENT_TYPES = [
        "application/xml",
        "text/xml",
        "application/xhtml+xml",
        "application/soap+xml",
        "application/rss+xml",
        "application/atom+xml"
    ]
    
    XXE_SAFE_PAYLOAD = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<test>&xxe;</test>'''
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="XML External Entity (XXE)",
            id="xxe",
            severity_hint="high",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects XXE indicators"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        xxe_indicators = []
        
        for endpoint in context.attack_surface.api_endpoints:
            if any(ct in endpoint.content_type.lower() for ct in ["xml", "soap"]):
                xxe_indicators.append({
                    "url": endpoint.url,
                    "type": "XML API Endpoint",
                    "content_type": endpoint.content_type
                })
        
        for form in context.attack_surface.forms:
            for field in form.fields:
                if "xml" in field.name.lower():
                    xxe_indicators.append({
                        "url": form.action,
                        "type": "XML Form Field",
                        "field": field.name
                    })
        
        for url in list(context.attack_surface.urls)[:20]:
            if any(ext in url.lower() for ext in [".xml", ".soap", ".wsdl", ".xsd"]):
                try:
                    response = requests.get(
                        url,
                        timeout=context.timeout,
                        headers={"User-Agent": context.user_agent},
                        verify=True
                    )
                    
                    content_type = response.headers.get("Content-Type", "")
                    if any(ct in content_type.lower() for ct in self.XML_CONTENT_TYPES):
                        if "<!DOCTYPE" not in response.text:
                            xxe_indicators.append({
                                "url": url,
                                "type": "XML File",
                                "content_type": content_type
                            })
                            
                except Exception:
                    pass
        
        for url in list(context.attack_surface.urls)[:10]:
            try:
                response = requests.post(
                    url,
                    data='<?xml version="1.0"?><test>data</test>',
                    timeout=context.timeout,
                    headers={
                        "User-Agent": context.user_agent,
                        "Content-Type": "application/xml"
                    },
                    verify=True
                )
                
                if response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "")
                    if any(ct in content_type.lower() for ct in self.XML_CONTENT_TYPES):
                        xxe_indicators.append({
                            "url": url,
                            "type": "XML Processing Endpoint",
                            "accepts_xml": True
                        })
                        
            except Exception:
                pass
        
        if xxe_indicators:
            finding = self.create_finding(
                vuln_name="XML External Entity (XXE) Indicators",
                short_intro=f"Found {len(xxe_indicators)} XML processing points. "
                           "May be vulnerable to XXE attacks for file reading or SSRF.",
                description=(
                    "The application processes XML input at various endpoints. XML parsers "
                    "that are not properly configured may be vulnerable to XXE attacks, "
                    "allowing attackers to read local files, perform SSRF attacks, or "
                    "cause denial of service. XXE can lead to sensitive data exposure "
                    "including credentials and configuration files."
                ),
                affected_endpoints=[i["url"] for i in xxe_indicators],
                impact=[
                    f"{i['type']} at {i['url'][:50]}"
                    for i in xxe_indicators
                ] + [
                    "Local file read (/etc/passwd, config files)",
                    "Internal network SSRF",
                    "Denial of Service (billion laughs attack)",
                    "Port scanning of internal network"
                ],
                proof_of_concept=[
                    "1. Identify XML processing endpoints",
                    "2. Send XML with external entity declaration",
                    "3. Check if entity is resolved in response",
                    "4. NOTE: Only detection performed, no exploitation"
                ],
                evidence=[{
                    "request": f"Examined {i['type']}: {i['url'][:80]}",
                    "response": f"Type: {i['type']}\nContent-Type: {i.get('content_type', 'N/A')}",
                    "description": "XML processing detected"
                } for i in xxe_indicators[:5]],
                remediation=[
                    "Disable external entity processing in XML parsers",
                    "Use less complex data formats (JSON) where possible",
                    "Validate and sanitize XML input",
                    "Use XML parsers with XXE disabled by default",
                    "Implement input validation for XML structure",
                    "Keep XML parsing libraries updated"
                ],
                references=[
                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                    "https://portswigger.net/web-security/xxe"
                ],
                confidence="Low",
                suggested_cvss={
                    "AV": "N",
                    "AC": "L",
                    "PR": "N",
                    "UI": "N",
                    "S": "C",
                    "C": "H",
                    "I": "L",
                    "A": "L"
                }
            )
            finding.target_url = context.target_url
            findings.append(finding)
        
        return findings
