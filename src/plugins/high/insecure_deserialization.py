"""
Insecure Deserialization Detection Plugin.
Detects fingerprints of insecure deserialization.
"""

import re
import requests
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class InsecureDeserializationPlugin(PluginBase):
    """Detects insecure deserialization fingerprints."""
    
    SERIALIZATION_PATTERNS = {
        "Java Serialized Object": [
            r"rO0AB",
            r"aced0005",
            r"H4sIAAAA"
        ],
        "PHP Serialized Object": [
            r'[aOCbsi]:\d+:',
            r'a:\d+:\{',
            r'O:\d+:"[^"]+":\d+:\{'
        ],
        ".NET ViewState": [
            r"__VIEWSTATE",
            r"__EVENTVALIDATION"
        ],
        "Python Pickle": [
            r"gASV",
            r"Y3BpY2ts"
        ],
        "Ruby Marshal": [
            r"BAh"
        ]
    }
    
    COOKIE_PATTERNS = [
        "session",
        "sess",
        "token",
        "auth",
        "user",
        "data",
        "state"
    ]
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Insecure Deserialization",
            id="insecure-deserialization",
            severity_hint="high",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects insecure deserialization fingerprints"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        deser_indicators = []
        
        for cookie in context.attack_surface.cookies:
            for pattern_name, patterns in self.SERIALIZATION_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, cookie.value):
                        deser_indicators.append({
                            "type": "Cookie",
                            "name": cookie.name,
                            "format": pattern_name,
                            "value_snippet": cookie.value[:50]
                        })
                        break
        
        try:
            response = requests.get(
                context.target_url,
                timeout=context.timeout,
                headers={"User-Agent": context.user_agent},
                verify=True
            )
            
            if "__VIEWSTATE" in response.text:
                match = re.search(r'value="([^"]+)"[^>]*name="__VIEWSTATE"', response.text)
                if not match:
                    match = re.search(r'name="__VIEWSTATE"[^>]*value="([^"]+)"', response.text)
                
                if match:
                    viewstate = match.group(1)
                    deser_indicators.append({
                        "type": "ViewState",
                        "name": "__VIEWSTATE",
                        "format": ".NET ViewState",
                        "value_snippet": viewstate[:50]
                    })
                    
                    if not viewstate.endswith("=="):
                        deser_indicators[-1]["additional"] = "ViewState may not be properly encrypted"
            
            for form in context.attack_surface.forms[:10]:
                for field in form.fields:
                    if field.field_type == "hidden" and field.value:
                        for pattern_name, patterns in self.SERIALIZATION_PATTERNS.items():
                            for pattern in patterns:
                                if re.search(pattern, field.value):
                                    deser_indicators.append({
                                        "type": "Hidden Field",
                                        "name": field.name,
                                        "format": pattern_name,
                                        "url": form.source_url,
                                        "value_snippet": field.value[:50]
                                    })
                                    break
                                    
        except Exception as e:
            self.log_debug(f"Error checking deserialization: {e}")
        
        if deser_indicators:
            finding = self.create_finding(
                vuln_name="Insecure Deserialization Indicators",
                short_intro=f"Found {len(deser_indicators)} serialized objects that may be vulnerable. "
                           "Attackers could achieve remote code execution.",
                description=(
                    "The application uses serialized objects in cookies, hidden fields, or other "
                    "user-controllable inputs. If these objects are deserialized without proper "
                    "validation, attackers could craft malicious serialized data to execute "
                    "arbitrary code on the server. This is a critical vulnerability that often "
                    "leads to complete server compromise."
                ),
                affected_endpoints=[context.target_url],
                impact=[
                    f"{i['type']} '{i['name']}': {i['format']} detected"
                    for i in deser_indicators
                ] + [
                    "Remote Code Execution (RCE) possible",
                    "Complete server compromise",
                    "Data theft or destruction",
                    "Lateral movement in network"
                ],
                proof_of_concept=[
                    "1. Identify serialized data in cookies/hidden fields",
                    "2. Determine serialization format (Java, PHP, .NET, etc.)",
                    "3. Research known gadget chains for the framework",
                    "4. NOTE: Only fingerprinting performed, no exploitation"
                ],
                evidence=[{
                    "request": f"Examined {i['type']}: {i['name']}",
                    "response": f"Format: {i['format']}\nValue: {i['value_snippet']}...",
                    "description": f"{i['format']} serialization detected"
                } for i in deser_indicators[:5]],
                remediation=[
                    "Avoid deserializing untrusted data",
                    "Use data formats that don't allow code (JSON, XML)",
                    "Implement integrity checks (signed serialized data)",
                    "Use deserialization filters (Java, .NET)",
                    "Run deserializing code in low-privilege containers",
                    "Log deserialization exceptions for monitoring",
                    "Keep frameworks updated (patch known gadgets)"
                ],
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests",
                    "https://portswigger.net/web-security/deserialization"
                ],
                confidence="Medium",
                suggested_cvss={
                    "AV": "N",
                    "AC": "H",
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
