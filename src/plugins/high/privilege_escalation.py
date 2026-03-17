"""
Privilege Escalation Detection Plugin.
Detects potential privilege escalation vulnerabilities.
"""

import re
import requests
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class PrivilegeEscalationPlugin(PluginBase):
    """Detects potential privilege escalation vulnerabilities."""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Privilege Escalation Signals",
            id="privilege-escalation",
            severity_hint="high",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects potential privilege escalation vulnerabilities"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        priv_esc_indicators = []
        
        for form in context.attack_surface.forms:
            sensitive_fields = []
            
            for field in form.fields:
                field_lower = field.name.lower()
                
                if any(x in field_lower for x in ["role", "admin", "level", "permission", 
                                                   "privilege", "group", "type", "is_admin",
                                                   "isadmin", "is_staff", "user_type"]):
                    sensitive_fields.append({
                        "field": field.name,
                        "type": field.field_type,
                        "value": field.value
                    })
                
                if "user" in field_lower and "id" in field_lower:
                    sensitive_fields.append({
                        "field": field.name,
                        "type": field.field_type,
                        "value": field.value,
                        "risk": "IDOR - User ID manipulation"
                    })
            
            if sensitive_fields:
                priv_esc_indicators.append({
                    "url": form.action,
                    "source": form.source_url,
                    "method": form.method,
                    "fields": sensitive_fields,
                    "type": "Sensitive Form Fields"
                })
        
        for param in context.attack_surface.url_parameters:
            param_lower = param.name.lower()
            
            if any(x in param_lower for x in ["role", "admin", "level", "user_id", 
                                               "userid", "uid", "account_id", "id"]):
                priv_esc_indicators.append({
                    "url": param.source_url,
                    "param": param.name,
                    "value": param.value,
                    "type": "Sensitive URL Parameter"
                })
        
        for url in list(context.attack_surface.urls)[:20]:
            try:
                response = requests.get(
                    url,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
                
                jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
                matches = re.findall(jwt_pattern, response.text)
                
                if matches:
                    for match in matches[:1]:
                        priv_esc_indicators.append({
                            "url": url,
                            "type": "JWT Token Exposed",
                            "token_preview": match[:50] + "..."
                        })
                        
            except Exception:
                pass
        
        if priv_esc_indicators:
            finding = self.create_finding(
                vuln_name="Privilege Escalation Indicators",
                short_intro=f"Found {len(priv_esc_indicators)} potential privilege escalation vectors. "
                           "Users may be able to gain unauthorized access levels.",
                description=(
                    "The application exposes parameters or fields that could allow users to "
                    "manipulate their privilege level. This includes role parameters in forms, "
                    "user ID parameters (IDOR), or exposed authentication tokens. Attackers "
                    "could modify these to gain administrative access or access other users' data."
                ),
                affected_endpoints=[i["url"] for i in priv_esc_indicators],
                impact=[
                    f"{i['type']}: {i.get('param', i.get('fields', [{}])[0].get('field', 'N/A')) if isinstance(i.get('fields'), list) else 'N/A'}"
                    for i in priv_esc_indicators
                ] + [
                    "Unauthorized administrative access",
                    "Access to other users' data (IDOR)",
                    "Bypass of role-based access controls",
                    "Complete application compromise"
                ],
                proof_of_concept=[
                    "1. Identify role/privilege parameters in forms or URLs",
                    "2. Modify values (e.g., role=admin, is_admin=true)",
                    "3. Submit and check for elevated access",
                    "4. For IDOR: Change user_id to access other accounts"
                ],
                evidence=[{
                    "request": f"Examined: {i['url'][:80]}",
                    "response": f"Type: {i['type']}\n" + 
                               (f"Fields: {[f['field'] for f in i['fields']]}" if 'fields' in i else
                                f"Param: {i.get('param', 'N/A')}")[:200],
                    "description": i['type']
                } for i in priv_esc_indicators[:5]],
                remediation=[
                    "Never trust client-side role/privilege data",
                    "Validate permissions server-side for every request",
                    "Use indirect object references instead of direct IDs",
                    "Implement proper session-based role management",
                    "Use signed tokens for authorization claims",
                    "Audit all privilege-changing operations"
                ],
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema",
                    "https://portswigger.net/web-security/access-control/idor"
                ],
                confidence="Medium",
                suggested_cvss={
                    "AV": "N",
                    "AC": "L",
                    "PR": "L",
                    "UI": "N",
                    "S": "U",
                    "C": "H",
                    "I": "H",
                    "A": "N"
                }
            )
            finding.target_url = context.target_url
            findings.append(finding)
        
        return findings
