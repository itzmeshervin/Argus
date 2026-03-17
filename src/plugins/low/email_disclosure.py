"""
Email Disclosure Detection Plugin.
Detects exposed email addresses.
"""

import re
import requests
from typing import List, Set

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class EmailDisclosurePlugin(PluginBase):
    """Detects email address disclosure."""
    
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    COMMON_GENERIC = {
        "info@", "contact@", "support@", "help@", "sales@",
        "admin@", "webmaster@", "noreply@", "no-reply@"
    }
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Email Disclosure",
            id="email-disclosure",
            severity_hint="low",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects email address disclosure"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        emails_found: Set[str] = set()
        email_locations: dict = {}
        
        urls_to_check = list(context.attack_surface.urls)[:30]
        
        for url in urls_to_check:
            try:
                response = requests.get(
                    url,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
                
                matches = re.findall(self.EMAIL_PATTERN, response.text)
                
                for email in matches:
                    email_lower = email.lower()
                    if not any(email_lower.endswith(ext) for ext in ['.png', '.jpg', '.gif', '.css', '.js']):
                        emails_found.add(email)
                        if email not in email_locations:
                            email_locations[email] = []
                        email_locations[email].append(url)
                        
            except Exception as e:
                self.log_debug(f"Error checking {url}: {e}")
                continue
        
        personal_emails = [e for e in emails_found 
                         if not any(e.lower().startswith(g) for g in self.COMMON_GENERIC)]
        
        if emails_found:
            finding = self.create_finding(
                vuln_name="Email Address Disclosure",
                short_intro=f"Found {len(emails_found)} email addresses exposed on the website. "
                           f"{len(personal_emails)} appear to be personal/staff emails.",
                description=(
                    "Email addresses are exposed on the website. While contact emails may be "
                    "intentional, personal staff emails can be used for targeted phishing, "
                    "social engineering, or included in spam lists. Attackers often harvest "
                    "emails from websites to build targeted attack campaigns."
                ),
                affected_endpoints=list(set(url for urls in email_locations.values() for url in urls))[:10],
                impact=[
                    f"Found {len(emails_found)} total email addresses",
                    f"Found {len(personal_emails)} potentially personal/staff emails",
                    "Risk of targeted phishing attacks",
                    "Risk of social engineering attempts",
                    "Potential spam and unwanted communications"
                ],
                proof_of_concept=[
                    "1. Browse the website pages",
                    "2. Search for email patterns in page content",
                    f"3. Identified emails: {', '.join(list(emails_found)[:5])}"
                ],
                evidence=[{
                    "request": f"GET {email_locations[email][0]}",
                    "response": f"Email found: {email}",
                    "description": f"Email address disclosed"
                } for email in list(emails_found)[:5]],
                remediation=[
                    "Use contact forms instead of exposing email addresses",
                    "Obfuscate emails using JavaScript or encoding",
                    "Use generic role-based emails (support@, info@) instead of personal",
                    "Implement CAPTCHA on contact forms to prevent harvesting",
                    "Consider using email aliasing services"
                ],
                references=[
                    "https://owasp.org/www-community/attacks/Spamming"
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
        
        return findings
