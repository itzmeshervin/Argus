"""
Subdomain Takeover Detection Plugin.
Detects potential subdomain takeover vulnerabilities.
"""

import requests
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class SubdomainTakeoverPlugin(PluginBase):
    """Detects potential subdomain takeover signals."""
    
    TAKEOVER_SIGNATURES = {
        "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
        "GitHub Pages": ["There isn't a GitHub Pages site here", "For root URLs"],
        "Heroku": ["No such app", "herokucdn.com"],
        "Azure": ["404 Web Site not found"],
        "Shopify": ["Sorry, this shop is currently unavailable"],
        "Tumblr": ["Whatever you were looking for doesn't currently exist"],
        "WordPress.com": ["Do you want to register"],
        "Fastly": ["Fastly error: unknown domain"],
        "Pantheon": ["404 error unknown site"],
        "Zendesk": ["Help Center Closed"],
        "Unbounce": ["The requested URL was not found on this server"],
        "Ghost": ["The thing you were looking for is no longer here"],
    }
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Subdomain Takeover Signals",
            id="subdomain-takeover",
            severity_hint="medium",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects potential subdomain takeover vulnerabilities"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        takeover_candidates = []
        
        try:
            response = requests.get(
                context.target_url,
                timeout=context.timeout,
                headers={"User-Agent": context.user_agent},
                verify=True
            )
            
            for service, signatures in self.TAKEOVER_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in response.text.lower():
                        takeover_candidates.append({
                            "url": context.target_url,
                            "service": service,
                            "signature": sig,
                            "status_code": response.status_code
                        })
                        break
                        
        except requests.exceptions.SSLError:
            takeover_candidates.append({
                "url": context.target_url,
                "service": "Unknown (SSL Error)",
                "signature": "SSL certificate error - possible dangling record",
                "status_code": "SSL Error"
            })
        except requests.exceptions.ConnectionError as e:
            if "NXDOMAIN" in str(e) or "Name or service not known" in str(e):
                takeover_candidates.append({
                    "url": context.target_url,
                    "service": "Unknown (NXDOMAIN)",
                    "signature": "Domain does not resolve - possible dangling record",
                    "status_code": "NXDOMAIN"
                })
        except Exception as e:
            self.log_debug(f"Error checking target: {e}")
        
        if takeover_candidates:
            finding = self.create_finding(
                vuln_name="Potential Subdomain Takeover",
                short_intro=f"Found {len(takeover_candidates)} potential subdomain takeover signals. "
                           "Attackers could claim these subdomains.",
                description=(
                    "The target shows signs of a potential subdomain takeover vulnerability. "
                    "This occurs when a subdomain points to an external service that is no longer "
                    "in use or configured. An attacker could register the unclaimed resource and "
                    "serve malicious content from your domain, leading to phishing, cookie theft, "
                    "or reputation damage."
                ),
                affected_endpoints=[c["url"] for c in takeover_candidates],
                impact=[
                    f"{c['url']}: {c['service']} - {c['signature'][:50]}"
                    for c in takeover_candidates
                ] + [
                    "Attackers could host phishing pages on your domain",
                    "Cookies could be stolen via subdomain cookie scope",
                    "Email could be intercepted if MX records are affected",
                    "Brand reputation damage"
                ],
                proof_of_concept=[
                    f"1. Access {takeover_candidates[0]['url']}",
                    f"2. Observe the response indicating unclaimed resource",
                    f"3. Service detected: {takeover_candidates[0]['service']}",
                    "4. Verify the DNS record points to this service"
                ],
                evidence=[{
                    "request": f"GET {c['url']}",
                    "response": f"Status: {c['status_code']}\nSignature: {c['signature']}",
                    "description": f"Potential {c['service']} takeover"
                } for c in takeover_candidates],
                remediation=[
                    "Remove DNS records pointing to unused services",
                    "Regularly audit subdomain configurations",
                    "Properly decommission cloud resources before removing DNS",
                    "Implement subdomain monitoring",
                    "Use DNS CAA records to restrict certificate issuance"
                ],
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                    "https://github.com/EdOverflow/can-i-take-over-xyz"
                ],
                confidence="Medium",
                suggested_cvss={
                    "AV": "N",
                    "AC": "L",
                    "PR": "N",
                    "UI": "N",
                    "S": "C",
                    "C": "L",
                    "I": "L",
                    "A": "N"
                }
            )
            finding.target_url = context.target_url
            findings.append(finding)
        
        return findings
