import requests
from typing import List
from http.cookies import SimpleCookie

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class CookieMisconfigPlugin(PluginBase):
    """Detects cookie security misconfigurations."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Cookie Misconfiguration",
            id="cookie-misconfig",
            severity_hint="low",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects insecure cookie configurations"
        )

    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []

        try:
            response = requests.get(
                context.target_url,
                timeout=context.timeout,
                headers={"User-Agent": context.user_agent},
                allow_redirects=True,
                verify=True
            )

            raw_cookies = response.headers.get_all("Set-Cookie") \
                if hasattr(response.headers, "get_all") \
                else response.headers.get("Set-Cookie", "").split(",")

            cookies_with_issues = []

            for raw in raw_cookies:
                cookie = SimpleCookie()
                cookie.load(raw)

                for name, morsel in cookie.items():
                    issues = []

                    is_https = context.target_url.startswith("https")

                    secure = "secure" in raw.lower()
                    httponly = "httponly" in raw.lower()
                    samesite = morsel["samesite"].lower() if morsel["samesite"] else None
                    domain = morsel["domain"]
                    path = morsel["path"]
                    max_age = morsel["max-age"]
                    expires = morsel["expires"]

                    # Secure flag
                    if is_https and not secure:
                        issues.append("Missing Secure flag")

                    # HttpOnly
                    if not httponly:
                        issues.append("Missing HttpOnly flag")

                    # SameSite logic
                    if not samesite:
                        issues.append("Missing SameSite attribute")
                    elif samesite == "none" and not secure:
                        issues.append("SameSite=None without Secure flag")

                    # Domain scope
                    if domain and domain.startswith("."):
                        issues.append(f"Overly broad domain scope ({domain})")

                    # Path scope
                    if path == "/":
                        issues.append("Cookie path set to '/' (overly permissive)")

                    # Session fixation
                    if not max_age and not expires:
                        issues.append("Session cookie without Max-Age or Expires")

                    # Prefix checks
                    if name.startswith("__Host-"):
                        if domain or path != "/" or not secure:
                            issues.append("__Host- prefix misused")
                    if name.startswith("__Secure-") and not secure:
                        issues.append("__Secure- prefix without Secure flag")

                    if issues:
                        cookies_with_issues.append({
                            "name": name,
                            "issues": issues,
                            "raw": raw[:200]
                        })

            if cookies_with_issues:
                finding = self.create_finding(
                    vuln_name="Insecure Cookie Configuration",
                    short_intro=f"Detected {len(cookies_with_issues)} cookies with security weaknesses.",
                    description=(
                        "Cookies lacking proper security attributes can be abused for session hijacking, "
                        "CSRF, and cross-subdomain attacks. Each affected cookie is listed with specific issues."
                    ),
                    affected_endpoints=[context.target_url],
                    impact=[f"{c['name']}: {', '.join(c['issues'])}" for c in cookies_with_issues],
                    proof_of_concept=[
                        f"1. Send a request to {context.target_url}",
                        "2. Inspect the Set-Cookie headers",
                        "3. Identify missing or weak cookie attributes"
                    ],
                    evidence=[{
                        "request": f"GET {context.target_url}",
                        "response": "\n".join(
                            f"Set-Cookie: {c['raw']} → Issues: {', '.join(c['issues'])}"
                            for c in cookies_with_issues
                        )
                    }],
                    remediation=[
                        "Always set Secure on cookies served over HTTPS",
                        "Use HttpOnly for session and auth cookies",
                        "Set SameSite=Lax or Strict unless cross-site usage is required",
                        "Avoid broad Domain attributes unless necessary",
                        "Use __Host- and __Secure- prefixes correctly"
                    ],
                    references=[
                        "https://owasp.org/www-community/controls/SecureCookieAttribute",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"
                    ],
                    confidence="High",
                    suggested_cvss={
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        "score": "5.3",
                        "severity": "Medium"
                    }
                )

                finding.target_url = context.target_url
                findings.append(finding)

        except Exception as e:
            self.log_warning(f"Cookie scan failed: {e}")

        return findings
