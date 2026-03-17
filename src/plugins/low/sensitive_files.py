"""
Sensitive File Exposure Detection Plugin.
Detects exposed sensitive files.
"""

import requests
from typing import List, Dict

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class SensitiveFilesPlugin(PluginBase):
    """Detects exposed sensitive files."""
    
    SENSITIVE_FILES = {
        ".env": {"severity": "critical", "description": "Environment configuration with secrets"},
        ".git/config": {"severity": "high", "description": "Git repository configuration"},
        ".git/HEAD": {"severity": "high", "description": "Git repository HEAD reference"},
        ".svn/entries": {"severity": "high", "description": "SVN repository metadata"},
        ".htaccess": {"severity": "medium", "description": "Apache configuration file"},
        ".htpasswd": {"severity": "critical", "description": "Apache password file"},
        "wp-config.php": {"severity": "critical", "description": "WordPress configuration"},
        "config.php": {"severity": "high", "description": "PHP configuration file"},
        "database.yml": {"severity": "critical", "description": "Database configuration"},
        "config.yml": {"severity": "high", "description": "YAML configuration file"},
        "settings.py": {"severity": "high", "description": "Python settings file"},
        "web.config": {"severity": "high", "description": "IIS configuration file"},
        "phpinfo.php": {"severity": "medium", "description": "PHP information page"},
        "info.php": {"severity": "medium", "description": "PHP information page"},
        "backup.sql": {"severity": "critical", "description": "Database backup file"},
        "backup.zip": {"severity": "high", "description": "Backup archive"},
        "dump.sql": {"severity": "critical", "description": "Database dump"},
        ".DS_Store": {"severity": "low", "description": "macOS directory metadata"},
        "Thumbs.db": {"severity": "low", "description": "Windows thumbnail cache"},
        "crossdomain.xml": {"severity": "medium", "description": "Flash cross-domain policy"},
        "clientaccesspolicy.xml": {"severity": "medium", "description": "Silverlight policy"},
        ".well-known/security.txt": {"severity": "info", "description": "Security contact info"},
        "robots.txt": {"severity": "info", "description": "Robots exclusion file"},
        "sitemap.xml": {"severity": "info", "description": "Site map file"},
        "server-status": {"severity": "medium", "description": "Apache server status"},
        "server-info": {"severity": "medium", "description": "Apache server info"},
        "composer.json": {"severity": "low", "description": "PHP Composer dependencies"},
        "package.json": {"severity": "low", "description": "Node.js package file"},
        "Gemfile": {"severity": "low", "description": "Ruby Gem dependencies"},
        "requirements.txt": {"severity": "low", "description": "Python requirements"},
    }
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Sensitive File Exposure",
            id="sensitive-files",
            severity_hint="low",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects exposed sensitive files"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        exposed_files: List[Dict] = []
        
        for file_path, info in self.SENSITIVE_FILES.items():
            try:
                url = f"{context.target_url.rstrip('/')}/{file_path}"
                response = requests.get(
                    url,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True,
                    allow_redirects=False
                )
                
                if response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "")
                    
                    if "text/html" in content_type and "404" in response.text.lower():
                        continue
                    if "error" in response.text.lower()[:200] and response.status_code == 200:
                        if len(response.text) < 500:
                            continue
                    
                    exposed_files.append({
                        "file": file_path,
                        "url": url,
                        "severity": info["severity"],
                        "description": info["description"],
                        "size": len(response.content),
                        "content_preview": response.text[:200] if len(response.text) > 0 else ""
                    })
                    
            except Exception as e:
                self.log_debug(f"Error checking {file_path}: {e}")
                continue
        
        if exposed_files:
            actionable_files = [f for f in exposed_files if f["severity"] not in ("info",)]
            if not actionable_files:
                return findings
            
            critical_files = [f for f in actionable_files if f["severity"] == "critical"]
            high_files = [f for f in actionable_files if f["severity"] == "high"]
            
            finding = self.create_finding(
                vuln_name="Sensitive File Exposure",
                short_intro=f"Found {len(actionable_files)} sensitive files publicly accessible. "
                           f"{len(critical_files)} are critical, {len(high_files)} are high severity.",
                description=(
                    "Sensitive files are accessible without authentication. These files may "
                    "contain credentials, configuration details, source code, or backup data "
                    "that could be used to compromise the application or underlying systems."
                ),
                affected_endpoints=[f["url"] for f in actionable_files],
                impact=[
                    f"{f['file']}: {f['description']} ({f['severity']})"
                    for f in actionable_files
                ],
                proof_of_concept=[
                    "1. Access the following URLs directly:",
                    *[f"   - {f['url']}" for f in actionable_files[:5]],
                    "2. Observe that sensitive content is returned",
                    "3. Review file contents for credentials or sensitive data"
                ],
                evidence=[{
                    "request": f"GET {f['url']}",
                    "response": f"Size: {f['size']} bytes\nPreview: {f['content_preview'][:100]}...",
                    "description": f"{f['description']}"
                } for f in actionable_files[:5]],
                remediation=[
                    "Remove sensitive files from web-accessible directories",
                    "Configure web server to deny access to sensitive file types",
                    "Use .htaccess or web.config to block access to config files",
                    "Move backup files outside the web root",
                    "Implement proper access controls for all sensitive resources",
                    "Regularly audit web directories for exposed files"
                ],
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"
                ],
                confidence="High",
                suggested_cvss={
                    "AV": "N",
                    "AC": "L",
                    "PR": "N",
                    "UI": "N",
                    "S": "U",
                    "C": "H" if critical_files else "L",
                    "I": "N",
                    "A": "N"
                }
            )
            finding.target_url = context.target_url
            findings.append(finding)
        
        return findings
