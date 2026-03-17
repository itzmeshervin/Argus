"""
Directory Indexing Detection Plugin.
Detects enabled directory listing.
"""

import re
import requests
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class DirectoryIndexingPlugin(PluginBase):
    """Detects enabled directory indexing/listing."""
    
    COMMON_DIRS = [
        "/images/", "/img/", "/assets/", "/static/", "/css/", "/js/",
        "/uploads/", "/files/", "/backup/", "/temp/", "/tmp/",
        "/admin/", "/include/", "/includes/", "/lib/", "/scripts/"
    ]
    
    INDEXING_INDICATORS = [
        "Index of /",
        "Directory listing for",
        "<title>Index of",
        "Parent Directory</a>",
        "[To Parent Directory]",
        "Directory Listing",
        "<h1>Index of"
    ]
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Directory Indexing",
            id="directory-indexing",
            severity_hint="low",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects enabled directory listing"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        indexed_dirs = []
        
        dirs_to_check = list(self.COMMON_DIRS)
        
        for url in list(context.attack_surface.urls)[:20]:
            path = url.replace(context.target_url, "")
            if "/" in path:
                dir_path = "/".join(path.split("/")[:-1]) + "/"
                if dir_path and dir_path not in dirs_to_check:
                    dirs_to_check.append(dir_path)
        
        for dir_path in dirs_to_check[:30]:
            try:
                url = f"{context.target_url.rstrip('/')}{dir_path}"
                response = requests.get(
                    url,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True,
                    allow_redirects=False
                )
                
                if response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "")
                    if "text/html" not in content_type:
                        continue
                    for indicator in self.INDEXING_INDICATORS:
                        if indicator.lower() in response.text.lower():
                            indexed_dirs.append({
                                "url": url,
                                "indicator": indicator,
                                "snippet": response.text[:500]
                            })
                            break
                            
            except Exception as e:
                self.log_debug(f"Error checking {dir_path}: {e}")
                continue
        
        if indexed_dirs:
            finding = self.create_finding(
                vuln_name="Directory Indexing Enabled",
                short_intro=f"Found {len(indexed_dirs)} directories with listing enabled. "
                           "This exposes file structure and potentially sensitive files.",
                description=(
                    "Directory indexing (directory listing) is enabled on the web server, "
                    "allowing anyone to browse the contents of directories. This can expose "
                    "sensitive files, backup files, configuration files, and internal "
                    "application structure to attackers."
                ),
                affected_endpoints=[d["url"] for d in indexed_dirs],
                impact=[
                    "Exposure of directory structure and file names",
                    "Potential access to backup files (.bak, .old, .zip)",
                    "Exposure of configuration files",
                    "Information gathering for further attacks",
                    "Possible exposure of sensitive data in files"
                ],
                proof_of_concept=[
                    f"1. Navigate to one of the following URLs:",
                    *[f"   - {d['url']}" for d in indexed_dirs[:5]],
                    "2. Observe the directory listing showing all files",
                    "3. Browse through files and identify sensitive content"
                ],
                evidence=[{
                    "request": f"GET {d['url']}",
                    "response": d["snippet"][:200] + "...",
                    "description": f"Directory listing at {d['url']}"
                } for d in indexed_dirs[:3]],
                remediation=[
                    "Disable directory indexing in web server configuration",
                    "For Apache: Options -Indexes in .htaccess or httpd.conf",
                    "For Nginx: autoindex off; in server block",
                    "Add index files (index.html) to all directories",
                    "Review and remove unnecessary files from web directories"
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
                    "C": "L",
                    "I": "N",
                    "A": "N"
                }
            )
            finding.target_url = context.target_url
            findings.append(finding)
        
        return findings
