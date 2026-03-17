"""
File Upload Misconfiguration Detection Plugin.
Uses safe upload of harmless text files.
"""

import uuid
import time
import requests
from typing import List

from src.plugins.base import PluginBase, PluginMetadata
from src.models.finding import Finding
from src.models.scan_context import ScanContext


class FileUploadPlugin(PluginBase):
    """Detects file upload misconfigurations using safe test files."""
    
    def __init__(self):
        super().__init__()
        payloads = self.load_wordlist("file_upload.txt")
        if not payloads:
            payloads = []
        seen = set()
        deduped = []
        for p in payloads:
            if p and p not in seen:
                seen.add(p)
                deduped.append(p)
        self.set_payloads(deduped)
        self.set_payload_limits(low=10, medium=30, high=60)
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="File Upload Misconfiguration",
            id="file-upload-misconfig",
            severity_hint="medium",
            intrusive=False,
            author="VulnScanner Team",
            description="Detects file upload misconfigurations"
        )
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        upload_issues = []
        
        for endpoint in context.attack_surface.file_upload_endpoints[:5]:
            test_results = self._test_upload_endpoint(endpoint, context)
            if test_results:
                upload_issues.extend(test_results)
        
        for form in context.attack_surface.forms[:10]:
            file_fields = [f for f in form.fields if f.field_type == "file"]
            if not file_fields:
                continue
            
            for field in file_fields:
                from src.models.scan_context import FileUploadEndpoint
                endpoint = FileUploadEndpoint(
                    url=form.action,
                    method=form.method,
                    field_name=field.name,
                    accepted_types=[]
                )
                
                test_results = self._test_upload_endpoint(endpoint, context)
                if test_results:
                    upload_issues.extend(test_results)
        
        if upload_issues:
            finding = self.create_finding(
                vuln_name="File Upload Vulnerability Indicators",
                short_intro=f"Found {len(upload_issues)} file upload issues. "
                           "Upload functionality may allow malicious file uploads.",
                description=(
                    "The application's file upload functionality shows signs of misconfiguration. "
                    "While only safe text files were uploaded during testing, the behavior suggests "
                    "that the application may not properly validate file types, extensions, or content. "
                    "Attackers could potentially upload malicious files like web shells."
                ),
                affected_endpoints=[i["url"] for i in upload_issues],
                impact=[
                    f"{i['url']}: {i['issue']}"
                    for i in upload_issues
                ] + [
                    "Malicious files could be uploaded and executed",
                    "Web shells could provide remote access",
                    "Server-side code execution possible",
                    "Storage exhaustion through large file uploads"
                ],
                proof_of_concept=[
                    "1. Locate the file upload form",
                    "2. Attempt to upload a text file",
                    "3. Observe upload behavior and responses",
                    "4. NOTE: Only harmless text files were used in testing"
                ],
                evidence=[{
                    "request": f"POST {i['url']}\nFile: {i.get('filename', 'test.txt')}",
                    "response": i.get("response_snippet", "Upload appeared successful"),
                    "description": i["issue"]
                } for i in upload_issues[:5]],
                remediation=[
                    "Implement strict file type validation (allowlist approach)",
                    "Validate file content, not just extension",
                    "Store uploads outside web root",
                    "Use random filenames, don't preserve original names",
                    "Implement file size limits",
                    "Scan uploads for malware",
                    "Serve files with Content-Disposition: attachment"
                ],
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                    "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
                ],
                confidence="Medium",
                suggested_cvss={
                    "AV": "N",
                    "AC": "L",
                    "PR": "L",
                    "UI": "N",
                    "S": "U",
                    "C": "L",
                    "I": "L",
                    "A": "N"
                }
            )
            finding.target_url = context.target_url
            findings.append(finding)
        
        return findings
    
    def _test_upload_endpoint(self, endpoint, context) -> List[dict]:
        """Test a file upload endpoint with safe files."""
        issues = []
        
        test_id = uuid.uuid4().hex[:8]
        payloads = self.get_payloads_for_level(context.scan_level)
        
        test_files = [{
            "name": f"test_{test_id}.txt",
            "content": b"This is a safe test file for vulnerability scanning.",
            "content_type": "text/plain",
            "issue_if_success": "Text file upload allowed"
        }]
        
        for name in payloads:
            test_files.append({
                "name": f"{name}",
                "content": b"This is a safe test file for vulnerability scanning.",
                "content_type": "text/plain",
                "issue_if_success": f"Suspicious filename accepted ({name})"
            })
        
        for test_file in test_files:
            try:
                files = {
                    endpoint.field_name: (
                        test_file["name"],
                        test_file["content"],
                        test_file["content_type"]
                    )
                }
                
                response = requests.post(
                    endpoint.url,
                    files=files,
                    timeout=context.timeout,
                    headers={"User-Agent": context.user_agent},
                    verify=True
                )
                
                if response.status_code in [200, 201, 302]:
                    if "error" not in response.text.lower() and "invalid" not in response.text.lower():
                        issues.append({
                            "url": endpoint.url,
                            "issue": test_file["issue_if_success"],
                            "filename": test_file["name"],
                            "response_snippet": response.text[:200]
                        })
                
                time.sleep(context.rate_limit)
                
            except Exception as e:
                self.log_debug(f"Error testing upload: {e}")
                continue
        
        return issues
