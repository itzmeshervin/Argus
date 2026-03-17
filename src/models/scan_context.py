"""Scan context and attack surface models."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any


@dataclass
class FormField:
    """Represents a form field."""
    name: str
    field_type: str
    value: str = ""
    required: bool = False


@dataclass
class Form:
    """Represents an HTML form."""
    action: str
    method: str
    fields: List[FormField] = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"
    source_url: str = ""


@dataclass
class URLParameter:
    """Represents a URL parameter."""
    name: str
    value: str
    source_url: str


@dataclass
class Cookie:
    """Represents a cookie."""
    name: str
    value: str
    domain: str = ""
    path: str = "/"
    secure: bool = False
    httponly: bool = False
    samesite: str = ""


@dataclass
class APIEndpoint:
    """Represents an API endpoint."""
    url: str
    method: str
    content_type: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileUploadEndpoint:
    """Represents a file upload endpoint."""
    url: str
    method: str
    field_name: str
    accepted_types: List[str] = field(default_factory=list)


@dataclass
class AttackSurface:
    """
    Complete attack surface discovered from crawling.
    Contains all injectable points for vulnerability testing.
    """
    urls: Set[str] = field(default_factory=set)
    forms: List[Form] = field(default_factory=list)
    url_parameters: List[URLParameter] = field(default_factory=list)
    cookies: List[Cookie] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    api_endpoints: List[APIEndpoint] = field(default_factory=list)
    file_upload_endpoints: List[FileUploadEndpoint] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "urls": list(self.urls),
            "forms": [{"action": f.action, "method": f.method, 
                      "fields": [{"name": ff.name, "type": ff.field_type, "value": ff.value} 
                                for ff in f.fields],
                      "enctype": f.enctype, "source_url": f.source_url} 
                     for f in self.forms],
            "url_parameters": [{"name": p.name, "value": p.value, "source_url": p.source_url} 
                              for p in self.url_parameters],
            "cookies": [{"name": c.name, "value": c.value, "domain": c.domain, 
                        "path": c.path, "secure": c.secure, "httponly": c.httponly} 
                       for c in self.cookies],
            "headers": self.headers,
            "api_endpoints": [{"url": e.url, "method": e.method, "content_type": e.content_type} 
                             for e in self.api_endpoints],
            "file_upload_endpoints": [{"url": e.url, "method": e.method, "field_name": e.field_name} 
                                     for e in self.file_upload_endpoints]
        }


@dataclass
class ScanContext:
    """
    Context passed to plugins during scanning.
    Contains target information and discovered attack surface.
    """
    target_url: str
    attack_surface: AttackSurface
    scan_level: str = "medium"
    allow_intrusive: bool = False
    rate_limit: float = 0.5
    timeout: int = 10
    user_agent: str = "VulnScanner/1.0"
    session_cookies: Dict[str, str] = field(default_factory=dict)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    def get_all_urls(self) -> List[str]:
        """Get all discovered URLs."""
        return list(self.attack_surface.urls)
    
    def get_all_forms(self) -> List[Form]:
        """Get all discovered forms."""
        return self.attack_surface.forms
    
    def get_all_parameters(self) -> List[URLParameter]:
        """Get all URL parameters."""
        return self.attack_surface.url_parameters
