"""
Base plugin class and metadata definitions.
All vulnerability plugins must inherit from PluginBase.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import logging
import os

from src.models.finding import Finding
from src.models.scan_context import ScanContext


logger = logging.getLogger(__name__)


@dataclass
class PluginMetadata:
    """
    Plugin metadata required for all vulnerability plugins.
    """
    name: str
    id: str
    severity_hint: str
    intrusive: bool = False
    author: str = "VulnScanner Team"
    description: str = ""
    version: str = "1.0.0"
    
    def validate(self) -> bool:
        """Validate metadata values."""
        valid_severities = ["low", "medium", "high"]
        return (
            bool(self.name) and 
            bool(self.id) and 
            self.severity_hint.lower() in valid_severities
        )


class PluginBase(ABC):
    """
    Abstract base class for all vulnerability detection plugins.
    
    Plugins must:
    1. Define metadata with name, id, severity_hint, intrusive flag
    2. Implement analyze() method returning list of Finding objects
    3. NOT compute or print CVSS scores (core engine handles this)
    """
    
    def __init__(self):
        self._metadata: Optional[PluginMetadata] = None
        self._payloads: List[str] = []
        self._payload_limits = {"low": 50, "medium": 200, "high": None}
    
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        pass
    
    @abstractmethod
    def analyze(self, context: ScanContext) -> List[Finding]:
        """
        Perform vulnerability analysis.
        
        Args:
            context: ScanContext with target info and attack surface
            
        Returns:
            List of Finding objects (never print CVSS scores)
        """
        pass
    
    def should_run(self, scan_level: str, allow_intrusive: bool) -> bool:
        """
        Determine if plugin should run based on scan level and intrusive setting.
        """
        meta = self.metadata
        severity = meta.severity_hint.lower()
        
        if meta.intrusive and not allow_intrusive:
            return False
        
        level_map = {
            "low": ["low"],
            "medium": ["low", "medium"],
            "high": ["low", "medium", "high"]
        }
        
        allowed = level_map.get(scan_level.lower(), [])
        return severity in allowed
    
    def create_finding(
        self,
        vuln_name: str,
        short_intro: str,
        description: str,
        affected_endpoints: List[str],
        impact: List[str],
        proof_of_concept: List[str],
        evidence: List[Dict[str, str]],
        remediation: List[str],
        references: List[str],
        confidence: str,
        suggested_cvss: Dict[str, str]
    ) -> Finding:
        """
        Helper method to create a properly formatted Finding.
        """
        from src.models.finding import Evidence
        
        evidence_objs = [
            Evidence(
                request=e.get("request", ""),
                response=e.get("response", ""),
                description=e.get("description", "")
            )
            for e in evidence
        ]
        
        finding = Finding(
            vuln_name=vuln_name,
            short_intro=short_intro,
            description=description,
            affected_endpoints=affected_endpoints,
            impact=impact,
            proof_of_concept=proof_of_concept,
            evidence=evidence_objs,
            remediation=remediation,
            references=references,
            confidence=confidence,
            suggested_cvss=suggested_cvss,
            plugin_id=self.metadata.id,
            plugin_name=self.metadata.name
        )
        
        return finding
    
    def set_payloads(self, payloads: List[str]):
        """Set payload list for this plugin."""
        self._payloads = payloads
    
    def set_payload_limits(self, low: int = 50, medium: int = 200, high: Optional[int] = None):
        """Set payload caps by scan level. Use None for no cap."""
        self._payload_limits = {"low": low, "medium": medium, "high": high}
    
    def get_payloads_for_level(self, scan_level: str) -> List[str]:
        """Return payloads capped by scan level."""
        limit = self._payload_limits.get(scan_level.lower())
        if limit is None:
            return list(self._payloads)
        return list(self._payloads[:limit])
    
    def get_payload_count(self, scan_level: str) -> int:
        """Return payload count for the given scan level."""
        return len(self.get_payloads_for_level(scan_level))
    
    def load_wordlist(self, *relative_parts: str) -> List[str]:
        """Load a wordlist file from src/wordlists. Returns list of non-empty lines."""
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "wordlists"))
        path = os.path.join(base_dir, *relative_parts)
        if not os.path.exists(path):
            return []
        items: List[str] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        items.append(line)
        except Exception:
            return []
        return items
    
    def log_debug(self, message: str):
        """Log debug message with plugin context."""
        logger.debug(f"[{self.metadata.id}] {message}")
    
    def log_info(self, message: str):
        """Log info message with plugin context."""
        logger.info(f"[{self.metadata.id}] {message}")
    
    def log_warning(self, message: str):
        """Log warning message with plugin context."""
        logger.warning(f"[{self.metadata.id}] {message}")
