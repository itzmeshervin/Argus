"""Finding data model for vulnerability results."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
import uuid


@dataclass
class Evidence:
    """Evidence for a vulnerability finding."""
    request: str = ""
    response: str = ""
    description: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Finding:
    """
    Represents a vulnerability finding from a plugin.
    Plugins must populate all required fields but NOT compute CVSS scores.
    """
    vuln_name: str
    short_intro: str
    description: str
    affected_endpoints: List[str]
    impact: List[str]
    proof_of_concept: List[str]
    evidence: List[Evidence]
    remediation: List[str]
    references: List[str]
    confidence: str
    suggested_cvss: Dict[str, str]
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str = ""
    plugin_name: str = ""
    target_url: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    cvss_vector: str = ""
    cvss_score: float = 0.0
    cvss_severity: str = "None"
    
    verified: bool = False
    false_positive: bool = False
    analyst_notes: str = ""
    
    cvss_audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for export."""
        return {
            "id": self.id,
            "vuln_name": self.vuln_name,
            "short_intro": self.short_intro,
            "description": self.description,
            "affected_endpoints": self.affected_endpoints,
            "impact": self.impact,
            "proof_of_concept": self.proof_of_concept,
            "evidence": [{"request": e.request, "response": e.response, 
                         "description": e.description, "timestamp": e.timestamp} 
                        for e in self.evidence],
            "remediation": self.remediation,
            "references": self.references,
            "confidence": self.confidence,
            "suggested_cvss": self.suggested_cvss,
            "plugin_id": self.plugin_id,
            "plugin_name": self.plugin_name,
            "target_url": self.target_url,
            "timestamp": self.timestamp,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "cvss_severity": self.cvss_severity,
            "verified": self.verified,
            "false_positive": self.false_positive,
            "analyst_notes": self.analyst_notes,
            "cvss_audit_trail": self.cvss_audit_trail
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create Finding from dictionary."""
        evidence_list = [Evidence(**e) for e in data.get("evidence", [])]
        finding = cls(
            vuln_name=data.get("vuln_name", ""),
            short_intro=data.get("short_intro", ""),
            description=data.get("description", ""),
            affected_endpoints=data.get("affected_endpoints", []),
            impact=data.get("impact", []),
            proof_of_concept=data.get("proof_of_concept", []),
            evidence=evidence_list,
            remediation=data.get("remediation", []),
            references=data.get("references", []),
            confidence=data.get("confidence", "Low"),
            suggested_cvss=data.get("suggested_cvss", {})
        )
        finding.id = data.get("id", finding.id)
        finding.plugin_id = data.get("plugin_id", "")
        finding.plugin_name = data.get("plugin_name", "")
        finding.target_url = data.get("target_url", "")
        finding.timestamp = data.get("timestamp", finding.timestamp)
        finding.cvss_vector = data.get("cvss_vector", "")
        finding.cvss_score = data.get("cvss_score", 0.0)
        finding.cvss_severity = data.get("cvss_severity", "None")
        finding.verified = data.get("verified", False)
        finding.false_positive = data.get("false_positive", False)
        finding.analyst_notes = data.get("analyst_notes", "")
        finding.cvss_audit_trail = data.get("cvss_audit_trail", [])
        return finding
