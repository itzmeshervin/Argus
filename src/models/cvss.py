"""CVSS v3.1 metrics and result models."""

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class CVSSMetrics:
    """
    CVSS v3.1 Base Metrics.
    AV: Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)
    AC: Attack Complexity (L=Low, H=High)
    PR: Privileges Required (N=None, L=Low, H=High)
    UI: User Interaction (N=None, R=Required)
    S: Scope (U=Unchanged, C=Changed)
    C: Confidentiality Impact (N=None, L=Low, H=High)
    I: Integrity Impact (N=None, L=Low, H=High)
    A: Availability Impact (N=None, L=Low, H=High)
    """
    AV: str = "N"
    AC: str = "L"
    PR: str = "N"
    UI: str = "N"
    S: str = "U"
    C: str = "N"
    I: str = "N"
    A: str = "N"
    
    VALID_VALUES = {
        "AV": ["N", "A", "L", "P"],
        "AC": ["L", "H"],
        "PR": ["N", "L", "H"],
        "UI": ["N", "R"],
        "S": ["U", "C"],
        "C": ["N", "L", "H"],
        "I": ["N", "L", "H"],
        "A": ["N", "L", "H"]
    }
    
    def validate(self) -> bool:
        """Validate all metric values."""
        return all(
            getattr(self, metric) in values 
            for metric, values in self.VALID_VALUES.items()
        )
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'CVSSMetrics':
        """Create metrics from dictionary with defaults for missing values."""
        return cls(
            AV=data.get("AV", "N"),
            AC=data.get("AC", "L"),
            PR=data.get("PR", "N"),
            UI=data.get("UI", "N"),
            S=data.get("S", "U"),
            C=data.get("C", "N"),
            I=data.get("I", "N"),
            A=data.get("A", "N")
        )
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary."""
        return {
            "AV": self.AV,
            "AC": self.AC,
            "PR": self.PR,
            "UI": self.UI,
            "S": self.S,
            "C": self.C,
            "I": self.I,
            "A": self.A
        }


@dataclass
class CVSSResult:
    """Result of CVSS calculation."""
    vector: str
    score: float
    severity: str
    metrics: CVSSMetrics
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "vector": self.vector,
            "score": self.score,
            "severity": self.severity,
            "metrics": self.metrics.to_dict()
        }
