"""
CVSS v3.1 Calculator Engine.
Computes CVSS vector strings, scores, and severity from metrics.
"""

from typing import Dict, Tuple
from src.models.cvss import CVSSMetrics, CVSSResult


class CVSSCalculator:
    """
    CVSS v3.1 Score Calculator.
    Based on the official CVSS v3.1 specification.
    """
    
    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    CIA_WEIGHTS = {"N": 0, "L": 0.22, "H": 0.56}
    
    SEVERITY_RANGES = [
        (0.0, "None"),
        (0.1, "Low"),
        (4.0, "Medium"),
        (7.0, "High"),
        (9.0, "Critical")
    ]
    
    @classmethod
    def calculate(cls, metrics: CVSSMetrics) -> CVSSResult:
        """
        Calculate CVSS score from metrics.
        Returns CVSSResult with vector, score, and severity.
        """
        if not metrics.validate():
            return CVSSResult(
                vector="INVALID",
                score=0.0,
                severity="None",
                metrics=metrics
            )
        
        vector = cls._build_vector(metrics)
        score = cls._calculate_score(metrics)
        severity = cls._get_severity(score)
        
        return CVSSResult(
            vector=vector,
            score=score,
            severity=severity,
            metrics=metrics
        )
    
    @classmethod
    def _build_vector(cls, metrics: CVSSMetrics) -> str:
        """Build CVSS v3.1 vector string."""
        return (f"CVSS:3.1/AV:{metrics.AV}/AC:{metrics.AC}/PR:{metrics.PR}/"
                f"UI:{metrics.UI}/S:{metrics.S}/C:{metrics.C}/I:{metrics.I}/A:{metrics.A}")
    
    @classmethod
    def _calculate_score(cls, metrics: CVSSMetrics) -> float:
        """Calculate numeric CVSS score."""
        iss = cls._calculate_iss(metrics)
        
        if iss <= 0:
            return 0.0
        
        exploitability = cls._calculate_exploitability(metrics)
        impact = cls._calculate_impact(metrics, iss)
        
        if metrics.S == "U":
            score = min(impact + exploitability, 10)
        else:
            score = min(1.08 * (impact + exploitability), 10)
        
        return round(score * 10) / 10
    
    @classmethod
    def _calculate_iss(cls, metrics: CVSSMetrics) -> float:
        """Calculate Impact Sub-Score."""
        c = cls.CIA_WEIGHTS[metrics.C]
        i = cls.CIA_WEIGHTS[metrics.I]
        a = cls.CIA_WEIGHTS[metrics.A]
        return 1 - ((1 - c) * (1 - i) * (1 - a))
    
    @classmethod
    def _calculate_exploitability(cls, metrics: CVSSMetrics) -> float:
        """Calculate Exploitability sub-score."""
        av = cls.AV_WEIGHTS[metrics.AV]
        ac = cls.AC_WEIGHTS[metrics.AC]
        
        if metrics.S == "U":
            pr = cls.PR_WEIGHTS_UNCHANGED[metrics.PR]
        else:
            pr = cls.PR_WEIGHTS_CHANGED[metrics.PR]
        
        ui = cls.UI_WEIGHTS[metrics.UI]
        
        return 8.22 * av * ac * pr * ui
    
    @classmethod
    def _calculate_impact(cls, metrics: CVSSMetrics, iss: float) -> float:
        """Calculate Impact score based on scope."""
        if metrics.S == "U":
            return 6.42 * iss
        else:
            return 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
    
    @classmethod
    def _get_severity(cls, score: float) -> str:
        """Get severity rating from score."""
        severity = "None"
        for threshold, rating in cls.SEVERITY_RANGES:
            if score >= threshold:
                severity = rating
        return severity
    
    @classmethod
    def parse_vector(cls, vector: str) -> CVSSMetrics:
        """Parse CVSS vector string to metrics."""
        metrics_dict = {}
        
        if not vector.startswith("CVSS:3."):
            return CVSSMetrics()
        
        parts = vector.split("/")[1:]
        for part in parts:
            if ":" in part:
                key, value = part.split(":", 1)
                metrics_dict[key] = value
        
        return CVSSMetrics.from_dict(metrics_dict)
    
    @classmethod
    def recalculate_from_vector(cls, vector: str) -> CVSSResult:
        """Recalculate score from vector string."""
        metrics = cls.parse_vector(vector)
        return cls.calculate(metrics)
