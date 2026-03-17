"""
Report Export Module.
Generates HTML, PDF, JSON, and CSV reports.
"""

import os
import json
import csv
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from jinja2 import Template

from src.models.finding import Finding


class ReportExporter:
    """
    Export scan results in multiple formats.
    Supports HTML, PDF, JSON, and CSV exports.
    """
    
    HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {{ target_url }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 40px 20px; margin-bottom: 30px; border-radius: 10px; }
        header h1 { font-size: 2.5em; margin-bottom: 10px; }
        header .meta { opacity: 0.9; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .summary-card.critical { border-top: 4px solid #dc3545; }
        .summary-card.high { border-top: 4px solid #fd7e14; }
        .summary-card.medium { border-top: 4px solid #ffc107; }
        .summary-card.low { border-top: 4px solid #28a745; }
        .summary-card .number { font-size: 2.5em; font-weight: bold; }
        .summary-card .label { color: #666; text-transform: uppercase; font-size: 0.85em; }
        .finding { background: white; margin-bottom: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
        .finding-header { padding: 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #eee; }
        .finding-header h2 { font-size: 1.3em; }
        .severity-badge { padding: 5px 15px; border-radius: 20px; font-weight: bold; font-size: 0.85em; color: white; }
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; color: #333; }
        .severity-low { background: #28a745; }
        .severity-none { background: #6c757d; }
        .finding-body { padding: 20px; }
        .finding-section { margin-bottom: 20px; }
        .finding-section h3 { color: #1a1a2e; margin-bottom: 10px; font-size: 1.1em; border-bottom: 2px solid #eee; padding-bottom: 5px; }
        .finding-section ul { margin-left: 20px; }
        .finding-section li { margin-bottom: 5px; }
        .cvss-info { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 10px; }
        .cvss-score { font-size: 1.5em; font-weight: bold; }
        .evidence { background: #1a1a2e; color: #00ff00; padding: 15px; border-radius: 5px; font-family: monospace; font-size: 0.9em; overflow-x: auto; white-space: pre-wrap; }
        .endpoint-list { background: #f8f9fa; padding: 10px; border-radius: 5px; }
        .endpoint-list code { background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
        footer { text-align: center; padding: 40px; color: #666; }
        @media print { body { background: white; } .finding { break-inside: avoid; } }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Vulnerability Scan Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> {{ target_url }}</p>
                <p><strong>Scan Level:</strong> {{ scan_level | upper }}</p>
                <p><strong>Date:</strong> {{ scan_date }}</p>
                <p><strong>Duration:</strong> {{ duration }}</p>
            </div>
        </header>
        
        <div class="summary">
            <div class="summary-card critical">
                <div class="number">{{ severity_counts.Critical }}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="number">{{ severity_counts.High }}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{{ severity_counts.Medium }}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="number">{{ severity_counts.Low }}</div>
                <div class="label">Low</div>
            </div>
        </div>
        
        <h2 style="margin-bottom: 20px;">Findings ({{ findings|length }} total)</h2>
        
        {% for finding in findings %}
        <div class="finding">
            <div class="finding-header">
                <h2>{{ finding.vuln_name }}</h2>
                <span class="severity-badge severity-{{ finding.cvss_severity|lower }}">
                    {{ finding.cvss_severity }} ({{ finding.cvss_score }})
                </span>
            </div>
            <div class="finding-body">
                <div class="finding-section">
                    <h3>Summary</h3>
                    <p>{{ finding.short_intro }}</p>
                </div>
                
                <div class="finding-section">
                    <h3>Description</h3>
                    <p>{{ finding.description }}</p>
                </div>
                
                <div class="finding-section">
                    <h3>Affected Endpoints</h3>
                    <div class="endpoint-list">
                        {% for endpoint in finding.affected_endpoints[:5] %}
                        <code>{{ endpoint }}</code><br>
                        {% endfor %}
                    </div>
                </div>
                
                <div class="finding-section">
                    <h3>Impact</h3>
                    <ul>
                        {% for impact in finding.impact %}
                        <li>{{ impact }}</li>
                        {% endfor %}
                    </ul>
                </div>
                
                <div class="finding-section">
                    <h3>Proof of Concept</h3>
                    <ol>
                        {% for step in finding.proof_of_concept %}
                        <li>{{ step }}</li>
                        {% endfor %}
                    </ol>
                </div>
                
                {% if finding.evidence %}
                <div class="finding-section">
                    <h3>Evidence</h3>
                    {% for evidence in finding.evidence[:2] %}
                    <div class="evidence">Request: {{ evidence.request[:200] }}...
Response: {{ evidence.response[:200] }}...</div>
                    {% endfor %}
                </div>
                {% endif %}
                
                <div class="finding-section">
                    <h3>Remediation</h3>
                    <ul>
                        {% for step in finding.remediation %}
                        <li>{{ step }}</li>
                        {% endfor %}
                    </ul>
                </div>
                
                <div class="cvss-info">
                    <strong>CVSS v3.1:</strong> <span class="cvss-score">{{ finding.cvss_score }}</span><br>
                    <strong>Vector:</strong> <code>{{ finding.cvss_vector }}</code><br>
                    <strong>Confidence:</strong> {{ finding.confidence }}
                </div>
                
                {% if finding.references %}
                <div class="finding-section" style="margin-top: 15px;">
                    <h3>References</h3>
                    <ul>
                        {% for ref in finding.references %}
                        <li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>
                        {% endfor %}
                    </ul>
                </div>
                {% endif %}
            </div>
        </div>
        {% endfor %}
        
        <footer>
            <p>Generated by VulnScanner v1.0.0</p>
            <p>{{ scan_date }}</p>
        </footer>
    </div>
</body>
</html>'''
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def export_html(self, findings: List[Finding], target_url: str,
                    scan_level: str, duration: float,
                    filename: Optional[str] = None) -> str:
        """Export findings to HTML report."""
        template = Template(self.HTML_TEMPLATE)
        
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
        for finding in findings:
            sev = finding.cvss_severity
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        findings_data = []
        for f in findings:
            findings_data.append({
                "vuln_name": f.vuln_name,
                "short_intro": f.short_intro,
                "description": f.description,
                "affected_endpoints": f.affected_endpoints,
                "impact": f.impact,
                "proof_of_concept": f.proof_of_concept,
                "evidence": [{"request": e.request, "response": e.response} for e in f.evidence],
                "remediation": f.remediation,
                "references": f.references,
                "cvss_vector": f.cvss_vector,
                "cvss_score": f.cvss_score,
                "cvss_severity": f.cvss_severity,
                "confidence": f.confidence
            })
        
        html = template.render(
            target_url=target_url,
            scan_level=scan_level,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            duration=f"{duration:.1f} seconds",
            severity_counts=severity_counts,
            findings=findings_data
        )
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.html"
        
        filepath = self.output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return str(filepath)
    
    def export_json(self, findings: List[Finding], target_url: str,
                    scan_level: str, duration: float,
                    attack_surface: Any = None,
                    filename: Optional[str] = None) -> str:
        """Export findings to JSON format."""
        report = {
            "scan_info": {
                "target_url": target_url,
                "scan_level": scan_level,
                "scan_date": datetime.now().isoformat(),
                "duration_seconds": duration,
                "total_findings": len(findings)
            },
            "summary": {
                "by_severity": {}
            },
            "findings": [f.to_dict() for f in findings]
        }
        
        for sev in ["Critical", "High", "Medium", "Low", "None"]:
            count = sum(1 for f in findings if f.cvss_severity == sev)
            report["summary"]["by_severity"][sev] = count
        
        if attack_surface:
            report["attack_surface"] = attack_surface.to_dict()
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.json"
        
        filepath = self.output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        return str(filepath)
    
    def export_csv(self, findings: List[Finding],
                   filename: Optional[str] = None) -> str:
        """Export findings to CSV format."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.csv"
        
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            writer.writerow([
                "ID", "Vulnerability", "Severity", "CVSS Score", "CVSS Vector",
                "Confidence", "Plugin", "Affected Endpoints", "Description",
                "Verified", "False Positive"
            ])
            
            for finding in findings:
                writer.writerow([
                    finding.id,
                    finding.vuln_name,
                    finding.cvss_severity,
                    finding.cvss_score,
                    finding.cvss_vector,
                    finding.confidence,
                    finding.plugin_name,
                    "; ".join(finding.affected_endpoints[:3]),
                    finding.short_intro[:200],
                    "Yes" if finding.verified else "No",
                    "Yes" if finding.false_positive else "No"
                ])
        
        return str(filepath)
    
    def export_pdf(self, findings: List[Finding], target_url: str,
                   scan_level: str, duration: float,
                   filename: Optional[str] = None) -> str:
        """Export findings to PDF format."""
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.platypus import PageBreak
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.pdf"
        
        filepath = self.output_dir / filename
        
        doc = SimpleDocTemplate(str(filepath), pagesize=A4,
                               rightMargin=72, leftMargin=72,
                               topMargin=72, bottomMargin=72)
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('Title', parent=styles['Heading1'],
                                     fontSize=24, spaceAfter=30)
        heading_style = ParagraphStyle('Heading', parent=styles['Heading2'],
                                       fontSize=14, spaceAfter=12, spaceBefore=20)
        body_style = styles['Normal']
        
        story = []
        
        story.append(Paragraph("Vulnerability Scan Report", title_style))
        story.append(Paragraph(f"<b>Target:</b> {target_url}", body_style))
        story.append(Paragraph(f"<b>Scan Level:</b> {scan_level.upper()}", body_style))
        story.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
        story.append(Paragraph(f"<b>Duration:</b> {duration:.1f} seconds", body_style))
        story.append(Spacer(1, 20))
        
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in findings:
            sev = finding.cvss_severity
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        summary_data = [
            ["Severity", "Count"],
            ["Critical", str(severity_counts["Critical"])],
            ["High", str(severity_counts["High"])],
            ["Medium", str(severity_counts["Medium"])],
            ["Low", str(severity_counts["Low"])],
            ["Total", str(len(findings))]
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dddddd')),
        ]))
        story.append(summary_table)
        story.append(PageBreak())
        
        for i, finding in enumerate(findings[:20]):
            story.append(Paragraph(f"{i+1}. {finding.vuln_name}", heading_style))
            
            severity_color = {
                "Critical": "#dc3545",
                "High": "#fd7e14",
                "Medium": "#ffc107",
                "Low": "#28a745"
            }.get(finding.cvss_severity, "#6c757d")
            
            story.append(Paragraph(
                f"<b>Severity:</b> <font color='{severity_color}'>{finding.cvss_severity}</font> | "
                f"<b>CVSS:</b> {finding.cvss_score} | "
                f"<b>Confidence:</b> {finding.confidence}",
                body_style
            ))
            story.append(Spacer(1, 10))
            
            story.append(Paragraph(f"<b>Summary:</b> {finding.short_intro}", body_style))
            story.append(Spacer(1, 10))
            
            story.append(Paragraph("<b>Affected Endpoints:</b>", body_style))
            for endpoint in finding.affected_endpoints[:3]:
                story.append(Paragraph(f"  - {endpoint[:80]}", body_style))
            story.append(Spacer(1, 10))
            
            story.append(Paragraph("<b>Remediation:</b>", body_style))
            for step in finding.remediation[:3]:
                story.append(Paragraph(f"  - {step}", body_style))
            
            story.append(Paragraph(f"<b>CVSS Vector:</b> {finding.cvss_vector}", body_style))
            story.append(Spacer(1, 20))
        
        doc.build(story)
        return str(filepath)
    
    def export_all(self, findings: List[Finding], target_url: str,
                   scan_level: str, duration: float,
                   attack_surface: Any = None) -> Dict[str, str]:
        """Export in all formats."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        return {
            "html": self.export_html(findings, target_url, scan_level, duration,
                                    f"report_{timestamp}.html"),
            "json": self.export_json(findings, target_url, scan_level, duration,
                                    attack_surface, f"report_{timestamp}.json"),
            "csv": self.export_csv(findings, f"report_{timestamp}.csv"),
            "pdf": self.export_pdf(findings, target_url, scan_level, duration,
                                  f"report_{timestamp}.pdf")
        }
