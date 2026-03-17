"""
Vulnerability Scanner Engine.
Orchestrates crawling, plugin execution, and CVSS calculation.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Callable, Optional
from datetime import datetime

from src.core.crawler import WebCrawler
from src.core.cvss_calculator import CVSSCalculator
from src.plugins.loader import PluginLoader
from src.plugins.base import PluginBase
from src.models.finding import Finding
from src.models.scan_context import ScanContext, AttackSurface
from src.models.cvss import CVSSMetrics

logger = logging.getLogger(__name__)


class ScanResult:
    """Container for scan results."""
    
    def __init__(self, target_url: str, scan_level: str):
        self.target_url = target_url
        self.scan_level = scan_level
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None
        self.findings: List[Finding] = []
        self.attack_surface: Optional[AttackSurface] = None
        self.plugins_run: List[str] = []
        self.errors: List[str] = []
        
    @property
    def duration(self) -> float:
        """Get scan duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now() - self.start_time).total_seconds()
    
    @property
    def finding_count(self) -> int:
        return len(self.findings)
    
    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
        for finding in self.findings:
            sev = finding.cvss_severity
            if sev in counts:
                counts[sev] += 1
        return counts


class VulnerabilityScanner:
    """
    Main vulnerability scanner engine.
    
    Orchestrates:
    1. Website crawling and attack surface discovery
    2. Plugin loading and execution
    3. CVSS score calculation
    4. Result aggregation
    """
    
    def __init__(self, max_workers: int = 10, rate_limit: float = 0.2,
                 timeout: int = 15, max_urls: int = 1000, max_depth: int = 5):
        self.max_workers = max_workers
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.max_urls = max_urls
        self.max_depth = max_depth
        
        self.plugin_loader = PluginLoader()
        self.cvss_calculator = CVSSCalculator
        
        self._progress_callback: Optional[Callable] = None
        self._sitemap_callback: Optional[Callable[[str], None]] = None
        self._should_stop = False
        
    def load_plugins(self) -> int:
        """Load all vulnerability plugins."""
        return self.plugin_loader.discover_plugins()
    
    def set_progress_callback(self, callback: Callable[[str, int], None]):
        """Set callback for progress updates."""
        self._progress_callback = callback

    def set_sitemap_callback(self, callback: Callable[[str], None]):
        """Set callback for site map URL discovery."""
        self._sitemap_callback = callback
    
    def stop_scan(self):
        """Signal the scanner to stop."""
        self._should_stop = True
    
    def scan(self, target_url: str, scan_level: str = "medium",
             allow_intrusive: bool = False) -> ScanResult:
        """
        Perform a complete vulnerability scan.
        
        Args:
            target_url: Target website URL
            scan_level: "low", "medium", or "high"
            allow_intrusive: Whether to run intrusive checks
            
        Returns:
            ScanResult containing all findings
        """
        self._should_stop = False
        result = ScanResult(target_url, scan_level)
        
        logger.info(f"Starting scan of {target_url} at level {scan_level}")
        self._current_scan_start_time = result.start_time
        self._update_progress("Initializing scan...", 0)
        
        try:
            self._update_progress("Loading plugins...", 5)
            plugin_count = self.load_plugins()
            logger.info(f"Loaded {plugin_count} plugins")
            
            if self._should_stop:
                return result
            
            self._update_progress("Crawling website...", 10)
            crawler = WebCrawler(
                target_url,
                max_depth=self.max_depth,
                max_urls=self.max_urls,
                rate_limit=self.rate_limit,
                timeout=self.timeout
            )
            
            attack_surface = crawler.crawl(
                progress_callback=lambda msg: self._update_progress(msg, 15),
                url_callback=self._sitemap_callback
            )
            result.attack_surface = attack_surface
            
            logger.info(f"Discovered {len(attack_surface.urls)} URLs, "
                       f"{len(attack_surface.forms)} forms, "
                       f"{len(attack_surface.url_parameters)} parameters")
            
            if self._should_stop:
                return result
            
            context = ScanContext(
                target_url=target_url,
                attack_surface=attack_surface,
                scan_level=scan_level,
                allow_intrusive=allow_intrusive,
                rate_limit=self.rate_limit,
                timeout=self.timeout
            )
            
            self._update_progress("Running vulnerability plugins...", 30)
            plugins = self.plugin_loader.get_plugins_for_scan(scan_level, allow_intrusive)
            
            all_findings = self._run_plugins(plugins, context, result)
            
            if self._should_stop:
                return result
            
            self._update_progress("Calculating CVSS scores...", 90)
            for finding in all_findings:
                self._calculate_cvss(finding)
                result.findings.append(finding)
            
            result.findings.sort(key=lambda f: f.cvss_score, reverse=True)
            
            result.end_time = datetime.now()
            
            self._update_progress("Scan complete!", 100)
            logger.info(f"Scan complete. Found {len(result.findings)} vulnerabilities "
                       f"in {result.duration:.1f} seconds")
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            result.errors.append(str(e))
            result.end_time = datetime.now()
        
        return result
    
    def _run_plugins(self, plugins: List[PluginBase], context: ScanContext,
                     result: ScanResult) -> List[Finding]:
        """Run all plugins in parallel and collect findings."""
        import threading
        all_findings = []
        total_plugins = len(plugins)
        completed = [0]
        lock = threading.Lock()

        def run_one(plugin):
            if self._should_stop:
                return []
            with lock:
                completed[0] += 1
                progress = 30 + int((completed[0] / total_plugins) * 55)
            self._update_progress(f"Running: {plugin.metadata.name}…", progress)
            try:
                findings = plugin.analyze(context)
                for finding in findings:
                    finding.plugin_id = plugin.metadata.id
                    finding.plugin_name = plugin.metadata.name
                    finding.target_url = context.target_url
                if findings:
                    logger.info(f"Plugin {plugin.metadata.id} found {len(findings)} issues")
                result.plugins_run.append(plugin.metadata.id)
                return findings
            except Exception as e:
                logger.error(f"Plugin {plugin.metadata.id} error: {e}")
                result.errors.append(f"{plugin.metadata.id}: {e}")
                return []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(run_one, p): p for p in plugins}
            for future in as_completed(futures):
                if self._should_stop:
                    break
                try:
                    all_findings.extend(future.result())
                except Exception as e:
                    logger.error(f"Plugin future error: {e}")

        return all_findings

    
    def _calculate_cvss(self, finding: Finding):
        """Calculate and attach CVSS score to finding."""
        metrics = CVSSMetrics.from_dict(finding.suggested_cvss)
        cvss_result = self.cvss_calculator.calculate(metrics)
        
        finding.cvss_vector = cvss_result.vector
        finding.cvss_score = cvss_result.score
        finding.cvss_severity = cvss_result.severity
        
        finding.cvss_audit_trail.append({
            "timestamp": datetime.now().isoformat(),
            "action": "initial_calculation",
            "vector": cvss_result.vector,
            "score": cvss_result.score,
            "severity": cvss_result.severity,
            "source": "automatic"
        })
    
    def update_finding_cvss(self, finding: Finding, new_metrics: Dict[str, str],
                           analyst: str = "analyst") -> Finding:
        """
        Update CVSS metrics for a finding and recalculate.
        Records change in audit trail.
        """
        old_vector = finding.cvss_vector
        old_score = finding.cvss_score
        
        metrics = CVSSMetrics.from_dict(new_metrics)
        cvss_result = self.cvss_calculator.calculate(metrics)
        
        finding.cvss_vector = cvss_result.vector
        finding.cvss_score = cvss_result.score
        finding.cvss_severity = cvss_result.severity
        finding.suggested_cvss = new_metrics
        
        finding.cvss_audit_trail.append({
            "timestamp": datetime.now().isoformat(),
            "action": "manual_override",
            "old_vector": old_vector,
            "old_score": old_score,
            "new_vector": cvss_result.vector,
            "new_score": cvss_result.score,
            "new_severity": cvss_result.severity,
            "analyst": analyst
        })
        
        return finding
    
    def _update_progress(self, message: str, percentage: int):
        """Update progress via callback."""
        if self._progress_callback:
            self._progress_callback(message, percentage)
        logger.debug(f"Progress {percentage}%: {message}")
    
    def get_plugin_info(self) -> Dict[str, List[Dict]]:
        """Get information about loaded plugins."""
        if not self.plugin_loader.plugins:
            self.load_plugins()
        
        info = {
            "low": [],
            "medium": [],
            "high": [],
            "intrusive": []
        }
        
        for plugin in self.plugin_loader.get_all_plugins():
            meta = plugin.metadata
            category = "intrusive" if meta.intrusive else meta.severity_hint.lower()
            
            info[category].append({
                "id": meta.id,
                "name": meta.name,
                "description": meta.description,
                "author": meta.author,
                "intrusive": meta.intrusive
            })
        
        return info
