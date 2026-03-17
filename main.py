#!/usr/bin/env python3
"""
VulnScanner - Professional Web Vulnerability Scanner

A modular, plugin-driven web vulnerability scanner with:
- Automatic website crawling and attack surface discovery
- 20+ vulnerability detection plugins (low/medium/high severity)
- CVSS v3.1 automatic scoring
- Burp Suite-style reporting interface
- Safe, non-destructive scanning by default

Usage:
    python main.py           # Launch GUI
    python main.py --help    # Show help
"""

import sys
import argparse
import logging


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def run_gui():
    """Run the Tkinter GUI application."""
    try:
        import tkinter as tk
    except ImportError:
        print("Error: Tkinter is not available.")
        print("Please install tkinter for your Python installation.")
        sys.exit(1)
    
    from src.ui.main_window import VulnScannerApp
    
    root = tk.Tk()
    app = VulnScannerApp(root)
    root.mainloop()


def run_cli(args):
    """Run scan from command line."""
    from src.core.scanner import VulnerabilityScanner
    from src.reporting.exporter import ReportExporter
    
    print(f"\n{'='*60}")
    print("VulnScanner - Web Vulnerability Scanner")
    print(f"{'='*60}\n")
    
    print(f"Target: {args.url}")
    print(f"Scan Level: {args.level.upper()}")
    print(f"Intrusive: {'Yes' if args.intrusive else 'No'}")
    print()
    
    scanner = VulnerabilityScanner()
    
    def progress_callback(message: str, percentage: int):
        bar_length = 30
        filled = int(bar_length * percentage / 100)
        bar = '=' * filled + '-' * (bar_length - filled)
        print(f"\r[{bar}] {percentage}% - {message[:50]:<50}", end='', flush=True)
    
    scanner.set_progress_callback(progress_callback)
    
    result = scanner.scan(args.url, args.level.lower(), args.intrusive)
    
    print("\n")
    print(f"{'='*60}")
    print("SCAN RESULTS")
    print(f"{'='*60}")
    print(f"Duration: {result.duration:.1f} seconds")
    print(f"URLs discovered: {len(result.attack_surface.urls) if result.attack_surface else 0}")
    print(f"Total findings: {result.finding_count}")
    print()
    
    counts = result.severity_counts
    print("Findings by severity:")
    print(f"  Critical: {counts['Critical']}")
    print(f"  High: {counts['High']}")
    print(f"  Medium: {counts['Medium']}")
    print(f"  Low: {counts['Low']}")
    print()
    
    if result.findings:
        print("Top findings:")
        for i, finding in enumerate(result.findings[:10], 1):
            print(f"  {i}. [{finding.cvss_severity}] {finding.vuln_name} (CVSS: {finding.cvss_score})")
    
    if args.output:
        exporter = ReportExporter()
        
        if args.format == "html":
            path = exporter.export_html(result.findings, args.url, args.level, 
                                       result.duration, args.output)
        elif args.format == "json":
            path = exporter.export_json(result.findings, args.url, args.level,
                                       result.duration, result.attack_surface, args.output)
        elif args.format == "pdf":
            path = exporter.export_pdf(result.findings, args.url, args.level,
                                      result.duration, args.output)
        elif args.format == "csv":
            path = exporter.export_csv(result.findings, args.output)
        else:
            paths = exporter.export_all(result.findings, args.url, args.level,
                                       result.duration, result.attack_surface)
            print(f"\nReports exported:")
            for fmt, path in paths.items():
                print(f"  {fmt.upper()}: {path}")
            return
        
        print(f"\nReport exported: {path}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="VulnScanner - Professional Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                           # Launch GUI
  python main.py -u https://example.com    # CLI scan with default settings
  python main.py -u https://example.com -l high -o report.html
  python main.py -u https://example.com --intrusive  # Enable intrusive checks

Scan Levels:
  low    - Only low-severity checks (headers, cookies, info disclosure)
  medium - Low + medium severity (XSS, CSRF, open redirect, etc.)
  high   - All checks including SQL injection, SSRF, command injection

Note: Only scan systems you have permission to test.
        """
    )
    
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-l', '--level', choices=['low', 'medium', 'high'],
                       default='medium', help='Scan level (default: medium)')
    parser.add_argument('--intrusive', action='store_true',
                       help='Enable intrusive checks (time-based detection)')
    parser.add_argument('-o', '--output', help='Output file path for report')
    parser.add_argument('-f', '--format', choices=['html', 'json', 'pdf', 'csv', 'all'],
                       default='html', help='Report format (default: html)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--gui', action='store_true',
                       help='Force GUI mode even with other arguments')
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    if args.gui or not args.url:
        run_gui()
    else:
        run_cli(args)


if __name__ == "__main__":
    main()
