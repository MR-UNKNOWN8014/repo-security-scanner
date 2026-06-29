"""Main entry point for repository security scanner"""

import sys
import json
from colorama import init, Fore, Style

from repo_scanner.cli.arguments import parse_arguments
from repo_scanner.scanner.core import RepoScanner
from repo_scanner.report.formatter import ReportFormatter
from repo_scanner.report.exporters import ReportExporter
from repo_scanner.models.scan_result import ScanSummary
from repo_scanner.config import __version__

init(autoreset=True)

def print_banner():
    banner = f"""
============================================================
  REPOSITORY SECURITY SCANNER v{__version__}
  Advanced detection for malicious code in repositories
  Safe cloning starts with verification!
============================================================
"""
    print(banner)

def main():
    args = parse_arguments()
    print_banner()
    
    try:
        scanner = RepoScanner(
            repo_url=args.repo_url,
            scan_mode=args.mode,
            verbose=args.verbose
        )
        
        print(f"\nStarting scan...")
        summary = scanner.scan(keep_repo=args.keep_repo)
        
        formatter = ReportFormatter()
        
        if args.format == 'all':
            print(formatter.format_simple(summary))
            print(formatter.format_multi_factor(summary))
            print(formatter.format_risk_categories(summary))
            if args.detailed:
                print(formatter.format_detailed(summary))
        elif args.format == 'simple':
            print(formatter.format_simple(summary))
        elif args.format == 'multi':
            print(formatter.format_multi_factor(summary))
        elif args.format == 'categories':
            print(formatter.format_risk_categories(summary))
        elif args.format == 'detailed':
            print(formatter.format_detailed(summary, show_findings=True))
        
        if args.output:
            exporter = ReportExporter()
            if args.output.endswith('.json'):
                exporter.export_json(summary, args.output)
            elif args.output.endswith('.csv'):
                exporter.export_csv(summary, args.output)
            print(f"\nReport saved to: {args.output}")
        
        if not args.auto_decision:
            decision = handle_decision(summary)
            if decision:
                print(f"\nYou chose to proceed with this repository.")
            else:
                print(f"\nYou chose to skip this repository.")
        
        if summary.overall_risk_score >= 50:
            return 1
        
        return 0
        
    except KeyboardInterrupt:
        print(f"\nScan interrupted by user")
        return 1
    except Exception as e:
        print(f"\nError: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

def handle_decision(summary: ScanSummary) -> bool:
    score = summary.overall_risk_score
    
    print(f"\nDecision Time")
    print("-" * 40)
    
    if score < 25:
        print(f"Repository appears SAFE")
        print(f"Risk Score: {score:.1f}/100")
        response = input("Would you like to clone this repository? (yes/no): ").lower()
        return response.startswith('y')
    
    elif score < 50:
        print(f"Repository has MEDIUM risk")
        print(f"Risk Score: {score:.1f}/100")
        print("\nWould you like to:")
        print("1. Clone anyway (review the code)")
        print("2. Skip cloning (recommended)")
        print("3. Clone and quarantine (clone but don't execute)")
        choice = input("Enter your choice (1-3): ")
        return choice in ['1', '3']
    
    else:
        print(f"Repository has HIGH risk!")
        print(f"Risk Score: {score:.1f}/100")
        print(f"\nWARNING: Multiple malicious patterns detected!")
        print("\nWould you like to:")
        print("1. Still clone (not recommended)")
        print("2. Skip cloning (recommended)")
        print("3. View detailed findings first")
        choice = input("Enter your choice (1-3): ")
        
        if choice == '3':
            print("\nDetailed Findings:")
            for i, finding in enumerate(summary.findings[:20], 1):
                print(f"  {i}. [{finding.severity}] {finding.category}: {finding.description}")
            print("\nWould you like to clone? (yes/no): ")
            return input().lower().startswith('y')
        
        return choice == '1'

if __name__ == "__main__":
    sys.exit(main())