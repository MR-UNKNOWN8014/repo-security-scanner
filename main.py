"""Main entry point for repository security scanner"""

import logging
import sys
from colorama import init

from repo_scanner.cli.arguments import parse_arguments
from repo_scanner.scanner.core import RepoScanner
from repo_scanner.report.formatter import ReportFormatter
from repo_scanner.report.exporters import ReportExporter
from repo_scanner.utils.file_utils import FileUtils
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
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format='%(message)s')
    print_banner()

    try:
        scanner = RepoScanner(
            repo_url=args.repo_url,
            scan_mode=args.mode,
            verbose=args.verbose,
            check_vulns=args.check_vulns
        )
        is_local = FileUtils.is_local_path(args.repo_url)

        if args.keep_repo and not args.auto_decision and not is_local:
            print("\nNote: --keep-repo is ignored in interactive mode, your answer below decides.")

        print(f"\nStarting scan...")
        summary = scanner.scan(keep_repo=args.keep_repo, auto_cleanup=args.auto_decision)
        
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
            try:
                if args.output.endswith('.json'):
                    exporter.export_json(summary, args.output)
                    print(f"\nReport saved to: {args.output}")
                elif args.output.endswith('.csv'):
                    exporter.export_csv(summary, args.output)
                    print(f"\nReport saved to: {args.output}")
                else:
                    print(f"\nUnsupported output format, use .json or .csv: {args.output}")
            except OSError as e:
                print(f"\nFailed to save report to {args.output}: {e}")
        
        if not args.auto_decision:
            decision = handle_decision(summary, is_local)
            if decision:
                print(f"\nYou chose to proceed with this repository.")
                if not is_local:
                    print(f"Cloned copy kept at: {scanner.repo_path}")
            else:
                print(f"\nYou chose to skip this repository.")
                if not is_local:
                    scanner.cleanup()
        
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

def handle_decision(summary: ScanSummary, is_local: bool) -> bool:
    score = summary.overall_risk_score
    action = "proceed with" if is_local else "clone"

    print(f"\nDecision Time")
    print("-" * 40)

    if score < 25:
        print(f"Repository appears SAFE")
        print(f"Risk Score: {score:.1f}/100")
        response = input(f"Would you like to {action} this repository? (yes/no): ").lower()
        return response.startswith('y')

    elif score < 50:
        print(f"Repository has MEDIUM risk")
        print(f"Risk Score: {score:.1f}/100")
        print("\nWould you like to:")
        if is_local:
            print("1. Proceed anyway (review the code)")
            print("2. Stop here (recommended)")
            choice = input("Enter your choice (1-2): ")
            return choice == '1'
        else:
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
        if is_local:
            print("1. Proceed anyway (not recommended)")
            print("2. Stop here (recommended)")
            print("3. View detailed findings first")
        else:
            print("1. Still clone (not recommended)")
            print("2. Skip cloning (recommended)")
            print("3. View detailed findings first")
        choice = input("Enter your choice (1-3): ")

        if choice == '3':
            print("\nDetailed Findings:")
            for i, finding in enumerate(summary.findings[:20], 1):
                location = f"{finding.file_path}:{finding.line} " if finding.line else ""
                print(f"  {i}. [{finding.severity}] {location}{finding.category}: {finding.description}")
            response = input(f"\nWould you like to {action} this repository? (yes/no): ").lower()
            return response.startswith('y')

        return choice == '1'

if __name__ == "__main__":
    sys.exit(main())