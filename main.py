"""Main entry point for repository security scanner"""

import logging
import sys
from pathlib import Path
from typing import List
from colorama import init

from repo_scanner.cli.arguments import parse_arguments
from repo_scanner.scanner.core import RepoScanner
from repo_scanner.report.formatter import ReportFormatter
from repo_scanner.report.exporters import ReportExporter
from repo_scanner.utils.file_utils import FileUtils
from repo_scanner.models.scan_result import RiskLevel, ScanSummary, risk_level_for
from repo_scanner.config import EXIT_ERROR, EXIT_OK, EXIT_THRESHOLD, RISK_THRESHOLDS, __version__

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
        
        for message in export_reports(summary, args.output):
            print(f"\n{message}")
        
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
        
        if exceeds_threshold(summary.overall_risk_score, args.fail_on):
            print(f"\nRisk score {summary.overall_risk_score:.1f} reached the --fail-on {args.fail_on} threshold.")
            return EXIT_THRESHOLD

        return EXIT_OK

    except KeyboardInterrupt:
        print(f"\nScan interrupted by user")
        return EXIT_ERROR
    except Exception as e:
        print(f"\nError: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return EXIT_ERROR


EXPORTERS_BY_SUFFIX = {
    '.json': ReportExporter.export_json,
    '.csv': ReportExporter.export_csv,
    '.sarif': ReportExporter.export_sarif,
}


def export_reports(summary: ScanSummary, paths) -> List[str]:
    """Write every requested report in one pass, so one scan can emit several formats."""
    messages = []
    for path in paths or []:
        suffix = Path(path).suffix.lower()
        exporter = EXPORTERS_BY_SUFFIX.get(suffix)
        if exporter is None:
            messages.append(f"Unsupported output format, use {', '.join(sorted(EXPORTERS_BY_SUFFIX))}: {path}")
            continue
        try:
            exporter(summary, path)
            messages.append(f"Report saved to: {path}")
        except OSError as e:
            messages.append(f"Failed to save report to {path}: {e}")
    return messages


def exceeds_threshold(score: float, fail_on: str) -> bool:
    if fail_on == 'none':
        return False
    return score >= RISK_THRESHOLDS[fail_on]

def handle_decision(summary: ScanSummary, is_local: bool) -> bool:
    score = summary.overall_risk_score
    action = "proceed with" if is_local else "clone"

    print(f"\nDecision Time")
    print("-" * 40)

    level = risk_level_for(score)

    if level in (RiskLevel.SAFE, RiskLevel.LOW):
        print(f"Repository appears {'SAFE' if level is RiskLevel.SAFE else 'LOW risk'}")
        print(f"Risk Score: {score:.1f}/100")
        response = input(f"Would you like to {action} this repository? (yes/no): ").lower()
        return response.startswith('y')

    elif level is RiskLevel.MEDIUM:
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
                location = f"{finding.file_path}:{finding.line}" if finding.line is not None else finding.file_path
                print(f"  {i}. [{finding.severity}] {location} {finding.category}: {finding.description}")
            if summary.cautions:
                print(f"\nPlus {len(summary.cautions)} best practice cautions, not scored. See the detailed report.")
            response = input(f"\nWould you like to {action} this repository? (yes/no): ").lower()
            return response.startswith('y')

        return choice == '1'

if __name__ == "__main__":
    sys.exit(main())