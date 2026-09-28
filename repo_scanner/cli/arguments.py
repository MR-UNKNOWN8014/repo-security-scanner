"""CLI argument parsing"""

import argparse

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Repository Security Scanner - Detect malicious code',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  repo-scanner https://github.com/user/repo.git
  repo-scanner /path/to/local/repo --mode thorough --detailed
  repo-scanner https://github.com/user/repo.git --output report.json
  repo-scanner https://github.com/user/repo.git -A -F critical

Exit codes:
  0  scan completed below the --fail-on threshold
  1  risk score reached the --fail-on threshold
  2  the scan itself failed
        """
    )

    parser.add_argument('repo_url', help='Git repository URL or local path')

    parser.add_argument(
        '--mode', '-m',
        choices=['quick', 'balanced', 'thorough', 'smart'],
        default='balanced',
        help='Scan mode (default: balanced)'
    )

    parser.add_argument(
        '--output', '-o', action='append', metavar='FILE',
        help='Output report file (.json, .csv or .sarif). Repeat to write several formats from one scan.'
    )
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--detailed', '-d', action='store_true', help='Show detailed breakdown')

    parser.add_argument(
        '--format', '-f',
        choices=['simple', 'multi', 'categories', 'detailed', 'all'],
        default='all',
        help='Report format (default: all)'
    )

    parser.add_argument(
        '--fail-on', '-F',
        choices=['none', 'low', 'medium', 'high', 'critical'],
        default='high',
        help='Exit 1 when the risk score reaches this level (default: high)'
    )

    parser.add_argument(
        '--keep-repo', '-k', action='store_true',
        help='Keep the cloned repo after scanning instead of deleting it. '
             'Only takes effect with --auto-decision; in interactive mode your answer decides instead.'
    )
    parser.add_argument('--auto-decision', '-A', action='store_true', help='Skip the interactive prompt, decide based on risk score and --keep-repo')
    parser.add_argument(
        '--check-vulns', '-c', action='store_true',
        help='Query the OSV.dev API for live known vulnerabilities in every pinned dependency '
             '(sends dependency names/versions to a third-party service; off by default)'
    )

    return parser.parse_args()
