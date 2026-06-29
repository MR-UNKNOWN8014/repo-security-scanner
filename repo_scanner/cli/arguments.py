"""CLI argument parsing"""

import argparse

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Repository Security Scanner - Detect malicious code',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_scanner.py https://github.com/user/repo.git
  python run_scanner.py /path/to/local/repo --mode thorough --detailed
  python run_scanner.py https://github.com/user/repo.git --output report.json
        """
    )
    
    parser.add_argument('repo_url', help='Git repository URL or local path')
    
    parser.add_argument(
        '--mode', '-m',
        choices=['quick', 'balanced', 'thorough', 'smart'],
        default='balanced',
        help='Scan mode (default: balanced)'
    )
    
    parser.add_argument('--output', '-o', help='Output report file (JSON)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--detailed', '-d', action='store_true', help='Show detailed breakdown')
    
    parser.add_argument(
        '--format',
        choices=['simple', 'multi', 'categories', 'detailed', 'all'],
        default='all',
        help='Report format (default: all)'
    )
    
    parser.add_argument('--keep-repo', action='store_true', help='Keep cloned repo')
    parser.add_argument('--auto-decision', action='store_true', help='Auto-decision based on risk')
    
    return parser.parse_args()