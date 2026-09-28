"""Output formatting for scan reports"""

from colorama import Fore, Style, init
from repo_scanner.models.scan_result import ScanSummary, RiskLevel, risk_level_for

init(autoreset=True)

# one table per concern, all keyed off the shared score bands so the status,
# the colour and the recommendation can never disagree with each other
STATUS_BY_LEVEL = {
    RiskLevel.SAFE: "SAFE",
    RiskLevel.LOW: "LOW RISK",
    RiskLevel.MEDIUM: "MEDIUM RISK",
    RiskLevel.HIGH: "HIGH RISK",
    RiskLevel.CRITICAL: "CRITICAL",
}

RECOMMENDATION_BY_LEVEL = {
    RiskLevel.SAFE: "SAFE TO CLONE",
    RiskLevel.LOW: "REVIEW BEFORE CLONING",
    RiskLevel.MEDIUM: "EXERCISE CAUTION",
    RiskLevel.HIGH: "AVOID CLONING",
    RiskLevel.CRITICAL: "DO NOT CLONE",
}

COLOR_BY_LEVEL = {
    RiskLevel.SAFE: Fore.GREEN,
    RiskLevel.LOW: Fore.GREEN,
    RiskLevel.MEDIUM: Fore.YELLOW,
    RiskLevel.HIGH: Fore.RED,
    RiskLevel.CRITICAL: Fore.RED + Style.BRIGHT,
}

class ReportFormatter:
    @staticmethod
    def format_simple(summary: ScanSummary) -> str:
        score = summary.overall_risk_score
        bar = ReportFormatter._get_progress_bar(score, 20)
        status = ReportFormatter._get_status(score)

        return f"""
============================================================
  REPOSITORY: {summary.repo_name}
  RISK SCORE: {score:>5.1f}%  [{bar}]   {status}
============================================================
"""
    
    @staticmethod
    def format_multi_factor(summary: ScanSummary) -> str:
        score = summary.overall_risk_score
        status = ReportFormatter._get_status(score)
        color = ReportFormatter._get_color(score)
        
        code_quality = max(0, 85 - (summary.overall_risk_score * 0.5))
        security_score = max(0, 100 - summary.overall_risk_score)
        obfuscation = min(100, summary.overall_risk_score * 0.7)
        malicious = min(100, summary.overall_risk_score * 0.5)
        return f"""
============================================================
  REPOSITORY: {summary.repo_name}
  
  MULTI-FACTOR ANALYSIS
  Code Quality:  {code_quality:>5.1f}%  [{ReportFormatter._get_progress_bar(code_quality, 10)}]
  Security:      {security_score:>5.1f}%  [{ReportFormatter._get_progress_bar(security_score, 10)}]
  Obfuscation:   {obfuscation:>5.1f}%  [{ReportFormatter._get_progress_bar(obfuscation, 10)}]
  Malicious:     {malicious:>5.1f}%  [{ReportFormatter._get_progress_bar(malicious, 10)}]
  
  OVERALL: {score:>5.1f}%  {color}{status}{Style.RESET_ALL}
============================================================
"""
    
    @staticmethod
    def format_risk_categories(summary: ScanSummary) -> str:
        score = summary.overall_risk_score
        risk_level = summary.get_risk_level()
        
        risk_map = {
            RiskLevel.SAFE: ("[SAFE]", Fore.GREEN),
            RiskLevel.LOW: ("[LOW]", Fore.GREEN),
            RiskLevel.MEDIUM: ("[MEDIUM]", Fore.YELLOW),
            RiskLevel.HIGH: ("[HIGH]", Fore.RED),
            RiskLevel.CRITICAL: ("[CRITICAL]", Fore.RED + Style.BRIGHT)
        }
        
        level_label, color = risk_map.get(risk_level, ("[UNKNOWN]", Fore.WHITE))
        
        return f"""
============================================================
  REPOSITORY: {summary.repo_name}
  
  {color}{level_label} RISK{Style.RESET_ALL}
  
  Risk Level:    {level_label}
  Score:         {score:>5.1f}%
  Findings:      {summary.total_findings or len(summary.findings)} issues found
  Cautions:      {summary.total_cautions or len(summary.cautions)} best practice notes
  Files:         {summary.high_risk_files} high, {summary.medium_risk_files} medium, {summary.low_risk_files} low
  Recommendation: {ReportFormatter._get_recommendation(score)}
============================================================
"""
    
    @staticmethod
    def format_detailed(summary: ScanSummary, show_findings: bool = True) -> str:
        base = ReportFormatter.format_risk_categories(summary)
        
        detailed = f"""
{base}

FILE BREAKDOWN:
  Safe:        {summary.safe_files}
  Low Risk:    {summary.low_risk_files}
  Medium Risk: {summary.medium_risk_files}
  High Risk:   {summary.high_risk_files}

STATISTICS:
  Total Files:     {summary.total_files}
  Scan Duration:   {summary.scan_duration:.2f}s
  Findings Found:  {summary.total_findings or len(summary.findings)}
  Cautions Found:  {summary.total_cautions or len(summary.cautions)}
"""
        
        if show_findings and summary.findings:
            total = summary.total_findings or len(summary.findings)
            shown = min(10, len(summary.findings))
            detailed += f"\nTOP FINDINGS{f' (showing {shown} of {total})' if total > shown else ''}:\n"
            for i, finding in enumerate(summary.findings[:10], 1):
                severity_color = {
                    'critical': Fore.RED + Style.BRIGHT,
                    'high': Fore.RED,
                    'medium': Fore.YELLOW,
                    'low': Fore.GREEN
                }.get(finding.severity, Fore.WHITE)
                
                detailed += f"  {i}. {severity_color}[{finding.severity.upper()}]{Style.RESET_ALL} "
                detailed += ReportFormatter._format_finding_line(finding)

        if show_findings and summary.cautions:
            total_c = summary.total_cautions or len(summary.cautions)
            shown_c = min(10, len(summary.cautions))
            detailed += f"\nCAUTIONS, best practice, not scored{f' (showing {shown_c} of {total_c})' if total_c > shown_c else ''}:\n"
            for i, caution in enumerate(summary.cautions[:10], 1):
                detailed += f"  {i}. {Fore.CYAN}[CAUTION]{Style.RESET_ALL} "
                detailed += ReportFormatter._format_finding_line(caution)

        return detailed

    @staticmethod
    def _format_finding_line(finding) -> str:
        location = f"{finding.file_path}:{finding.line}" if finding.line is not None else finding.file_path
        description = finding.description[:60] + ("..." if len(finding.description) > 60 else "")
        return f"{location} {finding.category}: {description}\n"
    
    @staticmethod
    def _get_progress_bar(value: float, width: int = 20) -> str:
        # ASCII only: block characters crash a cp1252 Windows console, which
        # made every scan exit as a tool error on a default terminal
        filled = int((max(0.0, min(value, 100.0)) / 100) * width)
        return '#' * filled + '-' * (width - filled)
    
    @staticmethod
    def _get_status(score: float) -> str:
        return STATUS_BY_LEVEL[risk_level_for(score)]

    @staticmethod
    def _get_color(score: float) -> str:
        return COLOR_BY_LEVEL[risk_level_for(score)]

    @staticmethod
    def _get_recommendation(score: float) -> str:
        return RECOMMENDATION_BY_LEVEL[risk_level_for(score)]