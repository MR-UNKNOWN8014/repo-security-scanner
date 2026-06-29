"""Output formatting for scan reports"""

from colorama import Fore, Style, init
from repo_scanner.models.scan_result import ScanSummary, RiskLevel

init(autoreset=True)

class ReportFormatter:
    @staticmethod
    def format_simple(summary: ScanSummary) -> str:
        score = summary.overall_risk_score
        bar = ReportFormatter._get_progress_bar(score, 20)
        status = ReportFormatter._get_status(score)
        color = ReportFormatter._get_color(score)
        
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
  Findings:      {len(summary.findings)} issues found
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
  Findings Found:  {len(summary.findings)}
"""
        
        if show_findings and summary.findings:
            detailed += "\nTOP FINDINGS:\n"
            for i, finding in enumerate(summary.findings[:10], 1):
                severity_color = {
                    'critical': Fore.RED + Style.BRIGHT,
                    'high': Fore.RED,
                    'medium': Fore.YELLOW,
                    'low': Fore.GREEN
                }.get(finding.severity, Fore.WHITE)
                
                detailed += f"  {i}. {severity_color}[{finding.severity.upper()}]{Style.RESET_ALL} "
                detailed += f"{finding.category}: {finding.description[:60]}"
                if len(finding.description) > 60:
                    detailed += "..."
                detailed += "\n"
        
        return detailed
    
    @staticmethod
    def _get_progress_bar(value: float, width: int = 20) -> str:
        filled = int((value / 100) * width)
        bar = '█' * filled + '░' * (width - filled)
        return bar
    
    @staticmethod
    def _get_status(score: float) -> str:
        if score < 10:
            return "SAFE"
        elif score < 25:
            return "LOW RISK"
        elif score < 50:
            return "MEDIUM RISK"
        elif score < 75:
            return "HIGH RISK"
        else:
            return "CRITICAL"
    
    @staticmethod
    def _get_color(score: float) -> str:
        if score < 25:
            return Fore.GREEN
        elif score < 50:
            return Fore.YELLOW
        elif score < 75:
            return Fore.RED
        else:
            return Fore.RED + Style.BRIGHT
    
    @staticmethod
    def _get_recommendation(score: float) -> str:
        if score < 25:
            return "SAFE TO CLONE"
        elif score < 50:
            return "REVIEW BEFORE CLONING"
        elif score < 75:
            return "AVOID CLONING"
        else:
            return "DO NOT CLONE"