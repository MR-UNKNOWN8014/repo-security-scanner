"""Data models for scan results"""

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
from enum import Enum
from repo_scanner.config import RISK_THRESHOLDS

class RiskLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def risk_level_for(score: float) -> RiskLevel:
    """Single definition of the score bands, shared by files, summaries and --fail-on."""
    for name in ('critical', 'high', 'medium', 'low'):
        if score >= RISK_THRESHOLDS[name]:
            return RiskLevel(name)
    return RiskLevel.SAFE

@dataclass
class Finding:
    file_path: str
    severity: str = "low"
    category: str = "unknown"
    description: str = ""
    pattern: Optional[str] = None
    line: Optional[int] = None

@dataclass
class FileScanResult:
    file_path: str
    risk_score: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    file_type: str = "unknown"
    entropy: float = 0.0
    is_binary: bool = False
    size_bytes: int = 0
    
    def get_risk_level(self) -> RiskLevel:
        return risk_level_for(self.risk_score)

@dataclass
class ScanSummary:
    repo_name: str
    repo_url: str
    total_files: int
    files_analyzed: int
    files_skipped: int
    high_risk_files: int
    medium_risk_files: int
    low_risk_files: int
    safe_files: int
    overall_risk_score: float
    findings: List[Finding] = field(default_factory=list)
    # best practice notes, never scored, kept out of the findings list
    cautions: List[Finding] = field(default_factory=list)
    # directory the scan ran against, used to relativize paths for SARIF
    scan_root: str = ''
    # totals before the report truncates, so counts never understate the scan
    total_findings: int = 0
    total_cautions: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    scan_duration: float = 0.0
    error_count: int = 0
    
    def get_risk_level(self) -> RiskLevel:
        return risk_level_for(self.overall_risk_score)
    
    def to_dict(self):
        return {
            'repo_name': self.repo_name,
            'repo_url': self.repo_url,
            'total_files': self.total_files,
            'overall_risk_score': self.overall_risk_score,
            'risk_level': self.get_risk_level().value,
            'high_risk_files': self.high_risk_files,
            'medium_risk_files': self.medium_risk_files,
            'low_risk_files': self.low_risk_files,
            'safe_files': self.safe_files,
            'findings_count': self.total_findings or len(self.findings),
            'cautions_count': self.total_cautions or len(self.cautions),
            'findings_reported': len(self.findings),
            'cautions_reported': len(self.cautions),
            'scan_duration': self.scan_duration
        }