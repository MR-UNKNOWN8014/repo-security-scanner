"""Data models for scan results"""

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
from enum import Enum

class RiskLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class Finding:
    file_path: str
    severity: str = "low"
    category: str = "unknown"
    description: str = ""
    pattern: Optional[str] = None

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
        if self.risk_score >= 75:
            return RiskLevel.CRITICAL
        elif self.risk_score >= 50:
            return RiskLevel.HIGH
        elif self.risk_score >= 25:
            return RiskLevel.MEDIUM
        elif self.risk_score >= 10:
            return RiskLevel.LOW
        return RiskLevel.SAFE

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
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    scan_duration: float = 0.0
    error_count: int = 0
    
    def get_risk_level(self) -> RiskLevel:
        if self.overall_risk_score >= 75:
            return RiskLevel.CRITICAL
        elif self.overall_risk_score >= 50:
            return RiskLevel.HIGH
        elif self.overall_risk_score >= 25:
            return RiskLevel.MEDIUM
        elif self.overall_risk_score >= 10:
            return RiskLevel.LOW
        return RiskLevel.SAFE
    
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
            'findings_count': len(self.findings),
            'scan_duration': self.scan_duration
        }