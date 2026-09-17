"""Core scanner orchestrator"""

import fnmatch
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, List
from datetime import datetime
from tqdm import tqdm

from repo_scanner.models.scan_result import FileScanResult, ScanSummary, Finding, RiskLevel
from repo_scanner.scanner.file_analyzer import FileAnalyzer
from repo_scanner.scanner.dependency_checker import DependencyChecker
from repo_scanner.utils.git_utils import GitUtils
from repo_scanner.utils.file_utils import FileUtils
from repo_scanner.config import MAX_FILES_TO_SCAN, SKIP_DIRS, SKIP_FILENAMES, SKIP_FILENAME_PATTERNS

logger = logging.getLogger(__name__)

class RepoScanner:
    def __init__(self, repo_url: str, scan_mode: str = 'balanced', verbose: bool = False, check_vulns: bool = False):
        self.repo_url = repo_url
        self.scan_mode = scan_mode
        self.verbose = verbose
        self.check_vulns = check_vulns
        self.repo_name = Path(repo_url.rstrip('/')).resolve().name.replace('.git', '')
        self.repo_path: Optional[Path] = None
        self.ignore_patterns: List[str] = []

        self.file_analyzer = FileAnalyzer()
        self.dependency_checker = DependencyChecker()
        self.git_utils = GitUtils()
        self.file_utils = FileUtils()

        self.results: List[FileScanResult] = []
        self.summary: Optional[ScanSummary] = None

    def scan(self, keep_repo: bool = False) -> ScanSummary:
        start_time = datetime.now()

        if self.file_utils.is_local_path(self.repo_url):
            self.repo_path = Path(self.repo_url)
            print(f"Using local repository: {self.repo_path}")
        else:
            self.repo_path = self.git_utils.clone_repo(self.repo_url)
            if not self.repo_path:
                raise Exception(f"Failed to clone repository: {self.repo_url}")
            print(f"Repository cloned to: {self.repo_path}")

        self.ignore_patterns = self.file_utils.load_ignore_patterns(self.repo_path)
        if self.ignore_patterns:
            logger.info(f"Loaded {len(self.ignore_patterns)} ignore pattern(s) from .reposecurityignore")

        try:
            self._scan_files()
            self._check_dependencies()
            self.summary = self._generate_summary(start_time)
            return self.summary
        finally:
            if not keep_repo and not self.file_utils.is_local_path(self.repo_url):
                try:
                    self.file_utils.force_rmtree(self.repo_path)
                except Exception:
                    pass

    def _scan_files(self):
        if not self.repo_path:
            return

        files_to_scan = self._get_files_to_scan()
        logger.info(f"Found {len(files_to_scan)} files to scan")

        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(self.file_analyzer.analyze_file, fp): fp for fp in files_to_scan}
            for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning files", disable=not self.verbose):
                file_path = futures[future]
                try:
                    self.results.append(future.result())
                except Exception as e:
                    logger.info(f"Error scanning {file_path}: {e}")

    def _get_files_to_scan(self) -> List[Path]:
        if not self.repo_path:
            return []

        files_to_scan = []
        skip_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',
                          '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.pdf',
                          '.zip', '.tar', '.gz', '.rar', '.7z'}

        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for file in files:
                file_path = Path(root) / file

                if file_path.suffix.lower() in skip_extensions:
                    continue

                if file in SKIP_FILENAMES or any(fnmatch.fnmatch(file, p) for p in SKIP_FILENAME_PATTERNS):
                    continue

                if not self.file_utils.should_scan_file(file_path, self.scan_mode):
                    continue

                if self.ignore_patterns and self.file_utils.is_ignored(file_path, self.repo_path, self.ignore_patterns):
                    continue

                if self.scan_mode == 'quick' and len(files_to_scan) >= MAX_FILES_TO_SCAN:
                    break

                files_to_scan.append(file_path)

            if self.scan_mode == 'quick' and len(files_to_scan) >= MAX_FILES_TO_SCAN:
                break

        return files_to_scan

    def _check_dependencies(self):
        if not self.repo_path:
            return

        dep_score, dep_findings = self.dependency_checker.check_dependencies(self.repo_path, online=self.check_vulns)

        if dep_findings:
            dep_result = FileScanResult(
                file_path="dependencies",
                risk_score=dep_score,
                findings=dep_findings
            )
            self.results.append(dep_result)

    def _generate_summary(self, start_time: datetime) -> ScanSummary:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        high_risk = 0
        medium_risk = 0
        low_risk = 0
        safe = 0
        all_findings = []

        for result in self.results:
            all_findings.extend(result.findings)
            risk_level = result.get_risk_level()

            if risk_level == RiskLevel.CRITICAL or risk_level == RiskLevel.HIGH:
                high_risk += 1
            elif risk_level == RiskLevel.MEDIUM:
                medium_risk += 1
            elif risk_level == RiskLevel.LOW:
                low_risk += 1
            else:
                safe += 1

        overall_score = max((r.risk_score for r in self.results), default=0)

        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        all_findings.sort(key=lambda f: severity_order.get(f.severity, 4))

        return ScanSummary(
            repo_name=self.repo_name,
            repo_url=self.repo_url,
            total_files=len(self.results),
            files_analyzed=len(self.results),
            files_skipped=0,
            high_risk_files=high_risk,
            medium_risk_files=medium_risk,
            low_risk_files=low_risk,
            safe_files=safe,
            overall_risk_score=overall_score,
            findings=all_findings[:50],
            start_time=start_time,
            end_time=end_time,
            scan_duration=duration,
            error_count=0
        )
