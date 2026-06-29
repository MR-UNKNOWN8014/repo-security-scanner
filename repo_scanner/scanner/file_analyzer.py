"""File analysis module"""

from pathlib import Path
from repo_scanner.models.scan_result import FileScanResult, Finding
from repo_scanner.scanner.pattern_matcher import PatternMatcher
from repo_scanner.scanner.entropy_calculator import EntropyCalculator
from repo_scanner.utils.file_utils import FileUtils
from repo_scanner.config import MAX_FILE_SIZE_MB

class FileAnalyzer:
    def __init__(self):
        self.pattern_matcher = PatternMatcher()
        self.entropy_calculator = EntropyCalculator()
        self.file_utils = FileUtils()
    
    def analyze_file(self, file_path: Path) -> FileScanResult:
        result = FileScanResult(
            file_path=str(file_path),
            size_bytes=file_path.stat().st_size
        )
        
        if result.size_bytes > MAX_FILE_SIZE_MB * 1024 * 1024:
            result.findings.append(Finding(
                file_path=str(file_path),
                severity="low",
                category="size",
                description=f"File exceeds max size ({MAX_FILE_SIZE_MB}MB)"
            ))
            return result
        
        result.is_binary = self.file_utils.is_binary(file_path)
        result.file_type = file_path.suffix or "unknown"
        
        entropy = self.entropy_calculator.calculate_file_entropy(file_path)
        if entropy is not None:
            result.entropy = entropy
            if self.entropy_calculator.is_high_entropy(entropy):
                result.findings.append(Finding(
                    file_path=str(file_path),
                    severity="medium",
                    category="obfuscation",
                    description=f"High entropy: {entropy:.2f} (possible obfuscation)"
                ))
                result.risk_score += 20
        
        if not result.is_binary:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    pattern_score, pattern_findings = self.pattern_matcher.detect_malicious_patterns(content)
                    result.risk_score += pattern_score
                    for category, pattern in pattern_findings:
                        severity = "high" if category in ['crypto_miner', 'backdoor', 'data_exfiltration'] else "medium" if category == 'obfuscation' else "low"
                        result.findings.append(Finding(
                            file_path=str(file_path),
                            severity=severity,
                            category=category,
                            description=f"Malicious pattern: {pattern}",
                            pattern=pattern
                        ))
                    
                    func_score, funcs = self.pattern_matcher.detect_dangerous_functions(
                        content, result.file_type
                    )
                    result.risk_score += func_score
                    for func in funcs:
                        result.findings.append(Finding(
                            file_path=str(file_path),
                            severity="low",
                            category="dangerous_function",
                            description=f"Dangerous function: {func}"
                        ))
                    
                    base64_score, base64_findings = self.pattern_matcher.detect_base64_encoding(content)
                    result.risk_score += base64_score
                    for finding in base64_findings:
                        result.findings.append(Finding(
                            file_path=str(file_path),
                            severity="medium" if "Multiple" in finding or "decode" in finding else "low",
                            category="encoding",
                            description=finding
                        ))
                    
                    for finding in self.pattern_matcher.detect_network_connections(content):
                        result.findings.append(Finding(
                            file_path=str(file_path),
                            severity="low",
                            category="network",
                            description=finding
                        ))
                        
            except Exception as e:
                result.findings.append(Finding(
                    file_path=str(file_path),
                    severity="low",
                    category="error",
                    description=f"Error reading file: {str(e)}"
                ))
        
        result.risk_score = min(result.risk_score, 100)
        return result