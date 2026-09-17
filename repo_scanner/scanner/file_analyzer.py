"""File analysis module"""

from pathlib import Path
from repo_scanner.models.scan_result import FileScanResult, Finding
from repo_scanner.scanner.pattern_matcher import PatternMatcher
from repo_scanner.scanner.entropy_calculator import EntropyCalculator
from repo_scanner.scanner.secret_detector import SecretDetector
from repo_scanner.scanner.dockerfile_scanner import DockerfileScanner, is_dockerfile
from repo_scanner.utils.file_utils import FileUtils
from repo_scanner.config import MAX_FILE_SIZE_MB, SCORE_ENTROPY

class FileAnalyzer:
    def __init__(self):
        self.pattern_matcher = PatternMatcher()
        self.entropy_calculator = EntropyCalculator()
        self.secret_detector = SecretDetector()
        self.dockerfile_scanner = DockerfileScanner()
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
                result.risk_score += SCORE_ENTROPY
        
        if not result.is_binary:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    pattern_score, pattern_findings = self.pattern_matcher.detect_malicious_patterns(content)
                    result.risk_score += pattern_score
                    for category, pattern in pattern_findings:
                        result.findings.append(Finding(
                            file_path=str(file_path),
                            severity="medium" if pattern_score > 20 else "low",
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
                            severity="medium" if base64_score > 20 else "low",
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

                    secret_score, secret_findings = self.secret_detector.detect_secrets(content)
                    result.risk_score += secret_score
                    for name, redacted_value, line in secret_findings:
                        result.findings.append(Finding(
                            file_path=str(file_path),
                            severity="critical",
                            category="secret",
                            description=f"{name} detected: {redacted_value}",
                            line=line
                        ))

                    if is_dockerfile(file_path):
                        docker_score, docker_findings = self.dockerfile_scanner.scan(content)
                        result.risk_score += docker_score
                        for category, description, line in docker_findings:
                            result.findings.append(Finding(
                                file_path=str(file_path),
                                severity="medium" if docker_score > 20 else "low",
                                category=f"dockerfile_{category}",
                                description=description,
                                line=line
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