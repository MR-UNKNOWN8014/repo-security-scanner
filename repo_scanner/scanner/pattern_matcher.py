"""Pattern matching engine"""

import re
from typing import List, Tuple
from repo_scanner.config import (
    MALICIOUS_PATTERNS, DANGEROUS_FUNCTIONS,
    SCORE_PATTERN_MATCH, SCORE_LONG_LINE, SCORE_EXTREMELY_LONG_LINE,
    SCORE_DANGEROUS_FUNCTION, SCORE_BASE64_FEW, SCORE_BASE64_MANY,
    SCORE_BASE64_DECODE, SCORE_BASE64_ENCODE,
    LONG_LINE_CHARS, EXTREMELY_LONG_LINE_CHARS,
    BASE64_MIN_LENGTH, BASE64_FEW_COUNT, BASE64_MANY_COUNT, BASE64_MIN_ENTROPY,
)
from repo_scanner.scanner.entropy_calculator import EntropyCalculator

_BASE64_RE = re.compile(rf'[A-Za-z0-9+/]{{{BASE64_MIN_LENGTH},}}={{0,2}}')

_NETWORK_PATTERNS = [
    (re.compile(r'requests\.(get|post|put|delete|patch)', re.IGNORECASE), 'HTTP request'),
    (re.compile(r'socket\.connect', re.IGNORECASE), 'Socket connection'),
    (re.compile(r'urllib\.(request|urlopen)', re.IGNORECASE), 'URL request'),
    (re.compile(r'ftp\.connect', re.IGNORECASE), 'FTP connection'),
    (re.compile(r'websocket', re.IGNORECASE), 'WebSocket connection'),
]

_LANG_MAP = {
    '.py': 'python', '.js': 'javascript', '.jsx': 'javascript',
    '.ts': 'javascript', '.tsx': 'javascript', '.sh': 'bash',
    '.bash': 'bash', '.zsh': 'bash', '.php': 'php',
    '.rb': 'ruby', '.go': 'go', '.rs': 'rust',
    '.c': 'c', '.cpp': 'cpp', '.h': 'c', '.hpp': 'cpp',
    '.java': 'java'
}

class PatternMatcher:
    def __init__(self):
        self.compiled_patterns = {
            category: [re.compile(p, re.IGNORECASE) for p in patterns]
            for category, patterns in MALICIOUS_PATTERNS.items()
        }
        self.dangerous_funcs = DANGEROUS_FUNCTIONS

    def detect_malicious_patterns(self, content: str) -> Tuple[float, List[Tuple[str, str]]]:
        risk_score = 0.0
        findings = []

        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(content):
                    findings.append((category, pattern.pattern))
                    risk_score += SCORE_PATTERN_MATCH

        for line in content.split('\n'):
            if len(line) > EXTREMELY_LONG_LINE_CHARS:
                findings.append(('obfuscation', f'extremely long line: {len(line)} chars'))
                risk_score += SCORE_EXTREMELY_LONG_LINE
            elif len(line) > LONG_LINE_CHARS:
                findings.append(('obfuscation', f'long line: {len(line)} chars'))
                risk_score += SCORE_LONG_LINE

        return min(risk_score, 100), findings

    def detect_dangerous_functions(self, content: str, file_type: str) -> Tuple[float, List[str]]:
        score = 0.0
        found = []

        language = self._detect_language(file_type)

        if language in self.dangerous_funcs:
            for func in self.dangerous_funcs[language]:
                if func in content:
                    found.append(func)
                    score += SCORE_DANGEROUS_FUNCTION

        return min(score, 100), found

    def detect_base64_encoding(self, content: str) -> Tuple[float, List[str]]:
        findings = []
        score = 0.0

        # real base64 length is always a multiple of 4, and encoded binary
        # data has higher entropy than the identifiers/urls/hashes this
        # broad charset otherwise matches
        candidates = [
            m for m in _BASE64_RE.findall(content)
            if len(m) % 4 == 0
            and EntropyCalculator.calculate_entropy(m.encode('utf-8', errors='ignore')) >= BASE64_MIN_ENTROPY
        ]

        if len(candidates) > BASE64_MANY_COUNT:
            findings.append(f'Multiple base64 strings: {len(candidates)}')
            score += SCORE_BASE64_MANY
        elif len(candidates) > BASE64_FEW_COUNT:
            findings.append(f'Base64 strings: {len(candidates)}')
            score += SCORE_BASE64_FEW

        if 'base64.b64decode' in content.lower():
            findings.append('base64 decode function found')
            score += SCORE_BASE64_DECODE
        if 'base64.b64encode' in content.lower():
            findings.append('base64 encode function found')
            score += SCORE_BASE64_ENCODE

        return min(score, 100), findings

    def detect_network_connections(self, content: str) -> List[str]:
        return [description for pattern, description in _NETWORK_PATTERNS if pattern.search(content)]

    def _detect_language(self, file_extension: str) -> str:
        return _LANG_MAP.get(file_extension.lower(), 'unknown')
