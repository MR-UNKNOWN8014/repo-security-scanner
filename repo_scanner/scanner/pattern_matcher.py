"""Pattern matching engine"""

import re
from typing import List, Optional, Tuple
from repo_scanner.config import (
    MALICIOUS_PATTERNS, DANGEROUS_FUNCTIONS,
    SCORE_PATTERN_MATCH,
    SCORE_DANGEROUS_FUNCTION, SCORE_BASE64_FEW, SCORE_BASE64_MANY,
    SCORE_BASE64_DECODE, SCORE_BASE64_ENCODE,
    LONG_LINE_CHARS, EXTREMELY_LONG_LINE_CHARS,
    BASE64_MIN_LENGTH, BASE64_FEW_COUNT, BASE64_MANY_COUNT, BASE64_MIN_ENTROPY,
)
from repo_scanner.scanner.entropy_calculator import EntropyCalculator

_BASE64_RE = re.compile(rf'[A-Za-z0-9+/]{{{BASE64_MIN_LENGTH},}}={{0,2}}')


def _line_of(content: str, index: int) -> int:
    return content.count('\n', 0, index) + 1

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

    def detect_malicious_patterns(self, content: str) -> Tuple[float, List[Tuple[str, str, Optional[int]]]]:
        risk_score = 0.0
        findings = []

        # search over whole content, not per line, so one pattern scores once per file
        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                match = pattern.search(content)
                if match:
                    findings.append((category, pattern.pattern, _line_of(content, match.start())))
                    risk_score += SCORE_PATTERN_MATCH

        # long lines are reported for every file type but never scored: prose,
        # minified assets and data files are long for legitimate reasons
        for line_number, line in enumerate(content.split('\n'), start=1):
            if len(line) > EXTREMELY_LONG_LINE_CHARS:
                findings.append(('long_line', f'extremely long line: {len(line)} chars', line_number))
            elif len(line) > LONG_LINE_CHARS:
                findings.append(('long_line', f'long line: {len(line)} chars', line_number))

        return min(risk_score, 100), findings

    def detect_dangerous_functions(self, content: str, file_type: str) -> Tuple[float, List[Tuple[str, int]]]:
        score = 0.0
        found = []

        language = self._detect_language(file_type)

        if language in self.dangerous_funcs:
            for func in self.dangerous_funcs[language]:
                index = content.find(func)
                if index != -1:
                    found.append((func, _line_of(content, index)))
                    score += SCORE_DANGEROUS_FUNCTION

        return min(score, 100), found

    def detect_base64_encoding(self, content: str) -> Tuple[float, List[Tuple[str, Optional[int]]]]:
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

        if candidates:
            # the count is a whole-file signal, so anchor it at the first candidate
            first_line = _line_of(content, content.find(candidates[0]))
            if len(candidates) > BASE64_MANY_COUNT:
                findings.append((f'Multiple base64 strings: {len(candidates)}', first_line))
                score += SCORE_BASE64_MANY
            elif len(candidates) > BASE64_FEW_COUNT:
                findings.append((f'Base64 strings: {len(candidates)}', first_line))
                score += SCORE_BASE64_FEW

        lowered = content.lower()
        decode_index = lowered.find('base64.b64decode')
        if decode_index != -1:
            findings.append(('base64 decode function found', _line_of(content, decode_index)))
            score += SCORE_BASE64_DECODE
        encode_index = lowered.find('base64.b64encode')
        if encode_index != -1:
            findings.append(('base64 encode function found', _line_of(content, encode_index)))
            score += SCORE_BASE64_ENCODE

        return min(score, 100), findings

    def detect_network_connections(self, content: str) -> List[Tuple[str, int]]:
        found = []
        for pattern, description in _NETWORK_PATTERNS:
            match = pattern.search(content)
            if match:
                found.append((description, _line_of(content, match.start())))
        return found

    def _detect_language(self, file_extension: str) -> str:
        return _LANG_MAP.get(file_extension.lower(), 'unknown')
