"""Pattern matching engine"""

import re
from typing import List, Tuple
from repo_scanner.config import MALICIOUS_PATTERNS, DANGEROUS_FUNCTIONS

class PatternMatcher:
    def __init__(self):
        self.patterns = MALICIOUS_PATTERNS
        self.dangerous_funcs = DANGEROUS_FUNCTIONS
    
    def detect_malicious_patterns(self, content: str) -> Tuple[float, List[Tuple[str, str]]]:
        risk_score = 0.0
        findings = []
        
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, content, re.IGNORECASE):
                        findings.append((category, pattern))
                        risk_score += 5
                except re.error:
                    continue
        
        lines = content.split('\n')
        for line in lines:
            if len(line) > 1000:
                findings.append(('obfuscation', f'extremely long line: {len(line)} chars'))
                risk_score += 10
            elif len(line) > 500:
                findings.append(('obfuscation', f'long line: {len(line)} chars'))
                risk_score += 3
        
        return min(risk_score, 100), findings
    
    def detect_dangerous_functions(self, content: str, file_type: str) -> Tuple[float, List[str]]:
        score = 0.0
        found = []
        
        language = self._detect_language(file_type)
        
        if language in self.dangerous_funcs:
            for func in self.dangerous_funcs[language]:
                if func in content:
                    found.append(func)
                    score += 3
        
        return min(score, 100), found
    
    def detect_base64_encoding(self, content: str) -> Tuple[float, List[str]]:
        findings = []
        score = 0.0
        
        base64_patterns = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', content)
        if len(base64_patterns) > 5:
            findings.append(f'Multiple base64 strings: {len(base64_patterns)}')
            score += 10
        elif len(base64_patterns) > 2:
            findings.append(f'Base64 strings: {len(base64_patterns)}')
            score += 5
        
        if 'base64.b64decode' in content.lower():
            findings.append('base64 decode function found')
            score += 10
        if 'base64.b64encode' in content.lower():
            findings.append('base64 encode function found')
            score += 5
        
        return min(score, 100), findings
    
    def detect_network_connections(self, content: str) -> List[str]:
        findings = []
        
        network_patterns = [
            (r'requests\.(get|post|put|delete|patch)', 'HTTP request'),
            (r'socket\.connect', 'Socket connection'),
            (r'urllib\.(request|urlopen)', 'URL request'),
            (r'ftp\.connect', 'FTP connection'),
            (r'websocket', 'WebSocket connection'),
        ]
        
        for pattern, description in network_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(f'Network: {description}')
        
        return findings
    
    def _detect_language(self, file_extension: str) -> str:
        lang_map = {
            '.py': 'python', '.js': 'javascript', '.jsx': 'javascript',
            '.ts': 'javascript', '.tsx': 'javascript', '.sh': 'bash',
            '.bash': 'bash', '.zsh': 'bash', '.php': 'php',
            '.rb': 'ruby', '.go': 'go', '.rs': 'rust',
            '.c': 'c', '.cpp': 'cpp', '.h': 'c', '.hpp': 'cpp',
            '.java': 'java'
        }
        return lang_map.get(file_extension.lower(), 'unknown')