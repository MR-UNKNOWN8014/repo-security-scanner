"""Configuration and constants"""

__version__ = "1.0.0"

MALICIOUS_PATTERNS = {
    'crypto_miner': [
        r'cryptonight', r'stratum', r'mining', r'cpuminer',
        r'xmrig', r'minerd', r'cgminer', r'ethminer'
    ],
    'backdoor': [
        r'socket\.bind', r'socket\.connect', r'base64\.b64decode',
        r'exec\(', r'eval\(', r'__import__', r'subprocess\.call',
        r'os\.system', r'requests\.get.*post', r'urllib.*urlopen'
    ],
    'data_exfiltration': [
        r'requests\.post.*data', r'urllib.*urlopen.*data',
        r'smtplib', r'email\.send', r'telegram.*bot',
        r'discord.*webhook', r'slack.*webhook'
    ],
    'obfuscation': [
        r'base64\.b64encode', r'base64\.b64decode',
        r'zlib\.compress', r'zlib\.decompress',
        r'__import__.*base64', r'exec\(.*decode'
    ],
    'shell_commands': [
        r'subprocess\.', r'os\.popen', r'popen', r'system\('
    ]
}

DANGEROUS_FUNCTIONS = {
    'python': ['exec', 'eval', 'compile', '__import__', 'os.system',
               'subprocess.call', 'subprocess.Popen', 'os.popen'],
    'javascript': ['eval', 'Function', 'setTimeout', 'setInterval',
                   'document.write', 'innerHTML'],
    'bash': ['exec', 'eval', 'source', 'export', 'alias'],
    'php': ['eval', 'system', 'exec', 'passthru', 'shell_exec', 'assert']
}

HIGH_ENTROPY_THRESHOLD = 7.5
MAX_FILE_SIZE_MB = 50
MAX_FILES_TO_SCAN = 10000
SKIP_DIRS = {'.git', '__pycache__', 'node_modules', '.venv', 'venv',
             'dist', 'build', '.idea', '.vscode'}

# lock/minified files: long generated hashes and packed code, not secrets
SKIP_FILENAMES = {
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock',
    'Pipfile.lock', 'Cargo.lock', 'composer.lock', 'go.sum', 'Gemfile.lock',
}
SKIP_FILENAME_PATTERNS = ('*.min.js', '*.min.css')

RISK_THRESHOLDS = {
    'critical': 75,
    'high': 50,
    'medium': 25,
    'low': 10
}

# risk score point values, centralized so scoring logic isn't scattered magic numbers
SCORE_PATTERN_MATCH = 5
SCORE_LONG_LINE = 3
SCORE_EXTREMELY_LONG_LINE = 10
SCORE_DANGEROUS_FUNCTION = 3
SCORE_ENTROPY = 20
SCORE_BASE64_FEW = 5
SCORE_BASE64_MANY = 10
SCORE_BASE64_DECODE = 10
SCORE_BASE64_ENCODE = 5
SCORE_VULNERABLE_DEPENDENCY = 15
SCORE_VULNERABLE_DEPENDENCY_CONFIRMED = 20

LONG_LINE_CHARS = 500
EXTREMELY_LONG_LINE_CHARS = 1000
BASE64_MIN_LENGTH = 40
BASE64_FEW_COUNT = 2
BASE64_MANY_COUNT = 5
BASE64_MIN_ENTROPY = 4.5