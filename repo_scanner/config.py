"""Configuration and constants"""

__version__ = "0.1.1"

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

# name -> regex capturing the credential itself in group 1 (for redaction).
# Known-bad placeholder values (EXAMPLE keys, "changeme", etc.) are filtered
# separately in secret_detector.py, not baked into the regex.
SECRET_PATTERNS = {
    'AWS Access Key ID': r'(AKIA[0-9A-Z]{16})',
    'AWS Secret Access Key': r'aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
    'GitHub Token': r'(gh[pousr]_[A-Za-z0-9]{36,255})',
    'GitLab Token': r'(glpat-[A-Za-z0-9\-_]{20})',
    'Slack Token': r'(xox[baprs]-[A-Za-z0-9-]{10,72})',
    'Slack Webhook': r'(https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,})',
    'Google API Key': r'(AIza[0-9A-Za-z\-_]{35})',
    'Stripe Key': r'((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,})',
    'Private Key Block': r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)',
    'JWT': r'(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})',
    'Generic API Key Assignment': r'(?i)api[_-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
    'Generic Secret Assignment': r'(?i)(?:secret|token)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
    'Hardcoded Password': r'(?i)password\s*[:=]\s*["\']([^"\'\s]{8,})["\']',
    'Twilio API Key': r'(SK[0-9a-fA-F]{32})',
    'SendGrid API Key': r'(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})',
}

# these placeholder values are common in docs/tests and are never real secrets
SECRET_PLACEHOLDER_MARKERS = (
    'example', 'changeme', 'placeholder', 'xxxxxx', 'your_', 'your-',
    '<', 'dummy', 'fake', 'test_key', 'sample',
)

# deliberately high: a single confirmed secret alone should push the file
# past the CRITICAL threshold (75), not get averaged down by other checks
SCORE_SECRET_DETECTED = 80

DOCKERFILE_NAME_PATTERNS = ('Dockerfile', 'Dockerfile.*', '*.dockerfile')

SCORE_DOCKER_LATEST_TAG = 5
SCORE_DOCKER_ROOT_USER = 10
SCORE_DOCKER_ADD_VS_COPY = 3
SCORE_DOCKER_PIPE_SHELL = 20
SCORE_DOCKER_INSECURE_TLS = 10
SCORE_DOCKER_HARDCODED_SECRET = 15