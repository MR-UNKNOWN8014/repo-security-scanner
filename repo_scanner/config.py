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
        r'subprocess\.', r'os\.system', r'os\.popen',
        r'popen', r'system\(', r'exec\(', r'eval\('
    ]
}

DANGEROUS_FUNCTIONS = {
    'python': ['exec', 'eval', 'compile', '__import__', 'os.system', 
               'subprocess.call', 'subprocess.Popen', 'os.popen'],
    'javascript': ['eval', 'Function', 'setTimeout', 'setInterval',
                   'document.write', 'innerHTML'],
    'bash': ['exec', 'eval', 'source', '.', 'export', 'alias'],
    'php': ['eval', 'system', 'exec', 'passthru', 'shell_exec', 'assert']
}

HIGH_ENTROPY_THRESHOLD = 7.5
MAX_FILE_SIZE_MB = 50
MAX_FILES_TO_SCAN = 10000

RISK_THRESHOLDS = {
    'critical': 75,
    'high': 50,
    'medium': 25,
    'low': 10
}