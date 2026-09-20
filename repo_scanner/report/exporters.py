"""Report exporters for various formats"""

import json
import csv
import os
from repo_scanner.config import __version__
from repo_scanner.models.scan_result import ScanSummary

SARIF_LEVELS = {
    'critical': 'error',
    'high': 'error',
    'medium': 'warning',
    'low': 'note',
    'info': 'note',
}

TOOL_URI = 'https://github.com/MR-UNKNOWN8014/repo-security-scanner'


def _sarif_uri(file_path: str, scan_root: str = '') -> str:
    # GitHub Code Scanning matches results by repo-relative path, so an absolute
    # path silently fails to link. Separators are normalized by hand because
    # PurePath treats a backslash as a separator only when running on Windows.
    path = file_path
    if scan_root:
        try:
            relative = os.path.relpath(path, scan_root)
            if not relative.startswith('..'):
                path = relative
        except ValueError:
            pass
    return path.replace('\\', '/')


class ReportExporter:
    @staticmethod
    def export_json(summary: ScanSummary, file_path: str):
        data = summary.to_dict()
        
        def as_dict(f):
            return {
                'file': f.file_path,
                'severity': f.severity,
                'category': f.category,
                'description': f.description,
                'line': f.line
            }

        data['findings'] = [as_dict(f) for f in summary.findings]
        data['cautions'] = [as_dict(f) for f in summary.cautions]
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    
    @staticmethod
    def export_csv(summary: ScanSummary, file_path: str):
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['File', 'Line', 'Severity', 'Category', 'Description'])

            for finding in summary.findings + summary.cautions:
                writer.writerow([
                    finding.file_path,
                    finding.line if finding.line is not None else '',
                    finding.severity,
                    finding.category,
                    finding.description
                ])

    @staticmethod
    def export_sarif(summary: ScanSummary, file_path: str):
        rules = {}
        results = []

        # rule level is the most severe level the category can produce, not
        # whichever finding happened to be emitted first
        rank = {'note': 0, 'warning': 1, 'error': 2}

        for finding in summary.findings + summary.cautions:
            level = SARIF_LEVELS.get(finding.severity, 'warning')
            rule = rules.get(finding.category)
            if rule is None:
                rules[finding.category] = {
                    'id': finding.category,
                    'name': finding.category,
                    'shortDescription': {'text': finding.category.replace('_', ' ')},
                    'defaultConfiguration': {'level': level},
                }
            elif rank[level] > rank[rule['defaultConfiguration']['level']]:
                rule['defaultConfiguration']['level'] = level

            location = {'physicalLocation': {'artifactLocation': {'uri': _sarif_uri(finding.file_path, summary.scan_root)}}}
            if finding.line is not None:
                location['physicalLocation']['region'] = {'startLine': finding.line}

            results.append({
                'ruleId': finding.category,
                'level': level,
                'message': {'text': finding.description},
                'locations': [location],
            })

        sarif = {
            '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
            'version': '2.1.0',
            'runs': [{
                'tool': {'driver': {
                    'name': 'repo-security-scanner',
                    'version': __version__,
                    'informationUri': TOOL_URI,
                    'rules': list(rules.values()),
                }},
                'results': results,
            }],
        }

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2)