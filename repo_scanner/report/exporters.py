"""Report exporters for various formats"""

import json
import csv
from repo_scanner.models.scan_result import ScanSummary

class ReportExporter:
    @staticmethod
    def export_json(summary: ScanSummary, file_path: str):
        data = summary.to_dict()
        
        data['findings'] = [
            {
                'file': f.file_path,
                'severity': f.severity,
                'category': f.category,
                'description': f.description
            }
            for f in summary.findings
        ]
        
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    @staticmethod
    def export_csv(summary: ScanSummary, file_path: str):
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['File', 'Severity', 'Category', 'Description'])
            
            for finding in summary.findings:
                writer.writerow([
                    finding.file_path,
                    finding.severity,
                    finding.category,
                    finding.description
                ])