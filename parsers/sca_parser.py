"""
SCA (Software Composition Analysis) Parser
Supports: OWASP Dependency-Check, Snyk, pip-audit, Safety, Trivy
"""

import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from .base_parser import BaseParser


class SCAParser(BaseParser):
    """Parser for SCA security reports"""
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse SCA report - auto-detects format"""
        data = self.load_json()
        
        # Detect tool format
        if 'dependencies' in data:
            # OWASP Dependency-Check
            return self.parse_dependency_check(data)
        elif 'vulnerabilities' in data and isinstance(data.get('vulnerabilities'), list):
            # Could be pip-audit or aggregate summary
            if any('package' in v for v in data['vulnerabilities']):
                return self.parse_pip_audit(data)
            else:
                # Aggregate summary format
                return self.parse_aggregate_summary(data)
        elif 'packageManager' in data or 'policy' in data:
            # Snyk format
            return self.parse_snyk(data)
        elif 'Results' in data:
            # Trivy format
            return self.parse_trivy(data)
        else:
            raise ValueError(f"Unknown SCA report format in {self.report_path}")
    
    def parse_dependency_check(self, data: Dict) -> List[Dict[str, Any]]:
        """
        Parse OWASP Dependency-Check JSON report
        
        Format:
        {
          "dependencies": [{
            "fileName": "commons-beanutils-1.9.4.jar",
            "filePath": "/app/lib/commons-beanutils-1.9.4.jar",
            "vulnerabilities": [{
              "name": "CVE-2022-1471",
              "cvssv3": {"score": 9.8},
              "severity": "CRITICAL",
              "description": "...",
              "cwe": "CWE-502"
            }]
          }]
        }
        """
        vulnerabilities = []
        dependencies = data.get('dependencies', [])
        
        for dep in dependencies:
            file_name = dep.get('fileName', 'Unknown')
            file_path = dep.get('filePath', file_name)
            
            dep_vulns = dep.get('vulnerabilities', [])
            
            for vuln in dep_vulns:
                # Determine severity from CVSS score
                cvss_v3 = vuln.get('cvssv3', {})
                cvss_v2 = vuln.get('cvssv2', {})
                cvss_score = cvss_v3.get('score', cvss_v2.get('score', 0))
                
                severity = vuln.get('severity', self.cvss_to_severity(cvss_score))
                
                vuln_data = {
                    'id': vuln.get('name', 'UNKNOWN'),
                    'title': f"Vulnerable dependency: {file_name}",
                    'description': vuln.get('description', 'No description')[:500],
                    'severity': severity,
                    'cve': vuln.get('name'),
                    'cwe': vuln.get('cwe', 'CWE-937'),  # Using Components with Known Vulnerabilities
                    'file': file_path,
                    'package': file_name.replace('.jar', '').replace('.tar.gz', ''),
                    'remediation': f"Update {file_name} to a secure version",
                    'references': vuln.get('references', []),
                }
                
                vulnerabilities.append(self.normalize(vuln_data))
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def parse_snyk(self, data: Dict) -> List[Dict[str, Any]]:
        """
        Parse Snyk JSON report
        
        Format:
        {
          "vulnerabilities": [{
            "id": "SNYK-PYTHON-FLASK-...",
            "title": "Cross-site Scripting (XSS)",
            "severity": "high",
            "packageName": "flask",
            "version": "2.0.0",
            "identifiers": {
              "CVE": ["CVE-2023-1234"],
              "CWE": ["CWE-79"]
            }
          }]
        }
        """
        vulnerabilities = []
        vulns = data.get('vulnerabilities', [])
        
        for vuln in vulns:
            identifiers = vuln.get('identifiers', {})
            cve_list = identifiers.get('CVE', [])
            cwe_list = identifiers.get('CWE', [])
            
            vuln_data = {
                'id': vuln.get('id', 'SNYK-UNKNOWN'),
                'title': vuln.get('title', 'Dependency vulnerability'),
                'description': vuln.get('description', '')[:500],
                'severity': vuln.get('severity', 'MEDIUM').upper(),
                'cve': cve_list[0] if cve_list else None,
                'cwe': cwe_list[0] if cwe_list else 'CWE-937',
                'package': vuln.get('packageName', 'Unknown'),
                'version': vuln.get('version', 'Unknown'),
                'file': 'requirements.txt',
                'remediation': f"Upgrade {vuln.get('packageName', 'package')} to version {vuln.get('fixedIn', ['latest'])[0] if vuln.get('fixedIn') else 'latest'}",
                'references': [vuln.get('url')] if vuln.get('url') else [],
            }
            
            vulnerabilities.append(self.normalize(vuln_data))
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def parse_pip_audit(self, data: Dict) -> List[Dict[str, Any]]:
        """
        Parse pip-audit JSON report
        
        Format:
        {
          "vulnerabilities": [{
            "id": "PYSEC-2023-1234",
            "package": "flask",
            "installed_version": "2.0.0",
            "severity": "HIGH",
            "description": "...",
            "fix_versions": ["2.3.0"]
          }]
        }
        """
        vulnerabilities = []
        vulns = data.get('vulnerabilities', [])
        
        for vuln in vulns:
            vuln_data = {
                'id': vuln.get('id', 'UNKNOWN'),
                'title': f"Vulnerability in {vuln.get('package', 'package')}",
                'description': vuln.get('description', '')[:500],
                'severity': vuln.get('severity', 'MEDIUM'),
                'cve': vuln.get('id') if vuln.get('id', '').startswith('CVE') else None,
                'cwe': 'CWE-937',
                'package': vuln.get('package', 'Unknown'),
                'version': vuln.get('installed_version', 'Unknown'),
                'file': 'requirements.txt',
                'remediation': f"Upgrade to version {', '.join(vuln.get('fix_versions', ['latest']))}",
                'references': vuln.get('aliases', []),
            }
            
            vulnerabilities.append(self.normalize(vuln_data))
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def parse_trivy(self, data: Dict) -> List[Dict[str, Any]]:
        """
        Parse Trivy JSON report
        
        Format:
        {
          "Results": [{
            "Vulnerabilities": [{
              "VulnerabilityID": "CVE-2023-1234",
              "PkgName": "flask",
              "InstalledVersion": "2.0.0",
              "Severity": "HIGH",
              "Title": "...",
              "Description": "..."
            }]
          }]
        }
        """
        vulnerabilities = []
        results = data.get('Results', [])
        
        for result in results:
            vulns = result.get('Vulnerabilities', [])
            
            for vuln in vulns:
                vuln_data = {
                    'id': vuln.get('VulnerabilityID', 'UNKNOWN'),
                    'title': vuln.get('Title', 'Dependency vulnerability'),
                    'description': vuln.get('Description', '')[:500],
                    'severity': vuln.get('Severity', 'MEDIUM'),
                    'cve': vuln.get('VulnerabilityID'),
                    'cwe': vuln.get('CweIDs', ['CWE-937'])[0] if vuln.get('CweIDs') else 'CWE-937',
                    'package': vuln.get('PkgName', 'Unknown'),
                    'version': vuln.get('InstalledVersion', 'Unknown'),
                    'file': result.get('Target', 'requirements.txt'),
                    'remediation': f"Update to version {vuln.get('FixedVersion', 'latest')}",
                    'references': vuln.get('References', []),
                }
                
                vulnerabilities.append(self.normalize(vuln_data))
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def parse_aggregate_summary(self, data: Dict) -> List[Dict[str, Any]]:
        """
        Parse aggregate SCA summary format (from generate_sca_summary.py)
        This is already normalized, just need to convert
        """
        vulnerabilities = []
        vulns = data.get('vulnerabilities', [])
        
        for vuln in vulns:
            # Already mostly normalized, just ensure consistency
            vuln_data = {
                'id': vuln.get('cve', vuln.get('type', 'UNKNOWN')),
                'title': vuln.get('type', 'Dependency Vulnerability'),
                'description': vuln.get('description', '')[:500],
                'severity': vuln.get('severity', 'MEDIUM'),
                'cve': vuln.get('cve'),
                'cwe': vuln.get('cwe', 'CWE-937'),
                'package': vuln.get('package', 'Unknown'),
                'version': vuln.get('version', 'Unknown'),
                'file': vuln.get('file', 'requirements.txt'),
                'remediation': f"Update {vuln.get('package', 'dependency')} to latest secure version",
            }
            
            vulnerabilities.append(self.normalize(vuln_data))
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def cvss_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity level"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_tool_name(self) -> str:
        """Get SCA tool name"""
        path_lower = str(self.report_path).lower()
        
        if 'dependency-check' in path_lower or 'dependency_check' in path_lower:
            return 'OWASP Dependency-Check'
        elif 'snyk' in path_lower:
            return 'Snyk'
        elif 'pip-audit' in path_lower or 'pip_audit' in path_lower:
            return 'pip-audit'
        elif 'safety' in path_lower:
            return 'Safety'
        elif 'trivy' in path_lower:
            return 'Trivy'
        else:
            return 'SCA Scanner'
    
    def get_tool_type(self) -> str:
        """Get scan type"""
        return 'SCA'
