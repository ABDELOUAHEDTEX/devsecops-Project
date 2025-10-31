"""
DAST (Dynamic Application Security Testing) Parser
Supports: OWASP ZAP (JSON, XML, logs), Burp Suite
"""

import json
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from .base_parser import BaseParser


class DASTParser(BaseParser):
    """Parser for DAST security reports"""
    
    # ZAP plugin ID to CWE mapping
    ZAP_CWE_MAP = {
        '10020': 'CWE-1021',  # X-Frame-Options missing
        '10021': 'CWE-693',   # X-Content-Type-Options missing
        '10038': 'CWE-693',   # Content Security Policy missing
        '10036': 'CWE-200',   # Server header information leak
        '10202': 'CWE-352',   # Absence of Anti-CSRF tokens
        '10063': 'CWE-693',   # Permissions-Policy Header Not Set
        '10054': 'CWE-1275',  # Cookie without SameSite Attribute
        '40012': 'CWE-79',    # Cross Site Scripting (Reflected)
        '40014': 'CWE-79',    # Cross Site Scripting (Persistent)
        '40018': 'CWE-79',    # Cross Site Scripting (DOM)
        '90019': 'CWE-209',   # Server Side Code Injection
        '90020': 'CWE-78',    # Remote OS Command Injection
        '90021': 'CWE-611',   # XML External Entity Attack
        '90022': 'CWE-89',    # SQL Injection
        '90023': 'CWE-91',    # XML Injection
        '90024': 'CWE-90',    # LDAP Injection
        '90025': 'CWE-77',    # Command Injection
        '90026': 'CWE-94',    # Code Injection
        '40003': 'CWE-22',    # CRLF Injection
        '10017': 'CWE-829',   # Cross-Domain Misconfiguration
    }
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse DAST report - auto-detects format"""
        if self.report_path.suffix == '.json':
            return self.parse_json()
        elif self.report_path.suffix in ['.xml', '.html']:
            return self.parse_xml()
        elif self.report_path.suffix == '.log':
            return self.parse_zap_log()
        else:
            # Try JSON first
            try:
                return self.parse_json()
            except:
                # Fallback to log parsing
                return self.parse_zap_log()
    
    def parse_json(self) -> List[Dict[str, Any]]:
        """
        Parse OWASP ZAP JSON report
        
        Format:
        {
          "site": [{
            "@name": "http://localhost:5000",
            "alerts": [{
              "pluginid": "10020",
              "alert": "X-Frame-Options Header Not Set",
              "name": "X-Frame-Options Header Not Set",
              "riskcode": "2",
              "confidence": "2",
              "riskdesc": "Medium (Medium)",
              "desc": "...",
              "instances": [{
                "uri": "http://localhost:5000/login",
                "method": "GET",
                "evidence": ""
              }],
              "solution": "...",
              "reference": "...",
              "cweid": "1021",
              "wascid": "15"
            }]
          }]
        }
        """
        data = self.load_json()
        vulnerabilities = []
        
        sites = data.get('site', [])
        
        for site in sites:
            site_url = site.get('@name', site.get('name', 'Unknown'))
            alerts = site.get('alerts', [])
            
            for alert in alerts:
                plugin_id = str(alert.get('pluginid', 'UNKNOWN'))
                
                # Get instances (each instance is a separate finding)
                instances = alert.get('instances', [{}])
                
                # If no instances, create one generic entry
                if not instances:
                    instances = [{'uri': site_url, 'method': 'GET'}]
                
                for instance in instances:
                    # Parse risk description (e.g., "High (Medium)" -> severity=High, confidence=Medium)
                    risk_desc = alert.get('riskdesc', 'Medium (Medium)')
                    severity, confidence = self.parse_risk_desc(risk_desc)
                    
                    vuln = {
                        'id': plugin_id,
                        'title': alert.get('name', alert.get('alert', 'Unknown vulnerability')),
                        'description': alert.get('desc', '')[:500],
                        'severity': severity,
                        'confidence': confidence,
                        'cwe': f"CWE-{alert.get('cweid', self.ZAP_CWE_MAP.get(plugin_id, 'N/A'))}",
                        'url': instance.get('uri', site_url),
                        'method': instance.get('method', 'GET'),
                        'file': instance.get('uri', site_url),  # For consistency
                        'remediation': alert.get('solution', ''),
                        'references': self.parse_references(alert.get('reference', '')),
                    }
                    
                    vulnerabilities.append(self.normalize(vuln))
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def parse_xml(self) -> List[Dict[str, Any]]:
        """
        Parse OWASP ZAP XML report
        
        Format similar to JSON but in XML structure
        """
        tree = ET.parse(self.report_path)
        root = tree.getroot()
        
        vulnerabilities = []
        
        for site in root.findall('.//site'):
            site_url = site.get('name', 'Unknown')
            
            for alertitem in site.findall('.//alertitem'):
                plugin_id = alertitem.findtext('pluginid', 'UNKNOWN')
                
                # Get all instances
                instances = alertitem.findall('instances/instance')
                
                if not instances:
                    instances = [ET.Element('instance')]  # Create dummy
                
                for instance in instances:
                    risk_desc = alertitem.findtext('riskdesc', 'Medium (Medium)')
                    severity, confidence = self.parse_risk_desc(risk_desc)
                    
                    vuln = {
                        'id': plugin_id,
                        'title': alertitem.findtext('alert', 'Unknown vulnerability'),
                        'description': alertitem.findtext('desc', '')[:500],
                        'severity': severity,
                        'confidence': confidence,
                        'cwe': f"CWE-{alertitem.findtext('cweid', self.ZAP_CWE_MAP.get(plugin_id, 'N/A'))}",
                        'url': instance.findtext('uri', site_url),
                        'method': instance.findtext('method', 'GET'),
                        'file': instance.findtext('uri', site_url),
                        'remediation': alertitem.findtext('solution', ''),
                        'references': self.parse_references(alertitem.findtext('reference', '')),
                    }
                    
                    vulnerabilities.append(self.normalize(vuln))
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def parse_zap_log(self) -> List[Dict[str, Any]]:
        """
        Parse OWASP ZAP baseline/full scan log file
        
        Format:
        WARN-NEW: X-Frame-Options Header Not Set [10020] x 3
        FAIL-NEW: SQL Injection [90022] x 2
        """
        content = self.load_text()
        vulnerabilities = []
        
        # Patterns for log parsing
        warn_pattern = r'WARN-NEW:\s+(.+?)\s+\[(\d+)\]\s+x\s+(\d+)'
        fail_pattern = r'FAIL-NEW:\s+(.+?)\s+\[(\d+)\]\s+x\s+(\d+)'
        url_pattern = r'(https?://[^\s]+)'
        
        # Parse WARN-NEW entries (Medium severity)
        for match in re.finditer(warn_pattern, content):
            alert_name = match.group(1).strip()
            plugin_id = match.group(2)
            count = match.group(3)
            
            vuln = {
                'id': plugin_id,
                'title': alert_name,
                'description': f"{alert_name} (found {count} time(s))",
                'severity': 'MEDIUM',
                'confidence': 'MEDIUM',
                'cwe': self.ZAP_CWE_MAP.get(plugin_id, 'N/A'),
                'url': 'Multiple URLs',
                'method': 'Multiple',
                'file': 'Multiple URLs',
                'remediation': 'Refer to OWASP ZAP documentation for remediation guidance.',
                'references': [
                    f'https://www.zaproxy.org/docs/alerts/{plugin_id}/'
                ],
            }
            
            vulnerabilities.append(self.normalize(vuln))
        
        # Parse FAIL-NEW entries (High severity)
        for match in re.finditer(fail_pattern, content):
            alert_name = match.group(1).strip()
            plugin_id = match.group(2)
            count = match.group(3)
            
            vuln = {
                'id': plugin_id,
                'title': alert_name,
                'description': f"{alert_name} (found {count} time(s))",
                'severity': 'HIGH',
                'confidence': 'MEDIUM',
                'cwe': self.ZAP_CWE_MAP.get(plugin_id, 'N/A'),
                'url': 'Multiple URLs',
                'method': 'Multiple',
                'file': 'Multiple URLs',
                'remediation': 'Refer to OWASP ZAP documentation for remediation guidance.',
                'references': [
                    f'https://www.zaproxy.org/docs/alerts/{plugin_id}/'
                ],
            }
            
            vulnerabilities.append(self.normalize(vuln))
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def parse_risk_desc(self, risk_desc: str) -> tuple:
        """
        Parse ZAP risk description
        
        Args:
            risk_desc: String like "High (Medium)" or "Low (High)"
            
        Returns:
            Tuple of (severity, confidence)
        """
        # Pattern: "Severity (Confidence)"
        match = re.match(r'(\w+)\s*\((\w+)\)', risk_desc)
        if match:
            severity = match.group(1)
            confidence = match.group(2)
            return severity, confidence
        
        # Fallback
        return 'MEDIUM', 'MEDIUM'
    
    def parse_references(self, references: str) -> List[str]:
        """Parse reference URLs from ZAP report"""
        if not references:
            return []
        
        # Split by newlines and filter URLs
        refs = []
        for line in references.split('\n'):
            line = line.strip()
            if line.startswith('http'):
                refs.append(line)
        
        return refs
    
    def get_tool_name(self) -> str:
        """Get DAST tool name"""
        path_lower = str(self.report_path).lower()
        
        if 'zap' in path_lower:
            return 'OWASP ZAP'
        elif 'burp' in path_lower:
            return 'Burp Suite'
        else:
            return 'DAST Scanner'
    
    def get_tool_type(self) -> str:
        """Get scan type"""
        return 'DAST'
