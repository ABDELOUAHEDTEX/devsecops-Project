### 4.1 Create `parsers/sast_parser.py`

"""
SAST (Static Application Security Testing) Parser
Supports: SonarQube, SARIF (CodeQL, Semgrep), Bandit
"""

import json
import re
from typing import List, Dict, Any
from .base_parser import BaseParser


class SASTParser(BaseParser):
    """Parser for SAST security reports"""
    
    # CWE mapping for common SAST rules
    RULE_CWE_MAP = {
        # SonarQube rules
        'S2077': 'CWE-89',   # SQL Injection
        'S3649': 'CWE-89',   # SQL Injection
        'S5131': 'CWE-79',   # XSS
        'S5146': 'CWE-352',  # CSRF
        'S2068': 'CWE-798',  # Hard-coded credentials
        'S4502': 'CWE-611',  # XML External Entities
        'S5144': 'CWE-79',   # XSS in JSP/JSF
        'S3330': 'CWE-352',  # CSRF in HTTP
        'S2076': 'CWE-78',   # OS Command Injection
        
        # Bandit rules
        
        'B501': 'CWE-295',   # Request with verify=False
        'B506': 'CWE-798',   # YAML load
        'B608': 'CWE-89',    # SQL injection
        'B201': 'CWE-78',    # Command injection
    }
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse SAST report - auto-detects format"""
        data = self.load_json()
        
        # Detect format
        if 'issues' in data:
            # SonarQube API format
            return self.parse_sonarqube(data)
        elif '$schema' in data and 'sarif' in str(data.get('$schema', '')).lower():
            # SARIF 2.1.0 format
            return self.parse_sarif(data)
        elif 'results' in data and 'metrics' in data:
            # Bandit format
            return self.parse_bandit(data)
        else:
            raise ValueError(f"Unknown SAST report format in {self.report_path}")
    
    def parse_sonarqube(self, data: Dict) -> List[Dict[str, Any]]:
        """
        Parse SonarQube issues.json format
        
        Format:
        {
          "total": 10,
          "issues": [
            {
              "key": "AXyz123",
              "rule": "python:S2077",
              "severity": "MAJOR",
              "component": "my-app:src/app.py",
              "line": 45,
              "message": "Make sure using SQL queries is safe",
              "type": "VULNERABILITY"
            }
          ]
        }
        """
        vulnerabilities = []
        issues = data.get('issues', [])
        
        for issue in issues:
            # Only include security issues
            issue_type = issue.get('type', '')
            if issue_type not in ['VULNERABILITY', 'SECURITY_HOTSPOT']:
                continue
            
            # Extract rule ID
            rule = issue.get('rule', '')
            rule_id = rule.split(':')[-1] if ':' in rule else rule
            
            # Build vulnerability
            vuln = {
                'id': issue.get('key', rule),
                'title': issue.get('message', 'No description'),
                'description': issue.get('message', ''),
                'severity': issue.get('severity', 'MEDIUM'),
                'cwe': self.RULE_CWE_MAP.get(rule_id, self.extract_cwe_from_text(issue.get('message', ''))),
                'file': issue.get('component', '').replace(f"{issue.get('project', '')}:", ''),
                'line': issue.get('line'),
                'remediation': f"Review and fix {rule}. Check SonarQube documentation for guidance.",
                'references': [f"https://rules.sonarsource.com/{rule.replace(':', '/')}"],
            }
            
            vulnerabilities.append(self.normalize(vuln))
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def parse_sarif(self, data: Dict) -> List[Dict[str, Any]]:
        """
        Parse SARIF 2.1.0 format (CodeQL, Semgrep, etc.)
        
        Format:
        {
          "$schema": "...",
          "version": "2.1.0",
          "runs": [{
            "tool": {"driver": {"name": "CodeQL"}},
            "results": [{
              "ruleId": "py/sql-injection",
              "level": "error",
              "message": {"text": "SQL injection vulnerability"},
              "locations": [{
                "physicalLocation": {
                  "artifactLocation": {"uri": "src/app.py"},
                  "region": {"startLine": 45}
                }
              }]
            }]
          }]
        }
        """
        vulnerabilities = []
        runs = data.get('runs', [])
        
        for run in runs:
            tool_info = run.get('tool', {}).get('driver', {})
            tool_name = tool_info.get('name', 'Unknown SAST Tool')
            
            results = run.get('results', [])
            
            for result in results:
                # Extract location
                locations = result.get('locations', [{}])
                if locations:
                    physical_loc = locations[0].get('physicalLocation', {})
                    artifact = physical_loc.get('artifactLocation', {})
                    region = physical_loc.get('region', {})
                    
                    file_path = artifact.get('uri', '')
                    line_number = region.get('startLine')
                else:
                    file_path = ''
                    line_number = None
                
                # Extract message
                message = result.get('message', {})
                message_text = message.get('text', 'No description provided')
                
                # Extract rule properties
                rule_id = result.get('ruleId', 'UNKNOWN')
                properties = result.get('properties', {})
                tags = properties.get('tags', [])
                
                # Build vulnerability
                vuln = {
                    'id': rule_id,
                    'title': message_text[:100],
                    'description': message_text,
                    'severity': result.get('level', 'warning'),
                    'cwe': self.extract_cwe_from_tags(tags),
                    'file': file_path,
                    'line': line_number,
                    'remediation': self.extract_remediation(result),
                    'references': self.extract_references(result),
                }
                
                vulnerabilities.append(self.normalize(vuln))
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def parse_bandit(self, data: Dict) -> List[Dict[str, Any]]:
        """
        Parse Bandit JSON format
        
        Format:
        {
          "results": [
            {
              "code": "...",
              "filename": "app.py",
              "issue_confidence": "HIGH",
              "issue_severity": "MEDIUM",
              "issue_text": "SQL injection possible",
              "line_number": 45,
              "test_id": "B608",
              "test_name": "hardcoded_sql_expressions"
            }
          ],
          "metrics": {...}
        }
        """
        vulnerabilities = []
        results = data.get('results', [])
        
        for result in results:
            test_id = result.get('test_id', 'UNKNOWN')
            
            vuln = {
                'id': test_id,
                'title': result.get('issue_text', 'No description'),
                'description': f"{result.get('issue_text', '')}\\n\\nCode: {result.get('code', '')}",
                'severity': result.get('issue_severity', 'MEDIUM'),
                'confidence': result.get('issue_confidence', 'MEDIUM'),
                'cwe': self.RULE_CWE_MAP.get(test_id, 'N/A'),
                'file': result.get('filename', ''),
                'line': result.get('line_number'),
                'remediation': f"Review {result.get('test_name', 'this issue')} and apply security best practices.",
                'references': [
                    f"https://bandit.readthedocs.io/en/latest/plugins/{test_id.lower()}.html"
                ],
            }
            
            vulnerabilities.append(self.normalize(vuln))
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def extract_cwe_from_tags(self, tags: List[str]) -> str:
        """Extract CWE from SARIF tags"""
        for tag in tags:
            if tag.startswith('CWE-') or tag.startswith('cwe-'):
                return tag.upper()
        return 'N/A'
    
    def extract_cwe_from_text(self, text: str) -> str:
        """Extract CWE from description text"""
        match = re.search(r'CWE-(\d+)', text, re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"
        return 'N/A'
    
    def extract_remediation(self, result: Dict) -> str:
        """Extract remediation from SARIF result"""
        fixes = result.get('fixes', [])
        if fixes and len(fixes) > 0:
            fix_desc = fixes[0].get('description', {})
            return fix_desc.get('text', '')
        
        # Try to get from rule help
        help_text = result.get('message', {}).get('markdown', '')
        if help_text:
            return help_text[:200]
        
        return ''
    
    def extract_references(self, result: Dict) -> List[str]:
        """Extract reference URLs from SARIF result"""
        refs = []
        
        # From rule
        rule = result.get('rule', {})
        help_uri = rule.get('helpUri')
        if help_uri:
            refs.append(help_uri)
        
        # From properties
        properties = result.get('properties', {})
        ref_urls = properties.get('references', [])
        refs.extend(ref_urls)
        
        return refs
    
    def get_tool_name(self) -> str:
        """Get SAST tool name"""
        path_lower = str(self.report_path).lower()
        
        if 'sonarqube' in path_lower:
            return 'SonarQube'
        elif 'semgrep' in path_lower:
            return 'Semgrep'
        elif 'codeql' in path_lower:
            return 'CodeQL'
        elif 'bandit' in path_lower:
            return 'Bandit'
        else:
            return 'SAST Scanner'
    
    def get_tool_type(self) -> str:
        """Get scan type"""
        return 'SAST'

