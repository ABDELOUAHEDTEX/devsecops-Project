# DevSecOps Security Scanning - Complete Implementation Guide

## 🎯 Project Overview

This guide will help you build a **complete DevSecOps security scanning pipeline** from scratch in a new repository.

**What You'll Build:**
- ✅ SCA (Software Composition Analysis) scanning with multiple tools
- ✅ SAST (Static Application Security Testing)
- ✅ DAST (Dynamic Application Security Testing)
- ✅ Unified vulnerability reporting
- ✅ LLM-powered policy generation
- ✅ Automated CI/CD workflows

---

## 📋 Table of Contents

1. [Repository Setup](#step-1-repository-setup)
2. [Project Structure](#step-2-project-structure)
3. [Core Parser Framework](#step-3-core-parser-framework)
4. [SAST Parser](#step-4-sast-parser)
5. [DAST Parser](#step-5-dast-parser)
6. [SCA Parser](#step-6-sca-parser)
7. [Report Orchestration](#step-7-report-orchestration)
8. [Security Summary Generator](#step-8-security-summary-generator)
9. [GitHub Actions Workflows](#step-9-github-actions-workflows)
10. [LLM Integration](#step-10-llm-integration)
11. [Testing](#step-11-testing)
12. [Documentation](#step-12-documentation)

---

## Step 1: Repository Setup

### 1.1 Create New Repository

```bash
# Create new directory
mkdir devsecops-security-scanner
cd devsecops-security-scanner

# Initialize git
git init

# Create main branch
git checkout -b main
```

### 1.2 Create Initial Files

```bash
# Create .gitignore
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
ENV/
*.egg-info/
.pytest_cache/
.coverage
htmlcov/

# Reports
reports/*.json
reports/*.html
reports/*.xml
reports/*.sarif
reports/*.log
reports/*.txt
!reports/.gitkeep

# Environment
.env
.env.local

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
EOF

# Create README
cat > README.md << 'EOF'
# DevSecOps Security Scanner

Comprehensive security scanning pipeline with SCA, SAST, and DAST capabilities.

## Features

- 🔍 Software Composition Analysis (SCA)
- 🔬 Static Application Security Testing (SAST)
- 🌐 Dynamic Application Security Testing (DAST)
- 📊 Unified vulnerability reporting
- 🤖 LLM-powered policy generation
- ⚡ Automated CI/CD workflows

## Quick Start

See [SETUP.md](docs/SETUP.md) for detailed setup instructions.

## License

MIT
EOF

# Create requirements.txt
cat > requirements.txt << 'EOF'
# Core dependencies
pyyaml==6.0.1
python-dotenv==1.0.0
requests==2.31.0

# LLM Integration
openai==1.3.0
huggingface-hub==0.26.0

# Evaluation
nltk==3.8.1
rouge-score==0.1.2
sacrebleu==2.3.1

# Data processing
pandas==2.2.3
beautifulsoup4==4.12.2
lxml>=5.0.0
xmltodict==0.13.0
EOF
```

### 1.3 Initial Commit

```bash
git add .
git commit -m "chore: initial repository setup"
```

---

## Step 2: Project Structure

### 2.1 Create Directory Structure

```bash
# Create directories
mkdir -p parsers
mkdir -p scripts
mkdir -p workflows
mkdir -p LLM/{Scripts,reports}
mkdir -p reports
mkdir -p tests/{unit,integration}
mkdir -p docs
mkdir -p .github/workflows

# Create __init__.py files
touch parsers/__init__.py
touch LLM/__init__.py
touch LLM/Scripts/__init__.py
touch tests/__init__.py
touch tests/unit/__init__.py
touch tests/integration/__init__.py

# Create placeholder files
touch reports/.gitkeep
touch LLM/reports/.gitkeep
```

### 2.2 Final Structure

```
devsecops-security-scanner/
├── .github/
│   └── workflows/          # GitHub Actions workflows
├── parsers/                # Security report parsers
│   ├── __init__.py
│   ├── base_parser.py
│   ├── sast_parser.py
│   ├── dast_parser.py
│   └── sca_parser.py
├── scripts/                # Orchestration scripts
│   ├── parse_reports.py
│   └── generate_security_summary.py
├── LLM/                    # LLM integration
│   ├── Scripts/
│   │   ├── generate_policies.py
│   │   ├── mappings.py
│   │   └── prompt_template.txt
│   └── reports/
├── reports/                # Generated reports (gitignored)
├── tests/                  # Test suite
│   ├── unit/
│   └── integration/
├── docs/                   # Documentation
├── .gitignore
├── README.md
└── requirements.txt
```

---

## Step 3: Core Parser Framework

### 3.1 Create `parsers/__init__.py`

```python
"""Security report parsers package"""

from .base_parser import BaseParser
from .sast_parser import SASTParser
from .dast_parser import DASTParser
from .sca_parser import SCAParser

__all__ = [
    'BaseParser',
    'SASTParser',
    'DASTParser',
    'SCAParser',
]

__version__ = '1.0.0'
```

**File:** `parsers/__init__.py`

### 3.2 Create `parsers/base_parser.py`

```python
"""
Base Parser Class for Security Reports
Provides common functionality for all security scanners
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import json
from pathlib import Path


class BaseParser(ABC):
    """Abstract base class for security report parsers"""
    
    # Severity normalization mapping
    SEVERITY_MAP = {
        'critical': 'CRITICAL',
        'blocker': 'CRITICAL',
        'high': 'HIGH',
        'major': 'HIGH',
        'error': 'HIGH',
        'medium': 'MEDIUM',
        'moderate': 'MEDIUM',
        'warning': 'MEDIUM',
        'warn': 'MEDIUM',
        'low': 'LOW',
        'minor': 'LOW',
        'info': 'LOW',
        'informational': 'LOW',
        'note': 'LOW',
    }
    
    def __init__(self, report_path: str):
        """
        Initialize parser with report file path
        
        Args:
            report_path: Path to the security report file
        """
        self.report_path = Path(report_path)
        self.vulnerabilities: List[Dict[str, Any]] = []
        
        if not self.report_path.exists():
            raise FileNotFoundError(f"Report file not found: {report_path}")
    
    @abstractmethod
    def parse(self) -> List[Dict[str, Any]]:
        """
        Parse the security report and return list of vulnerabilities
        
        Returns:
            List of vulnerability dictionaries in unified schema
        """
        pass
    
    @abstractmethod
    def get_tool_name(self) -> str:
        """
        Get the name of the security tool
        
        Returns:
            Tool name (e.g., "OWASP ZAP", "SonarQube")
        """
        pass
    
    @abstractmethod
    def get_tool_type(self) -> str:
        """
        Get the type of security scan
        
        Returns:
            One of: "SCA", "SAST", "DAST"
        """
        pass
    
    def normalize_severity(self, severity: str) -> str:
        """
        Normalize severity to standard levels
        
        Args:
            severity: Raw severity value from tool
            
        Returns:
            Normalized severity: CRITICAL, HIGH, MEDIUM, or LOW
        """
        if not severity:
            return 'MEDIUM'
        
        normalized = self.SEVERITY_MAP.get(severity.lower())
        if normalized:
            return normalized
        
        # If not in map, try to infer from numeric score
        if isinstance(severity, (int, float)):
            if severity >= 9.0:
                return 'CRITICAL'
            elif severity >= 7.0:
                return 'HIGH'
            elif severity >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'
        
        # Default to MEDIUM if unknown
        return 'MEDIUM'
    
    def normalize_confidence(self, confidence: Any) -> str:
        """
        Normalize confidence level
        
        Args:
            confidence: Raw confidence value
            
        Returns:
            Normalized confidence: HIGH, MEDIUM, or LOW
        """
        if not confidence:
            return 'MEDIUM'
        
        if isinstance(confidence, str):
            conf_lower = confidence.lower()
            if conf_lower in ['high', 'certain', 'confirmed']:
                return 'HIGH'
            elif conf_lower in ['medium', 'firm', 'likely']:
                return 'MEDIUM'
            elif conf_lower in ['low', 'tentative', 'possible']:
                return 'LOW'
        
        return 'MEDIUM'
    
    def normalize(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize vulnerability to unified schema
        
        Args:
            vuln: Raw vulnerability dictionary from parser
            
        Returns:
            Normalized vulnerability in unified schema
        """
        return {
            # Tool identification
            'tool': self.get_tool_name(),
            'tool_type': self.get_tool_type(),
            
            # Core identification
            'id': str(vuln.get('id', 'UNKNOWN')),
            'title': vuln.get('title', vuln.get('vulnerability', 'No title provided')),
            'description': vuln.get('description', '')[:500],  # Limit length
            
            # Severity and confidence
            'severity': self.normalize_severity(vuln.get('severity', 'MEDIUM')),
            'confidence': self.normalize_confidence(vuln.get('confidence', 'MEDIUM')),
            
            # Security identifiers
            'cwe': vuln.get('cwe', 'N/A'),
            'cve': vuln.get('cve'),
            
            # Location information
            'file': vuln.get('file', ''),
            'line': vuln.get('line'),
            'url': vuln.get('url'),
            'method': vuln.get('method'),
            
            # For SCA
            'package': vuln.get('package'),
            'version': vuln.get('version'),
            
            # Remediation
            'remediation': vuln.get('remediation', ''),
            'references': vuln.get('references', []),
        }
    
    def load_json(self) -> Dict[str, Any]:
        """
        Load JSON report file
        
        Returns:
            Parsed JSON data
        """
        with open(self.report_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def load_text(self) -> str:
        """
        Load text report file
        
        Returns:
            File contents as string
        """
        with open(self.report_path, 'r', encoding='utf-8') as f:
            return f.read()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about parsed vulnerabilities
        
        Returns:
            Dictionary with counts by severity
        """
        stats = {
            'total': len(self.vulnerabilities),
            'by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
            }
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'MEDIUM')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
        
        return stats


class ParserFactory:
    """Factory for creating appropriate parser instances"""
    
    @staticmethod
    def create_parser(report_path: str) -> Optional[BaseParser]:
        """
        Create appropriate parser based on report file
        
        Args:
            report_path: Path to report file
            
        Returns:
            Parser instance or None if type cannot be determined
        """
        from .sast_parser import SASTParser
        from .dast_parser import DASTParser
        from .sca_parser import SCAParser
        
        path_lower = report_path.lower()
        
        # SAST detection
        if any(x in path_lower for x in ['sonarqube', 'sast', 'semgrep', 'bandit', 'codeql']):
            return SASTParser(report_path)
        
        # DAST detection
        if any(x in path_lower for x in ['zap', 'dast', 'burp']):
            return DASTParser(report_path)
        
        # SCA detection
        if any(x in path_lower for x in ['snyk', 'dependency', 'pip-audit', 'safety', 'sca', 'trivy']):
            return SCAParser(report_path)
        
        return None
```

**File:** `parsers/base_parser.py`

### 3.3 Commit Changes

```bash
git add parsers/
git commit -m "feat: add base parser framework"
```

---

## Step 4: SAST Parser

### 4.1 Create `parsers/sast_parser.py`

```python
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
        'B201': 'CWE-78',    # Flask debug mode
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
```

**File:** `parsers/sast_parser.py`

### 4.2 Commit Changes

```bash
git add parsers/sast_parser.py
git commit -m "feat: add SAST parser with SonarQube, SARIF, and Bandit support"
```

---

## Step 5: DAST Parser

### 5.1 Create `parsers/dast_parser.py`

I'll continue with the complete source code for all remaining components.

