# DevSecOps Security Scanning Architecture Analysis & Implementation Plan

**Date:** October 31, 2025  
**Focus:** SCA, SAST, and DAST Orchestration

---

## Table of Contents
1. [Current SCA Pipeline Overview](#1-current-sca-pipeline-overview)
2. [File-by-File Analysis](#2-file-by-file-analysis)
3. [Current Unified Schema](#3-current-unified-schema)
4. [Gaps and Requirements for SAST/DAST](#4-gaps-and-requirements-for-sastdast)
5. [Proposed Architecture](#5-proposed-architecture)
6. [Implementation Plan](#6-implementation-plan)
7. [Example Workflow YAMLs](#7-example-workflow-yamls)
8. [Local Development Commands](#8-local-development-commands)
9. [Validation Checklist](#9-validation-checklist)
10. [Risks and Assumptions](#10-risks-and-assumptions)

---

## 1. Current SCA Pipeline Overview

### High-Level Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    GitHub Actions Workflow                       │
│                    (.github/workflows/sca.yml)                   │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ├─> Trigger: Push/PR to main/develop
                     │
                     ├─> Run Multiple SCA Tools:
                     │   ├─> Snyk (Python dependencies)
                     │   ├─> Snyk Code
                     │   ├─> OWASP Dependency-Check
                     │   ├─> pip-audit
                     │   ├─> Safety
                     │   └─> Trivy (vuln/secret/license)
                     │
                     ├─> Raw Reports → reports/ directory
                     │   ├─> snyk-python-report.json
                     │   ├─> snyk-code-report.json
                     │   ├─> dependency-check-report.json
                     │   ├─> pip-audit-report.json
                     │   ├─> safety-detailed-report.json
                     │   └─> trivy.sarif
                     │
                     ├─> Parse & Aggregate:
                     │   └─> scripts/generate_sca_summary.py
                     │       └─> Outputs: reports/sca-summary.json
                     │
                     ├─> Upload Artifacts (all reports)
                     │
                     └─> Upload SARIF to GitHub Code Scanning
```

### Data Flow Summary

1. **Workflow Trigger** → CI runs on push/PR events
2. **Tool Execution** → Multiple SCA scanners run in parallel/sequence
3. **Raw Reports** → JSON/SARIF files saved to `reports/` directory
4. **Aggregation** → `generate_sca_summary.py` reads all raw reports
5. **Unified Report** → Single `sca-summary.json` with normalized schema
6. **Artifacts** → Reports uploaded for download
7. **Code Scanning** → SARIF uploaded to GitHub Security tab

### Current Problems

- **No parser abstraction**: Each tool format is parsed directly in `generate_sca_summary.py`
- **No SAST/DAST support**: Only SCA tools are integrated
- **Inconsistent schema**: Different tools have different severity mappings
- **No unified parsing layer**: Missing `scripts/parse_reports.py` integration with SCA
- **LLM integration disconnected**: Policy generation works on `unified-vulnerabilities.json`, but SCA creates `sca-summary.json`

---

## 2. File-by-File Analysis

### 2.1 Parsers: `parsers/sca_parser.py`

**Purpose:** Parse OWASP Dependency-Check reports (JSON/XML)

**Current Status:** ✅ EXISTS

**Inputs:**
- OWASP Dependency-Check JSON reports
- SCA summary JSON (from `generate_sca_summary.py`)

**Key Features:**
- Inherits from `BaseParser` (not shown, but referenced)
- Handles both JSON and XML formats
- Normalizes vulnerabilities to unified schema
- Maps CVSS scores to severity levels

**Output Schema (per vulnerability):**
```python
{
    'vulnerability': str,      # e.g., "Dependency Vulnerability: CVE-2022-1471"
    'severity': str,          # CRITICAL|HIGH|MEDIUM|LOW
    'cwe': str,               # e.g., "CWE-937"
    'file': str,              # Dependency file path
    'line': str,              # Usually 'N/A' for dependencies
    'description': str,       # Vulnerability description
    'remediation': str,       # Fix suggestion
    'cve': str,              # CVE identifier
    'dependency': str,        # Package name
    'package': str,          # Package name (duplicate)
    'version': str,          # Package version
    'tool': str              # Scanner name
}
```

**Issues:**
- Handles two different input formats (Dependency-Check native vs. sca-summary)
- No clear separation between raw tool parsing and summary parsing
- Mixing concerns: should focus on raw Dependency-Check reports only

---

### 2.2 Scripts: `scripts/parse_reports.py`

**Purpose:** Orchestrate parsing of all security reports and generate unified output

**Current Status:** ⚠️ EXISTS BUT INCOMPLETE

**Current Implementation:**
```python
# Attempts to parse:
- SAST: reports/sast-report.json → SASTParser
- SCA: reports/sca-summary.json OR reports/sca-report.json → SCAParser
- DAST: reports/dast-report.json → DASTParser

# Output: reports/unified-vulnerabilities.json
```

**Issues:**
1. **References non-existent parsers**: `SASTParser` and `DASTParser` don't exist
2. **Wrong SCA source**: Should read raw tool outputs, not pre-aggregated summary
3. **No tool detection logic**: Hardcoded file paths
4. **Missing error handling**: Fails silently if parsers don't exist

**What It Should Do:**
- Detect all available tool reports in `reports/` directory
- Invoke appropriate parser for each tool
- Aggregate all findings into single unified schema
- Handle multiple reports from same tool type
- Produce `reports/unified-vulnerabilities.json` for LLM consumption

---

### 2.3 Scripts: `scripts/generate_sca_summary.py`

**Purpose:** Aggregate multiple SCA tool outputs into summary report

**Current Status:** ✅ EXISTS AND WORKING

**Inputs (all from `reports/` directory):**
- `snyk-python-report.json` (Snyk dependency scan)
- `snyk-code-report.json` (Snyk SAST, but treated as SCA)
- `dependency-check-report.json` (OWASP Dependency-Check)
- `pip-audit-report.json` (pip-audit)
- `safety-detailed-report.json` (Safety)

**Outputs:**
- `reports/sca-summary.json` (structured JSON)
- `reports/sca-summary.txt` (human-readable)

**Output Schema:**
```json
{
  "scan_type": "SCA Summary Report",
  "tools_used": ["Snyk Python", "OWASP Dependency-Check", ...],
  "total_vulnerabilities": 42,
  "vulnerabilities_by_severity": {
    "CRITICAL": 5,
    "HIGH": 15,
    "MEDIUM": 20,
    "LOW": 2
  },
  "vulnerabilities_by_package": {
    "flask": 3,
    "requests": 2,
    ...
  },
  "vulnerabilities": [
    {
      "tool": "Snyk Python",
      "type": "Dependency Vulnerability",
      "severity": "HIGH",
      "file": "requirements.txt",
      "line": "N/A",
      "description": "...",
      "cwe": "CWE-937",
      "package": "commons-beanutils",
      "version": "1.9.4",
      "cve": "CVE-2022-1471"
    }
  ],
  "tool_summaries": {
    "Snyk Python": {
      "total_issues": 10,
      "packages_scanned": 25
    }
  }
}
```

**Issues:**
- **Mixes SAST and SCA**: Snyk Code is a SAST tool, not SCA
- **Hardcoded tool list**: Not extensible
- **Direct parsing**: Should use parser classes instead
- **No schema validation**: Output format not enforced

---

### 2.4 Workflows: `.github/workflows/sca.yml`

**Purpose:** Run SCA security scans in CI/CD

**Triggers:**
- Push to `main` or `develop`
- Pull requests to `main`
- Manual workflow dispatch

**Tools Executed:**
1. **Snyk** (with authentication via `SNYK_TOKEN`)
   - Python dependency scan → `snyk-python-report.json`
   - Code analysis → `snyk-code-report.json`
2. **OWASP Dependency-Check** → `dependency-check-report.json`
3. **pip-audit** → `pip-audit-report.json`
4. **Safety** → `safety-detailed-report.json`
5. **Trivy** (via aquasecurity action) → `trivy.sarif`

**Final Steps:**
- Run `generate_sca_summary.py` to aggregate results
- Upload all reports as artifacts
- Upload Trivy SARIF to GitHub Code Scanning

**Issues:**
- **No unified parsing step**: Should call `parse_reports.py` after summary generation
- **SARIF not aggregated**: Trivy SARIF uploaded separately, not unified with other tools
- **No LLM integration**: Policy generation not triggered

---

### 2.5 Workflows: `.github/workflows/sast-sonarqube.yml`

**Purpose:** Run SAST analysis using SonarQube

**Current Status:** ⚠️ WORKS BUT NOT INTEGRATED

**Process:**
1. Starts SonarQube in Docker container (service)
2. Waits for SonarQube to be ready
3. Configures project and generates token
4. Runs SonarScanner
5. Downloads issues via API: `sonarqube-reports/issues.json`
6. Uploads as artifact: `sonarqube-sast-issues`

**Output Format (SonarQube API):**
```json
{
  "total": 10,
  "issues": [
    {
      "key": "...",
      "rule": "python:S1234",
      "severity": "MAJOR",
      "component": "src/main/java/com/acme/UserRepository.java",
      "line": 57,
      "message": "User-controlled input concatenated into SQL query",
      "type": "VULNERABILITY"
    }
  ]
}
```

**Issues:**
- **Not called by parse_reports.py**: Output not aggregated
- **Custom API format**: Not SARIF (harder to parse)
- **No CWE mapping**: SonarQube uses own rule IDs
- **No unified schema**: Different from SCA output

---

### 2.6 Workflows: `.github/workflows/dast.yml`

**Purpose:** Run DAST scans using OWASP ZAP

**Current Status:** ⚠️ WORKS BUT NOT INTEGRATED

**Process:**
1. Start Flask application
2. Run ZAP Baseline Scan → `baseline_scan.log`
3. Run ZAP Full Scan → `full_scan.log`
4. Parse logs with grep/sed (counts WARN-NEW and FAIL-NEW)
5. Generate GitHub Step Summary (Markdown table)
6. Upload logs as artifacts

**Output Format:** Plain text logs (not JSON)

**Issues:**
- **No structured output**: Logs are plain text, not JSON
- **Manual parsing**: Grep/sed in bash instead of proper parser
- **No CWE/CVE mapping**: Just rule IDs from ZAP
- **Not integrated**: No call to `parse_reports.py`

---

### 2.7 LLM Integration

**Current Files:**
- `LLM/Scripts/generate_policies.py` → Generates security policies from vulnerabilities
- `LLM/Scripts/mappings.py` → CWE to theme mappings
- `LLM/reports/unified-vulnerabilities.json` → Expected input (manually created sample)

**Process:**
1. Reads `unified-vulnerabilities.json`
2. Groups findings by security theme (SQL Injection, XSS, etc.)
3. Calls OpenAI/HuggingFace APIs to generate policies
4. Outputs policy YAML files

**Current Problems:**
- **Sample data only**: `unified-vulnerabilities.json` is hand-crafted, not generated by CI
- **No CI integration**: Policy generation not automated
- **Schema mismatch**: Expected schema doesn't match `sca-summary.json`

---

## 3. Current Unified Schema

### Expected by LLM (`unified-vulnerabilities.json`)

```json
[
  {
    "tool": "OWASP Dependency-Check",
    "id": "CVE-2022-1471",
    "title": "Vulnerable component: commons-beanutils-1.9.4.jar",
    "description": "Known vulnerability in Apache Commons BeanUtils...",
    "severity": "HIGH",
    "cwe": "CWE-937",
    "file": "/app/lib/commons-beanutils-1.9.4.jar",
    "package": "commons-beanutils",
    "version": "1.9.4"
  },
  {
    "tool": "SonarQube",
    "id": "SAST-001",
    "title": "Possible SQL Injection in UserRepository.findByEmail",
    "description": "User-controlled input concatenated into SQL query string.",
    "severity": "CRITICAL",
    "cwe": "CWE-89",
    "file": "src/main/java/com/acme/UserRepository.java:57",
    "package": "",
    "version": ""
  },
  {
    "tool": "OWASP ZAP",
    "id": "10020",
    "title": "Missing X-Frame-Options Header",
    "description": "The response does not include the X-Frame-Options header...",
    "severity": "MEDIUM",
    "cwe": "CWE-1021",
    "file": "/login",
    "package": "",
    "version": ""
  }
]
```

### Key Fields

| Field | Required | Description | Example |
|-------|----------|-------------|---------|
| `tool` | Yes | Scanner name | "OWASP ZAP" |
| `id` | Yes | Vulnerability ID | "CVE-2022-1471" |
| `title` | Yes | Short description | "SQL Injection in login" |
| `description` | Yes | Detailed explanation | "User input not sanitized..." |
| `severity` | Yes | CRITICAL/HIGH/MEDIUM/LOW | "HIGH" |
| `cwe` | Yes | CWE identifier | "CWE-89" |
| `file` | Yes | File path or endpoint | "app.py:45" or "/api/login" |
| `package` | Optional | For SCA only | "flask" |
| `version` | Optional | For SCA only | "2.0.0" |

### Schema Issues

1. **Inconsistent severity**: Some tools use INFO/LOW/MEDIUM/HIGH/CRITICAL, others use different scales
2. **CWE mapping missing**: Not all tools provide CWE; needs manual mapping
3. **File format varies**: SCA uses package names, SAST uses source files, DAST uses URLs
4. **Missing fields**: No line numbers for DAST, no URLs for SAST
5. **ID collisions**: Different tools may use same IDs

---

## 4. Gaps and Requirements for SAST/DAST

### 4.1 Missing Components

#### Parsers
- ❌ `parsers/sast_parser.py` - Parse SARIF/SonarQube JSON
- ❌ `parsers/dast_parser.py` - Parse ZAP logs/JSON
- ❌ `parsers/base_parser.py` - Abstract base class (referenced but not shown)

#### Scripts
- ⚠️ `scripts/parse_reports.py` - Exists but doesn't work (missing parsers)
- ❌ `scripts/generate_security_summary.py` - Generalized version of SCA summary

#### Workflows
- ⚠️ `.github/workflows/sast-sonarqube.yml` - Works but not integrated
- ⚠️ `.github/workflows/dast.yml` - Works but needs JSON output

### 4.2 Required Changes

#### Schema Enhancements
```json
{
  "tool": "string",
  "tool_type": "SCA|SAST|DAST",  // NEW: distinguish scan types
  "id": "string",
  "title": "string",
  "description": "string",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",  // Normalized
  "confidence": "HIGH|MEDIUM|LOW",  // NEW: for DAST false positives
  "cwe": "string",
  "cve": "string|null",  // NEW: optional CVE
  "file": "string",
  "line": "int|null",  // NEW: line number for SAST
  "url": "string|null",  // NEW: endpoint for DAST
  "method": "string|null",  // NEW: HTTP method for DAST
  "package": "string|null",
  "version": "string|null",
  "remediation": "string|null",  // NEW: fix recommendation
  "references": ["string"]  // NEW: external links
}
```

#### Tool Detection Logic
```python
def detect_tool_type(filename, content):
    """Auto-detect scanner type from report"""
    if "sonarqube" in filename or "issues" in content:
        return "SAST", "SonarQube"
    elif "zap" in filename or "OWASP" in content.get("name", ""):
        return "DAST", "OWASP ZAP"
    elif "dependency-check" in filename:
        return "SCA", "OWASP Dependency-Check"
    # ... more rules
```

---

## 5. Proposed Architecture

### 5.1 Parser Hierarchy

```
parsers/
├── base_parser.py          # Abstract base class
├── sca_parser.py           # SCA tools (Dependency-Check, Snyk, etc.)
├── sast_parser.py          # NEW: SAST tools (SonarQube, Semgrep, etc.)
└── dast_parser.py          # NEW: DAST tools (ZAP, Burp, etc.)
```

### 5.2 Processing Flow

```
┌─────────────────────────────────────────────────────────────┐
│  CI/CD Workflows (.github/workflows/)                       │
│  ├─ sca.yml     → reports/snyk-*.json, dep-check.json, ... │
│  ├─ sast.yml    → reports/sonarqube-issues.json            │
│  └─ dast.yml    → reports/zap-report.json                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ├─> All reports in reports/
                         │
┌────────────────────────▼────────────────────────────────────┐
│  scripts/parse_reports.py                                   │
│  ├─ Scan reports/ directory                                 │
│  ├─ Detect tool type                                        │
│  ├─ Invoke appropriate parser                               │
│  ├─ Normalize to unified schema                             │
│  └─ Write reports/unified-vulnerabilities.json              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ├─> unified-vulnerabilities.json
                         │
┌────────────────────────▼────────────────────────────────────┐
│  scripts/generate_security_summary.py                       │
│  ├─ Read unified JSON                                       │
│  ├─ Generate aggregate statistics                           │
│  ├─ Create visualizations (optional)                        │
│  └─ Write summary reports                                   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ├─> security-summary.json/txt
                         │
┌────────────────────────▼────────────────────────────────────┐
│  LLM/Scripts/generate_policies.py                           │
│  ├─ Read unified-vulnerabilities.json                       │
│  ├─ Group by theme (SQL Injection, XSS, etc.)              │
│  ├─ Call LLM API (OpenAI/HuggingFace)                      │
│  └─ Generate policy YAML files                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Implementation Plan

### Phase 1: Create Missing Parsers (Priority: HIGH)

#### Step 1.1: Create `parsers/base_parser.py`

```python
"""Base parser class for security reports"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseParser(ABC):
    def __init__(self, report_path: str):
        self.report_path = report_path
        self.vulnerabilities = []
    
    @abstractmethod
    def parse(self) -> List[Dict[str, Any]]:
        """Parse report and return list of vulnerabilities"""
        pass
    
    @abstractmethod
    def get_tool_name(self) -> str:
        """Return name of the tool"""
        pass
    
    def normalize_severity(self, severity: str) -> str:
        """Normalize severity to CRITICAL|HIGH|MEDIUM|LOW"""
        mapping = {
            'critical': 'CRITICAL', 'blocker': 'CRITICAL',
            'high': 'HIGH', 'major': 'HIGH', 'error': 'HIGH',
            'medium': 'MEDIUM', 'moderate': 'MEDIUM', 'warning': 'MEDIUM',
            'low': 'LOW', 'minor': 'LOW', 'info': 'LOW', 'note': 'LOW'
        }
        return mapping.get(severity.lower(), 'MEDIUM')
    
    def normalize(self, vuln: Dict) -> Dict:
        """Normalize vulnerability to unified schema"""
        return {
            'tool': self.get_tool_name(),
            'tool_type': self.get_tool_type(),
            'id': vuln.get('id', 'UNKNOWN'),
            'title': vuln.get('title', vuln.get('vulnerability', 'No title')),
            'description': vuln.get('description', ''),
            'severity': self.normalize_severity(vuln.get('severity', 'MEDIUM')),
            'confidence': vuln.get('confidence', 'MEDIUM'),
            'cwe': vuln.get('cwe', 'N/A'),
            'cve': vuln.get('cve'),
            'file': vuln.get('file', ''),
            'line': vuln.get('line'),
            'url': vuln.get('url'),
            'method': vuln.get('method'),
            'package': vuln.get('package'),
            'version': vuln.get('version'),
            'remediation': vuln.get('remediation', ''),
            'references': vuln.get('references', [])
        }
    
    @abstractmethod
    def get_tool_type(self) -> str:
        """Return tool type: SCA|SAST|DAST"""
        pass
```

**File:** `parsers/base_parser.py`  
**Lines:** ~60

---

#### Step 1.2: Create `parsers/sast_parser.py`

```python
"""SAST Report Parser - SonarQube and SARIF formats"""
import json
from typing import List, Dict, Any
from .base_parser import BaseParser

class SASTParser(BaseParser):
    """Parser for SAST tools (SonarQube, Semgrep, CodeQL, etc.)"""
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse SAST report"""
        with open(self.report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Detect format
        if 'issues' in data:  # SonarQube API format
            return self.parse_sonarqube(data)
        elif '$schema' in data and 'sarif' in data['$schema'].lower():  # SARIF
            return self.parse_sarif(data)
        else:
            raise ValueError(f"Unknown SAST format in {self.report_path}")
    
    def parse_sonarqube(self, data: Dict) -> List[Dict]:
        """Parse SonarQube issues.json"""
        vulnerabilities = []
        issues = data.get('issues', [])
        
        for issue in issues:
            # Only include VULNERABILITY and SECURITY_HOTSPOT types
            if issue.get('type') not in ['VULNERABILITY', 'SECURITY_HOTSPOT']:
                continue
            
            vuln = {
                'id': issue.get('key', issue.get('rule', 'UNKNOWN')),
                'title': issue.get('message', 'No title'),
                'description': issue.get('message', ''),
                'severity': issue.get('severity', 'MEDIUM'),
                'cwe': self.extract_cwe_from_rule(issue.get('rule', '')),
                'file': issue.get('component', '').replace('my-flask-app:', ''),
                'line': issue.get('line'),
                'remediation': f"Review and fix {issue.get('rule', 'this issue')}"
            }
            vulnerabilities.append(self.normalize(vuln))
        
        return vulnerabilities
    
    def parse_sarif(self, data: Dict) -> List[Dict]:
        """Parse SARIF 2.1.0 format"""
        vulnerabilities = []
        runs = data.get('runs', [])
        
        for run in runs:
            tool_name = run.get('tool', {}).get('driver', {}).get('name', 'Unknown')
            results = run.get('results', [])
            
            for result in results:
                location = result.get('locations', [{}])[0]
                physical_location = location.get('physicalLocation', {})
                
                vuln = {
                    'id': result.get('ruleId', 'UNKNOWN'),
                    'title': result.get('message', {}).get('text', 'No title'),
                    'description': result.get('message', {}).get('text', ''),
                    'severity': result.get('level', 'warning'),
                    'cwe': self.extract_cwe_from_tags(result.get('properties', {}).get('tags', [])),
                    'file': physical_location.get('artifactLocation', {}).get('uri', ''),
                    'line': physical_location.get('region', {}).get('startLine'),
                    'remediation': result.get('fixes', [{}])[0].get('description', {}).get('text', '')
                }
                vulnerabilities.append(self.normalize(vuln))
        
        return vulnerabilities
    
    def extract_cwe_from_rule(self, rule: str) -> str:
        """Extract CWE from SonarQube rule ID"""
        # SonarQube rule mapping (simplified)
        cwe_map = {
            'S2077': 'CWE-89',   # SQL Injection
            'S3649': 'CWE-89',   # SQL Injection
            'S5131': 'CWE-79',   # XSS
            'S5146': 'CWE-352',  # CSRF
            'S2068': 'CWE-798',  # Hard-coded credentials
        }
        return cwe_map.get(rule.split(':')[-1], 'N/A')
    
    def extract_cwe_from_tags(self, tags: List[str]) -> str:
        """Extract CWE from SARIF tags"""
        for tag in tags:
            if tag.startswith('CWE-'):
                return tag
        return 'N/A'
    
    def get_tool_name(self) -> str:
        return 'SAST Scanner'
    
    def get_tool_type(self) -> str:
        return 'SAST'
```

**File:** `parsers/sast_parser.py`  
**Lines:** ~100

---

#### Step 1.3: Create `parsers/dast_parser.py`

```python
"""DAST Report Parser - OWASP ZAP formats"""
import json
import re
from typing import List, Dict, Any
from .base_parser import BaseParser

class DASTParser(BaseParser):
    """Parser for DAST tools (OWASP ZAP, Burp, etc.)"""
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse DAST report"""
        if self.report_path.endswith('.json'):
            return self.parse_json()
        elif self.report_path.endswith('.log'):
            return self.parse_zap_log()
        else:
            raise ValueError(f"Unsupported DAST format: {self.report_path}")
    
    def parse_json(self) -> List[Dict]:
        """Parse ZAP JSON report"""
        with open(self.report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        vulnerabilities = []
        sites = data.get('site', [])
        
        for site in sites:
            alerts = site.get('alerts', [])
            for alert in alerts:
                instances = alert.get('instances', [{}])
                for instance in instances:
                    vuln = {
                        'id': str(alert.get('pluginid', 'UNKNOWN')),
                        'title': alert.get('name', 'No title'),
                        'description': alert.get('desc', ''),
                        'severity': alert.get('riskdesc', 'MEDIUM').split()[0],  # "High (Medium)" -> "High"
                        'confidence': alert.get('confidence', 'MEDIUM'),
                        'cwe': f"CWE-{alert.get('cweid', 'N/A')}",
                        'url': instance.get('uri', alert.get('url', '')),
                        'method': instance.get('method', 'GET'),
                        'remediation': alert.get('solution', ''),
                        'references': alert.get('reference', '').split('\n')
                    }
                    vulnerabilities.append(self.normalize(vuln))
        
        return vulnerabilities
    
    def parse_zap_log(self) -> List[Dict]:
        """Parse ZAP log file (baseline/full scan)"""
        with open(self.report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        vulnerabilities = []
        
        # Parse WARN-NEW and FAIL-NEW lines
        warn_pattern = r'WARN-NEW: (.+?) \[(.+?)\] x (\d+)'
        fail_pattern = r'FAIL-NEW: (.+?) \[(.+?)\] x (\d+)'
        
        for match in re.finditer(warn_pattern, content):
            vuln = {
                'id': match.group(2),
                'title': match.group(1).strip(),
                'description': match.group(1).strip(),
                'severity': 'MEDIUM',
                'confidence': 'MEDIUM',
                'cwe': self.zap_id_to_cwe(match.group(2)),
                'url': 'Multiple URLs',
                'remediation': 'See ZAP documentation for details'
            }
            vulnerabilities.append(self.normalize(vuln))
        
        for match in re.finditer(fail_pattern, content):
            vuln = {
                'id': match.group(2),
                'title': match.group(1).strip(),
                'description': match.group(1).strip(),
                'severity': 'HIGH',
                'confidence': 'MEDIUM',
                'cwe': self.zap_id_to_cwe(match.group(2)),
                'url': 'Multiple URLs',
                'remediation': 'See ZAP documentation for details'
            }
            vulnerabilities.append(self.normalize(vuln))
        
        return vulnerabilities
    
    def zap_id_to_cwe(self, zap_id: str) -> str:
        """Map ZAP plugin IDs to CWE"""
        mapping = {
            '10020': 'CWE-1021',  # X-Frame-Options
            '10021': 'CWE-693',   # X-Content-Type-Options
            '10038': 'CWE-693',   # Content Security Policy
            '10202': 'CWE-352',   # Absence of Anti-CSRF tokens
            '40012': 'CWE-79',    # Cross Site Scripting (Reflected)
            '40014': 'CWE-79',    # Cross Site Scripting (Persistent)
            '90019': 'CWE-209',   # Server Side Code Injection
        }
        return mapping.get(zap_id, 'N/A')
    
    def get_tool_name(self) -> str:
        return 'OWASP ZAP'
    
    def get_tool_type(self) -> str:
        return 'DAST'
```

**File:** `parsers/dast_parser.py`  
**Lines:** ~120

---

### Phase 2: Update Orchestration Scripts

#### Step 2.1: Update `scripts/parse_reports.py`

Replace entire file with:

```python
"""
Parse all security reports and generate unified vulnerability list
"""
import os
import json
import sys
from pathlib import Path
from typing import List, Dict

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from parsers.sast_parser import SASTParser
from parsers.sca_parser import SCAParser
from parsers.dast_parser import DASTParser

def detect_report_type(filepath: str) -> str:
    """Detect report type from filename"""
    name = filepath.lower()
    if 'sonarqube' in name or 'sast' in name or 'issues' in name:
        return 'SAST'
    elif 'zap' in name or 'dast' in name:
        return 'DAST'
    elif any(x in name for x in ['snyk', 'dependency', 'pip-audit', 'safety', 'sca']):
        return 'SCA'
    return 'UNKNOWN'

def get_parser(report_type: str, filepath: str):
    """Get appropriate parser for report type"""
    parsers = {
        'SAST': SASTParser,
        'DAST': DASTParser,
        'SCA': SCAParser
    }
    parser_class = parsers.get(report_type)
    if parser_class:
        return parser_class(filepath)
    return None

def main():
    print("=" * 60)
    print("Unified Security Report Parser")
    print("=" * 60)
    
    reports_dir = Path('reports')
    if not reports_dir.exists():
        print(f"ERROR: Reports directory not found: {reports_dir}")
        sys.exit(1)
    
    all_vulnerabilities = []
    parsed_count = {'SAST': 0, 'DAST': 0, 'SCA': 0}
    
    # Find all JSON and log files in reports directory
    report_files = list(reports_dir.glob('*.json')) + list(reports_dir.glob('*.log'))
    
    # Exclude summary files
    report_files = [f for f in report_files if 'summary' not in f.name.lower()]
    
    print(f"\nFound {len(report_files)} report files to parse")
    
    for report_file in report_files:
        report_type = detect_report_type(str(report_file))
        
        if report_type == 'UNKNOWN':
            print(f"\n⚠️  Skipping unknown report type: {report_file.name}")
            continue
        
        print(f"\n📄 Parsing {report_type} report: {report_file.name}")
        
        try:
            parser = get_parser(report_type, str(report_file))
            if parser:
                vulns = parser.parse()
                all_vulnerabilities.extend(vulns)
                parsed_count[report_type] += len(vulns)
                print(f"   ✓ Found {len(vulns)} vulnerabilities")
            else:
                print(f"   ✗ No parser available for {report_type}")
        except Exception as e:
            print(f"   ✗ Error parsing {report_file.name}: {e}")
    
    # Save unified report
    output_file = reports_dir / 'unified-vulnerabilities.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_vulnerabilities, f, indent=2)
    
    # Copy to LLM directory for policy generation
    llm_output = Path('LLM/reports/unified-vulnerabilities.json')
    llm_output.parent.mkdir(parents=True, exist_ok=True)
    with open(llm_output, 'w', encoding='utf-8') as f:
        json.dump(all_vulnerabilities, f, indent=2)
    
    print(f"\n{'=' * 60}")
    print(f"✓ Unified report saved to: {output_file}")
    print(f"✓ Copy saved to: {llm_output}")
    print(f"\n📊 Summary:")
    print(f"   SAST vulnerabilities: {parsed_count['SAST']}")
    print(f"   DAST vulnerabilities: {parsed_count['DAST']}")
    print(f"   SCA vulnerabilities:  {parsed_count['SCA']}")
    print(f"   TOTAL:                {len(all_vulnerabilities)}")
    print("=" * 60)
    
    # Print severity breakdown
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for vuln in all_vulnerabilities:
        severity = vuln.get('severity', 'MEDIUM')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"\n🔥 Severity Breakdown:")
    for severity, count in severity_counts.items():
        print(f"   {severity}: {count}")

if __name__ == "__main__":
    main()
```

**File:** `scripts/parse_reports.py`  
**Lines:** ~130 (complete rewrite)

---

#### Step 2.2: Create `scripts/generate_security_summary.py`

New generalized version of `generate_sca_summary.py`:

```python
#!/usr/bin/env python3
"""
Generate Security Summary Report from Unified Vulnerabilities
Replaces generate_sca_summary.py with tool-type-aware version
"""

import json
import sys
from pathlib import Path
from typing import Dict, List
from collections import defaultdict

def load_unified_report(filepath: str = 'reports/unified-vulnerabilities.json') -> List[Dict]:
    """Load unified vulnerabilities report"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Unified report not found: {filepath}")
        print("Run scripts/parse_reports.py first to generate it.")
        sys.exit(1)

def generate_summary(vulnerabilities: List[Dict]) -> Dict:
    """Generate comprehensive summary from vulnerabilities"""
    
    summary = {
        'scan_date': None,  # Could add timestamp
        'total_vulnerabilities': len(vulnerabilities),
        'by_severity': defaultdict(int),
        'by_tool_type': defaultdict(int),
        'by_tool': defaultdict(int),
        'by_cwe': defaultdict(int),
        'top_files': defaultdict(int),
        'top_cwes': [],
        'critical_findings': [],
        'tool_coverage': {
            'SAST': False,
            'DAST': False,
            'SCA': False
        }
    }
    
    for vuln in vulnerabilities:
        # Count by severity
        severity = vuln.get('severity', 'UNKNOWN')
        summary['by_severity'][severity] += 1
        
        # Count by tool type
        tool_type = vuln.get('tool_type', 'UNKNOWN')
        summary['by_tool_type'][tool_type] += 1
        summary['tool_coverage'][tool_type] = True
        
        # Count by specific tool
        tool = vuln.get('tool', 'UNKNOWN')
        summary['by_tool'][tool] += 1
        
        # Count by CWE
        cwe = vuln.get('cwe', 'N/A')
        if cwe != 'N/A':
            summary['by_cwe'][cwe] += 1
        
        # Track affected files
        file = vuln.get('file') or vuln.get('url', 'UNKNOWN')
        if file != 'UNKNOWN':
            summary['top_files'][file] += 1
        
        # Collect critical findings
        if severity == 'CRITICAL':
            summary['critical_findings'].append({
                'title': vuln.get('title', 'Unknown'),
                'file': file,
                'tool': tool,
                'cwe': cwe
            })
    
    # Sort and limit top items
    summary['top_cwes'] = sorted(
        summary['by_cwe'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]
    
    summary['top_files'] = dict(sorted(
        summary['top_files'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:20])
    
    # Convert defaultdicts to regular dicts
    summary['by_severity'] = dict(summary['by_severity'])
    summary['by_tool_type'] = dict(summary['by_tool_type'])
    summary['by_tool'] = dict(summary['by_tool'])
    
    return summary

def write_json_summary(summary: Dict, filepath: str = 'reports/security-summary.json'):
    """Write JSON summary report"""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    print(f"✓ JSON summary written to: {filepath}")

def write_text_summary(summary: Dict, filepath: str = 'reports/security-summary.txt'):
    """Write human-readable text summary"""
    lines = []
    lines.append("=" * 70)
    lines.append("SECURITY SCAN SUMMARY REPORT")
    lines.append("=" * 70)
    lines.append("")
    
    lines.append(f"Total Vulnerabilities Found: {summary['total_vulnerabilities']}")
    lines.append("")
    
    lines.append("Tool Coverage:")
    for tool_type, covered in summary['tool_coverage'].items():
        status = "✓" if covered else "✗"
        lines.append(f"  {status} {tool_type}")
    lines.append("")
    
    lines.append("Vulnerabilities by Severity:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = summary['by_severity'].get(severity, 0)
        lines.append(f"  {severity:10} : {count}")
    lines.append("")
    
    lines.append("Vulnerabilities by Scan Type:")
    for tool_type, count in summary['by_tool_type'].items():
        lines.append(f"  {tool_type:10} : {count}")
    lines.append("")
    
    lines.append("Vulnerabilities by Tool:")
    for tool, count in sorted(summary['by_tool'].items(), key=lambda x: x[1], reverse=True):
        lines.append(f"  {tool:30} : {count}")
    lines.append("")
    
    if summary['top_cwes']:
        lines.append("Top 10 CWE Categories:")
        for cwe, count in summary['top_cwes']:
            lines.append(f"  {cwe:15} : {count} occurrences")
        lines.append("")
    
    if summary['critical_findings']:
        lines.append("Critical Findings (Immediate Action Required):")
        for i, finding in enumerate(summary['critical_findings'][:10], 1):
            lines.append(f"  {i}. {finding['title']}")
            lines.append(f"     File: {finding['file']}")
            lines.append(f"     CWE: {finding['cwe']} | Tool: {finding['tool']}")
            lines.append("")
    
    lines.append("Most Affected Files:")
    for file, count in list(summary['top_files'].items())[:10]:
        lines.append(f"  {count:3} issues in {file}")
    
    lines.append("")
    lines.append("=" * 70)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    
    print(f"✓ Text summary written to: {filepath}")

def main():
    print("\n" + "=" * 70)
    print("Security Summary Generator")
    print("=" * 70 + "\n")
    
    # Load unified report
    vulnerabilities = load_unified_report()
    
    # Generate summary
    summary = generate_summary(vulnerabilities)
    
    # Ensure reports directory exists
    Path('reports').mkdir(exist_ok=True)
    
    # Write outputs
    write_json_summary(summary)
    write_text_summary(summary)
    
    print("\n📊 Summary Statistics:")
    print(f"   Total Issues: {summary['total_vulnerabilities']}")
    print(f"   Critical: {summary['by_severity'].get('CRITICAL', 0)}")
    print(f"   High: {summary['by_severity'].get('HIGH', 0)}")
    print(f"   SAST: {summary['by_tool_type'].get('SAST', 0)} issues")
    print(f"   DAST: {summary['by_tool_type'].get('DAST', 0)} issues")
    print(f"   SCA: {summary['by_tool_type'].get('SCA', 0)} issues")
    print("\n" + "=" * 70 + "\n")

if __name__ == "__main__":
    main()
```

**File:** `scripts/generate_security_summary.py`  
**Lines:** ~180

---

### Phase 3: Update Workflows

#### Step 3.1: Update `.github/workflows/sca.yml`

Add at the end (before artifact upload):

```yaml
    - name: Parse and Aggregate All Reports
      run: |
        echo "Parsing security reports..."
        python scripts/parse_reports.py
        
    - name: Generate Security Summary
      run: |
        echo "Generating security summary..."
        python scripts/generate_security_summary.py
```

---

#### Step 3.2: Update `.github/workflows/sast-sonarqube.yml`

Add after "Download SAST issues only":

```yaml
    - name: Parse and Aggregate Reports
      run: |
        echo "Parsing SAST reports..."
        python scripts/parse_reports.py
        
    - name: Generate Security Summary
      run: |
        echo "Generating security summary..."
        python scripts/generate_security_summary.py
```

---

#### Step 3.3: Update `.github/workflows/dast.yml`

**Problem:** ZAP outputs logs, not JSON. Need to generate JSON first.

Add after "Run OWASP ZAP Full Scan":

```yaml
    - name: Export ZAP Results to JSON
      if: always()
      run: |
        echo "Converting ZAP results to JSON..."
        docker run --network="host" \
          -v $(pwd):/zap/wrk/:rw \
          ghcr.io/zaproxy/zaproxy:stable \
          zap-full-scan.py -t http://localhost:5000 \
          -J /zap/wrk/reports/zap-report.json || true
    
    - name: Parse and Aggregate Reports
      if: always()
      run: |
        echo "Parsing DAST reports..."
        python scripts/parse_reports.py
        
    - name: Generate Security Summary
      if: always()
      run: |
        echo "Generating security summary..."
        python scripts/generate_security_summary.py
```

---

## 7. Example Workflow YAMLs

### Minimal SAST Workflow (Alternative to SonarQube)

```yaml
name: SAST Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:

jobs:
  sast-scan:
    name: Static Application Security Testing (SAST)
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      security-events: write  # For SARIF upload
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
    
    - name: Prepare reports directory
      run: mkdir -p reports
    
    # Option 1: Semgrep (open source, no authentication)
    - name: Run Semgrep
      run: |
        pip install semgrep
        semgrep --config=auto --json --output=reports/semgrep-report.json . || true
    
    # Option 2: Bandit (Python-specific)
    - name: Run Bandit
      run: |
        pip install bandit
        bandit -r . -f json -o reports/bandit-report.json || true
    
    # Option 3: CodeQL (GitHub native)
    - name: Initialize CodeQL
      uses: github/codeql-action/init@v3
      with:
        languages: python
    
    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v3
      with:
        category: "sast"
        output: reports/codeql-report.sarif
    
    # Parse and aggregate
    - name: Parse SAST Reports
      run: python scripts/parse_reports.py
    
    - name: Generate Security Summary
      run: python scripts/generate_security_summary.py
    
    # Upload artifacts
    - name: Upload SAST Reports
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: sast-reports
        path: |
          reports/semgrep-report.json
          reports/bandit-report.json
          reports/codeql-report.sarif
          reports/unified-vulnerabilities.json
          reports/security-summary.*
        retention-days: 30
    
    # Upload to GitHub Security tab
    - name: Upload SARIF to Code Scanning
      uses: github/codeql-action/upload-sarif@v3
      if: always()
      with:
        sarif_file: reports/codeql-report.sarif
```

### Minimal DAST Workflow (Improved)

```yaml
name: DAST Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:

jobs:
  dast-scan:
    name: Dynamic Application Security Testing (DAST)
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    
    - name: Prepare reports directory
      run: mkdir -p reports
    
    - name: Start Flask Application
      run: |
        echo "Starting Flask application..."
        python app.py &
        APP_PID=$!
        echo "APP_PID=$APP_PID" >> $GITHUB_ENV
        
        # Wait for app to be ready
        for i in {1..30}; do
          if curl -sf http://localhost:5000 > /dev/null 2>&1; then
            echo "✓ Application is running"
            break
          fi
          echo "Waiting for app... attempt $i/30"
          sleep 2
        done
      env:
        FLASK_ENV: testing
        SECRET_KEY: test-secret-key
    
    - name: Run OWASP ZAP Full Scan with JSON Output
      run: |
        echo "Running OWASP ZAP scan..."
        docker run --network="host" \
          -v $(pwd):/zap/wrk/:rw \
          ghcr.io/zaproxy/zaproxy:stable \
          zap-full-scan.py -t http://localhost:5000 \
          -J /zap/wrk/reports/zap-report.json \
          -r /zap/wrk/reports/zap-report.html || true
        
        echo "ZAP scan completed"
    
    - name: Stop Flask Application
      if: always()
      run: |
        if [ -n "$APP_PID" ]; then
          kill $APP_PID || true
        fi
    
    - name: Parse DAST Reports
      if: always()
      run: python scripts/parse_reports.py
    
    - name: Generate Security Summary
      if: always()
      run: python scripts/generate_security_summary.py
    
    - name: Upload DAST Reports
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: dast-reports
        path: |
          reports/zap-report.*
          reports/unified-vulnerabilities.json
          reports/security-summary.*
        retention-days: 30
    
    - name: Display Summary
      if: always()
      run: |
        if [ -f reports/security-summary.txt ]; then
          cat reports/security-summary.txt
        fi
```

---

## 8. Local Development Commands

### Simulate CI Pipeline Locally

```bash
# 1. Create reports directory
mkdir -p reports

# 2. Run SCA scans (requires tools installed)
pip install pip-audit safety
pip-audit --format=json --output=reports/pip-audit-report.json || true
safety check --json --output=reports/safety-detailed-report.json || true

# 3. Run SAST scan (Semgrep example)
pip install semgrep
semgrep --config=auto --json --output=reports/semgrep-report.json . || true

# 4. Run DAST scan (requires app running)
# Terminal 1: Start app
python app.py

# Terminal 2: Run ZAP
docker run --network="host" \
  -v $(pwd):/zap/wrk/:rw \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:5000 \
  -J /zap/wrk/reports/zap-report.json

# 5. Parse all reports
python scripts/parse_reports.py

# 6. Generate summary
python scripts/generate_security_summary.py

# 7. Generate policies (optional)
cd LLM/Scripts
python generate_policies.py
```

### Test Individual Parsers

```bash
# Test SAST parser
python3 << EOF
from parsers.sast_parser import SASTParser
parser = SASTParser('reports/semgrep-report.json')
vulns = parser.parse()
print(f"Found {len(vulns)} SAST vulnerabilities")
for v in vulns[:3]:
    print(f"  - {v['title']} ({v['severity']})")
EOF

# Test DAST parser
python3 << EOF
from parsers.dast_parser import DASTParser
parser = DASTParser('reports/zap-report.json')
vulns = parser.parse()
print(f"Found {len(vulns)} DAST vulnerabilities")
EOF

# Test SCA parser
python3 << EOF
from parsers.sca_parser import SCAParser
parser = SCAParser('reports/pip-audit-report.json')
vulns = parser.parse()
print(f"Found {len(vulns)} SCA vulnerabilities")
EOF
```

---

## 9. Validation Checklist

### Pre-Implementation
- [ ] Review current workflow files
- [ ] Backup existing scripts (`generate_sca_summary.py`, `parse_reports.py`)
- [ ] Create feature branch: `git checkout -b feature/unified-security-scanning`

### Phase 1: Parsers
- [ ] Create `parsers/base_parser.py`
  - [ ] Test severity normalization: CRITICAL, HIGH, MEDIUM, LOW work
  - [ ] Test normalize() method with sample data
- [ ] Create `parsers/sast_parser.py`
  - [ ] Test with SonarQube issues.json
  - [ ] Test with SARIF file
  - [ ] Verify CWE extraction works
- [ ] Create `parsers/dast_parser.py`
  - [ ] Test with ZAP JSON report
  - [ ] Test with ZAP log file
  - [ ] Verify plugin ID to CWE mapping

### Phase 2: Orchestration
- [ ] Update `scripts/parse_reports.py`
  - [ ] Test report type detection
  - [ ] Test with no reports (should not crash)
  - [ ] Test with SCA-only reports
  - [ ] Test with SAST-only reports
  - [ ] Test with DAST-only reports
  - [ ] Test with all three types
  - [ ] Verify unified-vulnerabilities.json is valid JSON
  - [ ] Verify file is copied to LLM/reports/
- [ ] Create `scripts/generate_security_summary.py`
  - [ ] Test with empty input
  - [ ] Test with unified-vulnerabilities.json
  - [ ] Verify JSON output format
  - [ ] Verify text output is readable

### Phase 3: Workflows
- [ ] Update `.github/workflows/sca.yml`
  - [ ] Add parse_reports.py step
  - [ ] Add generate_security_summary.py step
  - [ ] Test workflow runs successfully
  - [ ] Verify artifacts are uploaded
- [ ] Update `.github/workflows/sast-sonarqube.yml`
  - [ ] Add parse_reports.py step
  - [ ] Test workflow runs successfully
- [ ] Update `.github/workflows/dast.yml`
  - [ ] Add JSON export from ZAP
  - [ ] Add parse_reports.py step
  - [ ] Test workflow runs successfully

### Integration Testing
- [ ] Run all three workflows in sequence
- [ ] Verify unified-vulnerabilities.json contains findings from all types
- [ ] Verify security-summary.json has correct counts
- [ ] Test LLM policy generation with real data
- [ ] Check GitHub Security tab for SARIF uploads

### Acceptance Criteria
- [ ] All parsers handle their input formats without errors
- [ ] `parse_reports.py` produces valid unified JSON
- [ ] `generate_security_summary.py` creates readable summaries
- [ ] Workflows complete successfully (even if scans find issues)
- [ ] Artifacts are downloadable
- [ ] LLM can generate policies from unified report
- [ ] No regression: SCA still works as before

---

## 10. Risks and Assumptions

### Risks

#### 1. Tool Output Format Changes
**Risk:** Scanner tools update their output format  
**Mitigation:**
- Version-pin tools in workflows
- Add schema validation in parsers
- Log warnings for unknown fields

#### 2. Large Report Files
**Risk:** Unified JSON exceeds GitHub artifact size limits (2GB)  
**Mitigation:**
- Filter out low-severity findings in CI
- Compress artifacts before upload
- Store full reports in S3/external storage

#### 3. CWE Mapping Incomplete
**Risk:** Not all tools provide CWE; manual mapping incomplete  
**Mitigation:**
- Default to "N/A" for missing CWEs
- Maintain central mapping file
- Use LLM to suggest CWE based on description

#### 4. False Positives
**Risk:** DAST produces many false positives  
**Mitigation:**
- Use confidence scores in schema
- Implement filtering/suppression rules
- Add manual review step for critical findings

#### 5. Secrets in CI
**Risk:** API tokens exposed in logs  
**Mitigation:**
- Use GitHub Secrets for all tokens
- Mask secrets in workflow logs
- Never log full vulnerability details in CI

#### 6. Performance Impact
**Risk:** Running all scans slows down CI significantly  
**Mitigation:**
- Run scans in parallel where possible
- Cache dependencies
- Use workflow_dispatch for full scans, lighter scans on PR

### Assumptions

1. **Tool Availability:**
   - Snyk requires `SNYK_TOKEN` secret
   - SonarQube runs in Docker (self-hosted)
   - ZAP is available via Docker Hub
   - Semgrep/Bandit are open source (no auth needed)

2. **File Structure:**
   - All reports go to `reports/` directory
   - Parsers are in `parsers/` directory
   - Scripts are in `scripts/` directory
   - LLM integration expects `LLM/reports/unified-vulnerabilities.json`

3. **Schema Consistency:**
   - All tools can be normalized to unified schema
   - Severity always maps to CRITICAL/HIGH/MEDIUM/LOW
   - CWE is optional but preferred

4. **Environment:**
   - Python 3.9+ available
   - Docker available for ZAP and SonarQube
   - GitHub Actions runner has sufficient resources

5. **Missing Tools:**
   - If a tool is not installed/configured, workflow should not fail
   - Parsers should handle missing files gracefully
   - Summary should show which scan types were skipped

---

## Next Steps

1. **Immediate:**
   - Create `parsers/base_parser.py`
   - Create `parsers/sast_parser.py`
   - Create `parsers/dast_parser.py`

2. **Week 1:**
   - Update `scripts/parse_reports.py`
   - Create `scripts/generate_security_summary.py`
   - Test locally with sample reports

3. **Week 2:**
   - Update workflow YAMLs
   - Test in CI environment
   - Fix any integration issues

4. **Week 3:**
   - Integrate LLM policy generation into CI
   - Add GitHub Step Summaries with charts
   - Document new process in README

5. **Future Enhancements:**
   - Add Slack/email notifications for critical findings
   - Implement trend analysis (compare with previous scans)
   - Add custom filtering/suppression rules
   - Integrate with Jira/Linear for ticket creation
   - Add vulnerability deduplication across tools

---

## Appendix: File Tree After Implementation

```
.
├── .github/
│   └── workflows/
│       ├── sca.yml                    # ✏️ Updated
│       ├── sast-sonarqube.yml        # ✏️ Updated  
│       └── dast.yml                   # ✏️ Updated
├── parsers/
│   ├── __init__.py
│   ├── base_parser.py                 # ✨ NEW
│   ├── sast_parser.py                 # ✨ NEW
│   ├── dast_parser.py                 # ✨ NEW
│   └── sca_parser.py                  # ✅ Existing (minor updates)
├── scripts/
│   ├── parse_reports.py               # ✏️ Complete rewrite
│   ├── generate_security_summary.py   # ✨ NEW (replaces generate_sca_summary.py)
│   └── generate_sca_summary.py        # 🗑️ Deprecated (keep for compatibility)
├── LLM/
│   ├── Scripts/
│   │   ├── generate_policies.py       # ✅ No changes needed
│   │   └── mappings.py                # ✅ No changes needed
│   └── reports/
│       └── unified-vulnerabilities.json  # Auto-generated by parse_reports.py
├── reports/                           # Generated by CI
│   ├── snyk-*.json
│   ├── dependency-check-report.json
│   ├── sonarqube-issues.json
│   ├── zap-report.json
│   ├── unified-vulnerabilities.json   # ✨ NEW: Main unified report
│   ├── security-summary.json          # ✨ NEW: Aggregate statistics
│   └── security-summary.txt           # ✨ NEW: Human-readable summary
└── README.md                          # ✏️ Update with new process
```

---

**End of Document**
