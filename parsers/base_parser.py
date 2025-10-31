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
