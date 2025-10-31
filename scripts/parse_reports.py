#!/usr/bin/env python3
"""
Security Report Parser - Orchestration Script
Parses all security reports and generates unified vulnerability list

Usage:
    python scripts/parse_reports.py [--reports-dir DIRECTORY] [--output FILE]
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from parsers import SASTParser, DASTParser, SCAParser, ParserFactory


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Parse security reports and generate unified output'
    )
    parser.add_argument(
        '--reports-dir',
        default='reports',
        help='Directory containing security reports (default: reports)'
    )
    parser.add_argument(
        '--output',
        default='reports/unified-vulnerabilities.json',
        help='Output file path (default: reports/unified-vulnerabilities.json)'
    )
    parser.add_argument(
        '--llm-output',
        default='LLM/reports/unified-vulnerabilities.json',
        help='Additional output for LLM integration (default: LLM/reports/unified-vulnerabilities.json)'
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    return parser.parse_args()


def find_report_files(reports_dir: Path) -> List[Path]:
    """
    Find all security report files in directory
    
    Args:
        reports_dir: Path to reports directory
        
    Returns:
        List of report file paths
    """
    if not reports_dir.exists():
        print(f"❌ ERROR: Reports directory not found: {reports_dir}")
        sys.exit(1)
    
    # Supported file extensions
    patterns = ['*.json', '*.log', '*.xml', '*.sarif']
    
    report_files = []
    for pattern in patterns:
        report_files.extend(reports_dir.glob(pattern))
    
    # Exclude summary files
    report_files = [
        f for f in report_files
        if 'summary' not in f.name.lower() and
           'unified' not in f.name.lower()
    ]
    
    return sorted(report_files)


def detect_report_type(filepath: Path) -> str:
    """
    Detect report type from filename
    
    Args:
        filepath: Path to report file
        
    Returns:
        One of: 'SAST', 'DAST', 'SCA', 'UNKNOWN'
    """
    name = filepath.name.lower()
    
    # SAST detection
    sast_keywords = ['sonarqube', 'sast', 'semgrep', 'bandit', 'codeql', 'issues']
    if any(keyword in name for keyword in sast_keywords):
        return 'SAST'
    
    # DAST detection
    dast_keywords = ['zap', 'dast', 'burp', 'baseline', 'full_scan', 'full-scan']
    if any(keyword in name for keyword in dast_keywords):
        return 'DAST'
    
    # SCA detection
    sca_keywords = [
        'snyk', 'dependency', 'pip-audit', 'pip_audit',
        'safety', 'sca', 'trivy', 'dep-check'
    ]
    if any(keyword in name for keyword in sca_keywords):
        return 'SCA'
    
    return 'UNKNOWN'


def parse_report(filepath: Path, verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Parse a single report file
    
    Args:
        filepath: Path to report file
        verbose: Enable verbose output
        
    Returns:
        List of vulnerabilities
    """
    report_type = detect_report_type(filepath)
    
    if report_type == 'UNKNOWN':
        if verbose:
            print(f"   ⚠️  Cannot determine type, skipping")
        return []
    
    try:
        # Create parser using factory
        parser = ParserFactory.create_parser(str(filepath))
        
        if not parser:
            if verbose:
                print(f"   ⚠️  No parser available")
            return []
        
        # Parse report
        vulnerabilities = parser.parse()
        
        if verbose:
            stats = parser.get_statistics()
            print(f"   ✓ Found {stats['total']} vulnerabilities")
            print(f"     - CRITICAL: {stats['by_severity']['CRITICAL']}")
            print(f"     - HIGH: {stats['by_severity']['HIGH']}")
            print(f"     - MEDIUM: {stats['by_severity']['MEDIUM']}")
            print(f"     - LOW: {stats['by_severity']['LOW']}")
        
        return vulnerabilities
    
    except Exception as e:
        print(f"   ❌ Error parsing: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return []


def generate_summary(vulnerabilities: List[Dict]) -> Dict[str, Any]:
    """
    Generate quick summary statistics
    
    Args:
        vulnerabilities: List of all vulnerabilities
        
    Returns:
        Summary dictionary
    """
    summary = {
        'total': len(vulnerabilities),
        'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
        'by_type': {'SAST': 0, 'DAST': 0, 'SCA': 0},
        'by_tool': {},
    }
    
    for vuln in vulnerabilities:
        # Count by severity
        severity = vuln.get('severity', 'MEDIUM')
        summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
        
        # Count by type
        tool_type = vuln.get('tool_type', 'UNKNOWN')
        summary['by_type'][tool_type] = summary['by_type'].get(tool_type, 0) + 1
        
        # Count by tool
        tool = vuln.get('tool', 'Unknown')
        summary['by_tool'][tool] = summary['by_tool'].get(tool, 0) + 1
    
    return summary


def main():
    """Main execution function"""
    args = parse_arguments()
    
    print("=" * 70)
    print("🔍 UNIFIED SECURITY REPORT PARSER")
    print("=" * 70)
    print()
    
    # Setup paths
    reports_dir = Path(args.reports_dir)
    output_file = Path(args.output)
    llm_output_file = Path(args.llm_output)
    
    # Ensure output directories exist
    output_file.parent.mkdir(parents=True, exist_ok=True)
    llm_output_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Find report files
    print(f"📂 Scanning directory: {reports_dir}")
    report_files = find_report_files(reports_dir)
    
    if not report_files:
        print(f"\n⚠️  No report files found in {reports_dir}")
        print("   Make sure your security scans have generated reports.")
        sys.exit(0)
    
    print(f"   Found {len(report_files)} report files")
    print()
    
    # Parse all reports
    all_vulnerabilities = []
    parsed_count = {'SAST': 0, 'DAST': 0, 'SCA': 0}
    
    for report_file in report_files:
        report_type = detect_report_type(report_file)
        
        print(f"📄 Parsing {report_type} report: {report_file.name}")
        
        vulnerabilities = parse_report(report_file, args.verbose)
        
        if vulnerabilities:
            all_vulnerabilities.extend(vulnerabilities)
            parsed_count[report_type] += len(vulnerabilities)
            print(f"   ✓ Added {len(vulnerabilities)} vulnerabilities")
        else:
            print(f"   ⚠️  No vulnerabilities found")
        
        print()
    
    # Save unified report
    print("💾 Saving unified report...")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_vulnerabilities, f, indent=2, ensure_ascii=False)
    
    print(f"   ✓ Saved to: {output_file}")
    
    # Copy to LLM directory
    with open(llm_output_file, 'w', encoding='utf-8') as f:
        json.dump(all_vulnerabilities, f, indent=2, ensure_ascii=False)
    
    print(f"   ✓ Copied to: {llm_output_file}")
    print()
    
    # Generate and display summary
    summary = generate_summary(all_vulnerabilities)
    
    print("=" * 70)
    print("📊 PARSING SUMMARY")
    print("=" * 70)
    print()
    print(f"Total Vulnerabilities: {summary['total']}")
    print()
    print("By Scan Type:")
    print(f"   SAST:  {summary['by_type'].get('SAST', 0):4d}")
    print(f"   DAST:  {summary['by_type'].get('DAST', 0):4d}")
    print(f"   SCA:   {summary['by_type'].get('SCA', 0):4d}")
    print()
    print("By Severity:")
    print(f"   CRITICAL: {summary['by_severity']['CRITICAL']:4d}")
    print(f"   HIGH:     {summary['by_severity']['HIGH']:4d}")
    print(f"   MEDIUM:   {summary['by_severity']['MEDIUM']:4d}")
    print(f"   LOW:      {summary['by_severity']['LOW']:4d}")
    print()
    
    if summary['by_tool']:
        print("By Tool:")
        for tool, count in sorted(summary['by_tool'].items(), key=lambda x: x[1], reverse=True):
            print(f"   {tool:30s}: {count:4d}")
        print()
    
    print("=" * 70)
    print("✅ PARSING COMPLETE")
    print("=" * 70)
    
    # Exit with appropriate code
    if summary['by_severity']['CRITICAL'] > 0:
        print("\n⚠️  WARNING: Critical vulnerabilities found!")
        sys.exit(1)
    elif summary['total'] == 0:
        print("\n🎉 No vulnerabilities detected!")
        sys.exit(0)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
