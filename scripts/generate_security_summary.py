#!/usr/bin/env python3
"""
Security Summary Generator
Creates comprehensive summary reports from unified vulnerabilities

Usage:
    python scripts/generate_security_summary.py [--input FILE] [--output-dir DIRECTORY]
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict
from datetime import datetime


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Generate security summary reports from unified vulnerabilities'
    )
    parser.add_argument(
        '--input',
        default='reports/unified-vulnerabilities.json',
        help='Input unified vulnerabilities file (default: reports/unified-vulnerabilities.json)'
    )
    parser.add_argument(
        '--output-dir',
        default='reports',
        help='Output directory for summary files (default: reports)'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'text', 'both'],
        default='both',
        help='Output format (default: both)'
    )
    
    return parser.parse_args()


def load_vulnerabilities(input_file: Path) -> List[Dict[str, Any]]:
    """
    Load unified vulnerabilities from JSON file
    
    Args:
        input_file: Path to unified vulnerabilities JSON
        
    Returns:
        List of vulnerability dictionaries
    """
    if not input_file.exists():
        print(f"❌ ERROR: Input file not found: {input_file}")
        print("\n💡 TIP: Run 'python scripts/parse_reports.py' first")
        sys.exit(1)
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ ERROR: Invalid JSON in {input_file}: {e}")
        sys.exit(1)


def generate_summary(vulnerabilities: List[Dict]) -> Dict[str, Any]:
    """
    Generate comprehensive summary from vulnerabilities
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        
    Returns:
        Summary dictionary with statistics and analysis
    """
    summary = {
        'generated_at': datetime.now().isoformat(),
        'total_vulnerabilities': len(vulnerabilities),
        'by_severity': defaultdict(int),
        'by_tool_type': defaultdict(int),
        'by_tool': defaultdict(int),
        'by_cwe': defaultdict(int),
        'by_confidence': defaultdict(int),
        'top_files': defaultdict(int),
        'top_cwes': [],
        'critical_findings': [],
        'high_findings': [],
        'tool_coverage': {
            'SAST': False,
            'DAST': False,
            'SCA': False
        },
        'packages_affected': defaultdict(int),
        'urls_affected': set(),
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
        if cwe and cwe != 'N/A':
            summary['by_cwe'][cwe] += 1
        
        # Count by confidence
        confidence = vuln.get('confidence', 'MEDIUM')
        summary['by_confidence'][confidence] += 1
        
        # Track affected files/URLs
        file_path = vuln.get('file') or vuln.get('url', '')
        if file_path and file_path != 'Multiple URLs':
            summary['top_files'][file_path] += 1
        
        # Track packages (SCA)
        package = vuln.get('package')
        if package:
            summary['packages_affected'][package] += 1
        
        # Track URLs (DAST)
        url = vuln.get('url')
        if url and url not in ['Multiple URLs', '']:
            summary['urls_affected'].add(url)
        
        # Collect critical findings
        if severity == 'CRITICAL':
            summary['critical_findings'].append({
                'title': vuln.get('title', 'Unknown'),
                'tool': tool,
                'tool_type': tool_type,
                'file': file_path,
                'cwe': cwe,
                'line': vuln.get('line'),
            })
        
        # Collect high findings
        if severity == 'HIGH':
            summary['high_findings'].append({
                'title': vuln.get('title', 'Unknown'),
                'tool': tool,
                'tool_type': tool_type,
                'file': file_path,
                'cwe': cwe,
                'line': vuln.get('line'),
            })
    
    # Sort and limit top items
    summary['top_cwes'] = sorted(
        summary['by_cwe'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:15]
    
    summary['top_files'] = dict(sorted(
        summary['top_files'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:20])
    
    # Convert sets to lists for JSON serialization
    summary['urls_affected'] = list(summary['urls_affected'])
    
    # Convert defaultdicts to regular dicts
    summary['by_severity'] = dict(summary['by_severity'])
    summary['by_tool_type'] = dict(summary['by_tool_type'])
    summary['by_tool'] = dict(summary['by_tool'])
    summary['by_cwe'] = dict(summary['by_cwe'])
    summary['by_confidence'] = dict(summary['by_confidence'])
    summary['packages_affected'] = dict(summary['packages_affected'])
    
    return summary


def write_json_summary(summary: Dict, output_file: Path):
    """Write JSON summary report"""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    print(f"   ✓ JSON summary: {output_file}")


def write_text_summary(summary: Dict, output_file: Path):
    """Write human-readable text summary"""
    lines = []
    
    # Header
    lines.append("=" * 80)
    lines.append("SECURITY SCAN SUMMARY REPORT")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Generated: {summary['generated_at']}")
    lines.append(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
    lines.append("")
    
    # Tool Coverage
    lines.append("=" * 80)
    lines.append("SCAN COVERAGE")
    lines.append("=" * 80)
    lines.append("")
    for scan_type, covered in summary['tool_coverage'].items():
        status = "✓ ENABLED " if covered else "✗ DISABLED"
        count = summary['by_tool_type'].get(scan_type, 0)
        lines.append(f"   {status} {scan_type:10s} - {count:4d} vulnerabilities")
    lines.append("")
    
    # Severity Breakdown
    lines.append("=" * 80)
    lines.append("SEVERITY BREAKDOWN")
    lines.append("=" * 80)
    lines.append("")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = summary['by_severity'].get(severity, 0)
        bar = "█" * min(count, 50)
        lines.append(f"   {severity:10s} : {count:4d}  {bar}")
    lines.append("")
    
    # Tool Breakdown
    if summary['by_tool']:
        lines.append("=" * 80)
        lines.append("VULNERABILITIES BY TOOL")
        lines.append("=" * 80)
        lines.append("")
        for tool, count in sorted(summary['by_tool'].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"   {tool:35s} : {count:4d}")
        lines.append("")
    
    # Top CWEs
    if summary['top_cwes']:
        lines.append("=" * 80)
        lines.append("TOP 15 CWE CATEGORIES")
        lines.append("=" * 80)
        lines.append("")
        for i, (cwe, count) in enumerate(summary['top_cwes'], 1):
            lines.append(f"   {i:2d}. {cwe:20s} : {count:4d} occurrences")
        lines.append("")
    
    # Critical Findings
    if summary['critical_findings']:
        lines.append("=" * 80)
        lines.append("CRITICAL FINDINGS (IMMEDIATE ACTION REQUIRED)")
        lines.append("=" * 80)
        lines.append("")
        for i, finding in enumerate(summary['critical_findings'][:20], 1):
            lines.append(f"   {i}. [{finding['tool_type']}] {finding['title']}")
            lines.append(f"      File: {finding['file']}")
            if finding.get('line'):
                lines.append(f"      Line: {finding['line']}")
            lines.append(f"      CWE: {finding['cwe']} | Tool: {finding['tool']}")
            lines.append("")
    
    # High Findings (summary)
    if summary['high_findings']:
        lines.append("=" * 80)
        lines.append(f"HIGH SEVERITY FINDINGS ({len(summary['high_findings'])} total)")
        lines.append("=" * 80)
        lines.append("")
        for i, finding in enumerate(summary['high_findings'][:10], 1):
            lines.append(f"   {i}. [{finding['tool_type']}] {finding['title']}")
            lines.append(f"      {finding['file']}")
        
        if len(summary['high_findings']) > 10:
            lines.append(f"\n   ... and {len(summary['high_findings']) - 10} more")
        lines.append("")
    
    # Most Affected Files
    if summary['top_files']:
        lines.append("=" * 80)
        lines.append("MOST AFFECTED FILES")
        lines.append("=" * 80)
        lines.append("")
        for file, count in list(summary['top_files'].items())[:15]:
            lines.append(f"   {count:3d} issues → {file}")
        lines.append("")
    
    # Affected Packages (SCA)
    if summary['packages_affected']:
        lines.append("=" * 80)
        lines.append("VULNERABLE PACKAGES (SCA)")
        lines.append("=" * 80)
        lines.append("")
        sorted_packages = sorted(
            summary['packages_affected'].items(),
            key=lambda x: x[1],
            reverse=True
        )
        for package, count in sorted_packages[:15]:
            lines.append(f"   {package:40s} : {count:2d} vulnerabilities")
        lines.append("")
    
    # Affected URLs (DAST)
    if summary['urls_affected']:
        lines.append("=" * 80)
        lines.append(f"TESTED ENDPOINTS (DAST) - {len(summary['urls_affected'])} unique")
        lines.append("=" * 80)
        lines.append("")
        for url in sorted(summary['urls_affected'])[:20]:
            lines.append(f"   {url}")
        
        if len(summary['urls_affected']) > 20:
            lines.append(f"\n   ... and {len(summary['urls_affected']) - 20} more")
        lines.append("")
    
    # Recommendations
    lines.append("=" * 80)
    lines.append("RECOMMENDATIONS")
    lines.append("=" * 80)
    lines.append("")
    
    critical_count = summary['by_severity'].get('CRITICAL', 0)
    high_count = summary['by_severity'].get('HIGH', 0)
    
    if critical_count > 0:
        lines.append("   🚨 URGENT: Address all CRITICAL vulnerabilities immediately")
        lines.append("             These represent severe security risks")
        lines.append("")
    
    if high_count > 0:
        lines.append("   ⚠️  HIGH PRIORITY: Review and fix HIGH severity issues")
        lines.append("             Schedule remediation within the next sprint")
        lines.append("")
    
    if not summary['tool_coverage']['SAST']:
        lines.append("   💡 SUGGESTION: Enable SAST scanning for code-level analysis")
        lines.append("")
    
    if not summary['tool_coverage']['DAST']:
        lines.append("   💡 SUGGESTION: Enable DAST scanning for runtime testing")
        lines.append("")
    
    if not summary['tool_coverage']['SCA']:
        lines.append("   💡 SUGGESTION: Enable SCA scanning for dependency analysis")
        lines.append("")
    
    # Footer
    lines.append("=" * 80)
    lines.append("END OF REPORT")
    lines.append("=" * 80)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    
    print(f"   ✓ Text summary: {output_file}")


def main():
    """Main execution function"""
    args = parse_arguments()
    
    print("\n" + "=" * 70)
    print("📊 SECURITY SUMMARY GENERATOR")
    print("=" * 70)
    print()
    
    # Load vulnerabilities
    input_file = Path(args.input)
    output_dir = Path(args.output_dir)
    
    print(f"📂 Loading vulnerabilities from: {input_file}")
    vulnerabilities = load_vulnerabilities(input_file)
    print(f"   ✓ Loaded {len(vulnerabilities)} vulnerabilities")
    print()
    
    if len(vulnerabilities) == 0:
        print("⚠️  No vulnerabilities to summarize")
        sys.exit(0)
    
    # Generate summary
    print("⚙️  Generating summary...")
    summary = generate_summary(vulnerabilities)
    print("   ✓ Summary generated")
    print()
    
    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Write outputs
    print("💾 Writing summary files...")
    
    if args.format in ['json', 'both']:
        json_file = output_dir / 'security-summary.json'
        write_json_summary(summary, json_file)
    
    if args.format in ['text', 'both']:
        text_file = output_dir / 'security-summary.txt'
        write_text_summary(summary, text_file)
    
    print()
    
    # Display key statistics
    print("=" * 70)
    print("📈 KEY STATISTICS")
    print("=" * 70)
    print()
    print(f"Total Vulnerabilities:  {summary['total_vulnerabilities']}")
    print()
    print("By Severity:")
    print(f"   CRITICAL: {summary['by_severity'].get('CRITICAL', 0):4d}")
    print(f"   HIGH:     {summary['by_severity'].get('HIGH', 0):4d}")
    print(f"   MEDIUM:   {summary['by_severity'].get('MEDIUM', 0):4d}")
    print(f"   LOW:      {summary['by_severity'].get('LOW', 0):4d}")
    print()
    print("By Scan Type:")
    print(f"   SAST:  {summary['by_tool_type'].get('SAST', 0):4d} vulnerabilities")
    print(f"   DAST:  {summary['by_tool_type'].get('DAST', 0):4d} vulnerabilities")
    print(f"   SCA:   {summary['by_tool_type'].get('SCA', 0):4d} vulnerabilities")
    print()
    print("=" * 70)
    print("✅ SUMMARY GENERATION COMPLETE")
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
