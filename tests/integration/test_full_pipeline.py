import subprocess
import json
from pathlib import Path

def test_full_pipeline():
    """Test complete scan → parse → summarize pipeline"""
    
    # 1. Create sample reports
    reports_dir = Path('reports')
    reports_dir.mkdir(exist_ok=True)
    
    # 2. Run parser
    result = subprocess.run(
        ['python', 'scripts/parse_reports.py'],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    
    # 3. Verify unified report
    unified = Path('reports/unified-vulnerabilities.json')
    assert unified.exists()
    
    data = json.loads(unified.read_text())
    assert isinstance(data, list)
    
    # 4. Run summary generator
    result = subprocess.run(
        ['python', 'scripts/generate_security_summary.py'],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    
    # 5. Verify summary files
    assert Path('reports/security-summary.json').exists()
    assert Path('reports/security-summary.txt').exists()