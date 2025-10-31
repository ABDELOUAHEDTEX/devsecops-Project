# Quick Start Guide

## Local Testing

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Security Scans

**SCA Scan:**
```bash
pip install pip-audit safety
pip-audit --format=json --output=reports/pip-audit-report.json
```

**SAST Scan:**
```bash
pip install semgrep
semgrep --config=auto --json --output=reports/semgrep-report.json .
```

**DAST Scan:**
```bash
# Terminal 1: Start app
python app.py

# Terminal 2: Run ZAP
docker run --network="host" \
  -v $(pwd):/zap/wrk/:rw \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:5000 \
  -J /zap/wrk/reports/zap-report.json
```

### 3. Parse Reports
```bash
python scripts/parse_reports.py --verbose
```

### 4. Generate Summary
```bash
python scripts/generate_security_summary.py
```

### 5. Generate Policies (Optional)
```bash
export OPENAI_API_KEY="your-key"
cd LLM/Scripts
python generate_policies.py
```

## Expected Output

- `reports/unified-vulnerabilities.json` - All findings
- `reports/security-summary.json` - Statistics
- `reports/security-summary.txt` - Human-readable report
- `LLM/reports/policies_openai.yaml` - Generated policies