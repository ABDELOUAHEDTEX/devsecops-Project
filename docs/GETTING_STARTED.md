# Getting Started Guide

## 🚀 Quick Start (Step-by-Step)

This guide will help you run your first security scan and generate reports.

---

## Prerequisites Check

First, make sure you have Python installed:

```powershell
python --version
```

You should see Python 3.11 or higher.

---

## Step 1: Install Dependencies

```powershell
# Activate virtual environment (if using one)
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

---

## Step 2: Run Your First Security Scans

You have two options:

### Option A: Quick Automated Script (Recommended)

Run the automated scan script:

```powershell
.\scripts\quick_scan.ps1
```

This will automatically run:
- ✅ Bandit (Python SAST)
- ✅ Semgrep (General SAST)
- ✅ pip-audit (SCA - dependency vulnerabilities)
- ✅ Safety (SCA - dependency vulnerabilities)

### Option B: Manual Scans

Run scans individually:

```powershell
# SAST Scans
pip install bandit semgrep
bandit -r . -f json -o reports/bandit-report.json
semgrep --config=auto --json --output=reports/semgrep-report.json .

# SCA Scans
pip install pip-audit safety
pip-audit --format=json --output=reports/pip-audit-report.json
safety check --json --output=reports/safety-report.json
```

---

## Step 3: Parse Security Reports

Once you have scan reports, parse them into a unified format:

```powershell
python scripts/parse_reports.py --verbose
```

**Expected Output:**
```
🔍 UNIFIED SECURITY REPORT PARSER
======================================================================
📂 Scanning directory: reports
   Found 4 report files

📄 Parsing SAST report: bandit-report.json
   ✓ Added 15 vulnerabilities

📄 Parsing SAST report: semgrep-report.json
   ✓ Added 8 vulnerabilities

📄 Parsing SCA report: pip-audit-report.json
   ✓ Added 2 vulnerabilities

💾 Saving unified report...
   ✓ Saved to: reports/unified-vulnerabilities.json
   ✓ Copied to: LLM/reports/unified-vulnerabilities.json
```

This creates:
- `reports/unified-vulnerabilities.json`
- `LLM/reports/unified-vulnerabilities.json` (for LLM processing)

---

## Step 4: Generate Security Summary

Generate human-readable summaries:

```powershell
python scripts/generate_security_summary.py
```

**Expected Output:**
```
📊 SECURITY SUMMARY GENERATOR
======================================================================
📂 Loading vulnerabilities from: reports/unified-vulnerabilities.json
   ✓ Loaded 25 vulnerabilities

💾 Saving summaries...
   ✓ JSON summary: reports/security-summary.json
   ✓ Text summary: reports/security-summary.txt
```

This creates:
- `reports/security-summary.json` (machine-readable)
- `reports/security-summary.txt` (human-readable)

---

## Step 5: Generate Security Policies (Optional)

If you have LLM API keys configured in `.env`, generate policies:

```powershell
# Make sure .env file exists with your API keys
python LLM/Scripts/generate_policies.py
```

**Expected Output:**
```
[+] Generating with OpenAI...
[OK] Saved OpenAI policies to LLM/reports/policies_openai.yaml

[+] Generating with Hugging Face Inference API...
[OK] Saved HF policies to LLM/reports/policies_hf.yaml

[✓] Done.
```

**Requirements:**
- `.env` file with `OPENAI_API_KEY` and/or `HF_TOKEN`
- See `docs/SECRETS_SETUP.md` for setup instructions

---

## 📋 Complete Workflow

Here's the complete workflow from start to finish:

```powershell
# 1. Activate environment
.\venv\Scripts\Activate.ps1

# 2. Run scans
.\scripts\quick_scan.ps1

# 3. Parse reports
python scripts/parse_reports.py --verbose

# 4. Generate summary
python scripts/generate_security_summary.py

# 5. Generate policies (optional, requires API keys)
python LLM/Scripts/generate_policies.py
```

---

## 🔍 Verify Your Results

Check what files were generated:

```powershell
# List report files
Get-ChildItem reports\*.json

# View summary
Get-Content reports\security-summary.txt
```

---

## 🐛 Troubleshooting

### Error: "No report files found"

**Problem:** No scan reports exist yet.

**Solution:** Run Step 2 (security scans) first.

### Error: "Input file not found: reports\unified-vulnerabilities.json"

**Problem:** You're trying to generate summary before parsing reports.

**Solution:** Run `python scripts/parse_reports.py` first.

### Error: Module not found

**Problem:** Dependencies not installed.

**Solution:** 
```powershell
pip install -r requirements.txt
```

### Error: Permission denied (script execution)

**Problem:** PowerShell execution policy blocking scripts.

**Solution:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 📊 Expected File Structure

After running all steps, you should have:

```
reports/
├── bandit-report.json          # SAST scan results
├── semgrep-report.json         # SAST scan results
├── pip-audit-report.json       # SCA scan results
├── safety-report.json          # SCA scan results
├── unified-vulnerabilities.json  # Parsed unified format
├── security-summary.json       # Machine-readable summary
└── security-summary.txt         # Human-readable summary

LLM/reports/
├── unified-vulnerabilities.json  # Copy for LLM processing
├── policies_openai.yaml         # Generated policies (if API keys set)
└── policies_hf.yaml             # Generated policies (if API keys set)
```

---

## 🎯 Next Steps

1. **Set up GitHub Secrets** - See `docs/SECRETS_SETUP.md`
2. **Review Security Findings** - Check `reports/security-summary.txt`
3. **Fix Vulnerabilities** - Address high/critical findings
4. **Run CI/CD Workflows** - Push to GitHub to trigger automated scans
5. **Customize Policies** - Edit `LLM/Scripts/prompt_template.txt`

---

## 📚 Additional Resources

- **Quick Reference:** `docs/QUICKSTART.md`
- **Secrets Setup:** `docs/SECRETS_SETUP.md`
- **Architecture:** `docs/ARCHITECTURE.md`
- **Implementation:** `docs/IMPLEMENTATION.md`

---

## ✅ Success Checklist

- [ ] Dependencies installed
- [ ] Security scans completed
- [ ] Reports parsed successfully
- [ ] Summary generated
- [ ] Policies generated (optional)
- [ ] GitHub Secrets configured (for CI/CD)
- [ ] CI/CD workflows tested

---

**Ready to start? Run `.\scripts\quick_scan.ps1` now!** 🚀

