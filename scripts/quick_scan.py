#!/usr/bin/env python3
"""
Quick Security Scan Runner (cross-platform)

Runs:
  - Bandit (SAST)
  - Semgrep (SAST)
  - pip-audit (SCA)
  - Safety (SCA)

Outputs JSON reports into ./reports, then (optionally) tells you
how to parse & summarize with your existing scripts.

Exit codes:
  - Returns 0 if all tools ran (even if they found issues)
  - Returns 1 only if a tool failed to execute for reasons other than findings
"""

import os
import sys
import subprocess
from pathlib import Path
from shutil import which

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = REPO_ROOT / "reports"

def run(cmd: list[str], name: str, ok_codes=(0, 1)) -> int:
    """Run a command, treat return codes in ok_codes as success."""
    print("=" * 70)
    print(f"▶ {name}")
    print("=" * 70)
    print("$", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, cwd=REPO_ROOT)
    except FileNotFoundError as e:
        print(f"⚠ {name} not found: {e}")
        return 127

    rc = proc.returncode
    if rc in ok_codes:
        print(f"✓ {name} completed (exit {rc})")
        return 0
    else:
        print(f"❌ {name} failed (exit {rc})")
        return rc

def pip_install(pkg: str) -> int:
    """Install a package into the current environment."""
    print(f"… ensuring '{pkg}' is installed")
    return run([sys.executable, "-m", "pip", "install", "-q", pkg], f"pip install {pkg}", ok_codes=(0,))

def ensure_reports_dir():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"✓ Using reports directory: {REPORTS_DIR}")

def main() -> int:
    os.chdir(REPO_ROOT)
    print("🚀 Starting Quick Security Scans...")
    ensure_reports_dir()

    overall_rc = 0

    # 1) Bandit
    overall_rc |= pip_install("bandit")
    overall_rc |= run(
        ["bandit", "-r", ".", "-f", "json", "-o", str(REPORTS_DIR / "bandit-report.json"), "--quiet"],
        "Bandit (SAST)"
    )

    # 2) Semgrep
    overall_rc |= pip_install("semgrep")
    # Use the public CI ruleset. If you prefer local heuristics, swap to: ["--config=auto"]
    semgrep_result = run(
        ["semgrep", "--config", "p/ci", "--json", "--output", str(REPORTS_DIR / "semgrep-report.json"), ".", "--quiet"],
        "Semgrep (SAST)"
    )
    # If p/ci config fails, try auto config as fallback
    if semgrep_result != 0:
        print("⚠ Semgrep with p/ci config failed, trying auto config...")
        semgrep_result = run(
            ["semgrep", "--config", "auto", "--json", "--output", str(REPORTS_DIR / "semgrep-report.json"), ".", "--quiet"],
            "Semgrep (SAST)"
        )
    overall_rc |= semgrep_result

    # 3) pip-audit
    overall_rc |= pip_install("pip-audit")
    overall_rc |= run(
        ["pip-audit", "--format=json", f"--output={REPORTS_DIR / 'pip-audit-report.json'}"],
        "pip-audit (SCA)"
    )

    # 4) Safety
    overall_rc |= pip_install("safety")
    # Safety's --output flag only accepts 'screen' or 'text', not file paths
    # So we need to redirect stdout to a file instead
    safety_report = REPORTS_DIR / "safety-report.json"
    safety_cmd = ["safety", "check", "--json"]
    if os.getenv("SAFETY_API_KEY"):
        safety_cmd.extend(["--key", os.getenv("SAFETY_API_KEY")])
    
    # Run safety and capture output
    print("=" * 70)
    print("▶ Safety (SCA)")
    print("=" * 70)
    print("$", " ".join(safety_cmd), ">", str(safety_report))
    try:
        with open(safety_report, 'w', encoding='utf-8') as f:
            proc = subprocess.run(safety_cmd, cwd=REPO_ROOT, stdout=f, stderr=subprocess.PIPE, text=True)
        if proc.stderr:
            print(proc.stderr, end='')
        rc = proc.returncode
        # Safety returns 1 if vulnerabilities found (which is OK), 0 if none found
        if rc in (0, 1):
            print(f"✓ Safety (SCA) completed (exit {rc})")
            safety_result = 0
        else:
            print(f"❌ Safety (SCA) failed (exit {rc})")
            safety_result = rc
    except FileNotFoundError as e:
        print(f"⚠ Safety not found: {e}")
        safety_result = 127
    overall_rc |= safety_result

    print("=" * 70)
    print("📋 Next Steps:")
    print("  1) Parse:    python scripts/parse_reports.py --verbose")
    print("  2) Summary:  python scripts/generate_security_summary.py")
    print("=" * 70)

    # If any tool *failed to run*, return 1. Findings alone won't fail the script.
    return 1 if overall_rc != 0 else 0

if __name__ == "__main__":
    sys.exit(main())
