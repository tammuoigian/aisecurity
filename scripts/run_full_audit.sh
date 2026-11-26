#!/usr/bin/env bash
set -euo pipefail

DATE_TAG="${1:-$(date +%Y-%m-%d)}"
LAB="/mnt/f/ERP-Audit-Lab"
REPO="$LAB/repo"
REP="$LAB/reports/$DATE_TAG"
WIN_PY="/mnt/f/text2voice/runtime/Python311/python.exe"

mkdir -p "$REP"
echo "=========================================================="
echo " AI SECURITY AUDIT PLATFORM — FULL AUDIT ($DATE_TAG)"
echo "=========================================================="

echo "[1/4] Gitleaks Secret Scan..."
gitleaks detect --source "$REPO" --no-git --report-format json --report-path "$REP/01_gitleaks_secrets.json" --exit-code 0 || true
GL_CNT=$(jq 'length' "$REP/01_gitleaks_secrets.json" 2>/dev/null || echo 0)
echo "  -> Gitleaks findings: $GL_CNT"

echo "[2/4] Trivy SCA & Misconfiguration Scan..."
trivy fs --scanners vuln,misconfig --format json --output "$REP/02_trivy_sca.json" "$REPO" >/dev/null 2>&1 || true
TR_CNT=$(jq '[.Results[]? | (.Vulnerabilities // [])[], (.Misconfigurations // [])[]] | length' "$REP/02_trivy_sca.json" 2>/dev/null || echo 0)
echo "  -> Trivy findings: $TR_CNT"

echo "[3/4] Semgrep SAST Scan (15-Stack Security Rules)..."
semgrep scan --config "$LAB/rules" --json --output "$REP/03_semgrep_sast.json" "$REPO" >/dev/null 2>&1 || true
SG_CNT=$(jq '.results | length' "$REP/03_semgrep_sast.json" 2>/dev/null || echo 0)
echo "  -> Semgrep findings: $SG_CNT"

echo "[4/4] AI 3-Agent Deep Audit (Local Ollama qwen3:30b-a3b + deepseek-r1:14b)..."
"$WIN_PY" 'F:\ERP-Audit-Lab\scripts\ai_auditor.py' --mode full --repo 'F:\ERP-Audit-Lab\repo' --reports "F:\\ERP-Audit-Lab\\reports\\$DATE_TAG"

echo "=========================================================="
echo " FULL AUDIT COMPLETE -> F:\\ERP-Audit-Lab\\reports\\$DATE_TAG"
echo "=========================================================="
