#!/usr/bin/env bash
set -euo pipefail

OLD_REF="${1:-HEAD~1}"
NEW_REF="${2:-HEAD}"
DATE_TAG="$(date +%Y-%m-%d)"
LAB="/mnt/f/ERP-Audit-Lab"
REP="$LAB/reports/$DATE_TAG"
WIN_PY="/mnt/f/text2voice/runtime/Python311/python.exe"

mkdir -p "$REP"
echo "=== PATCH-DIFF & VARIANT AUDIT: $OLD_REF .. $NEW_REF ==="
"$WIN_PY" 'F:\ERP-Audit-Lab\scripts\ai_auditor.py' --mode diff --repo 'F:\ERP-Audit-Lab\repo' --reports "F:\\ERP-Audit-Lab\\reports\\$DATE_TAG" --old-ref "$OLD_REF" --new-ref "$NEW_REF"
