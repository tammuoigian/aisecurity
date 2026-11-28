#!/usr/bin/env bash
SRC="$1"
REP="$2"
TSTAGE="/tmp/trivy_stage_$$"
rm -rf "$TSTAGE" && mkdir -p "$TSTAGE"

# 1. Stage app manifests & IaC/Docker configs onto ext4 /tmp (~2s scan)
(
  cd "$SRC" && find . -maxdepth 5 -type f \( \
    -name 'package.json' -o -name 'package-lock.json' -o -name 'yarn.lock' -o -name 'pnpm-lock.yaml' \
    -o -name 'requirements.txt' -o -name 'Pipfile.lock' -o -name 'poetry.lock' \
    -o -name 'go.mod' -o -name 'go.sum' -o -name 'composer.lock' -o -name '*.csproj' -o -name 'packages.config' \
    -o -name 'Dockerfile*' -o -name '*docker-compose*.yml' -o -name '*docker-compose*.yaml' -o -name 'compose.y*ml' -o -name '*.tf' \
  \) -not -path '*/node_modules/*' -not -path '*/.next/*' -not -path '*/vendor/*' -not -path '*/.git/*' \
  -exec cp --parents {} "$TSTAGE/" \; 2>/dev/null || true
)

TCNT=$(find "$TSTAGE" -type f | wc -l)
echo "  -> [App SCA] Fast-staged $TCNT manifest/config files on ext4 /tmp for Trivy..."
if [ "$TCNT" -gt 0 ]; then
  trivy fs --timeout 3m --scanners vuln,misconfig --misconfig-scanners dockerfile,terraform,kubernetes --format json --output "$REP/02_trivy_sca.json" "$TSTAGE" || true
  trivy fs --timeout 2m --format cyclonedx --output "$REP/08_sbom_cyclonedx.json" "$TSTAGE" 2>/dev/null || true
else
  printf '{"Results":[]}\n' > "$REP/02_trivy_sca.json"
fi

# 2. Qualys/Nessus-style OS Package CVE Scan (Linux dpkg/os-release staged to ext4 /tmp)
if [ -f "$SRC/os_packages/var/lib/dpkg/status" ]; then
  OSSTAGE="/tmp/trivy_os_$$"
  rm -rf "$OSSTAGE" && mkdir -p "$OSSTAGE/var/lib/dpkg" "$OSSTAGE/etc"
  cp "$SRC/os_packages/var/lib/dpkg/status" "$OSSTAGE/var/lib/dpkg/status"
  [ -f "$SRC/os_packages/etc/os-release" ] && cp "$SRC/os_packages/etc/os-release" "$OSSTAGE/etc/os-release"
  echo "  -> [OS CVE Engine] Running Trivy rootfs OS package CVE scan (Qualys/Nessus-grade)..."
  trivy rootfs --timeout 3m --scanners vuln --severity CRITICAL,HIGH,MEDIUM --format json --output "/tmp/trivy_os_out_$$.json" "$OSSTAGE" 2>/dev/null || true
  if [ -s "/tmp/trivy_os_out_$$.json" ]; then
    python3 - "$REP/02_trivy_sca.json" "/tmp/trivy_os_out_$$.json" <<'PY'
import json, sys
p_main, p_os = sys.argv[1], sys.argv[2]
try:
    main_d = json.loads(open(p_main, encoding="utf-8").read())
except Exception:
    main_d = {"Results": []}
try:
    os_d = json.loads(open(p_os, encoding="utf-8").read())
    os_res = os_d.get("Results") or []
    for r in os_res:
        r["Target"] = "[OS Packages] " + str(r.get("Target", ""))
    main_d.setdefault("Results", []).extend(os_res)
    cnt = sum(len(r.get("Vulnerabilities") or []) for r in os_res)
    print(f"  -> [OS CVE Engine] Merged {cnt} Linux OS package CVEs into 02_trivy_sca.json!")
    open(p_main, "w", encoding="utf-8").write(json.dumps(main_d, ensure_ascii=False))
except Exception as ex:
    print(f"  -> [OS CVE Engine] Merge note: {ex}")
PY
  fi
  rm -rf "$OSSTAGE" "/tmp/trivy_os_out_$$.json"
fi

rm -rf "$TSTAGE"
