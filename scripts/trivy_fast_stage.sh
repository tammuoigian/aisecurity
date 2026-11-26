#!/usr/bin/env bash
SRC="$1"
REP="$2"
TSTAGE="/tmp/trivy_stage_$$"
rm -rf "$TSTAGE" && mkdir -p "$TSTAGE"
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
echo "  -> Fast-staged $TCNT manifest/config files on ext4 /tmp for Trivy..."
if [ "$TCNT" -gt 0 ]; then
  trivy fs --timeout 3m --scanners vuln,misconfig --misconfig-scanners dockerfile,terraform,kubernetes --format json --output "$REP/02_trivy_sca.json" "$TSTAGE" || true
else
  printf '{"Results":[]}\n' > "$REP/02_trivy_sca.json"
fi
rm -rf "$TSTAGE"
