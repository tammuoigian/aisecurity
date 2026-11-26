#!/usr/bin/env bash
set -euo pipefail
export DOTNET_ROOT=/usr/local/dotnet
export PATH="$PATH:/usr/local/bin:/usr/local/dotnet"
git config --global --add safe.directory '*' 

BACKUP_DIR="${1:-/mnt/f/ERP/backup-2026-11-26}"
LAB="/mnt/f/ERP-Audit-Lab"
REPO="$LAB/repo"
TAG="${2:-snapshot-$(basename "$BACKUP_DIR" | sed 's/^backup-//')}"

echo "=== INGEST SNAPSHOT: $BACKUP_DIR -> $REPO ($TAG) ==="
mkdir -p "$REPO"/{nginx,api/source,api/decompiled,app-erp/source,app-erp/decompiled,app-hrm/source,app-hrm/decompiled}

# 1. Clean working directories (preserve .git)
rm -rf "$REPO"/nginx/* "$REPO"/api/source/* "$REPO"/api/decompiled/* \
       "$REPO"/app-erp/source/* "$REPO"/app-erp/decompiled/* \
       "$REPO"/app-hrm/source/* "$REPO"/app-hrm/decompiled/*

# 2. Extract Nginx
NGINX_TGZ=$(find "$BACKUP_DIR" -maxdepth 2 -name '*nginx*.tar.gz' | head -n 1 || true)
if [ -n "$NGINX_TGZ" ]; then
  echo "[1/4] Extracting Nginx: $(basename "$NGINX_TGZ")"
  tar -xzf "$NGINX_TGZ" -C "$REPO/nginx" 2>/dev/null || true
fi

# 3. Extract API
API_TGZ=$(find "$BACKUP_DIR" -maxdepth 2 -name '*api*.tar.gz' | head -n 1 || true)
if [ -n "$API_TGZ" ]; then
  echo "[2/4] Extracting API: $(basename "$API_TGZ")"
  tar -xzf "$API_TGZ" -C "$REPO/api/source" 2>/dev/null || true
fi

# 4. Extract APP-ERP & APP-HRM
ERP_ZIP=$(find "$BACKUP_DIR" -maxdepth 2 -name 'app-erp-*.zip' | head -n 1 || true)
extract_win_zip() {
  python3 - "$1" "$2" <<'ZPY'
import os, sys, zipfile
zpath, outdir = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zpath, "r") as zf:
    for info in zf.infolist():
        rel = info.filename.replace("\\", "/").lstrip("/")
        if not rel or rel.endswith("/") or ".." in rel.split("/"):
            continue
        dest = os.path.join(outdir, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with zf.open(info, "r") as rf, open(dest, "wb") as wf:
            wf.write(rf.read())
ZPY
}

if [ -n "$ERP_ZIP" ]; then
  echo "[3/4] Extracting APP-ERP: $(basename "$ERP_ZIP")"
  extract_win_zip "$ERP_ZIP" "$REPO/app-erp/source"
fi

HRM_ZIP=$(find "$BACKUP_DIR" -maxdepth 2 -name 'app-hrm-*.zip' | head -n 1 || true)
if [ -n "$HRM_ZIP" ]; then
  echo "[4/4] Extracting APP-HRM: $(basename "$HRM_ZIP")"
  extract_win_zip "$HRM_ZIP" "$REPO/app-hrm/source"
fi

# 5. Smart .NET Decompilation (business/custom DLLs only — skip vendor/framework DLLs)
SKIP_REGEX='^(System\.|Microsoft\.|DevExpress\.|Newtonsoft\.|EntityFramework|BouncyCastle|Telerik\.|CrystalDecisions|ClosedXML|DocumentFormat|EPPlus|Serilog|AutoMapper|FluentValidation|Swashbuckle|NLog|log4net|Oracle\.|MySql\.|Npgsql|Dapper|StackExchange|RestSharp|Polly|MediatR|Hangfire|IdentityModel|Google\.|Grpc\.|Antlr|WebGrease|AjaxControlToolkit|ICSharpCode|SharpZipLib|HtmlAgilityPack|itext|PdfSharp|SkiaSharp|SixLabors|SixLabors|netstandard|mscorlib|vccorlib|api-ms-win|ucrtbase|clr|sni|e_sqlite3|lib|SQLite|Interop\.|stdole|Office|EnvDTE|VSLangProj)'

decompile_dir() {
  local src_dir="$1"
  local out_dir="$2"
  local label="$3"
  local count=0
  echo "--- Decompiling business .NET DLLs for $label ---"
  while IFS= read -r dll; do
    local base=$(basename "$dll")
    if ! echo "$base" | grep -qiE '^(SSE|AccessRight|appAccessRight|API|Cls|cls|CRM|HRM|ThienVuong|App_Code|App_Web)'; then
      continue
    fi
    # Skip localized resource satellite DLLs (*.resources.dll)
    if [[ "$base" == *.resources.dll ]]; then
      continue
    fi
    local proj_name="${base%.dll}"
    local target="$out_dir/$proj_name"
    mkdir -p "$target"
    if ilspycmd -p -o "$target" "$dll" >/dev/null 2>&1; then
      count=$((count + 1))
      echo "  [DECOMPILED] $base -> $proj_name/"
    else
      rmdir "$target" 2>/dev/null || true
    fi
  done < <(find "$src_dir" -maxdepth 3 -type f -iname '*.dll' ! -path '*/bk*' ! -path '*/runtimes/*' | sort)
  echo "  Total business DLLs decompiled for $label: $count"
}

decompile_dir "$REPO/api/source" "$REPO/api/decompiled" "API"
decompile_dir "$REPO/app-erp/source" "$REPO/app-erp/decompiled" "APP-ERP"
decompile_dir "$REPO/app-hrm/source" "$REPO/app-hrm/decompiled" "APP-HRM"

# 6. Initialize/Update Local Git Repo for Patch-Diff Tracking
cd "$REPO"
if [ ! -d .git ]; then
  git init -q
  git config user.name "AI Security Audit"
  git config user.email "audit@secops.local"
  cat > .gitignore <<'GI'
*.dll
*.exe
*.pdb
*.zip
*.tar.gz
*.jpg
*.jpeg
*.png
*.gif
*.pdf
*.xlsx
*.xls
*.doc
*.docx
*.bak
*.log
*.key
*.pem
*.pfx
*.crt
bk*/
runtimes/
GI
fi

git add -A
if ! git diff --cached --quiet; then
  git commit -q -m "Ingest $TAG from $BACKUP_DIR"
  git tag -f "$TAG"
  echo "GIT COMMITTED & TAGGED: $TAG ($(git rev-parse --short HEAD))"
else
  echo "GIT: No changes since last snapshot"
fi

echo "INGEST_COMPLETE_OK"
