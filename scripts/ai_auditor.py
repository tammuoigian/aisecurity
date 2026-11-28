import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
AUDIT_MODEL = os.environ.get("AUDIT_MODEL", "qwen3-vl:8b")
CRITIC_MODEL = os.environ.get("CRITIC_MODEL", "deepseek-r1:14b")

SKIP_DIRS = {"node_modules", ".next", "vendor", ".git", ".cache", "__pycache__", "dist", "build", "uploads", "storage", "site-packages"}

SECRET_PATTERNS = [
    (re.compile(r'(?i)(password|pwd|secret|apikey|api_key|token|connectionstring)\s*[:=]\s*["\']?([^"\';\r\n]{4,})["\']?'), r'\1=***REDACTED***'),
    (re.compile(r'(?i)Data Source=[^"\r\n]+'), 'Data Source=***REDACTED_CONNSTR***'),
    (re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----'), '***REDACTED_PRIVATE_KEY***'),
]

def redact(text: str) -> str:
    for pat, rep in SECRET_PATTERNS:
        text = pat.sub(rep, text)
    return text

def call_ollama(model: str, system_prompt: str, user_prompt: str, timeout: int = 360) -> str:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {"temperature": 0.1, "num_ctx": 16384},
    }
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        content = data.get("message", {}).get("content", "")
        content = re.sub(r"<think>[\s\S]*?</think>", "", content).strip()
        return content

def safe_iter_files(base: Path, exts: tuple):
    for root, dirs, files in os.walk(str(base), followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in sorted(files):
            fp = Path(root) / fn
            if exts and fp.suffix.lower() not in exts and fp.name.lower() not in exts:
                continue
            try:
                if fp.is_symlink():
                    continue
                st = fp.stat()
                if st.st_size > 1_500_000:
                    continue
            except OSError:
                continue
            yield fp

def collect_attack_surface(repo_dir: Path, out_file: Path) -> str:
    patterns = [
        ("API Endpoints & Auth Routes (`.NET / Node / Next.js / Python / PHP`)",
         (".cs", ".ts", ".tsx", ".js", ".py", ".php"),
         re.compile(r"\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|Route|AllowAnonymous|Authorize)[^\]]*\]|app\.(?:get|post|put|delete)\(|router\.(?:get|post)|@(?:app|router)\.(?:get|post|put|delete)|export\s+async\s+function\s+(?:GET|POST|PUT|DELETE)|wp_ajax_")),
        ("Database & Injection Sinks (`SQL / NoSQL / Shell Exec`)",
         (".cs", ".ts", ".js", ".py", ".php"),
         re.compile(r"SqlCommand|FromSqlRaw|ExecuteSqlRaw|CommandText\s*=|\$where|child_process|execSync|subprocess\.|os\.system|shell_exec|wpdb->query")),
        ("File Upload, Download & SSRF Sinks",
         (".cs", ".ts", ".js", ".py", ".php"),
         re.compile(r"IFormFile|SaveAs\(|WriteAllBytes|TransmitFile|multer|fsdUpload|axios\(|fetch\(|requests\.(?:get|post)|curl_exec")),
        ("Reverse Proxy, Container & DB Configs (`Nginx / HAProxy / Docker / DB`)",
         (".conf", ".yml", ".yaml", ".json", ".config", "dockerfile"),
         re.compile(r"proxy_pass|SecRuleRemoveById|network_mode|privileged|docker\.sock|bindIp|0\.0\.0\.0|mcpServers")),
    ]

    lines = ["# Attack Surface Map — Multi-Stack Target System\n"]
    for title, exts, regex in patterns:
        hits = []
        for fp in safe_iter_files(repo_dir, exts):
            try:
                txt = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for idx, ln in enumerate(txt.splitlines(), 1):
                if regex.search(ln):
                    rel = fp.relative_to(repo_dir).as_posix()
                    hits.append(f"- `{rel}:{idx}` — `{redact(ln.strip())[:160]}`")
                    if len(hits) >= 50:
                        break
            if len(hits) >= 50:
                break
        lines.append(f"\n## {title} (tối đa 50 mẫu đầu)\n")
        lines.extend(hits if hits else ["- *(Không tìm thấy mẫu khớp trong thư mục mục tiêu)*"])
    report = "\n".join(lines) + "\n"
    out_file.write_text(report, encoding="utf-8")
    return report

def build_auth_matrix_zeroday(repo_dir: Path, out_file: Path) -> str:
    """Zero-Day / Business Logic Hunter: Builds an Endpoint & Authorization Matrix highlighting unauthenticated routes & IDOR/BOLA risks."""
    route_re = re.compile(
        r"(\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|Route)\([^\)]*\)\]|"
        r"(?:app|router)\.(?:get|post|put|delete|patch)\(\s*['\"][^'\"]+['\"]|"
        r"@(?:app|router)\.(?:get|post|put|delete)\(\s*['\"][^'\"]+['\"]|"
        r"export\s+async\s+function\s+(?:GET|POST|PUT|DELETE)\b|"
        r"add_action\(\s*['\"]wp_ajax_nopriv_[^'\"]+['\"])"
    )
    auth_re = re.compile(r"Authorize|require_auth|authenticate|verifyToken|jwt|getServerSession|current_user|isAuthenticated|checkRole", re.I)
    idor_re = re.compile(r"(?:userId|user_id|customerCode|orderId|order_id|companyId|employeeId|accountId|idCheckIn|/:id\b|\{id\})", re.I)

    rows = []
    for fp in safe_iter_files(repo_dir, (".cs", ".ts", ".tsx", ".js", ".py", ".php")):
        try:
            txt = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        lines_list = txt.splitlines()
        file_has_auth = bool(auth_re.search(txt))
        for idx, ln in enumerate(lines_list, 1):
            m = route_re.search(ln)
            if not m:
                continue
            window = "\n".join(lines_list[max(0, idx - 4):min(len(lines_list), idx + 6)])
            has_local_auth = bool(auth_re.search(window)) or file_has_auth
            has_allow_anon = "AllowAnonymous" in window or "wp_ajax_nopriv_" in ln
            has_idor_param = bool(idor_re.search(window))
            risk = "HIGH (Public + IDOR Risk)" if (has_allow_anon or not has_local_auth) and has_idor_param else (
                "MEDIUM (Check Auth)" if (has_allow_anon or not has_local_auth) else (
                "MEDIUM (Check IDOR/BOLA)" if has_idor_param else "LOW (Auth Detected)"))
            rel = fp.relative_to(repo_dir).as_posix()
            rows.append(f"| `{rel}:{idx}` | `{redact(ln.strip())[:90]}` | {'Không/Public' if (has_allow_anon or not has_local_auth) else 'Có'} | {'Có tham số ID' if has_idor_param else '-'} | **{risk}** |")
            if len(rows) >= 80:
                break
        if len(rows) >= 80:
            break

    md = [
        "# Ma Trận Phân Quyền Endpoint & Nguy Cơ Zero-Day / IDOR (Auth Matrix v4.0)\n",
        f"- Tổng số route phân tích: **{len(rows)}** (tự động nhận diện từ `.NET / Node / Next.js / Python / PHP`)\n",
        "| Vị trí (File:Line) | Khai báo Route / Endpoint | Xác thực | Tham số ID | Đánh giá Zero-Day / IDOR |",
        "|---|---|---|---|---|",
    ]
    md.extend(rows if rows else ["| - | *(Không tìm thấy khai báo route HTTP trong workspace)* | - | - | - |"])
    res = "\n".join(md) + "\n"
    out_file.write_text(res, encoding="utf-8")
    return res

def load_semgrep_summary(semgrep_json: Path) -> str:
    if not semgrep_json.exists():
        return "Không có dữ liệu Semgrep."
    try:
        data = json.loads(semgrep_json.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return "Lỗi đọc JSON Semgrep."
    results = data.get("results", [])
    if not results:
        return "Semgrep: 0 phát hiện."
    out = [f"Tổng số phát hiện Semgrep: {len(results)} (hiển thị tối đa 40 phát hiện ưu tiên):"]
    for r in results[:40]:
        path = r.get("path", "")
        line = r.get("start", {}).get("line", 0)
        cid = r.get("check_id", "").split(".")[-1]
        sev = r.get("extra", {}).get("severity", "INFO")
        msg = r.get("extra", {}).get("message", "")
        code = redact(r.get("extra", {}).get("lines", "").strip())[:160]
        out.append(f"- [{sev}] `{cid}` @ `{path}:{line}` — {msg} | Code: `{code}`")
    return "\n".join(out)

def load_code_snippets(repo_dir: Path, exts: tuple, keyword_re: str, max_files: int = 6, max_chars_per_file: int = 2400) -> str:
    pat = re.compile(keyword_re, re.IGNORECASE)
    chunks = []
    for fp in safe_iter_files(repo_dir, exts):
        try:
            txt = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if pat.search(txt):
            rel = fp.relative_to(repo_dir).as_posix()
            chunks.append(f"### FILE: {rel}\n```\n{redact(txt[:max_chars_per_file])}\n```")
            if len(chunks) >= max_files:
                break
    return "\n\n".join(chunks)

def run_full_audit(repo_dir: Path, report_dir: Path):
    print("[AI-Auditor v4.0] [1/3] Building Multi-Stack Attack Surface & Zero-Day Auth Matrix...", flush=True)
    collect_attack_surface(repo_dir, report_dir / "04_attack_surface_map.md")
    auth_matrix = build_auth_matrix_zeroday(repo_dir, report_dir / "04b_auth_matrix_zeroday.md")
    semgrep_sum = load_semgrep_summary(report_dir / "03_semgrep_sast.json")

    # 11 Multi-Stack Auto-Adaptive Playbooks (including Playbook 11: Zero-Day Business Logic & IDOR)
    playbooks = [
        ("Playbook 1: Auth, Session, JWT, RBAC & IDOR/BOLA",
         (".cs", ".ts", ".tsx", ".js", ".py", ".php"),
         r"AllowAnonymous|Authorize|Jwt|jwt\.sign|verify|Login|Session|Role|CustomerCode|req\.user|current_user"),
        ("Playbook 2: Injection (SQLi, NoSQLi MongoDB, Command Injection, SSTI)",
         (".cs", ".ts", ".js", ".py", ".php"),
         r"SqlCommand|FromSqlRaw|ExecuteSqlRaw|CommandText|\$where|child_process|execSync|subprocess|os\.system|wpdb->query|eval\("),
        ("Playbook 3: File Upload, Path Traversal, SSRF & XXE",
         (".cs", ".ts", ".js", ".py", ".php"),
         r"IFormFile|SaveAs|WriteAllBytes|TransmitFile|Path\.Combine|multer|fsdUpload|axios\(|requests\.get|curl_exec|XmlDocument"),
        ("Playbook 4: Deserialization, XSS, Prototype Pollution & Supply-Chain",
         (".cs", ".ts", ".tsx", ".js", ".py", ".config", ".json"),
         r"BinaryFormatter|TypeNameHandling|dangerouslySetInnerHTML|innerHTML|pickle\.loads|yaml\.load\(|ValidateRequest|machineKey"),
        ("Playbook 5: Reverse Proxy, WAF, TLS & CORS (Nginx / HAProxy / IIS)",
         (".conf", ".config", ".cfg"),
         r"proxy_pass|SecRuleRemoveById|Access-Control-Allow-Origin|ssl_protocols|location\s+|customErrors|applicationHost"),
        ("Playbook 6: Container, Docker Compose & Secrets Hygiene",
         (".yml", ".yaml", "dockerfile", ".env"),
         r"network_mode|privileged|docker\.sock|ports:|image:|FROM\s+"),
        ("Playbook 7: Database & Cache Hardening (MSSQL / PG / MySQL / MongoDB / Redis)",
         (".conf", ".cnf", ".ini", ".sql", ".yml", ".yaml"),
         r"bindIp|pg_hba|requirepass|xp_cmdshell|listen_addresses|authorization:|0\.0\.0\.0"),
        ("Playbook 8: OS, CIS Benchmark & MITRE ATT&CK Persistence Audit",
         (".md",),
         r"Live System|CIS|MITRE|PermitRootLogin|Unquoted Service|SUID|Listening"),
        ("Playbook 9: AI / MCP Server & Prompt Injection Security",
         (".json", ".ts", ".js", ".py"),
         r"mcpServers|ModelContextProtocol|tool_call|stdio|fastmcp|@mcp\.tool"),
        ("Playbook 10: WordPress / CMS & Next.js Specific Security",
         (".php", ".ts", ".tsx", ".js", ".mjs"),
         r"wp-config|DISALLOW_FILE_EDIT|xmlrpc|next\.config|middleware\.ts|use server|getServerSideProps"),
        ("Playbook 11: Zero-Day Business Logic, IDOR/BOLA, Auth Bypass & Race Condition Hunter",
         (".cs", ".ts", ".js", ".py", ".php"),
         r"Approve|Payment|Transfer|Balance|OverTime|CheckIn|UpdateStatus|Delete|Role|Admin|userId|customerCode|orderId"),
    ]

    sys_auditor = (
        "Bạn là Chuyên gia Bảo mật Ứng dụng & Hạ tầng (Principal AppSec/SecOps Engineer) thực hiện kiểm toán phòng thủ. "
        "Trả lời bằng tiếng Việt rõ ràng, chính xác, chuyên nghiệp. "
        "CHỈ báo cáo lỗ hổng có bằng chứng trực tiếp trong đoạn code/cấu hình được cung cấp: nêu rõ tên file, dòng/hàm, "
        "xếp hạng chuẩn CRITICAL / HIGH / MEDIUM / LOW (không dùng WARNING/ERROR), nguyên nhân, "
        "**Giải pháp vá lỗi cụ thể (Solution / Code hoặc Config mẫu)**, và đề xuất ModSecurity WAF rule nếu phù hợp. KHÔNG bịa đặt."
    )

    draft_findings = []
    active_pbs = []
    for title, exts, kw in playbooks:
        snippets = load_code_snippets(repo_dir, exts, kw, max_files=5, max_chars_per_file=2200)
        if snippets:
            active_pbs.append((title, snippets))

    total_pb = max(1, len(active_pbs))
    print(f"[AI-Auditor v3.0] [2/3] Detected {len(active_pbs)}/10 applicable Playbooks — running with {AUDIT_MODEL}...", flush=True)
    for idx, (title, snippets) in enumerate(active_pbs, 1):
        prompt = (
            f"Hãy thực hiện **{title}** trên các tệp thực tế sau đây.\n\n"
            f"### Tóm tắt Semgrep liên quan:\n{semgrep_sum[:2000]}\n\n"
            f"### Mã nguồn / Cấu hình thực tế (đã che secret):\n{snippets}\n\n"
            f"Hãy liệt kê các lỗ hổng thực tế theo chuẩn **CRITICAL / HIGH / MEDIUM / LOW**, kèm **Giải pháp vá (Solution)** cụ thể."
        )
        t0 = time.time()
        print(f"  -> [{idx}/{total_pb}] Auditing: {title} ...", flush=True)
        try:
            res = call_ollama(AUDIT_MODEL, sys_auditor, prompt, timeout=900)
        except Exception as e:
            res = f"Lỗi gọi Ollama ({AUDIT_MODEL}): {e}"
        print(f"     Done in {time.time()-t0:.1f}s", flush=True)
        draft_findings.append(f"## {title}\n\n{res}\n")

    if not draft_findings:
        draft_findings.append("## Tổng quan\n- Không tìm thấy tệp mã nguồn hoặc cấu hình khớp với 10 Playbook.\n")
    combined_draft = "\n---\n".join(draft_findings)

    print(f"[AI-Auditor v3.0] [3/3] Running Critic / False-Positive Filter Agent with {CRITIC_MODEL}...", flush=True)
    sys_critic = (
        "Bạn là Chuyên gia Phản biện Bảo mật (Security Critic & Triage Lead). "
        "Đọc bản nháp kiểm toán từ Agent 1, LOẠI BỎ các cảnh báo giả/chung chung không có bằng chứng cụ thể, "
        "và xuất ra **Báo Cáo Điều Hành (Executive Summary & Prioritized Remediation Plan)** bằng tiếng Việt chuẩn mực gồm:\n"
        "1) Bảng tổng hợp Top phát hiện xác thực nhất theo chuẩn **CRITICAL / HIGH / MEDIUM / LOW** (ưu tiên P0 / P1 / P2);\n"
        "2) **Giải pháp vá lỗi chi tiết (Solutions)** cho từng vấn đề (code/config cụ thể + ModSecurity Virtual Patch nếu cần);\n"
        "3) Checklist bàn giao cho đội Dev & SysAdmin."
    )
    try:
        critic_summary = call_ollama(CRITIC_MODEL, sys_critic, combined_draft[:28000], timeout=900)
    except Exception as e:
        critic_summary = f"Lỗi gọi Critic model ({CRITIC_MODEL}): {e}"

    final_md = (
        f"# Báo Cáo AI Deep Security Audit v3.0 (100% On-Premise)\n\n"
        f"- **Audit Model:** `{AUDIT_MODEL}` | **Critic Model:** `{CRITIC_MODEL}`\n"
        f"- **Playbooks thực thi:** {len(active_pbs)}/10 Multi-Stack Playbooks (Tự động nhận diện)\n"
        f"- **Workspace:** `{repo_dir}` (Read-Only Analysis)\n\n"
        f"---\n\n"
        f"# PHẦN I: TỔNG HỢP PHẢN BIỆN & GIẢI PHÁP ƯU TIÊN (CRITIC AGENT)\n\n"
        f"{critic_summary}\n\n"
        f"---\n\n"
        f"# PHẦN II: CHI TIẾT PHÂN TÍCH THEO PLAYBOOK\n\n"
        f"{combined_draft}\n"
    )
    out_md = report_dir / "05_ai_deep_audit_report.md"
    out_md.write_text(final_md, encoding="utf-8")
    print(f"[AI-Auditor v3.0] SAVED: {out_md}", flush=True)

def run_patch_diff_audit(repo_dir: Path, report_dir: Path, old_ref: str, new_ref: str):
    print(f"[AI-Auditor v3.0] Running Patch-Diff & Variant Analysis: {old_ref}..{new_ref}", flush=True)
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "diff", "--unified=5", f"{old_ref}..{new_ref}"],
        capture_output=True, text=True, encoding="utf-8", errors="ignore"
    )
    diff_txt = redact(proc.stdout)
    if not diff_txt.strip():
        msg = f"# Báo Cáo Patch-Diff ({old_ref}..{new_ref})\n\nKhông có thay đổi mã nguồn giữa `{old_ref}` và `{new_ref}`.\n"
        (report_dir / "06_patch_diff_audit.md").write_text(msg, encoding="utf-8")
        return
    sys_diff = (
        "Bạn là Chuyên gia Patch-Diff & Variant Analysis (AppSec). Trả lời bằng tiếng Việt. "
        "Từ bản git diff giữa 2 phiên bản, phân tích: 1) Security Regression (CRITICAL/HIGH/MEDIUM/LOW), "
        "2) Variant Analysis (mẫu lỗi để săn biến thể), 3) Giải pháp khắc phục (Solutions)."
    )
    res = call_ollama(CRITIC_MODEL, sys_diff, f"```diff\n{diff_txt[:28000]}\n```", timeout=900)
    (report_dir / "06_patch_diff_audit.md").write_text(f"# Báo Cáo Patch-Diff & Variant Analysis (`{old_ref}` -> `{new_ref}`)\n\n{res}\n", encoding="utf-8")

def run_system_audit(repo_dir: Path, report_dir: Path):
    print(f"[AI-Auditor v3.0] Running CIS & MITRE ATT&CK System Audit with {AUDIT_MODEL}...", flush=True)
    snap = repo_dir / "live_system_audit.md"
    snap_txt = redact(snap.read_text(encoding="utf-8", errors="ignore"))[:24000] if snap.exists() else "No live_system_audit.md found."
    semgrep_sum = load_semgrep_summary(report_dir / "03_semgrep_sast.json")
    sys_prompt = (
        "Bạn là Chuyên gia Bảo mật Hệ thống & Hạ tầng (Principal SecOps Engineer — CIS Benchmark & MITRE ATT&CK). "
        "Hãy phân tích báo cáo hiện trạng hệ thống (OS/Hotfix, Firewall, Defender Exclusions, RDP/NLA, SMBv1, LSA/WDigest, "
        "Unquoted Service Paths, SUID, Sudoers NOPASSWD, SSH/Sysctl, Listening Ports, IIS/SQL/Docker) và trả về Báo cáo tiếng Việt chuẩn gồm:\n"
        "1) Đánh giá tổng quan theo mức chuẩn **CRITICAL / HIGH / MEDIUM / LOW**;\n"
        "2) Danh sách lỗ hổng & dấu hiệu bất thường cụ thể (kèm mã CIS / MITRE nếu phù hợp);\n"
        "3) **Giải pháp khắc phục & lệnh Hardening cụ thể (Solutions)** theo lộ trình ưu tiên P0 -> P1 -> P2."
    )
    user_prompt = f"### Hiện trạng hệ thống thực tế:\n{snap_txt}\n\n### Kết quả Semgrep SAST:\n{semgrep_sum[:3000]}"
    res = call_ollama(AUDIT_MODEL, sys_prompt, user_prompt, timeout=900)
    out_md = report_dir / "05_ai_deep_audit_report.md"
    out_md.write_text(
        f"# Báo Cáo AI CIS & MITRE System Security Audit v3.0 (100% On-Premise)\n\n- **Model:** `{AUDIT_MODEL}`\n\n---\n\n{res}\n",
        encoding="utf-8"
    )
    print(f"[AI-Auditor v3.0] SAVED: {out_md}", flush=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["full", "diff", "system"], required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--reports", required=True)
    ap.add_argument("--old-ref", default="HEAD~1")
    ap.add_argument("--new-ref", default="HEAD")
    ap.add_argument("--audit-model", default="")
    ap.add_argument("--critic-model", default="")
    global AUDIT_MODEL, CRITIC_MODEL
    args = ap.parse_args()
    if args.audit_model: AUDIT_MODEL = args.audit_model
    if args.critic_model: CRITIC_MODEL = args.critic_model
    repo_dir = Path(args.repo)
    report_dir = Path(args.reports)
    report_dir.mkdir(parents=True, exist_ok=True)
    if args.mode == "full":
        run_full_audit(repo_dir, report_dir)
    elif args.mode == "system":
        run_system_audit(repo_dir, report_dir)
    else:
        run_patch_diff_audit(repo_dir, report_dir, args.old_ref, args.new_ref)

if __name__ == "__main__":
    main()
