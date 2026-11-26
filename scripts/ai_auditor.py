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
AUDIT_MODEL = os.environ.get("AUDIT_MODEL", "qwen3:30b-a3b")
CRITIC_MODEL = os.environ.get("CRITIC_MODEL", "deepseek-r1:14b")

SECRET_PATTERNS = [
    (re.compile(r'(?i)(password|pwd|secret|apikey|api_key|token|connectionstring)\s*[:=]\s*["\']?([^"\';\r\n]{4,})["\']?'), r'\1=***REDACTED***'),
    (re.compile(r'(?i)Data Source=[^"\r\n]+'), 'Data Source=***REDACTED_CONNSTR***'),
    (re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----'), '***REDACTED_PRIVATE_KEY***'),
]

def redact(text: str) -> str:
    for pat, rep in SECRET_PATTERNS:
        text = pat.sub(rep, text)
    return text

def call_ollama(model: str, system_prompt: str, user_prompt: str, timeout: int = 300) -> str:
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
        # Strip <think>...</think> blocks from reasoning models for clean final report
        content = re.sub(r"<think>[\s\S]*?</think>", "", content).strip()
        return content

def safe_iter_files(base: Path, exts: tuple):
    for root, dirs, files in os.walk(str(base), followlinks=False):
        for fn in sorted(files):
            fp = Path(root) / fn
            if fp.suffix.lower() not in exts:
                continue
            try:
                if fp.is_symlink():
                    continue
                st = fp.stat()
                if st.st_size > 2 * 1024 * 1024:
                    continue
            except OSError:
                continue
            yield fp

def collect_attack_surface(repo_dir: Path, out_file: Path) -> str:
    sections = []
    patterns = [
        ("API Endpoints & Auth Attributes (`[Http*]`, `[AllowAnonymous]`, `[Authorize]`)",
         ["api/decompiled"], re.compile(r"\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|Route|AllowAnonymous|Authorize)[^\]]*\]")),
        ("ASP.NET WebServices & Handlers (`.asmx`, `.ashx`, `[WebMethod]`)",
         ["app-erp", "app-hrm"], re.compile(r"\[WebMethod|ProcessRequest\(|IHttpHandler")),
        ("Dynamic SQL & Database Sinks (`SqlCommand`, `FromSqlRaw`, `ExecuteSqlRaw`, `CommandText`)",
         ["api/decompiled", "app-erp/decompiled", "app-hrm/decompiled"], re.compile(r"SqlCommand|FromSqlRaw|ExecuteSqlRaw|CommandText\s*=|SqlDataAdapter")),
        ("File Upload / Download & Path Operations (`IFormFile`, `SaveAs`, `fsdUpload`, `WriteAllBytes`, `TransmitFile`)",
         ["api/decompiled", "app-erp/decompiled", "app-hrm/decompiled"], re.compile(r"IFormFile|SaveAs\(|fsdUpload|WriteAllBytes|TransmitFile|WriteFile\(")),
        ("Nginx Reverse Proxy & WAF Exclusions (`proxy_pass`, `SecRuleRemoveById`, `location`)",
         ["nginx"], re.compile(r"proxy_pass|SecRuleRemoveById|location\s+")),
    ]

    lines = ["# Attack Surface Map — Target System\n"]
    for title, subdirs, regex in patterns:
        hits = []
        for sub in subdirs:
            base = repo_dir / sub
            if not base.exists():
                continue
            for fp in safe_iter_files(base, (".cs", ".aspx", ".asmx", ".ashx", ".conf", ".config", ".json")):
                try:
                    txt = fp.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                for idx, ln in enumerate(txt.splitlines(), 1):
                    if regex.search(ln):
                        rel = fp.relative_to(repo_dir).as_posix()
                        hits.append(f"- `{rel}:{idx}` — `{redact(ln.strip())[:160]}`")
                        if len(hits) >= 60:
                            break
                if len(hits) >= 60:
                    break
        lines.append(f"\n## {title} (hiển thị tối đa 60 kết quả đầu)\n")
        if hits:
            lines.extend(hits)
        else:
            lines.append("- *(Không tìm thấy mẫu khớp)*")
    report = "\n".join(lines) + "\n"
    out_file.write_text(report, encoding="utf-8")
    return report

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
        cid = r.get("check_id", "")
        sev = r.get("extra", {}).get("severity", "INFO")
        msg = r.get("extra", {}).get("message", "")
        code = redact(r.get("extra", {}).get("lines", "").strip())[:160]
        out.append(f"- [{sev}] `{cid}` @ `{path}:{line}` — {msg} | Code: `{code}`")
    return "\n".join(out)

def load_code_snippets(repo_dir: Path, subdir: str, keyword_re: str, max_files: int = 8, max_chars_per_file: int = 3000) -> str:
    base = repo_dir / subdir
    if not base.exists():
        return ""
    pat = re.compile(keyword_re, re.IGNORECASE)
    chunks = []
    for fp in safe_iter_files(base, (".cs", ".conf", ".config", ".aspx", ".ashx")):
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
    print("[AI-Auditor] Step 1/3: Building Attack Surface Map...", flush=True)
    surface = collect_attack_surface(repo_dir, report_dir / "04_attack_surface_map.md")
    semgrep_sum = load_semgrep_summary(report_dir / "03_semgrep_sast.json")

    playbooks = [
        ("Playbook 1: Broken Auth, IDOR & Missing Authorization (API & ERP)",
         "api/decompiled", r"AllowAnonymous|Authorize|Controller|Jwt|Login|CustomerCode|idCheckIn"),
        ("Playbook 2: SQL Injection & Dynamic SQL (API & APP-ERP)",
         "api/decompiled", r"SqlCommand|FromSqlRaw|ExecuteSqlRaw|CommandText|SqlConnection"),
        ("Playbook 3: File Upload, Download & Path Traversal (fsdUpload / Export)",
         "api/decompiled", r"fsdUpload|IFormFile|SaveAs|WriteAllBytes|FileStream|Path\.Combine"),
        ("Playbook 4: Legacy .NET, Deserialization & Config Hardening (APP-ERP)",
         "app-erp/decompiled", r"BinaryFormatter|TypeNameHandling|Process\.Start|ValidateRequest|machineKey|SqlCommand"),
        ("Playbook 5: Nginx <-> IIS Desync & WAF Exclusion Review",
         "nginx", r"proxy_pass|SecRuleRemoveById|location|upstream"),
    ]

    sys_auditor = (
        "Bạn là Chuyên gia Bảo mật Ứng dụng (Principal AppSec Engineer) thực hiện kiểm toán mã nguồn phòng thủ (White-Box Defensive Code Audit) "
        "cho hệ thống ERP nội bộ. Trả lời bằng tiếng Việt rõ ràng, chính xác. "
        "CHỈ báo cáo lỗ hổng có bằng chứng trực tiếp trong đoạn code được cung cấp (nêu rõ tên file, hàm/dòng, nguyên nhân, mức độ Critical/High/Medium, "
        "cách sửa code cụ thể, và đề xuất rule ModSecurity Virtual Patch nếu cần). KHÔNG bịa đặt code không có trong ngữ cảnh."
    )

    draft_findings = []
    print(f"[AI-Auditor] Step 2/3: Running 5 Deep Audit Playbooks with {AUDIT_MODEL}...", flush=True)
    for title, subdir, kw in playbooks:
        snippets = load_code_snippets(repo_dir, subdir, kw, max_files=6, max_chars_per_file=2600)
        if not snippets:
            draft_findings.append(f"## {title}\n- Không tìm thấy file khớp từ khóa trong `{subdir}`.\n")
            continue
        prompt = (
            f"Hãy thực hiện **{title}** trên các file thực tế sau đây.\n\n"
            f"### Tóm tắt Semgrep liên quan:\n{semgrep_sum[:2500]}\n\n"
            f"### Mã nguồn / Cấu hình thực tế (đã che secret):\n{snippets}\n\n"
            f"Hãy liệt kê các lỗ hổng bảo mật thực tế (tập trung vào lỗi logic, IDOR, SQLi, Path Traversal, Deserialization, cấu hình sai) "
            f"kèm đề xuất sửa lỗi & rule ModSecurity WAF nếu phù hợp."
        )
        t0 = time.time()
        print(f"  -> Auditing: {title} ...", flush=True)
        try:
            res = call_ollama(AUDIT_MODEL, sys_auditor, prompt, timeout=900)
        except Exception as e:
            res = f"Lỗi gọi Ollama ({AUDIT_MODEL}): {e}"
        print(f"     Done in {time.time()-t0:.1f}s", flush=True)
        draft_findings.append(f"## {title}\n\n{res}\n")

    combined_draft = "\n---\n".join(draft_findings)

    print(f"[AI-Auditor] Step 3/3: Running Critic / False-Positive Filter Agent with {CRITIC_MODEL}...", flush=True)
    sys_critic = (
        "Bạn là Chuyên gia Phản biện Bảo mật (Security Critic & Triage Lead). "
        "Nhiệm vụ của bạn là đọc bản nháp kiểm toán từ Agent 1, LOẠI BỎ các cảnh báo giả/chung chung không có bằng chứng file cụ thể, "
        "và xuất ra **Báo Cáo Điều Hành (Executive Summary & Prioritized Action Plan)** bằng tiếng Việt: "
        "1) Top phát hiện Critical/High xác thực nhất (xếp hạng ưu tiên P0/P1/P2), "
        "2) Hướng dẫn vá nhanh bằng ModSecurity Virtual Patch (nếu cần), "
        "3) Danh sách việc cần yêu cầu đội Dev/SSE sửa trong code."
    )
    try:
        critic_summary = call_ollama(CRITIC_MODEL, sys_critic, combined_draft[:28000], timeout=900)
    except Exception as e:
        critic_summary = f"Lỗi gọi Critic model ({CRITIC_MODEL}): {e}"

    final_md = (
        f"# Báo Cáo AI Deep Code Audit (100% On-Premise)\n\n"
        f"- **Audit Model:** `{AUDIT_MODEL}` | **Critic Model:** `{CRITIC_MODEL}`\n"
        f"- **Workspace:** `{repo_dir}` (Read-Only Analysis)\n\n"
        f"---\n\n"
        f"# PHẦN I: TỔNG HỢP PHẢN BIỆN & ƯU TIÊN HÀNH ĐỘNG (CRITIC AGENT)\n\n"
        f"{critic_summary}\n\n"
        f"---\n\n"
        f"# PHẦN II: CHI TIẾT PHÂN TÍCH THEO 5 PLAYBOOK\n\n"
        f"{combined_draft}\n"
    )
    out_md = report_dir / "05_ai_deep_audit_report.md"
    out_md.write_text(final_md, encoding="utf-8")
    print(f"[AI-Auditor] SAVED: {out_md}", flush=True)

def run_patch_diff_audit(repo_dir: Path, report_dir: Path, old_ref: str, new_ref: str):
    print(f"[AI-Auditor] Running Patch-Diff & Variant Analysis: {old_ref}..{new_ref}", flush=True)
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "diff", "--unified=5", f"{old_ref}..{new_ref}"],
        capture_output=True, text=True, encoding="utf-8", errors="ignore"
    )
    diff_txt = redact(proc.stdout)
    if not diff_txt.strip():
        msg = f"# Báo Cáo Patch-Diff ({old_ref}..{new_ref})\n\nKhông có thay đổi mã nguồn giữa `{old_ref}` và `{new_ref}`.\n"
        (report_dir / "06_patch_diff_audit.md").write_text(msg, encoding="utf-8")
        print("[AI-Auditor] Empty diff.", flush=True)
        return

    sys_diff = (
        "Bạn là Chuyên gia Patch-Diff & Variant Analysis (AppSec). Trả lời bằng tiếng Việt. "
        "Từ bản git diff giữa 2 phiên bản ERP/API/Nginx, hãy phân tích 2 nội dung:\n"
        "1) **Security Regression:** Bản mới có vô tình tắt auth, mở lỗ hổng SQLi/IDOR/Path Traversal hay lộ thông tin nhạy cảm mới không?\n"
        "2) **Variant Analysis:** Nếu bản mới vừa vá 1 lỗ hổng bảo mật, hãy nêu rõ mẫu lỗi (pattern) để quét tìm các biến thể tương tự chưa được vá ở file khác."
    )
    res = call_ollama(CRITIC_MODEL, sys_diff, f"```diff\n{diff_txt[:28000]}\n```", timeout=900)
    out_md = report_dir / "06_patch_diff_audit.md"
    out_md.write_text(f"# Báo Cáo Patch-Diff & Variant Analysis (`{old_ref}` -> `{new_ref}`)\n\n{res}\n", encoding="utf-8")
    print(f"[AI-Auditor] SAVED: {out_md}", flush=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["full", "diff"], required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--reports", required=True)
    ap.add_argument("--old-ref", default="HEAD~1")
    ap.add_argument("--new-ref", default="HEAD")
    args = ap.parse_args()
    repo_dir = Path(args.repo)
    report_dir = Path(args.reports)
    report_dir.mkdir(parents=True, exist_ok=True)
    if args.mode == "full":
        run_full_audit(repo_dir, report_dir)
    else:
        run_patch_diff_audit(repo_dir, report_dir, args.old_ref, args.new_ref)

if __name__ == "__main__":
    main()
