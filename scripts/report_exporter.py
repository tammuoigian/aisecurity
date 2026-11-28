import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import markdown
import openpyxl
from openpyxl.styles import Alignment, Font, PatternFill
import enterprise_intel

# Remediation Knowledge Base (Solutions tiếng Việt chuyên sâu theo Rule / Nhóm lỗi)
REMEDIATION_KB = {
    "sql-injection": "Sử dụng Parameterized Query / Prepared Statement (SqlParameter, EF Core FromSqlInterpolated) thay cho nối chuỗi SQL trực tiếp; áp dụng ModSecurity WAF rule chặn tạm nếu chưa kịp vá code.",
    "sqli": "Sử dụng Parameterized Query / Prepared Statement; tuyệt đối không nối chuỗi biến đầu vào người dùng vào câu lệnh SQL.",
    "nosql": "Sanitize dữ liệu đầu vào (loại bỏ toán tử `$where`, `$ne`, `$gt`, `$regex`), ép kiểu string/ObjectId và tắt JavaScript execution trong MongoDB.",
    "deserialization": "Loại bỏ BinaryFormatter / TypeNameHandling.All; chuyển sang System.Text.Json hoặc Newtonsoft.Json với TypeNameHandling.None.",
    "binaryformatter": "Thay thế BinaryFormatter bằng System.Text.Json hoặc clone đối tượng an toàn (MemberwiseClone / AutoMapper).",
    "command-injection": "Không truyền input người dùng trực tiếp vào shell (`exec`, `Process.Start`, `os.system`); dùng danh sách tham số (array) và allowlist giá trị hợp lệ.",
    "path-traversal": "Chuẩn hóa đường dẫn bằng `Path.GetFullPath()` / `realpath()`, kiểm tra prefix nằm trong thư mục gốc cho phép và chỉ cho phép tên file theo allowlist.",
    "ssrf": "Chặn truy cập dải IP nội bộ/metadata (`127.0.0.0/8`, `10.0.0.0/8`, `169.254.169.254`), chỉ cho phép kết nối tới domain nằm trong danh sách allowlist.",
    "xss": "Encode dữ liệu đầu ra theo ngữ cảnh HTML/JS, tránh `dangerouslySetInnerHTML` / `innerHTML` (hoặc lọc bằng DOMPurify) và bật Content-Security-Policy (CSP).",
    "cors": "Thay `Access-Control-Allow-Origin: *` bằng danh sách domain tin cậy cụ thể; không kết hợp `*` với `Access-Control-Allow-Credentials: true`.",
    "tls": "Nâng cấp cấu hình lên TLS 1.2 / TLS 1.3; tắt SSLv3, TLS 1.0, TLS 1.1 và không tắt kiểm tra chứng chỉ (`rejectUnauthorized: false` / `verify=False`).",
    "docker-network-host": "Gỡ `network_mode: host` trong `docker-compose.yml`; sử dụng bridge network riêng của ứng dụng và chỉ publish đúng port cần thiết (bind `127.0.0.1` nếu đi qua Reverse Proxy).",
    "docker-privileged": "Tắt `privileged: true`; chỉ cấp quyền tối thiểu qua `cap_drop: [ALL]` và `cap_add` cần thiết, chạy container bằng user non-root.",
    "docker-sock": "Không mount `/var/run/docker.sock` vào container ứng dụng (tương đương quyền root host); nếu bắt buộc giám sát hãy dùng Docker Socket Proxy chỉ-đọc.",
    "hardcoded": "Gỡ bỏ mật khẩu/API key cứng khỏi mã nguồn; xoay vòng (rotate) khóa ngay lập tức và chuyển sang biến môi trường (.env) hoặc Secrets Manager.",
    "jwt": "Sử dụng thuật toán ký mạnh (HS256 với secret >= 32 ký tự ngẫu nhiên hoặc RS256), bắt buộc kiểm tra chữ ký & thời hạn `exp` và từ chối `alg: none`.",
    "nginx": "Ẩn phiên bản (`server_tokens off;`), bật Security Headers (HSTS, X-Frame-Options, X-Content-Type-Options, CSP), giới hạn `client_max_body_size` và bật ModSecurity WAF.",
    "haproxy": "Bật TLS 1.2+, cấu hình rate-limit (`stick-table`), ẩn header phiên bản và giới hạn quyền truy cập trang stats chỉ cho IP nội bộ.",
    "wordpress": "Tắt chỉnh sửa file trong wp-admin (`DISALLOW_FILE_EDIT`), chặn `xmlrpc.php`, giới hạn truy cập `wp-login.php` và cập nhật core/plugin/theme định kỳ.",
    "mcp": "Giới hạn quyền công cụ MCP theo nguyên tắc tối thiểu (least privilege), xác thực token/origin, không chạy shell tùy ý từ prompt không tin cậy.",
    "mongodb": "Bind `net.bindIp: 127.0.0.1` (hoặc IP VPN nội bộ), bật `security.authorization: enabled` và tạo tài khoản phân quyền theo từng database.",
    "postgres": "Giới hạn `pg_hba.conf` dùng `scram-sha-256`, không dùng `trust` hay mở `0.0.0.0/0` ra Internet; bật SSL cho kết nối DB.",
    "mysql": "Bind `127.0.0.1` hoặc mạng nội bộ, xóa tài khoản anonymous/root từ xa và bắt buộc kết nối qua TLS.",
    "mssql": "Cập nhật SQL Server Cumulative Update (CU/GDR) mới nhất, tắt `xp_cmdshell`, đổi cổng mặc định và giới hạn Windows Firewall chỉ cho IP APP/API.",
    "llm01": "Tách biệt chặt chẽ System Prompt và User Input, áp dụng input/output guardrails và lọc dữ liệu RAG trước khi đưa vào ngữ cảnh LLM.",
    "llm02": "Không bao giờ truyền trực tiếp output của LLM vào eval/exec/SQL/HTML; bắt buộc dùng parser cấu trúc (JSON Schema) và allowlist hành động.",
    "llm06": "Áp dụng nguyên tắc quyền tối thiểu (Least Privilege) cho AI Agent/MCP tools, loại bỏ shell=True và yêu cầu xác nhận con người (HITL) với thao tác ghi/xóa.",
    "llm07": "Kiểm soát allowlist domain trước khi nạp URL vào RAG và gắn nhãn dữ liệu ngoài là untrusted để chống Indirect Prompt Injection.",
}

CWE_CVSS_MAP = [
    (("sqli", "sql-injection"), "CWE-89", "9.8"),
    (("command-injection", "cmdi", "rce", "shell-exec", "llm02", "llm06"), "CWE-78", "9.8"),
    (("deserialization", "binaryformatter"), "CWE-502", "9.8"),
    (("hardcoded", "secret", "mcp01"), "CWE-798", "9.1"),
    (("nosql",), "CWE-943", "8.6"),
    (("ssrf", "llm07"), "CWE-918", "8.2"),
    (("path-traversal", "lfi"), "CWE-22", "8.1"),
    (("llm01", "prompt-injection"), "CWE-77", "8.1"),
    (("docker-privileged", "docker-sock"), "CWE-250", "8.8"),
    (("idor", "auth", "jwt"), "CWE-639", "8.1"),
    (("xss", "dangerouslysetinnerhtml"), "CWE-79", "6.8"),
    (("cors",), "CWE-942", "6.5"),
    (("docker-network-host", "mcp02"), "CWE-284", "6.5"),
    (("tls",), "CWE-327", "5.9"),
]

def get_cwe_cvss(rule_id: str, severity: str = "MEDIUM") -> tuple:
    rid = (rule_id or "").lower()
    for keys, cwe, cvss in CWE_CVSS_MAP:
        if any(k in rid for k in keys):
            return cwe, cvss
    fallback = {"CRITICAL": ("CWE-20", "9.1"), "HIGH": ("CWE-20", "7.8"), "MEDIUM": ("CWE-16", "5.5"), "LOW": ("CWE-16", "3.1")}
    return fallback.get((severity or "MEDIUM").upper(), ("CWE-16", "5.0"))

REFERENCE_LINKS = {
    "sql-injection": ("OWASP SQLi Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
    "sqli": ("OWASP SQLi Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
    "nosql": ("OWASP NoSQL Injection", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"),
    "deserialization": ("OWASP Deserialization", "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"),
    "binaryformatter": ("Microsoft BinaryFormatter Migration", "https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide"),
    "command-injection": ("OWASP OS Command Injection", "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"),
    "path-traversal": ("OWASP Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
    "ssrf": ("OWASP SSRF Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"),
    "xss": ("OWASP XSS Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
    "cors": ("MDN / OWASP CORS Guide", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"),
    "tls": ("Mozilla SSL Config Generator", "https://ssl-config.mozilla.org/"),
    "docker-network-host": ("CIS Docker Benchmark / Docker Docs", "https://docs.docker.com/engine/security/"),
    "docker-privileged": ("Docker Runtime Privilege Hardening", "https://docs.docker.com/engine/security/"),
    "docker-sock": ("Docker Socket Security", "https://docs.docker.com/engine/security/protect-daemon-socket/"),
    "jwt": ("OWASP JWT Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"),
    "nginx": ("Nginx Security Hardening", "https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens"),
    "llm01": ("OWASP LLM01 Prompt Injection", "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"),
    "llm02": ("OWASP LLM05 Improper Output Handling", "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/"),
    "llm06": ("OWASP LLM06 Excessive Agency", "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/"),
    "mcp": ("OWASP MCP Security Guide", "https://owasp.org/www-project-mcp-top-10/"),
}

def get_solution_html(rule_id: str, msg: str = "", cwe: str = "") -> str:
    """Nessus/Qualys-grade remediation with specific action + clickable MITRE CWE & OWASP/Vendor reference links."""
    base_sol = get_solution(rule_id, msg)
    links = []
    if cwe and cwe.upper().startswith("CWE-"):
        num = cwe.split("-", 1)[1]
        if num.isdigit():
            links.append(f"<a href='https://cwe.mitre.org/data/definitions/{num}.html' target='_blank' style='color:#0284c7'>{cwe}</a>")
    hay = f"{rule_id} {msg}".lower()
    for k, (lbl, url) in REFERENCE_LINKS.items():
        if k in hay:
            links.append(f"<a href='{url}' target='_blank' style='color:#0284c7'>{lbl}</a>")
            break
    ref_html = f"<br><small><b>Tham chiếu:</b> {' · '.join(links)}</small>" if links else ""
    return base_sol + ref_html

def get_secret_solution_html(rule_id: str, filepath: str = "") -> str:
    rid = (rule_id or "").lower()
    fp = (filepath or "").lower()
    if "private-key" in rid and any(x in fp for x in ("/etc/nginx", "/etc/haproxy", "/etc/ssl", "/etc/letsencrypt", ".pem", ".key")):
        sol = (
            "<b>1) Nếu là chứng chỉ SSL/TLS trên server:</b> Bảo vệ quyền file <code>chmod 600 &lt;file&gt; &amp;&amp; chown root:root &lt;file&gt;</code>, "
            "tuyệt đối không đưa vào Git; nếu đã hết hạn hãy xóa bỏ.<br>"
            "<b>2) Nếu khóa đã bị lộ ra ngoài/Git:</b> Thu hồi chứng chỉ (Revoke) và cấp phát cặp khóa mới ngay lập tức."
        )
    elif "github" in rid:
        sol = "Thu hồi ngay GitHub Token tại <i>Settings &rarr; Developer Settings &rarr; Personal Access Tokens</i>, tạo token quyền tối thiểu và lưu vào GitHub Secrets / biến môi trường."
    elif "aws" in rid:
        sol = "Vô hiệu hóa (Deactivate/Delete) ngay Access Key trong AWS IAM, rà soát AWS CloudTrail tìm truy cập bất thường và chuyển sang IAM Role."
    elif "jwt" in rid:
        sol = "Xoay vòng JWT Signing Secret (>= 256-bit ngẫu nhiên), thu hồi toàn bộ phiên cũ và nạp secret qua biến môi trường."
    else:
        sol = "Xoay vòng (rotate) mật khẩu/API key ngay trên hệ thống đích, gỡ khỏi mã nguồn/lịch sử Git (`git filter-repo`) và nạp qua `.env` hoặc Secrets Manager."
    return sol + "<br><small><b>Tham chiếu:</b> <a href='https://cwe.mitre.org/data/definitions/798.html' target='_blank' style='color:#0284c7'>CWE-798</a> · <a href='https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html' target='_blank' style='color:#0284c7'>OWASP Secrets Management</a></small>"

def get_trivy_solution_html(cve_id: str, pkg: str, fixed: str, target: str = "", primary_url: str = "") -> str:
    tgt_l = (target or "").lower()
    if fixed:
        if "[os packages]" in tgt_l or "ubuntu" in tgt_l or "debian" in tgt_l:
            cmd = f"<code>sudo apt-get update &amp;&amp; sudo apt-get install --only-upgrade {pkg}</code>"
        elif "package" in tgt_l or "yarn" in tgt_l or "pnpm" in tgt_l:
            cmd = f"<code>npm install {pkg}@{fixed}</code>"
        elif "requirements" in tgt_l or "pip" in tgt_l or "poetry" in tgt_l:
            cmd = f"<code>pip install \"{pkg}&gt;={fixed}\"</code>"
        elif "go.mod" in tgt_l:
            cmd = f"<code>go get {pkg}@v{fixed.lstrip('v')} &amp;&amp; go mod tidy</code>"
        elif ".csproj" in tgt_l or "packages.config" in tgt_l:
            cmd = f"<code>dotnet add package {pkg} --version {fixed}</code>"
        else:
            cmd = f"Nâng cấp <code>{pkg}</code> lên phiên bản <code>{fixed}</code>"
        sol = f"Nâng cấp gói <code>{pkg}</code> lên <code>{fixed}</code>: {cmd}"
    else:
        sol = f"Chưa có bản vá chính thức cho <code>{pkg}</code> — áp dụng biện pháp giảm thiểu (ModSecurity WAF / cô lập mạng) và theo dõi bản vá từ hãng."
    links = []
    if cve_id.upper().startswith("CVE-"):
        links.append(f"<a href='https://nvd.nist.gov/vuln/detail/{cve_id.upper()}' target='_blank' style='color:#0284c7'>NVD {cve_id.upper()}</a>")
    if primary_url and primary_url.startswith("http"):
        links.append(f"<a href='{primary_url}' target='_blank' style='color:#0284c7'>Vendor Advisory</a>")
    ref = f"<br><small><b>Tham chiếu:</b> {' · '.join(links)}</small>" if links else ""
    return sol + ref

CRITICAL_HINTS = ("sqli", "sql-injection", "rce", "command-injection", "deserialization", "binaryformatter", "docker-privileged", "docker-sock", "auth-bypass", "eval", "hardcoded-secret")
HIGH_HINTS = ("nosql", "ssrf", "path-traversal", "xxe", "jwt", "xss", "dangerouslysetinnerhtml", "tls-verify-disabled", "mongodb-no-auth", "postgres-trust", "mcp")
LOW_HINTS = ("info", "server-tokens", "header", "debug", "cookie-flag")

def normalize_severity(raw_sev: str, rule_id: str = "") -> str:
    s = (raw_sev or "").upper().strip()
    rid = (rule_id or "").lower()
    if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return s
    if any(k in rid for k in CRITICAL_HINTS):
        return "CRITICAL" if s == "ERROR" else "HIGH"
    if s == "ERROR":
        return "HIGH"
    if s == "WARNING":
        if any(k in rid for k in HIGH_HINTS):
            return "HIGH"
        return "MEDIUM"
    if any(k in rid for k in LOW_HINTS):
        return "LOW"
    return "LOW"

def get_solution(rule_id: str, msg: str = "") -> str:
    hay = f"{rule_id} {msg}".lower()
    for key, sol in REMEDIATION_KB.items():
        if key in hay:
            return sol
    return "Rà soát vị trí mã nguồn/cấu hình bị cảnh báo, áp dụng kiểm soát đầu vào (input validation), nguyên tắc quyền tối thiểu và kiểm thử lại sau khi vá."

def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return default

def _gather_report_data(report_dir: Path):
    gl = _load_json(report_dir / "01_gitleaks_secrets.json", [])
    if not isinstance(gl, list):
        gl = []
    sg_raw = _load_json(report_dir / "03_semgrep_sast.json", {})
    sg = sg_raw.get("results", []) if isinstance(sg_raw, dict) else []
    sg_norm = []
    for r in sg:
        cid = r.get("check_id", "").split(".")[-1]
        raw_s = r.get("extra", {}).get("severity", "INFO")
        msg = r.get("extra", {}).get("message", "")
        sev = normalize_severity(raw_s, cid)
        cwe, cvss = get_cwe_cvss(cid, sev)
        sg_norm.append({
            "severity": sev,
            "cwe": cwe,
            "cvss": cvss,
            "rule_id": cid,
            "path": r.get("path", "").replace("/mnt/f/ERP-Audit-Lab/repo/", "").replace("/mnt/f/ERP-Audit-Lab/targets/", ""),
            "line": r.get("start", {}).get("line", ""),
            "message": msg,
            "solution": get_solution(cid, msg),
            "solution_html": get_solution_html(cid, msg, cwe),
        })
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sg_norm.sort(key=lambda x: sev_order.get(x["severity"], 9))

    kev_set = enterprise_intel.load_cisa_kev_set()
    tr_raw = _load_json(report_dir / "02_trivy_sca.json", {})
    tr_items = []
    if isinstance(tr_raw, dict):
        for res in tr_raw.get("Results", []) or []:
            tgt = res.get("Target", "")
            for v in res.get("Vulnerabilities", []) or []:
                fixed = v.get("FixedVersion", "")
                pkg = v.get("PkgName", "")
                cid_v = v.get("VulnerabilityID", "")
                is_kev = enterprise_intel.is_cisa_kev(cid_v, kev_set)
                tr_items.append({
                    "severity": "CRITICAL" if is_kev else normalize_severity(v.get("Severity", "MEDIUM")),
                    "id": cid_v,
                    "is_kev": is_kev,
                    "target": f"{tgt} ({pkg})",
                    "installed": v.get("InstalledVersion", ""),
                    "fixed": fixed or "Theo dõi bản vá mới",
                    "desc": v.get("Title") or v.get("Description", "")[:180],
                    "solution": f"Nâng cấp gói `{pkg}` lên phiên bản `{fixed}` trở lên." if fixed else f"Áp dụng WAF/Virtual Patch và theo dõi bản vá cho `{pkg}`.",
                    "solution_html": get_trivy_solution_html(cid_v, pkg, fixed, tgt, v.get("PrimaryURL", "")),
                })
            for m in res.get("Misconfigurations", []) or []:
                m_sol = m.get("Resolution", "") or get_solution(m.get("ID", ""), m.get("Title", ""))
                m_url = m.get("PrimaryURL", "")
                m_ref = f"<br><small><b>Tham chiếu:</b> <a href='{m_url}' target='_blank' style='color:#0284c7'>{m.get('ID','Advisory')}</a></small>" if m_url else ""
                tr_items.append({
                    "severity": normalize_severity(m.get("Severity", "MEDIUM"), m.get("ID", "")),
                    "id": m.get("ID", ""),
                    "is_kev": False,
                    "target": tgt,
                    "installed": "-",
                    "fixed": m.get("Resolution", "")[:120],
                    "desc": m.get("Title", ""),
                    "solution": m_sol,
                    "solution_html": m_sol + m_ref,
                })
    tr_items.sort(key=lambda x: (0 if x.get("is_kev") else 1, sev_order.get(x["severity"], 9)))

    live_md_fp = report_dir / "00_live_system_audit.md"
    live_md_txt = live_md_fp.read_text(encoding="utf-8", errors="ignore") if live_md_fp.exists() else ""
    cis = enterprise_intel.compute_cis_scorecard(live_md_txt)
    attack_paths = enterprise_intel.detect_attack_paths(live_md_txt, sg_norm, gl, tr_items)
    delta = enterprise_intel.compute_scan_delta(report_dir.parent, report_dir)
    kev_count = sum(1 for x in tr_items if x.get("is_kev"))

    md_sections = []
    for fname, label in [
        ("05_ai_deep_audit_report.md", "Phân Tích Chuyên Sâu AI & Đề Xuất Khắc Phục"),
        ("06_patch_diff_audit.md", "Phân Tích So Sánh Bản Vá (Patch-Diff & Variant Analysis)"),
        ("07_web_surface_katana.md", "Khám Phá Bề Mặt Web & Nuclei Safe Scan"),
        ("00_live_system_audit.md", "Hiện Trạng Hệ Thống & Kiểm Toán CIS / MITRE"),
    ]:
        fp = report_dir / fname
        if fp.exists():
            md_sections.append((label, fp.read_text(encoding="utf-8", errors="ignore")))

    sast_crit = sum(1 for r in sg_norm if r["severity"] == "CRITICAL")
    sast_high = sum(1 for r in sg_norm if r["severity"] == "HIGH")
    sast_med = sum(1 for r in sg_norm if r["severity"] == "MEDIUM")
    sast_low = sum(1 for r in sg_norm if r["severity"] == "LOW")
    tr_crit = sum(1 for x in tr_items if x["severity"] in ("CRITICAL", "HIGH"))

    return {
        "folder": report_dir.name,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "gitleaks": gl,
        "semgrep": sg_norm,
        "trivy": tr_items,
        "md_sections": md_sections,
        "cis": cis,
        "attack_paths": attack_paths,
        "delta": delta,
        "kpi": {
            "sast_total": len(sg_norm),
            "sast_critical": sast_crit,
            "sast_high": sast_high,
            "sast_medium": sast_med,
            "sast_low": sast_low,
            "secrets_total": len(gl),
            "sca_total": len(tr_items),
            "sca_crit_high": tr_crit,
            "kev_count": kev_count,
        },
    }

def export_excel(report_dir: Path, out_xlsx: Path) -> Path:
    d = _gather_report_data(report_dir)
    wb = openpyxl.Workbook()

    hdr_fill = PatternFill("solid", fgColor="0F172A")
    hdr_font = Font(bold=True, color="FFFFFF", name="Calibri", size=11)
    title_font = Font(bold=True, color="0F172A", name="Calibri", size=15)
    crit_fill = PatternFill("solid", fgColor="FCA5A5")
    high_fill = PatternFill("solid", fgColor="FDBA74")
    med_fill = PatternFill("solid", fgColor="FEF08A")
    low_fill = PatternFill("solid", fgColor="BAE6FD")
    grn_fill = PatternFill("solid", fgColor="DCFCE7")
    sev_fills = {"CRITICAL": crit_fill, "HIGH": high_fill, "MEDIUM": med_fill, "LOW": low_fill}

    # Sheet 1: Tong_Quan
    ws1 = wb.active
    ws1.title = "Tong_Quan"
    ws1["A1"] = "BÁO CÁO KIỂM TOÁN BẢO MẬT HỆ THỐNG — AI SECURITY AUDIT v3.0"
    ws1["A1"].font = title_font
    ws1["A2"] = f"Đợt kiểm toán: {d['folder']}"
    ws1["A3"] = f"Ngày xuất báo cáo: {d['generated_at']}"

    ws1.append([])
    ws1.append(["Hạng mục kiểm toán", "Số lượng phát hiện", "Mức độ ưu tiên / Lộ trình xử lý"])
    for cell in ws1[5]:
        cell.fill = hdr_fill; cell.font = hdr_font

    rows_summary = [
        ("Lỗ hổng Mã nguồn SAST mức CRITICAL", d["kpi"]["sast_critical"], "P0 - Vá khẩn cấp trong 24h / Bật Virtual Patch WAF"),
        ("Lỗ hổng Mã nguồn SAST mức HIGH", d["kpi"]["sast_high"], "P0/P1 - Ưu tiên khắc phục trong 72h"),
        ("Lỗ hổng Mã nguồn SAST mức MEDIUM", d["kpi"]["sast_medium"], "P1 - Rà soát & khắc phục trong 7 ngày"),
        ("Lỗ hổng Mã nguồn SAST mức LOW", d["kpi"]["sast_low"], "P2 - Cải thiện hardening định kỳ"),
        ("Lộ thông tin nhạy cảm / Secrets (Gitleaks)", d["kpi"]["secrets_total"], "P0 - Xoay vòng mật khẩu/key ngay & gỡ khỏi mã nguồn"),
        ("Lỗ hổng Thư viện & Cấu hình (Trivy Critical/High)", d["kpi"]["sca_crit_high"], "P1 - Nâng cấp gói thư viện / vá cấu hình"),
    ]
    for r in rows_summary:
        ws1.append(list(r))
    for row in ws1.iter_rows(min_row=6, max_row=11):
        if row[1].value and int(row[1].value) > 0:
            row[1].fill = crit_fill if "P0" in str(row[2].value) else med_fill
        else:
            row[1].fill = grn_fill
    ws1.column_dimensions["A"].width = 48
    ws1.column_dimensions["B"].width = 22
    ws1.column_dimensions["C"].width = 50

    # Sheet 2: Lo_Hong_SAST (kèm CWE, CVSS & Giải pháp vá)
    ws2 = wb.create_sheet("Lo_Hong_SAST")
    ws2.append(["STT", "Mức độ", "CWE / CVSS", "Mã Rule", "Đường dẫn File", "Dòng", "Mô tả chi tiết", "Giải pháp khắc phục (Solution)"])
    for cell in ws2[1]:
        cell.fill = hdr_fill; cell.font = hdr_font
    for idx, r in enumerate(d["semgrep"], 1):
        ws2.append([idx, r["severity"], f"{r['cwe']} ({r['cvss']})", r["rule_id"], r["path"], r["line"], r["message"], r["solution"]])
        ws2.cell(idx + 1, 2).fill = sev_fills.get(r["severity"], low_fill)
        ws2.cell(idx + 1, 8).alignment = Alignment(wrap_text=True, vertical="top")
    ws2.auto_filter.ref = f"A1:H{max(1, len(d['semgrep'])+1)}"
    for col, w in [("A", 7), ("B", 13), ("C", 16), ("D", 32), ("E", 45), ("F", 8), ("G", 45), ("H", 58)]:
        ws2.column_dimensions[col].width = w

    # Sheet 3: Lo_Secret
    ws3 = wb.create_sheet("Lo_Secret")
    ws3.append(["STT", "Mức độ", "Loại Secret", "File", "Dòng", "Giá trị (Đã che)", "Giải pháp khắc phục (Solution)"])
    for cell in ws3[1]:
        cell.fill = hdr_fill; cell.font = hdr_font
    for idx, g in enumerate(d["gitleaks"], 1):
        fp = g.get("File", "").replace("/mnt/f/ERP-Audit-Lab/repo/", "").replace("/mnt/f/ERP-Audit-Lab/targets/", "")
        ws3.append([idx, "CRITICAL", g.get("RuleID", ""), fp, g.get("StartLine", ""), "***REDACTED***", REMEDIATION_KB["hardcoded"]])
        ws3.cell(idx + 1, 2).fill = crit_fill
    ws3.auto_filter.ref = f"A1:G{max(1, len(d['gitleaks'])+1)}"
    for col, w in [("A", 7), ("B", 12), ("C", 24), ("D", 50), ("E", 8), ("F", 20), ("G", 55)]:
        ws3.column_dimensions[col].width = w

    # Sheet 4: Lo_Hong_Thu_Vien
    ws4 = wb.create_sheet("Lo_Hong_Thu_Vien")
    ws4.append(["STT", "Mức độ", "CVE / Rule ID", "Gói / File", "Phiên bản hiện tại", "Phiên bản vá", "Mô tả", "Giải pháp khắc phục (Solution)"])
    for cell in ws4[1]:
        cell.fill = hdr_fill; cell.font = hdr_font
    for idx, t in enumerate(d["trivy"], 1):
        ws4.append([idx, t["severity"], t["id"], t["target"], t["installed"], t["fixed"], t["desc"], t["solution"]])
        ws4.cell(idx + 1, 2).fill = sev_fills.get(t["severity"], low_fill)
    ws4.auto_filter.ref = f"A1:H{max(1, len(d['trivy'])+1)}"
    for col, w in [("A", 7), ("B", 13), ("C", 22), ("D", 36), ("E", 16), ("F", 20), ("G", 45), ("H", 55)]:
        ws4.column_dimensions[col].width = w

    # Sheet 5: Phan_Tich_AI
    ws5 = wb.create_sheet("Phan_Tich_AI")
    ws5.append(["Chuyên mục", "Nội dung phân tích chi tiết"])
    for cell in ws5[1]:
        cell.fill = hdr_fill; cell.font = hdr_font
    for label, txt in d["md_sections"]:
        ws5.append([label, txt[:32000]])
    for row in ws5.iter_rows(min_row=2):
        row[1].alignment = Alignment(wrap_text=True, vertical="top")
    ws5.column_dimensions["A"].width = 36
    ws5.column_dimensions["B"].width = 110

    wb.save(str(out_xlsx))
    return out_xlsx

def _find_edge():
    for p in (
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ):
        if Path(p).exists():
            return p
    return shutil.which("msedge") or shutil.which("chrome")

def export_pdf(report_dir: Path, out_pdf: Path) -> Path:
    d = _gather_report_data(report_dir)
    sast_rows = "".join(
        f"<tr><td><span class='sev-{r['severity']}'>{r['severity']}</span><br><small><code>{r['cwe']} · {r['cvss']}</code></small></td>"
        f"<td><code>{r['rule_id']}</code></td>"
        f"<td><code>{r['path']}:{r['line']}</code></td>"
        f"<td>{r['message']}</td>"
        f"<td>{r.get('solution_html', r['solution'])}</td></tr>"
        for r in d["semgrep"][:60]
    ) or "<tr><td colspan='5'>Không phát hiện lỗ hổng SAST.</td></tr>"

    sec_rows = "".join(
        f"<tr><td><span class='sev-CRITICAL'>CRITICAL</span></td><td><code>{g.get('RuleID','')}</code></td>"
        f"<td><code>{g.get('File','').replace('/mnt/f/ERP-Audit-Lab/repo/','').replace('/mnt/f/ERP-Audit-Lab/targets/','')}</code></td>"
        f"<td>{g.get('StartLine','')}</td><td>{get_secret_solution_html(g.get('RuleID',''), g.get('File',''))}</td></tr>"
        for g in d["gitleaks"][:40]
    ) or "<tr><td colspan='5'>Không phát hiện lộ thông tin bí mật.</td></tr>"

    kev_tag = "<br><span class='sev-CRITICAL' style='margin-top:3px'>CISA KEV</span>"
    trivy_rows = "".join(
        f"<tr><td><span class='sev-{t['severity']}'>{t['severity']}</span>{kev_tag if t.get('is_kev') else ''}</td><td><code>{t['id']}</code></td>"
        f"<td><code>{t['target']}</code> ({t['installed']})</td><td><code>{t['fixed']}</code></td><td>{t.get('solution_html', t['solution'])}</td></tr>"
        for t in d["trivy"][:40]
    ) or "<tr><td colspan='5'>Không phát hiện lỗ hổng thư viện/cấu hình Trivy.</td></tr>"

    cis = d["cis"]
    cis_label = f"{cis['score']}/100 (Hạng {cis['grade']})" if cis.get("available") else "N/A"
    cis_html = ""
    if cis.get("available"):
        c_rows = "".join(
            f"<tr><td><code>{c['id']}</code></td><td>{c['name']}</td><td><b>{c['status']}</b></td><td>{c['detail']}</td></tr>"
            for c in cis["checks"]
        )
        cis_html = f"<h2>0A. Chấm Điểm Tuân Thủ CIS Security Scorecard ({cis_label})</h2><table><thead><tr><th style='width:14%'>Mã CIS</th><th style='width:34%'>Tiêu chí kiểm tra</th><th style='width:10%'>Kết quả</th><th>Chi tiết thực tế</th></tr></thead><tbody>{c_rows}</tbody></table>"

    ap_html = ""
    if d["attack_paths"]:
        ap_rows = "".join(
            f"<tr><td><span class='sev-{a['severity']}'>{a['severity']}</span></td><td><b>{a['title']}</b></td><td>{a['chain']}</td><td>{a['action']}</td></tr>"
            for a in d["attack_paths"]
        )
        ap_html = f"<h2>0B. Phân Tích Chuỗi Tấn Công Ghép (Wiz Attack Paths — {len(d['attack_paths'])} chuỗi)</h2><table><thead><tr><th style='width:10%'>Mức độ</th><th style='width:24%'>Kịch bản tấn công</th><th style='width:36%'>Chuỗi khai thác (Toxic Combination)</th><th>Hành động cắt đứt chuỗi</th></tr></thead><tbody>{ap_rows}</tbody></table>"

    delta_txt = ""
    if d["delta"].get("has_prev"):
        dt = d["delta"]
        delta_txt = f" &nbsp;|&nbsp; So với đợt trước (<code>{dt['prev_folder']}</code>): <b>+{dt['new_count']} lỗi mới</b>, <b>-{dt['fixed_count']} đã vá</b>"

    ai_html = ""
    for label, txt in d["md_sections"]:
        rendered = markdown.markdown(txt[:35000], extensions=["fenced_code", "tables"])
        ai_html += f"<div class='page-break'></div><h2>{label}</h2><div class='md-body'>{rendered}</div>"

    html = f"""<!doctype html>
<html lang="vi"><head><meta charset="utf-8">
<title>Báo Cáo Kiểm Toán Bảo Mật — {d['folder']}</title>
<style>
@page {{ size: A4; margin: 14mm 12mm; }}
body {{ font-family: 'Segoe UI', Arial, sans-serif; color: #0f172a; font-size: 10.5px; line-height: 1.5; margin: 0; }}
.cover {{ border-bottom: 3px solid #0284c7; padding-bottom: 10px; margin-bottom: 14px; }}
.cover h1 {{ margin: 0; font-size: 19px; color: #0f172a; }}
.cover .sub {{ color: #475569; font-size: 11.5px; margin-top: 4px; }}
.kpis {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 12px 0 16px; }}
.kpi {{ border: 1px solid #cbd5e1; border-radius: 8px; padding: 9px; background: #f8fafc; }}
.kpi .num {{ font-size: 20px; font-weight: 700; color: #0284c7; }}
.kpi .num.red {{ color: #dc2626; }} .kpi .num.org {{ color: #ea580c; }} .kpi .num.yel {{ color: #ca8a04; }}
.kpi .lbl {{ font-size: 9.5px; color: #475569; margin-top: 2px; }}
h2 {{ font-size: 13.5px; color: #0369a1; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; margin-top: 16px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 9.2px; table-layout: fixed; }}
thead {{ display: table-header-group; }}
tr {{ page-break-inside: avoid; }}
th, td {{ border: 1px solid #cbd5e1; padding: 6px 7px; text-align: left; vertical-align: top; overflow-wrap: anywhere; }}
th {{ background: #0f172a; color: #ffffff; font-weight: 600; }}
.sev-CRITICAL {{ background: #fee2e2; color: #991b1b; padding: 2px 6px; border-radius: 4px; font-weight: 700; display: inline-block; white-space: nowrap; font-size: 8.5px; }}
.sev-HIGH {{ background: #ffedd5; color: #c2410c; padding: 2px 6px; border-radius: 4px; font-weight: 700; display: inline-block; white-space: nowrap; font-size: 8.5px; }}
.sev-MEDIUM {{ background: #fef9c3; color: #a16207; padding: 2px 6px; border-radius: 4px; font-weight: 700; display: inline-block; white-space: nowrap; font-size: 8.5px; }}
.sev-LOW {{ background: #e0f2fe; color: #0369a1; padding: 2px 6px; border-radius: 4px; font-weight: 700; display: inline-block; white-space: nowrap; font-size: 8.5px; }}
a {{ color: #0284c7; text-decoration: none; }}
.plan-box {{ background: #f8fafc; border-left: 4px solid #0284c7; padding: 8px 12px; margin: 10px 0 14px; font-size: 10px; }}
code {{ background: #f1f5f9; padding: 1px 3px; border-radius: 3px; font-family: Consolas, monospace; font-size: 8.8px; overflow-wrap: anywhere; }}
pre {{ background: #f8fafc; border: 1px solid #e2e8f0; padding: 8px; border-radius: 6px; overflow: hidden; white-space: pre-wrap; font-size: 8.5px; }}
.page-break {{ page-break-before: always; }}
</style></head><body>
<div class="cover">
  <h1>BÁO CÁO KIỂM TOÁN BẢO MẬT HỆ THỐNG (AI SECURITY AUDIT v3.5)</h1>
  <div class="sub">Đợt kiểm toán: <b>{d['folder']}</b> &nbsp;|&nbsp; Ngày xuất: <b>{d['generated_at']}</b> &nbsp;|&nbsp; Điểm CIS: <b>{cis_label}</b>{delta_txt}</div>
</div>
<div class="kpis">
  <div class="kpi"><div class="num red">{d['kpi']['sast_critical']} / {d['kpi']['sast_high']}</div><div class="lbl">SAST Critical / High</div></div>
  <div class="kpi"><div class="num yel">{d['kpi']['sast_medium']} / {d['kpi']['sast_low']}</div><div class="lbl">SAST Medium / Low</div></div>
  <div class="kpi"><div class="num red">{d['kpi']['secrets_total']} / {d['kpi']['kev_count']}</div><div class="lbl">Lộ Secret / CISA KEV CVE</div></div>
  <div class="kpi"><div class="num org">{cis_label}</div><div class="lbl">CIS Score · {len(d['attack_paths'])} Attack Paths</div></div>
</div>
<div class="plan-box">
  <b>Lộ Trình Khắc Phục Ưu Tiên (Remediation Roadmap):</b><br>
  • <b>P0 (Khẩn cấp 24 giờ):</b> Xử lý toàn bộ lỗi <b>CRITICAL</b>, <b>CISA KEV CVE</b> &amp; <b>Lộ Secret</b> (xoay vòng mật khẩu/key, bật ModSecurity Virtual Patch chặn tạm trên WAF).<br>
  • <b>P1 (Trong 7 ngày):</b> Cắt đứt các chuỗi <b>Attack Path</b>, vá lỗi <b>HIGH / MEDIUM</b>, gỡ <code>network_mode: host</code>, nâng cấp gói thư viện có CVE.<br>
  • <b>P2 (Định kỳ 30 ngày):</b> Khắc phục các tiêu chí CIS <b>FAIL / WARN</b> để nâng Điểm An Toàn lên <b>&ge; 90/100 (Hạng A)</b>.
</div>
{cis_html}
{ap_html}
<h2>1. Tổng Hợp Phát Hiện Mã Nguồn &amp; Giải Pháp Vá (Semgrep SAST)</h2>
<table><thead><tr><th style="width:13%">Mức độ / CWE</th><th style="width:17%">Mã Rule</th><th style="width:20%">Vị trí</th><th style="width:20%">Mô tả</th><th style="width:30%">Giải pháp khắc phục &amp; Tham chiếu</th></tr></thead><tbody>{sast_rows}</tbody></table>
<h2>2. Phát Hiện Thông Tin Nhạy Cảm &amp; Giải Pháp (Gitleaks — Đã Che Giá Trị)</h2>
<table><thead><tr><th style="width:12%">Mức độ</th><th style="width:14%">Loại Secret</th><th style="width:26%">File</th><th style="width:7%">Dòng</th><th style="width:41%">Giải pháp khắc phục &amp; Tham chiếu</th></tr></thead><tbody>{sec_rows}</tbody></table>
<h2>3. Lỗ Hổng Thư Viện, Gói OS &amp; Sai Cấu Hình (Trivy SCA)</h2>
<table><thead><tr><th style="width:13%">Mức độ</th><th style="width:15%">CVE / Mã lỗi</th><th style="width:22%">Gói / Tệp</th><th style="width:14%">Bản vá</th><th style="width:36%">Giải pháp khắc phục &amp; Tham chiếu</th></tr></thead><tbody>{trivy_rows}</tbody></table>
{ai_html}
</body></html>"""

    tmp_html = out_pdf.with_suffix(".tmp.html")
    tmp_html.write_text(html, encoding="utf-8")
    browser = _find_edge()
    if not browser:
        raise RuntimeError("Microsoft Edge/Chrome not found for PDF rendering")
    try:
        subprocess.run(
            [browser, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-pdf-header-footer",
             f"--print-to-pdf={out_pdf}", tmp_html.as_uri()],
            check=True, timeout=60, capture_output=True
        )
    finally:
        if tmp_html.exists():
            tmp_html.unlink(missing_ok=True)
    return out_pdf
