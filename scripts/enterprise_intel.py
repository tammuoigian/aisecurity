import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

# Curated high-impact CISA KEV (Known Exploited Vulnerabilities) catalog (offline-first, zero external dependency)
CISA_KEV_BUILTIN = {
    "CVE-2021-44228", "CVE-2021-45046", "CVE-2022-22965", "CVE-2023-23397", "CVE-2023-34362",
    "CVE-2023-38545", "CVE-2023-44487", "CVE-2023-46604", "CVE-2023-4966", "CVE-2024-21626",
    "CVE-2024-21762", "CVE-2024-23897", "CVE-2024-27198", "CVE-2024-3094", "CVE-2024-3400",
    "CVE-2024-4577", "CVE-2024-6387", "CVE-2024-21413", "CVE-2024-38063", "CVE-2024-38077",
    "CVE-2024-43451", "CVE-2024-49112", "CVE-2025-29927", "CVE-2025-24813", "CVE-2025-32433",
    "CVE-2025-21298", "CVE-2025-55182", "CVE-2021-34527", "CVE-2020-1472", "CVE-2019-0708",
    "CVE-2017-0144", "CVE-2022-0847", "CVE-2021-4034", "CVE-2022-26134", "CVE-2023-22515",
    "CVE-2023-20198", "CVE-2024-0012", "CVE-2024-9474", "CVE-2024-50623", "CVE-2025-0282",
}

def load_cisa_kev_set(web_dir: Path = Path(r"F:\ERP-Audit-Lab\web")) -> set:
    kev = set(CISA_KEV_BUILTIN)
    fp = web_dir / "cisa_kev.json"
    if fp.exists():
        try:
            data = json.loads(fp.read_text(encoding="utf-8", errors="ignore"))
            for v in data.get("vulnerabilities", []):
                if v.get("cveID"):
                    kev.add(v["cveID"].upper())
        except Exception:
            pass
    return kev

def is_cisa_kev(cve_id: str, kev_set: set = None) -> bool:
    if not cve_id:
        return False
    s = kev_set if kev_set is not None else CISA_KEV_BUILTIN
    return cve_id.upper().strip() in s

def finding_fingerprint(kind: str, rule_or_cve: str, location: str) -> str:
    raw = f"{kind}|{rule_or_cve}|{location}".lower().strip()
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]

def load_triage(web_dir: Path = Path(r"F:\ERP-Audit-Lab\web")) -> dict:
    fp = web_dir / "finding_triage.json"
    if not fp.exists():
        return {}
    try:
        return json.loads(fp.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}

def save_triage(data: dict, web_dir: Path = Path(r"F:\ERP-Audit-Lab\web")):
    fp = web_dir / "finding_triage.json"
    fp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

# ---------------------------------------------------------------------------
# Module 1: Lynis / CIS-CAT / HardeningKitty Compliance Scorecard (0-100)
# ---------------------------------------------------------------------------
def compute_cis_scorecard(live_md: str) -> dict:
    if not live_md or len(live_md.strip()) < 40:
        return {"available": False, "score": None, "grade": "N/A", "os": "unknown", "checks": []}

    low = live_md.lower()
    is_win = ("windows" in low and ("hotfix" in low or "runasppl" in low or "smbv1" in low or "get-netfirewall" in low or "defender" in low))
    checks = []

    def add(cid, name, status, weight, detail):
        checks.append({"id": cid, "name": name, "status": status, "weight": weight, "detail": detail})

    if is_win:
        # Windows CIS & HardeningKitty checks
        fw_off = bool(re.search(r"(Domain|Private|Public)\s+False", live_md, re.I))
        add("CIS-WIN-01", "Windows Firewall (Tất cả Profile đang bật)", "FAIL" if fw_off else "PASS", 15,
            "Có ít nhất 1 Firewall Profile đang TẮT (False)" if fw_off else "Các profile Firewall đang bật")

        def_off = bool(re.search(r"RealTimeProtectionEnabled\s*:\s*False", live_md, re.I))
        add("CIS-WIN-02", "Windows Defender Real-Time Protection", "FAIL" if def_off else "PASS", 10,
            "Real-Time Protection đang tắt" if def_off else "Defender Real-Time đang hoạt động")

        nla_ok = bool(re.search(r"RDP NLA.*`1`", live_md)) or bool(re.search(r"RDP_NLA=1", live_md))
        add("CIS-WIN-03", "RDP bắt buộc NLA (Network Level Auth)", "PASS" if nla_ok else "WARN", 10,
            "NLA đã bật (=1)" if nla_ok else "Chưa xác nhận bật NLA (=1)")

        smb1_bad = bool(re.search(r"SMBv1.*`True`", live_md, re.I)) or bool(re.search(r"SMBv1_Enabled=True", live_md, re.I))
        add("CIS-WIN-04", "Vô hiệu hóa giao thức SMBv1 lỗi thời", "FAIL" if smb1_bad else "PASS", 10,
            "SMBv1 đang BẬT (nguy cơ WannaCry/EternalBlue)" if smb1_bad else "SMBv1 đã tắt")

        ppl_ok = bool(re.search(r"RunAsPPL.*`1`", live_md))
        add("CIS-WIN-05", "LSA Protection (RunAsPPL chống dump mật khẩu)", "PASS" if ppl_ok else "WARN", 10,
            "RunAsPPL = 1" if ppl_ok else "Chưa bật RunAsPPL = 1")

        wdig_bad = bool(re.search(r"WDigest.*`1`", live_md))
        add("CIS-WIN-06", "Tắt WDigest lưu mật khẩu dạng rõ", "FAIL" if wdig_bad else "PASS", 10,
            "UseLogonCredential = 1 (nguy hiểm)" if wdig_bad else "WDigest plaintext đã tắt")

        uac_ok = bool(re.search(r"EnableLUA.*`1`", live_md))
        add("CIS-WIN-07", "Bật User Account Control (UAC)", "PASS" if uac_ok else "WARN", 10,
            "EnableLUA = 1" if uac_ok else "Chưa xác nhận EnableLUA = 1")

        pslog_ok = bool(re.search(r"ScriptBlock Logging.*`1`", live_md))
        add("CIS-WIN-08", "PowerShell ScriptBlock Logging (MITRE Audit)", "PASS" if pslog_ok else "WARN", 5,
            "ScriptBlock Logging đã bật" if pslog_ok else "Khuyến nghị bật ScriptBlock Logging = 1")

        unq_match = re.search(r"\[Unquoted Service Paths\]([\s\S]*?)\[Non-Microsoft", live_md)
        has_unq = bool(unq_match and re.search(r"\.exe", unq_match.group(1), re.I))
        add("MITRE-WIN-09", "Không có lỗi Unquoted Service Path", "FAIL" if has_unq else "PASS", 10,
            "Phát hiện Service có Unquoted Service Path" if has_unq else "Không phát hiện Unquoted Service Path")

        ssl_warn = "SSL_EXPIRING_SOON" in live_md or "SSL_EXPIRED" in live_md
        add("SSL-WIN-10", "Chứng chỉ SSL/TLS còn hạn > 30 ngày", "FAIL" if ssl_warn else "PASS", 10,
            "Có chứng chỉ SSL đã hết hạn hoặc sắp hết hạn < 30 ngày" if ssl_warn else "Không phát hiện chứng chỉ SSL sắp hết hạn")
    else:
        # Linux CIS & Lynis checks
        ufw_ok = bool(re.search(r"Status:\s*active", live_md, re.I))
        add("CIS-LNX-01", "Tường lửa UFW đang kích hoạt", "PASS" if ufw_ok else "FAIL", 15,
            "UFW Status: active" if ufw_ok else "UFW chưa bật hoặc inactive")

        root_yes = bool(re.search(r"PermitRootLogin\s+yes\b", live_md, re.I))
        add("CIS-LNX-02", "SSH cấm đăng nhập Root bằng mật khẩu", "FAIL" if root_yes else "PASS", 12,
            "PermitRootLogin yes (nguy cơ brute-force root)" if root_yes else "Không bật PermitRootLogin yes")

        pass_yes = bool(re.search(r"PasswordAuthentication\s+yes\b", live_md, re.I))
        add("CIS-LNX-03", "SSH ưu tiên SSH Key (tắt PasswordAuthentication)", "WARN" if pass_yes else "PASS", 8,
            "PasswordAuthentication yes" if pass_yes else "PasswordAuthentication không mở rộng")

        aslr_ok = bool(re.search(r"ASLR[^0-9]*2\b", live_md))
        add("CIS-LNX-04", "Kernel ASLR mức đầy đủ (randomize_va_space = 2)", "PASS" if aslr_ok else "WARN", 8,
            "ASLR = 2" if aslr_ok else "ASLR chưa xác nhận = 2")

        sync_ok = bool(re.search(r"SYN[^0-9]*1\b", live_md, re.I))
        add("CIS-LNX-05", "Bảo vệ chống SYN Flood (tcp_syncookies = 1)", "PASS" if sync_ok else "WARN", 7,
            "tcp_syncookies = 1" if sync_ok else "Chưa xác nhận tcp_syncookies = 1")

        reboot_req = "CẦN REBOOT (YES)" in live_md or "REBOOT_REQUIRED: YES" in live_md
        add("CIS-LNX-06", "Trạng thái áp dụng bản vá Kernel (Reboot)", "WARN" if reboot_req else "PASS", 8,
            "Hệ thống có bản vá Kernel đang chờ Reboot" if reboot_req else "Không cần reboot")

        nopass = bool(re.search(r"NOPASSWD:\s*ALL", live_md))
        add("MITRE-LNX-07", "Không cấp quyền sudo NOPASSWD: ALL tùy tiện", "WARN" if nopass else "PASS", 8,
            "Phát hiện cấu hình NOPASSWD: ALL trong sudoers" if nopass else "Không có NOPASSWD: ALL")

        priv_dk = "Privileged=true" in live_md
        add("CIS-DKR-08", "Không chạy Docker Container chế độ Privileged", "FAIL" if priv_dk else "PASS", 12,
            "Phát hiện container chạy Privileged=true" if priv_dk else "Không có container Privileged")

        sock_dk = "/var/run/docker.sock" in live_md
        add("CIS-DKR-09", "Không mount docker.sock vào Container ứng dụng", "FAIL" if sock_dk else "PASS", 12,
            "Phát hiện mount /var/run/docker.sock" if sock_dk else "Không mount docker.sock")

        ssl_warn = "SSL_EXPIRING_SOON" in live_md or "SSL_EXPIRED" in live_md
        add("SSL-LNX-10", "Chứng chỉ SSL/TLS còn hạn > 30 ngày", "FAIL" if ssl_warn else "PASS", 10,
            "Có chứng chỉ SSL đã hết hạn hoặc sắp hết hạn < 30 ngày" if ssl_warn else "Các chứng chỉ SSL còn hạn an toàn")

    total_w = sum(c["weight"] for c in checks) or 100
    earned = sum(c["weight"] if c["status"] == "PASS" else (c["weight"] * 0.5 if c["status"] == "WARN" else 0) for c in checks)
    score = int(round((earned / total_w) * 100))
    grade = "A" if score >= 90 else ("B" if score >= 80 else ("C" if score >= 65 else ("D" if score >= 50 else "F")))
    return {
        "available": True, "score": score, "grade": grade,
        "os": "windows" if is_win else "linux",
        "pass_count": sum(1 for c in checks if c["status"] == "PASS"),
        "fail_count": sum(1 for c in checks if c["status"] == "FAIL"),
        "warn_count": sum(1 for c in checks if c["status"] == "WARN"),
        "checks": checks,
    }

# ---------------------------------------------------------------------------
# Module 4: Wiz-style Attack Path & Toxic Combination Engine
# ---------------------------------------------------------------------------
def detect_attack_paths(live_md: str, semgrep_norm: list, gitleaks: list, trivy_items: list) -> list:
    paths = []
    has_public_web = bool(re.search(r"(0\.0\.0\.0|\*|::):(80|443|8080|8081|8083|8085|3000)\b", live_md))
    has_public_db = bool(re.search(r"(0\.0\.0\.0|\*|::):(1433|3306|5432|27017|6379)\b", live_md))
    crit_sast = [r for r in semgrep_norm if r.get("severity") == "CRITICAL"]
    high_sast = [r for r in semgrep_norm if r.get("severity") == "HIGH"]
    kev_cves = [t for t in trivy_items if t.get("is_kev")]
    has_docker_risk = ("Privileged=true" in live_md or "/var/run/docker.sock" in live_md or "NetMode=host" in live_md or any("docker-network-host" in r.get("rule_id", "") for r in semgrep_norm))
    has_weak_auth = bool(re.search(r"PermitRootLogin\s+yes|PasswordAuthentication\s+yes|WDigest.*`1`", live_md, re.I))
    has_ioc = bool(re.search(r"IOC_SUSPICIOUS_PROC|Unquoted Service Paths[\s\S]{1,120}\.exe|NOPASSWD:\s*ALL", live_md))

    if (crit_sast or kev_cves) and (has_public_web or not live_md):
        ev = []
        if crit_sast: ev.append(f"{len(crit_sast)} lỗi SAST CRITICAL ({crit_sast[0]['rule_id']})")
        if kev_cves: ev.append(f"{len(kev_cves)} CVE thuộc danh sách CISA KEV ({kev_cves[0]['id']})")
        paths.append({
            "severity": "CRITICAL",
            "title": "Đường tấn công xâm nhập từ ngoài vào ứng dụng (External App Takeover)",
            "chain": "Internet / Exposed Web Port -> " + " + ".join(ev) + " -> Chiếm quyền thực thi / Đọc dữ liệu DB",
            "action": "Ưu tiên P0: Bật ModSecurity Virtual Patch chặn ngay mẫu khai thác và vá lỗ hổng mã nguồn / nâng cấp gói KEV trong 24h.",
        })

    if has_docker_risk and (gitleaks or crit_sast or high_sast):
        paths.append({
            "severity": "CRITICAL",
            "title": "Chuỗi thoát Container leo thang lên Root máy chủ (Container Breakout)",
            "chain": f"Lỗ hổng ứng dụng / Lộ {len(gitleaks)} Secret -> Container dùng network_mode:host / Privileged / docker.sock -> Kiểm soát toàn bộ Host",
            "action": "Gỡ network_mode: host, tắt privileged, không mount docker.sock và xoay vòng toàn bộ secret bị lộ.",
        })

    if gitleaks and (has_weak_auth or has_public_db or has_public_web):
        paths.append({
            "severity": "HIGH",
            "title": "Lộ thông tin xác thực dẫn tới truy cập trái phép (Credential Harvesting -> Lateral Movement)",
            "chain": f"Lộ {len(gitleaks)} Secret/Key trong mã nguồn -> Kết hợp SSH Password / Cổng dịch vụ mở -> Đăng nhập trái phép hệ thống",
            "action": "Xoay vòng (rotate) ngay toàn bộ mật khẩu/API key bị lộ, chuyển sang Secrets Manager và tắt SSH PasswordAuthentication.",
        })

    if has_public_db:
        paths.append({
            "severity": "HIGH",
            "title": "Cơ sở dữ liệu mở lắng nghe 0.0.0.0 (Direct Database Exposure)",
            "chain": "Cổng DB (1433/3306/5432/27017/6379) lắng nghe 0.0.0.0 -> Nguy cơ Brute-force hoặc khai thác CVE trực tiếp vào DB",
            "action": "Bind DB về 127.0.0.1 hoặc chỉ mở Firewall cho IP nội bộ của máy chủ APP/API.",
        })

    if has_ioc:
        paths.append({
            "severity": "HIGH",
            "title": "Dấu hiệu Leo thang đặc quyền / Persistence (MITRE ATT&CK)",
            "chain": "Phát hiện tiến trình bất thường (/tmp, AppData) hoặc Unquoted Service Path / sudoers NOPASSWD: ALL",
            "action": "Rà soát ngay danh sách tiến trình & phân quyền sudo/Service trong mục Threat Hunting của báo cáo.",
        })

    return paths

# ---------------------------------------------------------------------------
# Module 5: DefectDojo-style Scan-to-Scan Delta Tracking
# ---------------------------------------------------------------------------
def _extract_fps_from_folder(folder: Path) -> set:
    fps = set()
    try:
        sg = json.loads((folder / "03_semgrep_sast.json").read_text("utf-8", "ignore")).get("results", [])
        for r in sg:
            fps.add(finding_fingerprint("sast", r.get("check_id", "").split(".")[-1], f"{r.get('path','')}:{r.get('start',{}).get('line','')}"))
    except Exception:
        pass
    try:
        gl = json.loads((folder / "01_gitleaks_secrets.json").read_text("utf-8", "ignore"))
        if isinstance(gl, list):
            for g in gl:
                fps.add(finding_fingerprint("secret", g.get("RuleID", ""), f"{g.get('File','')}:{g.get('StartLine','')}"))
    except Exception:
        pass
    try:
        tr = json.loads((folder / "02_trivy_sca.json").read_text("utf-8", "ignore"))
        for res in tr.get("Results", []) or []:
            for v in res.get("Vulnerabilities", []) or []:
                fps.add(finding_fingerprint("trivy", v.get("VulnerabilityID", ""), f"{res.get('Target','')}:{v.get('PkgName','')}"))
    except Exception:
        pass
    return fps

def compute_scan_delta(reports_root: Path, current_folder: Path) -> dict:
    # Folder naming: YYYY-MM-DD_HHMM_<project_id>
    m = re.match(r"^\d{4}-\d{2}-\d{2}_\d{4}_(.+)$", current_folder.name)
    if not m or not reports_root.exists():
        return {"has_prev": False}
    suffix = m.group(1)
    siblings = sorted(
        [d for d in reports_root.iterdir() if d.is_dir() and d.name.endswith("_" + suffix) and d.name < current_folder.name],
        key=lambda x: x.name, reverse=True
    )
    if not siblings:
        return {"has_prev": False}
    prev_folder = siblings[0]
    cur_fps = _extract_fps_from_folder(current_folder)
    prev_fps = _extract_fps_from_folder(prev_folder)
    return {
        "has_prev": True,
        "prev_folder": prev_folder.name,
        "new_count": len(cur_fps - prev_fps),
        "fixed_count": len(prev_fps - cur_fps),
        "persisting_count": len(cur_fps & prev_fps),
    }
