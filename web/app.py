import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import tarfile
import threading
import time
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional

import markdown
import paramiko
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse
import sys as _sys
_sys.path.insert(0, r"F:\ERP-Audit-Lab\scripts")
import report_exporter
from itsdangerous import BadSignature, URLSafeTimedSerializer

LAB_ROOT = Path(r"F:\ERP-Audit-Lab")
WEB_DIR = LAB_ROOT / "web"
KEYS_DIR = WEB_DIR / "keys"
TARGETS_DIR = LAB_ROOT / "targets"
REPORTS_ROOT = LAB_ROOT / "reports"
PROJECTS_FILE = WEB_DIR / "projects.json"
SECRETS_FILE = WEB_DIR / "project_secrets.json"
AUTH_FILE = WEB_DIR / "auth.json"
JOBS_DIR = WEB_DIR / "jobs"
for _d in (KEYS_DIR, TARGETS_DIR, JOBS_DIR, REPORTS_ROOT):
    _d.mkdir(parents=True, exist_ok=True)

KEY_PRIV = KEYS_DIR / "ace_audit_ed25519"
KEY_PUB = KEYS_DIR / "ace_audit_ed25519.pub"
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
WIN_PY = r"F:\ERP-Audit-Lab\web-venv\Scripts\python.exe"

ALL_STACKS = [
    "owasp", "api", "dotnet", "mssql", "nginx", "haproxy", "ubuntu",
    "postgresql", "mysql", "mongodb", "docker", "mcp", "nextjs", "nodejs", "wordpress"
]

def ensure_ssh_key():
    if not KEY_PRIV.exists():
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "ai-security-audit@local", "-f", str(KEY_PRIV)],
            check=True, capture_output=True
        )
    return KEY_PUB.read_text(encoding="utf-8").strip()

PUB_KEY_STR = ensure_ssh_key()

def load_auth():
    cfg = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
    if "collector_token" not in cfg:
        cfg["collector_token"] = secrets.token_hex(20)
        AUTH_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return cfg

AUTH_CFG = load_auth()
SERIALIZER = URLSafeTimedSerializer(AUTH_CFG["session_secret"])

def verify_password(username: str, password: str) -> bool:
    if username != AUTH_CFG["username"]:
        return False
    salt = bytes.fromhex(AUTH_CFG["salt"])
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000).hex()
    return hmac.compare_digest(dk, AUTH_CFG["password_hash"])

def get_current_user(request: Request) -> Optional[str]:
    tok = request.cookies.get("ace_audit_session")
    if not tok:
        return None
    try:
        return SERIALIZER.loads(tok, max_age=86400 * 7).get("u")
    except BadSignature:
        return None

def require_auth(request: Request):
    u = get_current_user(request)
    if not u:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return u

def verify_collector_token(token: str):
    if not token or not hmac.compare_digest(token, AUTH_CFG["collector_token"]):
        raise HTTPException(status_code=403, detail="Invalid collector token")

def load_secrets():
    return json.loads(SECRETS_FILE.read_text(encoding="utf-8")) if SECRETS_FILE.exists() else {}

def save_secrets(data):
    SECRETS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")

def load_projects():
    if not PROJECTS_FILE.exists():
        default = [{
            "id": "default-local-repo",
            "name": "Default Local Repository",
            "mode": "local",
            "path": r"F:\ERP-Audit-Lab\repo",
            "stacks": ["owasp", "api", "dotnet", "mssql", "nginx", "ubuntu"],
            "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
        }]
        PROJECTS_FILE.write_text(json.dumps(default, indent=2, ensure_ascii=False), encoding="utf-8")
        return default
    projs = json.loads(PROJECTS_FILE.read_text(encoding="utf-8"))
    for p in projs:
        p.setdefault("mode", "local")
    return projs

def save_projects(projs):
    PROJECTS_FILE.write_text(json.dumps(projs, indent=2, ensure_ascii=False), encoding="utf-8")

def win_to_wsl(win_path: str) -> str:
    p = win_path.replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", p)
    return f"/mnt/{m.group(1).lower()}/{m.group(2)}" if m else p

def load_pkey_any(key_file: str):
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key_file(key_file)
        except Exception:
            continue
    raise ValueError("Unsupported private key format")

JOBS_HISTORY_FILE = JOBS_DIR / "jobs_history.json"
JOB_PROCS = {}

def load_jobs_store():
    if not JOBS_HISTORY_FILE.exists():
        return {}
    try:
        data = json.loads(JOBS_HISTORY_FILE.read_text(encoding="utf-8"))
        changed = False
        for j in data.values():
            if j.get("status") == "RUNNING":
                j["status"] = "INTERRUPTED"
                j["finished"] = j.get("finished") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                changed = True
        if changed:
            JOBS_HISTORY_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return data
    except Exception:
        return {}

def save_jobs_store():
    try:
        JOBS_HISTORY_FILE.write_text(json.dumps(JOBS, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

JOBS = load_jobs_store()

def start_job(title: str, steps: list):
    jid = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    log_path = JOBS_DIR / f"{jid}.log"
    now_ts = time.time()
    total_steps = max(1, len(steps))
    JOBS[jid] = {
        "id": jid, "title": title, "status": "RUNNING",
        "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "started_ts": now_ts, "finished": "", "finished_ts": None,
        "progress": 5, "step_label": steps[0][0] if steps else "",
        "total_steps": total_steps,
        "log_file": str(log_path), "rc": None, "steps": steps,
    }
    save_jobs_store()
    def runner():
        rc = 0
        with open(log_path, "w", encoding="utf-8", errors="replace") as lf:
            lf.write(f"[{datetime.now().strftime('%H:%M:%S')}] START: {title}\n")
            lf.flush()
            try:
                for idx, (step_name, cmd_list) in enumerate(steps):
                    base = int((idx / total_steps) * 95)
                    span = max(5, int((1 / total_steps) * 95))
                    JOBS[jid]["step_label"] = f"Bước {idx+1}/{total_steps}: {step_name}"
                    JOBS[jid]["progress"] = min(97, max(JOBS[jid].get("progress", 5), base + 3))
                    lf.write(f"\n>>> {step_name}\n")
                    lf.flush()
                    if JOBS[jid].get("stop_requested"):
                        rc = -1
                        break
                    proc = subprocess.Popen(
                        cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, encoding="utf-8", errors="replace"
                    )
                    JOB_PROCS[jid] = proc
                    for line in proc.stdout:
                        lf.write(line)
                        lf.flush()
                        m = re.search(r"\[(\d+)/(\d+)\]", line)
                        if m:
                            si, sn = int(m.group(1)), max(1, int(m.group(2)))
                            sub_p = base + int(((si - 0.35) / sn) * span)
                            JOBS[jid]["progress"] = min(98, max(JOBS[jid]["progress"], sub_p))
                        elif "AI-Auditor" in line or "Playbook" in line or "Critic" in line:
                            JOBS[jid]["progress"] = min(base + span - 2, JOBS[jid]["progress"] + 3)
                    rc = proc.wait()
                    if rc != 0:
                        lf.write(f"\n[STOPPED] Step '{step_name}' exited with code {rc}\n")
                        break
                    JOBS[jid]["progress"] = min(98, base + span)
                JOBS[jid]["rc"] = rc
                JOBS[jid]["status"] = "COMPLETED" if rc == 0 else "FAILED"
                if rc == 0:
                    JOBS[jid]["progress"] = 100
                    JOBS[jid]["step_label"] = "Hoàn tất"
                lf.write(f"\n[{datetime.now().strftime('%H:%M:%S')}] FINAL EXIT CODE: {rc}\n")
            except Exception as ex:
                JOBS[jid]["status"] = "FAILED"
                lf.write(f"\nERROR: {ex}\n")
            JOBS[jid]["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            JOBS[jid]["finished_ts"] = time.time()
            save_jobs_store()
    threading.Thread(target=runner, daemon=True).start()
    return jid

app = FastAPI(title="AI Security Audit Platform v3.0")

LOGIN_HTML = """<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><title>AI Security Audit v3.0</title>
<style>
body{margin:0;background:#0b1120;color:#e2e8f0;font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh}
.card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:32px;width:360px;box-shadow:0 20px 50px rgba(0,0,0,.5)}
h1{font-size:20px;margin:0 0 8px;color:#38bdf8} p{color:#94a3b8;font-size:13px;margin:0 0 20px}
label{display:block;font-size:12px;color:#94a3b8;margin:12px 0 4px}
input{width:100%;box-sizing:border-box;padding:10px 12px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#f8fafc;font-size:14px}
button{margin-top:20px;width:100%;padding:11px;background:#0284c7;border:none;border-radius:8px;color:#fff;font-weight:600;cursor:pointer;font-size:14px}
.err{color:#f87171;font-size:13px;margin-top:10px}
</style></head><body><div class="card">
<h1>AI Security Audit v3.0</h1>
<p>15 Ecosystems · Agentless SSH · 1-Line Push Collector (Port 2810)</p>
<form method="post" action="/login">
<label>Username</label><input name="username" value="admin" required>
<label>Password</label><input name="password" type="password" required autofocus>
<button type="submit">Đăng nhập</button>{ERR}
</form></div></body></html>"""

MAIN_HTML = r"""<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><title>AI Security Audit v3.0 — Port 2810</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0b1120;color:#e2e8f0;font-family:system-ui,-apple-system,sans-serif;font-size:14px}
header{background:#0f172a;border-bottom:1px solid #1e293b;padding:14px 24px;display:flex;align-items:center;justify-content:space-between}
header h1{margin:0;font-size:18px;color:#38bdf8}
.badge{display:inline-block;padding:3px 9px;border-radius:999px;font-size:11px;font-weight:600;background:#1e293b;color:#38bdf8;margin-left:6px}
.badge-ssh{background:#064e3b;color:#34d399} .badge-local{background:#1e3a8a;color:#93c5fd} .badge-push{background:#581c87;color:#d8b4fe}
.nav{display:flex;gap:6px;padding:10px 24px;background:#0f172a;border-bottom:1px solid #1e293b;flex-wrap:wrap}
.nav button{background:#1e293b;color:#cbd5e1;border:1px solid #334155;padding:6px 12px;border-radius:7px;cursor:pointer;font-weight:600;font-size:12.5px;transition:all .15s}
.nav button.active{background:#0284c7;color:#fff;border-color:#0284c7}
.wrap{max-width:1380px;margin:20px auto;padding:0 24px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px;margin-bottom:20px}
.card{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:18px;margin-bottom:18px}
.card h2{margin:0 0 12px;font-size:16px;color:#f8fafc}
.kpi{font-size:28px;font-weight:700;color:#38bdf8}
.kpi-lbl{font-size:12px;color:#94a3b8;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:10px;border-bottom:1px solid #1f2937;text-align:left;vertical-align:top}
th{color:#94a3b8;font-weight:600}
.btn{padding:6px 11px;border-radius:6px;border:none;cursor:pointer;font-weight:600;font-size:12px;margin:2px 4px 2px 0}
.btn-primary{background:#0284c7;color:#fff} .btn-ai{background:#7c3aed;color:#fff}
.btn-green{background:#059669;color:#fff} .btn-danger{background:#dc2626;color:#fff} .btn-gray{background:#334155;color:#e2e8f0}
input,select,textarea{background:#0f172a;color:#f8fafc;border:1px solid #334155;border-radius:6px;padding:8px 10px;font-size:13px;width:100%}
label{display:block;font-size:12px;color:#94a3b8;margin-bottom:4px}
textarea{font-family:ui-monospace,Consolas,monospace;min-height:110px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:12px}
.row3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:12px}
.stacks{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 14px}
.stacks label{background:#1e293b;padding:5px 10px;border-radius:6px;font-size:12px;cursor:pointer;display:flex;align-items:center;gap:5px;color:#e2e8f0;margin:0}
.stacks input{width:auto}
pre{background:#020617;border:1px solid #1e293b;border-radius:8px;padding:14px;overflow:auto;max-height:520px;font-size:12px;line-height:1.5;white-space:pre-wrap}
.md{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:20px;line-height:1.65;overflow:auto}
.md h1,.md h2,.md h3{color:#38bdf8} .md code{background:#1e293b;padding:2px 5px;border-radius:4px;font-size:12px}
.st-RUNNING{color:#facc15;font-weight:700} .st-COMPLETED{color:#4ade80;font-weight:700} .st-FAILED{color:#f87171;font-weight:700} .st-INTERRUPTED{color:#fb923c;font-weight:700}
.hidden{display:none}
.keybox{background:#020617;border:1px solid #1e293b;border-radius:8px;padding:10px 12px;font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all;color:#34d399;margin:6px 0}
.modal-bg{position:fixed;inset:0;background:rgba(2,6,23,.78);display:flex;align-items:center;justify-content:center;z-index:1000;padding:16px}
.modal-bg.hidden{display:none}
.modal-box{background:#111827;border:1px solid #334155;border-radius:12px;padding:22px;width:100%;max-width:780px;max-height:90vh;overflow-y:auto;box-shadow:0 24px 60px rgba(0,0,0,.65)}
.modal-box.sm{max-width:540px}
.modal-hd{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;border-bottom:1px solid #1e293b;padding-bottom:10px}
.modal-hd h2{margin:0;font-size:16px;color:#38bdf8}
.modal-close{background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer;padding:2px 8px;border-radius:6px}
.modal-close:hover{background:#1e293b;color:#fff}
.tip-box{background:#0f172a;border:1px solid #1e3a8a;border-radius:8px;padding:10px 14px;font-size:12.5px;color:#cbd5e1;line-height:1.6;margin:10px 0 14px}
.gpu-pill{display:inline-flex;align-items:center;gap:7px;background:#0f172a;border:1px solid #334155;border-radius:999px;padding:5px 12px;font-size:12px;font-weight:600;color:#86efac;margin-right:6px;white-space:nowrap}
.gpu-dot{width:8px;height:8px;border-radius:50%;background:#4ade80;display:inline-block;flex-shrink:0}
.gpu-pill.busy{border-color:#0284c7;color:#fde047}
.gpu-pill.busy .gpu-dot{background:#facc15;box-shadow:0 0 8px #facc15}
.pbar{background:#1e293b;border-radius:999px;height:7px;width:100%;overflow:hidden;margin-top:4px;min-width:90px}
.pbar-fill{height:100%;background:linear-gradient(90deg,#0284c7,#38bdf8);transition:width .35s}
.pbar-fill.done{background:#22c55e}
.pbar-fill.fail{background:#ef4444}
.sev-CRITICAL{background:#7f1d1d;color:#fecaca;padding:2px 7px;border-radius:4px;font-weight:700;font-size:11px;display:inline-block}
.sev-HIGH{background:#7c2d12;color:#fed7aa;padding:2px 7px;border-radius:4px;font-weight:700;font-size:11px;display:inline-block}
.sev-MEDIUM{background:#713f12;color:#fef08a;padding:2px 7px;border-radius:4px;font-weight:700;font-size:11px;display:inline-block}
.sev-LOW{background:#0c4a6e;color:#bae6fd;padding:2px 7px;border-radius:4px;font-weight:700;font-size:11px;display:inline-block}
</style></head><body>
<header>
  <div><h1>AI Security Audit v3.0 <span class="badge badge-ssh">Agentless SSH</span><span class="badge badge-push">1-Line Collector</span><span class="badge">15 Hệ sinh thái</span></h1></div>
  <div style="display:flex;align-items:center;flex-wrap:wrap;gap:6px"><span id="gpuPill" class="gpu-pill" title="Đang đọc thông số GPU..."><span class="gpu-dot"></span><span id="gpuText">GPU...</span></span><span id="ollamaBadge" class="badge">Đang kiểm tra Ollama...</span><a href="/logout" style="color:#94a3b8;margin-left:10px;text-decoration:none;font-size:13px">Đăng xuất</a></div>
</header>
<div class="nav">
  <button class="active" onclick="showTab('projects',this)">1. Dự án &amp; Quét</button>
  <button onclick="showTab('sshkey',this)">2. Kết nối &amp; Collector</button>
  <button onclick="showTab('diff',this)">3. So sánh Bản vá</button>
  <button onclick="showTab('jobs',this)">4. Tiến trình &amp; Log</button>
  <button onclick="showTab('katana',this)">5. Bề mặt Web</button>
  <button onclick="showTab('reports',this)">6. Báo cáo &amp; Xuất file</button>
  <button onclick="showTab('guide',this)">7. Hướng dẫn</button>
</div>
<div class="wrap">
  <div id="tab-projects">
    <div class="grid">
      <div class="card"><div class="kpi" id="kpiProj">-</div><div class="kpi-lbl">Dự án / Máy chủ đang quản lý</div></div>
      <div class="card"><div class="kpi" id="kpiRep">-</div><div class="kpi-lbl">Bộ báo cáo đã lưu</div></div>
      <div class="card"><div class="kpi">15</div><div class="kpi-lbl">OWASP · API · .NET · MSSQL · Nginx · HAProxy · Ubuntu · PG · MySQL · MongoDB · Docker · MCP · Next.js · Node · WP</div></div>
      <div class="card"><div class="kpi" id="kpiJobs">0</div><div class="kpi-lbl">Tác vụ đang chạy</div></div>
    </div>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:12px">
        <h2 style="margin:0">Danh sách Dự án &amp; Máy chủ (Kiểm toán 1-Click)</h2>
        <button class="btn btn-green" style="padding:8px 14px;font-size:13px" onclick="openCreateProjectModal()">+ Tạo dự án mới</button>
      </div>
      <table><thead><tr><th>Dự án / Chế độ</th><th>Kết nối / Nguồn</th><th>Hệ sinh thái</th><th>Hành động</th></tr></thead><tbody id="projTable"></tbody></table>
    </div>
  </div>

  <!-- Modal Tạo / Sửa Dự án -->
  <div id="projectModal" class="modal-bg hidden" onclick="if(event.target===this)closeProjectModal()">
    <div class="modal-box">
      <div class="modal-hd">
        <h2 id="formTitle">+ Tạo Dự án / Máy chủ mới</h2>
        <button class="modal-close" onclick="closeProjectModal()" title="Đóng">&times;</button>
      </div>
      <input type="hidden" id="editId" value="">
      <div class="row">
        <div><label>Tên dự án / Máy chủ</label><input id="pName" placeholder="VD: My-Server-01"></div>
        <div><label>Chế độ kết nối</label>
          <select id="pMode" onchange="toggleMode()">
            <option value="ssh">Agentless Remote Server (SSH — Tự động quét toàn bộ hệ thống)</option>
            <option value="local">Thư mục Local trên máy chủ Audit</option>
          </select>
        </div>
      </div>

      <div id="box-ssh">
        <div class="row3">
          <div><label>IP / Hostname máy chủ đích</label><input id="sHost" placeholder="VD: 192.168.1.10 hoặc 10.7.0.x"></div>
          <div><label>Cổng SSH</label><input id="sPort" value="22"></div>
          <div><label>Hệ điều hành</label><select id="sOs"><option value="linux">Linux / Ubuntu</option><option value="windows">Windows Server (OpenSSH)</option></select></div>
        </div>
        <div class="row3">
          <div><label>Username SSH</label><input id="sUser" value="ubuntu"></div>
          <div><label>Phương thức xác thực</label>
            <select id="sAuth" onchange="toggleAuth()">
              <option value="key">SSH Key của Audit Lab (ed25519 — Khuyến nghị)</option>
              <option value="custom_key">Dán SSH Private Key sẵn có của bạn</option>
              <option value="password">SSH Password (hỗ trợ cả keyboard-interactive)</option>
            </select>
          </div>
          <div id="box-pass" class="hidden"><label>Mật khẩu SSH / Sudo</label><input id="sPass" type="password" placeholder="Để trống nếu giữ nguyên mật khẩu cũ khi Sửa"></div>
        </div>
        <div id="box-ckey" class="hidden" style="margin-bottom:12px">
          <label>Dán nội dung Private Key (BEGIN OPENSSH/RSA PRIVATE KEY):</label>
          <textarea id="sCustomKey" placeholder="Dán SSH Private Key tại đây..."></textarea>
        </div>
        <div style="margin-bottom:12px">
          <label>Đường dẫn mã nguồn cụ thể (<b>ĐỂ TRỐNG = TỰ ĐỘNG QUÉT TOÀN BỘ HỆ THỐNG</b>: OS + Firewall + Docker + Nginx/DB/MongoDB + Tự dò ứng dụng trong /var/www, /opt, /srv, /home, /root):</label>
          <input id="sPaths" placeholder="Để trống để Auto-Discover toàn hệ thống — hoặc nhập đường dẫn VD: /var/www/app1, /opt/mcp">
        </div>
      </div>

      <div id="box-local" class="hidden" style="margin-bottom:12px">
        <label>Đường dẫn thư mục mã nguồn trên máy chủ Audit</label>
        <input id="pPath" placeholder="VD: F:\ERP-Audit-Lab\repo">
      </div>

      <label>Chọn hệ sinh thái cần quét (15 hệ sinh thái):</label>
      <div class="stacks" id="stackBoxes"></div>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:12px">
        <button class="btn btn-gray" onclick="closeProjectModal()">Hủy</button>
        <button class="btn btn-green" onclick="saveProject()">Lưu Dự án / Máy chủ</button>
      </div>
    </div>
  </div>

  <!-- Modal Chọn Model AI khi bắt đầu Kiểm toán AI sâu -->
  <div id="scanModelModal" class="modal-bg hidden" onclick="if(event.target===this)closeScanModal()">
    <div class="modal-box sm">
      <div class="modal-hd">
        <h2 id="scanModalTitle">Chọn Model AI để Kiểm toán sâu</h2>
        <button class="modal-close" onclick="closeScanModal()" title="Đóng">&times;</button>
      </div>
      <input type="hidden" id="scanTargetId" value="">
      <div class="tip-box">
        <b>Lưu ý phần cứng (GPU 8 GB VRAM + 32 GB RAM):</b><br>
        • Model <b>&lt; 8 GB</b> (như <code>qwen3-vl:8b</code>, <code>qwen2.5vl:7b</code>) nạp <b>100% vào GPU</b> &rarr; tốc độ nhanh nhất.<br>
        • Model <b>&gt; 8 GB</b> (<code>deepseek-r1:14b</code>, <code>qwen3:30b-a3b</code>, <code>gemma3:27b</code>) chạy lai <b>GPU + 32 GB RAM</b> &rarr; phân tích sâu hơn nhưng tốn thời gian hơn.
      </div>
      <div style="margin-bottom:12px">
        <label>Model AI quét chính (Phân tích lỗ hổng &amp; viết báo cáo)</label>
        <select id="auditModelSel"><option value="qwen3-vl:8b">qwen3-vl:8b</option></select>
      </div>
      <div style="margin-bottom:14px">
        <label>Model AI phản biện (Critic — Lọc báo động giả)</label>
        <select id="criticModelSel"><option value="deepseek-r1:14b">deepseek-r1:14b</option></select>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:8px">
        <button class="btn btn-gray" onclick="closeScanModal()">Hủy</button>
        <button class="btn btn-ai" onclick="confirmAiScan()">Bắt đầu Kiểm toán AI</button>
      </div>
    </div>
  </div>

  <div id="tab-sshkey" class="hidden">
    <div class="card">
      <h2>A. Thu thập nhanh 1-Dòng cho Windows Server (PowerShell — Không cần SSH / Agent)</h2>
      <p style="color:#94a3b8">Chạy 1 dòng dưới đây trong PowerShell (Administrator) trên bất kỳ máy Windows Server nào trong VPN <code>10.7.0.0/24</code>. Script tự thu thập chỉ-đọc OS/Hotfix, Firewall, Defender, Ports, IIS, <b>MS SQL Server</b>, MongoDB/Docker, gửi về <code><AUDIT_SERVER>:2810</code>, tự dọn file tạm và <b>tự động chạy quét ngay!</b></p>
      <div class="keybox" id="winColCmd">Đang tải...</div>
      <button class="btn btn-primary" onclick="copyText('winColCmd')">Sao chép lệnh PowerShell</button>
      <button class="btn btn-green" onclick="downloadCollector('win')">Tải file win_collector.ps1</button>
      <button class="btn btn-danger" onclick="rotateToken()">Xoay vòng Token bảo mật</button>
    </div>
    <div class="card">
      <h2>B. Thu thập nhanh 1-Dòng cho Linux / VPS (Khi không mở SSH từ ngoài)</h2>
      <div class="keybox" id="linColCmd">Đang tải...</div>
      <button class="btn btn-primary" onclick="copyText('linColCmd')">Sao chép lệnh Linux Bash</button>
      <button class="btn btn-green" onclick="downloadCollector('linux')">Tải file linux_collector.sh</button>
    </div>
    <div class="card">
      <h2>C. Khóa công khai SSH chuyên dụng (ed25519 — Quét không cần mật khẩu)</h2>
      <div class="keybox" id="pubKeyBox">Đang tải...</div>
      <label style="margin-top:10px">Lệnh cài nhanh 1 dòng trên máy chủ Linux đích:</label>
      <div class="keybox" id="pubCmdBox">Đang tải...</div>
      <button class="btn btn-primary" onclick="copyText('pubCmdBox')">Sao chép lệnh cài SSH Key</button>
    </div>
  </div>

  <div id="tab-diff" class="hidden">
    <div class="card">
      <h2>So sánh Bản vá &amp; Săn biến thể lỗ hổng (Patch-Diff &amp; Variant Analysis)</h2>
      <div class="row">
        <div><label>Tên đợt phân tích</label><input id="diffName" value="patch-diff-manual"></div>
        <div><label>Model AI phân tích</label><select id="diffModel"><option value="qwen3:30b-a3b">qwen3:30b-a3b (Nhanh, đọc code mạnh)</option><option value="deepseek-r1:14b">deepseek-r1:14b (Suy luận sâu)</option></select></div>
      </div>
      <label>Dán nội dung Patch / Git Diff:</label>
      <textarea id="diffText" style="min-height:180px" placeholder="diff --git a/... b/..."></textarea>
      <div style="margin-top:12px"><button class="btn btn-ai" onclick="runManualDiff()">Chạy AI Phân tích Bản vá &amp; Biến thể</button></div>
    </div>
  </div>

  <div id="tab-jobs" class="hidden">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px"><h2 style="margin:0">Lịch sử Tác vụ &amp; Nhật ký trực tiếp</h2><button class="btn btn-danger" onclick="clearFinishedJobs()">Xóa toàn bộ lịch sử đã xong/lỗi</button></div>
      <table><thead><tr><th>Mã tác vụ</th><th>Tên tác vụ</th><th>Trạng thái</th><th style="min-width:140px">Tiến độ / Thời gian</th><th>Bắt đầu</th><th>Thao tác</th></tr></thead><tbody id="jobsTable"></tbody></table>
    </div>
    <div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><h2 style="margin:0">Nhật ký chạy trực tiếp (Live Log)</h2><button class="btn btn-gray" onclick="scrollLogBottom()">Xuống cuối log</button></div><div id="liveProgWrap" class="hidden" style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:10px 14px;margin-bottom:10px"><div style="display:flex;justify-content:space-between;font-size:12.5px;margin-bottom:4px"><span id="liveProgStep" style="color:#38bdf8;font-weight:600">Đang chạy...</span><span id="liveProgMeta" style="color:#fde047;font-weight:600">0% · 00:00</span></div><div class="pbar"><div id="liveProgFill" class="pbar-fill" style="width:0%"></div></div></div><pre id="jobLog">Chọn một tác vụ ở bảng trên để xem nhật ký chạy trực tiếp...</pre></div>
  </div>

  <div id="tab-katana" class="hidden">
    <div class="card">
      <h2>Khám phá Bề mặt Web &amp; Endpoint ẩn (Katana + httpx)</h2>
      <p style="color:#94a3b8">Quét bề mặt ngoài vào (<b>Outside-In</b>) ở chế độ an toàn giới hạn tốc độ (<code>-rl 10 req/s</code>) cho các domain/URL thuộc quyền sở hữu: tự động tìm API ẩn trong JS bundle (Next.js/React/WordPress), kiểm tra TLS, Security Headers và Tech Stack.</p>
      <div class="row">
        <div><label>URL mục tiêu được phép quét (VD: https://app.domain.vn)</label><input id="kUrl" placeholder="https://..."></div>
        <div><label>Tên đợt quét</label><input id="kName" value="web-surface"></div>
      </div>
      <div class="row3">
        <div><label>Độ sâu crawl (1–5, mặc định 3)</label><input id="kDepth" value="3"></div>
        <div><label>Phân tích chéo bằng AI Local (Shadow API)?</label><select id="kAi"><option value="yes">Có — Phân tích bằng Ollama Local</option><option value="no">Không — Chỉ chạy Katana + httpx (~20 giây)</option></select></div>
        <div><label>Chọn Model AI phân tích Web Surface</label><select id="kModel"><option value="qwen3-vl:8b">qwen3-vl:8b</option></select></div>
      </div>
      <div style="margin:6px 0 12px"><label style="display:inline-flex;align-items:center;gap:7px;cursor:pointer;color:#e2e8f0"><input type="checkbox" id="kNuclei" checked style="width:auto"> Bật <b>ProjectDiscovery Nuclei (Safe Profile)</b> — Quét CVE Web, Misconfiguration, Exposed Panels (-severity critical,high,medium -rl 10)</label></div>
      <button class="btn btn-ai" onclick="runKatanaScan()">Chạy Khám phá Bề mặt Web &amp; Nuclei</button>
    </div>
  </div>

  <div id="tab-reports" class="hidden">
    <div class="card">
      <h2>Kho Báo cáo Kiểm toán &amp; Xuất File Gửi Lãnh Đạo</h2>
      <div class="row">
        <div><label>Chọn đợt báo cáo</label><select id="repFolder" onchange="loadReportFiles()"></select></div>
        <div><label>Chọn file báo cáo</label><select id="repFile" onchange="viewReportFile()"></select></div>
      </div>
      <div style="margin-top:10px">
        <button class="btn btn-danger" onclick="exportReport('pdf')">Xuất Báo Cáo PDF (Gửi Lãnh Đạo)</button>
        <button class="btn btn-green" onclick="exportReport('excel')">Xuất Báo Cáo Excel (.xlsx — 5 Sheet)</button>
        <button class="btn btn-gray" onclick="delReportFolder()">Xóa đợt báo cáo này</button>
      </div>
    </div>
    <div class="card"><div id="repContent" class="md">Chọn đợt báo cáo và file ở trên để xem chi tiết...</div></div>
  </div>
  <div id="tab-guide" class="hidden">
    <div class="card">
      <h2>1. Quy Trình 4 Bước Kiểm Toán Bảo Mật Chuẩn</h2>
      <table>
        <thead><tr><th style="width:12%">Bước</th><th style="width:26%">Thao tác trên Web</th><th>Mô tả &amp; Kết quả đạt được</th></tr></thead>
        <tbody>
          <tr><td><b>Bước 1</b></td><td><b>Tạo Dự án / Máy chủ</b><br>(Tab 1 hoặc Tab 2)</td><td>Chọn 1 trong 3 cách:<br>• <b>Bấm <code>+ Tạo dự án mới</code> (Tab 1):</b> thêm máy chủ <b>Agentless SSH</b> (nhập IP, User, SSH Key/Password — <i>để trống ô đường dẫn</i> để tự dò toàn bộ OS, Firewall, Docker, DB và mã nguồn) hoặc trỏ <b>Thư mục Local</b>.<br>• <b>Thu thập 1-Dòng (Tab 2):</b> dùng cho Windows/Linux không mở SSH. Bấm tải file <code>.ps1</code> / <code>.sh</code> hoặc copy lệnh 1 dòng &rarr; hệ thống tự tạo dự án và tự chạy quét ngay.</td></tr>
          <tr><td><b>Bước 2</b></td><td><b>Chọn Chế độ Quét &amp; Model AI</b><br>(Tab 1)</td><td>• Bấm <b>Quét nhanh (~30–60 giây):</b> chạy thẳng Gitleaks (lộ mật khẩu) + Trivy (CVE thư viện) + Semgrep (35 rule 15 hệ sinh thái) — không dùng AI.<br>• Bấm <b>Kiểm toán AI sâu:</b> hộp thoại <b>Chọn Model AI</b> sẽ hiện ra để bạn chọn Model Quét chính và Model Phản biện (Critic) phù hợp thời gian mong muốn.</td></tr>
          <tr><td><b>Bước 3</b></td><td><b>Theo dõi Tiến trình &amp; Mở rộng</b><br>(Tab 3, 4, 5)</td><td>• <b>Tab 4 (Tiến trình &amp; Log):</b> theo dõi nhật ký chạy trực tiếp, dừng / chạy lại / xóa tác vụ.<br>• <b>Tab 3 (So sánh Bản vá):</b> dán <code>git diff</code> giữa 2 phiên bản để săn lỗi hồi quy &amp; biến thể.<br>• <b>Tab 5 (Bề mặt Web):</b> dùng Katana + httpx soi từ ngoài vào tìm Shadow API / JS endpoints.</td></tr>
          <tr><td><b>Bước 4</b></td><td><b>Đọc &amp; Xuất Báo cáo</b><br>(Tab 6)</td><td>Xem trực tiếp bảng lỗi Gitleaks / Trivy / Semgrep &amp; báo cáo AI trên trình duyệt, sau đó bấm <b>Xuất Báo Cáo PDF (Gửi Lãnh Đạo)</b> hoặc <b>Xuất Báo Cáo Excel (.xlsx — 5 Sheet)</b>.</td></tr>
        </tbody>
      </table>
    </div>
    <div class="card">
      <h2>2. Hiểu Đúng Về GPU (8 GB VRAM) vs RAM (32 GB) &amp; 6 Model AI Thực Tế</h2>
      <div class="tip-box">
        <b>Cơ chế nạp Model của Ollama trên máy chủ AI Audit (RTX 3050 8 GB VRAM + 32 GB RAM + Core i7-12700F):</b><br>
        • Bộ nhớ tốc độ siêu nhanh của card đồ họa là <b>8 GB VRAM</b>. Model nào nhỏ hơn 8 GB sẽ nạp <b>100% vào GPU</b> &rarr; chạy rất nhanh.<br>
        • Model nào lớn hơn 8 GB sẽ <b>chạy lai (Hybrid GPU + RAM)</b>: Ollama nạp tối đa phần lớn vào 8 GB VRAM, phần dư còn lại <b>tự tràn sang 32 GB RAM hệ thống</b> (CPU xử lý phần tràn này). Nhờ 32 GB RAM máy bạn chạy được đầy đủ cả các model 14B–30B mà không bị thiếu bộ nhớ, nhưng phần chạy qua RAM sẽ chậm hơn 100% GPU.
      </div>
      <table>
        <thead><tr><th>Model AI thực tế (Ollama Local)</th><th>Dung lượng</th><th>Cách chạy trên RTX 3050 (8GB) + 32GB RAM</th><th>Khuyến nghị sử dụng</th></tr></thead>
        <tbody>
          <tr><td><code>qwen3-vl:8b</code></td><td>6.2 GB</td><td><b>100% GPU (VRAM)</b> — Rất nhanh</td><td><b>Mặc định hằng ngày</b> cho Kiểm toán sâu, 1-Line Push Audit &amp; Katana AI</td></tr>
          <tr><td><code>qwen2.5vl:7b</code></td><td>6.0 GB</td><td><b>100% GPU (VRAM)</b> — Rất nhanh</td><td>Model nhẹ dự phòng, phản hồi tức thì</td></tr>
          <tr><td><code>deepseek-r1:14b</code></td><td>9.0 GB</td><td><b>~75% GPU + ~25% RAM</b> — Khá nhanh</td><td><b>Model Phản biện (Critic)</b> lọc báo động giả &amp; So sánh Bản vá (Patch-Diff)</td></tr>
          <tr><td><code>qwen3:30b-a3b</code> (MoE)</td><td>18.0 GB</td><td><b>~35% GPU + ~65% RAM</b> — Trung bình</td><td>Kiến trúc MoE (chỉ kích hoạt 3B/token) — Kiểm toán sâu mã nguồn lõi (API, ERP, Auth)</td></tr>
          <tr><td><code>gemma3:27b</code> (Dense)</td><td>17.0 GB</td><td><b>~35% GPU + ~65% RAM</b> — Chậm</td><td>Kiến trúc Dense (kích hoạt đủ 27B/token) — Phù hợp chạy qua đêm / tổng hợp sâu</td></tr>
          <tr><td><code>qwen3-vl:30b</code> (MoE+VL)</td><td>19.0 GB</td><td><b>~35% GPU + ~65% RAM</b> — Trung bình</td><td>Bản 30B đa phương thức (code + hình ảnh)</td></tr>
        </tbody>
      </table>
    </div>
    <div class="card">
      <h2>3. Lưu Ý Bảo Mật &amp; Mẹo Vận Hành</h2>
      <ul style="line-height:1.8;color:#cbd5e1;padding-left:20px;margin:0">
        <li><b>Cảnh báo ClickFix của uBlock Origin khi bấm Sao chép ở Tab 2:</b> Dùng ngay nút <b>Tải file <code>win_collector.ps1</code> / <code>linux_collector.sh</code></b> để tải trực tiếp và chạy, hoặc tắt uBlock riêng cho địa chỉ IP nội bộ của trang Audit.</li>
        <li><b>Cuộn đọc Nhật ký (Tab 4):</b> Khi bạn lăn chuột lên đọc log cũ, hệ thống giữ nguyên vị trí không tự kéo xuống; bấm <b>Xuống cuối log</b> để quay lại dòng mới nhất.</li>
        <li><b>Quyền hạn quét:</b> Chỉ thực hiện kiểm toán và chạy Katana/SSH trên các máy chủ, ứng dụng và tên miền thuộc quyền sở hữu hợp pháp hoặc được cấp phép.</li>
      </ul>
    </div>
  </div>
</div>
<script>
const ALL_STACKS = ["owasp","api","dotnet","mssql","nginx","haproxy","ubuntu","postgresql","mysql","mongodb","docker","mcp","nextjs","nodejs","wordpress"];
let activeJobId = null;
let cachedProjects = [];

function copyText(id){
  const txt = document.getElementById(id).textContent;
  if(navigator.clipboard && window.isSecureContext){
    navigator.clipboard.writeText(txt).then(()=>alert('Đã copy!')).catch(()=>fallbackCopy(txt));
  } else { fallbackCopy(txt); }
}
function fallbackCopy(txt){
  const ta = document.createElement('textarea');
  ta.value = txt; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.focus(); ta.select();
  try { document.execCommand('copy'); alert('Đã copy!'); } catch(e) { prompt('Copy thủ công (Ctrl+C):', txt); }
  document.body.removeChild(ta);
}
function showTab(name, btn){
  document.querySelectorAll('[id^="tab-"]').forEach(el=>el.classList.add('hidden'));
  document.getElementById('tab-'+name).classList.remove('hidden');
  document.querySelectorAll('.nav button').forEach(b=>b.classList.remove('active'));
  if(btn) btn.classList.add('active');
  if(name==='projects') loadProjects();
  if(name==='jobs') loadJobs();
  if(name==='reports') loadReportFolders();
  if(name==='sshkey') loadCollectorInfo();
}
function toggleMode(){
  const m = document.getElementById('pMode').value;
  document.getElementById('box-ssh').classList.toggle('hidden', m!=='ssh');
  document.getElementById('box-local').classList.toggle('hidden', m!=='local');
}
function toggleAuth(){
  const a = document.getElementById('sAuth').value;
  document.getElementById('box-pass').classList.toggle('hidden', a!=='password');
  document.getElementById('box-ckey').classList.toggle('hidden', a!=='custom_key');
}
function resetForm(){
  document.getElementById('editId').value = '';
  document.getElementById('formTitle').textContent = '+ Tạo Dự án / Máy chủ mới';
  document.getElementById('pName').value = '';
  document.getElementById('pMode').value = 'ssh';
  document.getElementById('sHost').value = '';
  document.getElementById('sPort').value = '22';
  document.getElementById('sOs').value = 'linux';
  document.getElementById('sUser').value = 'ubuntu';
  document.getElementById('sAuth').value = 'key';
  document.getElementById('sPass').value = '';
  document.getElementById('sCustomKey').value = '';
  document.getElementById('sPaths').value = '';
  document.getElementById('pPath').value = '';
  document.querySelectorAll('#stackBoxes input').forEach(cb => cb.checked = true);
  toggleMode(); toggleAuth();
}
function openCreateProjectModal(){
  resetForm();
  document.getElementById('projectModal').classList.remove('hidden');
}
function closeProjectModal(){
  document.getElementById('projectModal').classList.add('hidden');
}
function openScanModal(pid){
  const p = cachedProjects.find(x=>x.id===pid);
  document.getElementById('scanTargetId').value = pid;
  document.getElementById('scanModalTitle').textContent = 'Chọn Model AI — ' + (p ? p.name : pid);
  document.getElementById('scanModelModal').classList.remove('hidden');
}
function closeScanModal(){
  document.getElementById('scanModelModal').classList.add('hidden');
}
function confirmAiScan(){
  const pid = document.getElementById('scanTargetId').value;
  closeScanModal();
  if(pid) triggerScan(pid, 'full');
}
document.addEventListener('keydown', e=>{ if(e.key==='Escape'){ closeProjectModal(); closeScanModal(); } });
function editProject(pid){
  const p = cachedProjects.find(x=>x.id===pid); if(!p) return;
  document.getElementById('editId').value = p.id;
  document.getElementById('formTitle').textContent = 'Sửa Dự án: ' + p.name;
  document.getElementById('pName').value = p.name;
  document.getElementById('pMode').value = p.mode === 'ssh' ? 'ssh' : 'local';
  toggleMode();
  if(p.mode === 'ssh'){
    document.getElementById('sHost').value = p.ssh_host || '';
    document.getElementById('sPort').value = p.ssh_port || 22;
    document.getElementById('sOs').value = p.os_type || 'linux';
    document.getElementById('sUser').value = p.ssh_user || 'ubuntu';
    document.getElementById('sAuth').value = p.ssh_auth || 'key';
    document.getElementById('sPaths').value = p.remote_paths || '';
    toggleAuth();
  } else {
    document.getElementById('pPath').value = p.path || '';
  }
  const st = new Set(p.stacks || []);
  document.querySelectorAll('#stackBoxes input').forEach(cb => cb.checked = st.has(cb.value));
  document.getElementById('projectModal').classList.remove('hidden');
}

async function init(){
  document.getElementById('stackBoxes').innerHTML = ALL_STACKS.map(s=>`<label><input type="checkbox" value="${s}" checked> ${s}</label>`).join('');
  toggleMode(); toggleAuth();
  loadStatus(); loadTelemetry(); loadProjects(); loadReportFolders(); loadCollectorInfo();
  setInterval(()=>{ loadJobs(); if(activeJobId) loadJobLog(activeJobId); }, 4000);
  setInterval(loadTelemetry, 3000);
}
async function loadStatus(){
  const r = await fetch('/api/status'); const d = await r.json();
  document.getElementById('ollamaBadge').textContent = d.ollama_ok ? `Ollama Sẵn sàng (${d.models.length} model)` : 'Ollama Ngoại tuyến';
  if(d.ollama_ok && d.models.length){
    const details = d.model_details || d.models.map(m=>({name:m, size_gb:0}));
    const opts = details.map(m=>{
      const tag = m.size_gb ? (m.size_gb <= 7.5 ? `${m.size_gb} GB — 100% GPU (Nhanh)` : `${m.size_gb} GB — GPU + RAM`) : '';
      return `<option value="${m.name}">${m.name}${tag ? ' ('+tag+')' : ''}</option>`;
    }).join('');
    ['auditModelSel','criticModelSel','diffModel','kModel'].forEach(id=>{
      const el = document.getElementById(id); if(!el) return;
      el.innerHTML = opts;
      if((id==='auditModelSel'||id==='diffModel'||id==='kModel') && d.models.includes('qwen3-vl:8b')) el.value = 'qwen3-vl:8b';
      if(id==='criticModelSel' && d.models.includes('deepseek-r1:14b')) el.value = 'deepseek-r1:14b';
    });
  }
}
async function loadCollectorInfo(){
  const r = await fetch('/api/collector-info'); const d = await r.json();
  window._collectorToken = d.token;
  const base = window.location.origin;
  document.getElementById('pubKeyBox').textContent = d.public_key;
  document.getElementById('pubCmdBox').textContent = `mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo "${d.public_key}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`;
  document.getElementById('winColCmd').textContent = `irm "${base}/download/win-collector?token=${d.token}" | iex`;
  document.getElementById('linColCmd').textContent = `curl -sS "${base}/download/linux-collector?token=${d.token}" | sudo bash`;
}
async function rotateToken(){
  if(!confirm('Xoay vòng Collector Token? Các lệnh 1-dòng cũ sẽ hết hiệu lực.')) return;
  await fetch('/api/collector/rotate-token', {method:'POST'});
  loadCollectorInfo();
}
async function loadProjects(){
  const r = await fetch('/api/projects'); const list = await r.json();
  cachedProjects = list;
  document.getElementById('kpiProj').textContent = list.length;
  document.getElementById('projTable').innerHTML = list.map(p=>{
    const isSsh = p.mode === 'ssh';
    const isPush = p.mode === 'push';
    const conn = isSsh
      ? `<code>${p.ssh_user}@${p.ssh_host}:${p.ssh_port||22}</code> (${p.ssh_auth})<br><small style="color:#94a3b8">${p.remote_paths ? 'Paths: '+p.remote_paths : 'Mặc định: Auto-Discover Toàn Hệ Thống'}</small>`
      : `<code>${p.path}</code>`;
    const badge = isSsh ? '<span class="badge badge-ssh">Agentless SSH</span>' : (isPush ? '<span class="badge badge-push">1-Line Push</span>' : '<span class="badge badge-local">Local</span>');
    return `<tr>
      <td><b>${p.name}</b> ${badge}</td>
      <td>${conn}</td>
      <td>${(p.stacks||[]).map(s=>`<span class="badge">${s}</span>`).join('')}</td>
      <td>
        ${isSsh ? `<button class="btn btn-gray" onclick="testSsh('${p.id}')">Kiểm tra SSH</button>` : ''}
        <button class="btn btn-primary" onclick="triggerScan('${p.id}','quick')">${isSsh?'Đồng bộ SSH + ':''}Quét nhanh</button>
        <button class="btn btn-ai" onclick="openScanModal('${p.id}')">${isSsh?'Đồng bộ SSH + ':''}Kiểm toán AI sâu</button>
        <button class="btn btn-gray" onclick="editProject('${p.id}')">Sửa</button>
        <button class="btn btn-danger" onclick="delProject('${p.id}')">Xóa</button>
      </td>
    </tr>`;
  }).join('');
}
async function saveProject(){
  const edit_id = document.getElementById('editId').value;
  const name = document.getElementById('pName').value.trim();
  const mode = document.getElementById('pMode').value;
  const stacks = [...document.querySelectorAll('#stackBoxes input:checked')].map(i=>i.value);
  if(!name) return alert('Vui lòng nhập Tên dự án!');
  const payload = {edit_id, name, mode, stacks};
  if(mode === 'ssh'){
    payload.ssh_host = document.getElementById('sHost').value.trim();
    payload.ssh_port = parseInt(document.getElementById('sPort').value || '22');
    payload.os_type = document.getElementById('sOs').value;
    payload.ssh_user = document.getElementById('sUser').value.trim();
    payload.ssh_auth = document.getElementById('sAuth').value;
    payload.ssh_password = document.getElementById('sPass').value;
    payload.custom_key = document.getElementById('sCustomKey').value;
    payload.remote_paths = document.getElementById('sPaths').value.trim();
    if(!payload.ssh_host || !payload.ssh_user) return alert('Vui lòng nhập IP/Host và Username SSH!');
  } else {
    payload.path = document.getElementById('pPath').value.trim();
    if(!payload.path) return alert('Vui lòng nhập Đường dẫn thư mục!');
  }
  const r = await fetch('/api/projects', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
  if(r.ok){ closeProjectModal(); resetForm(); loadProjects(); alert('Đã lưu dự án thành công!'); } else { alert('Lỗi lưu dự án!'); }
}
async function delProject(pid){
  if(!confirm('Xóa dự án này khỏi danh sách?')) return;
  await fetch('/api/projects/'+pid, {method:'DELETE'}); loadProjects();
}
async function testSsh(pid){
  const r = await fetch('/api/projects/'+pid+'/test-ssh', {method:'POST'});
  const d = await r.json();
  alert(d.ok ? ('KẾT NỐI SSH THÀNH CÔNG!\n' + d.info) : ('LỖI KẾT NỐI SSH:\n' + d.error));
}
async function triggerScan(projectId, mode){
  const r = await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({project_id:projectId, mode, audit_model:(document.getElementById('kModel')||{}).value||'qwen3-vl:8b', critic_model:(document.getElementById('criticModelSel')||{}).value||'deepseek-r1:14b'})});
  const d = await r.json();
  if(d.job_id){ activeJobId = d.job_id; showTab('jobs', document.querySelectorAll('.nav button')[3]); loadJobs(); loadJobLog(d.job_id); }
}
async function runManualDiff(){
  const name = document.getElementById('diffName').value.trim() || 'patch-diff';
  const model = document.getElementById('diffModel').value;
  const diff_text = document.getElementById('diffText').value;
  if(!diff_text.trim()) return alert('Vui lòng dán nội dung git diff!');
  const r = await fetch('/api/patch-diff', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name,model,diff_text})});
  const d = await r.json();
  if(d.job_id){ activeJobId = d.job_id; showTab('jobs', document.querySelectorAll('.nav button')[3]); loadJobs(); loadJobLog(d.job_id); }
}
function fmtDur(sec){
  sec = Math.max(0, Math.floor(sec || 0));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  const pad = n => String(n).padStart(2, '0');
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}
async function loadTelemetry(){
  try {
    const r = await fetch('/api/telemetry'); if(!r.ok) return;
    const d = await r.json();
    const pill = document.getElementById('gpuPill');
    const txt = document.getElementById('gpuText');
    if(!pill || !txt) return;
    const job = d.active_job;
    const isBusy = Boolean(job) || (d.gpu_ok && d.gpu_util >= 10);
    pill.classList.toggle('busy', isBusy);
    let label = '';
    if(d.gpu_ok){
      const stateTxt = isBusy ? `GPU ${d.gpu_util}%` : 'GPU Rảnh';
      label = `${stateTxt} · VRAM ${d.vram_used_mib} MiB / ${d.vram_total_mib} MiB`;
    } else {
      label = isBusy ? 'Đang chạy quét' : 'Hệ thống Rảnh';
    }
    if(job){
      label += ` · ${fmtDur(job.elapsed_sec)} (${job.progress}%)`;
    }
    txt.textContent = label;
    const mInfo = (d.loaded_models||[]).map(m=>`${m.name} (${m.gpu_pct}% GPU)`).join(', ') || 'Chưa nạp model';
    pill.title = (d.gpu_ok ? `GPU: ${d.gpu_util}% | VRAM: ${d.vram_used_mib}/${d.vram_total_mib} MiB | Nhiệt độ: ${d.gpu_temp}°C | ` : '') + `Ollama: ${mInfo}` + (job ? ` | Đang chạy: ${job.step_label}` : '');
  } catch(e){}
}
async function loadJobs(){
  const r = await fetch('/api/jobs'); const list = await r.json();
  document.getElementById('kpiJobs').textContent = list.filter(j=>j.status==='RUNNING').length;
  const nowSec = Date.now() / 1000;
  document.getElementById('jobsTable').innerHTML = list.map(j=>{
    const pct = j.status === 'COMPLETED' ? 100 : (j.progress || (j.status==='RUNNING'?5:0));
    const dur = j.started_ts ? ((j.status==='RUNNING' ? nowSec : (j.finished_ts||nowSec)) - j.started_ts) : 0;
    const cls = j.status==='COMPLETED' ? 'done' : (j.status==='FAILED'||j.status==='INTERRUPTED' ? 'fail' : '');
    return `<tr><td><code>${j.id}</code></td><td>${j.title}${j.status==='RUNNING'&&j.step_label?`<br><small style="color:#94a3b8">${j.step_label}</small>`:''}</td><td class="st-${j.status}">${statusLabel(j.status)}</td>
    <td><div style="display:flex;justify-content:space-between;font-size:11.5px"><span>${pct}%</span><span style="color:#94a3b8">${dur>0?fmtDur(dur):'-'}</span></div><div class="pbar"><div class="pbar-fill ${cls}" style="width:${pct}%"></div></div></td>
    <td>${j.started}</td>
    <td><button class="btn btn-primary" onclick="activeJobId='${j.id}';loadJobLog('${j.id}')">Xem Log</button>${j.status==='RUNNING'?`<button class="btn btn-danger" onclick="stopJob('${j.id}')">Dừng</button>`:`${j.steps?`<button class="btn btn-green" onclick="retryJob('${j.id}')">Chạy lại</button>`:''}<button class="btn btn-gray" onclick="delJob('${j.id}')">Xóa</button>`}</td></tr>`;
  }).join('');
  const cur = list.find(x=>x.id===activeJobId) || list.find(x=>x.status==='RUNNING');
  const wrap = document.getElementById('liveProgWrap');
  if(cur && wrap){
    wrap.classList.remove('hidden');
    const pct = cur.status==='COMPLETED' ? 100 : (cur.progress || 5);
    const dur = cur.started_ts ? ((cur.status==='RUNNING' ? nowSec : (cur.finished_ts||nowSec)) - cur.started_ts) : 0;
    document.getElementById('liveProgStep').textContent = `${cur.title} — ${cur.step_label || statusLabel(cur.status)}`;
    document.getElementById('liveProgMeta').textContent = `${pct}% · Đã chạy: ${fmtDur(dur)}`;
    const fill = document.getElementById('liveProgFill');
    fill.style.width = pct + '%';
    fill.className = 'pbar-fill ' + (cur.status==='COMPLETED'?'done':(cur.status==='FAILED'||cur.status==='INTERRUPTED'?'fail':''));
  }
}
async function stopJob(jid){ if(!confirm('Dừng tác vụ đang chạy?')) return; await fetch('/api/jobs/'+jid+'/stop', {method:'POST'}); loadJobs(); }
let lastLogText = '';
let lastLogJobId = '';
function statusLabel(st){
  return {RUNNING:'Đang chạy', COMPLETED:'Hoàn tất', FAILED:'Lỗi', INTERRUPTED:'Gián đoạn'}[st] || st;
}
function scrollLogBottom(){
  const pre = document.getElementById('jobLog');
  pre.scrollTop = pre.scrollHeight;
}
function downloadCollector(kind){
  if(!window._collectorToken) return alert('Chưa tải xong token!');
  const ep = kind === 'win' ? 'win-collector' : 'linux-collector';
  window.open(`/download/${ep}?token=${encodeURIComponent(window._collectorToken)}&dl=1`, '_blank');
}
async function loadJobLog(jid){
  const r = await fetch('/api/jobs/'+jid+'/log'); const d = await r.json();
  const pre = document.getElementById('jobLog');
  const txt = d.log || '(Chưa có dữ liệu nhật ký)';
  const isNewJob = (jid !== lastLogJobId);
  if(!isNewJob && txt === lastLogText) return;
  const wasAtBottom = (pre.scrollHeight - pre.scrollTop - pre.clientHeight) < 45;
  lastLogJobId = jid;
  lastLogText = txt;
  pre.textContent = txt;
  if(isNewJob || wasAtBottom) pre.scrollTop = pre.scrollHeight;
}
async function loadReportFolders(){
  const r = await fetch('/api/reports'); const folders = await r.json();
  document.getElementById('kpiRep').textContent = folders.length;
  const sel = document.getElementById('repFolder');
  sel.innerHTML = folders.map(f=>`<option value="${f}">${f}</option>`).join('');
  if(folders.length) loadReportFiles();
}
async function loadReportFiles(){
  const folder = document.getElementById('repFolder').value; if(!folder) return;
  const r = await fetch('/api/reports/'+encodeURIComponent(folder)); const files = await r.json();
  const sel = document.getElementById('repFile');
  sel.innerHTML = files.map(f=>`<option value="${f}">${f}</option>`).join('');
  if(files.length) viewReportFile();
}
async function viewReportFile(){
  const folder = document.getElementById('repFolder').value;
  const file = document.getElementById('repFile').value; if(!folder || !file) return;
  const r = await fetch('/api/reports/'+encodeURIComponent(folder)+'/'+encodeURIComponent(file));
  const d = await r.json();
  document.getElementById('repContent').innerHTML = d.html;
}

async function delJob(jid){
  if(!confirm('Xóa lịch sử và log của tác vụ này?')) return;
  await fetch('/api/jobs/'+jid, {method:'DELETE'}); loadJobs();
}
async function clearFinishedJobs(){
  if(!confirm('Xóa toàn bộ lịch sử các tác vụ đã xong / lỗi / gián đoạn?')) return;
  await fetch('/api/jobs', {method:'DELETE'}); loadJobs();
  document.getElementById('jobLog').textContent = 'Đã dọn sạch lịch sử tác vụ.';
}
async function retryJob(jid){
  const r = await fetch('/api/jobs/'+jid+'/retry', {method:'POST'});
  const d = await r.json();
  if(d.job_id){ activeJobId = d.job_id; loadJobs(); loadJobLog(d.job_id); }
}
async function delReportFolder(){
  const folder = document.getElementById('repFolder').value;
  if(!folder) return alert('Chưa chọn đợt báo cáo!');
  if(!confirm('Xóa vĩnh viễn toàn bộ thư mục báo cáo: ' + folder + ' ?')) return;
  const r = await fetch('/api/reports/'+encodeURIComponent(folder), {method:'DELETE'});
  if(r.ok){ document.getElementById('repContent').innerHTML = 'Đã xóa đợt báo cáo.'; loadReportFolders(); }
}

function exportReport(fmt){
  const folder = document.getElementById('repFolder').value;
  if(!folder) return alert('Vui lòng chọn đợt báo cáo!');
  window.open('/api/reports/'+encodeURIComponent(folder)+'/export/'+fmt, '_blank');
}
async function runKatanaScan(){
  const url = document.getElementById('kUrl').value.trim();
  const name = document.getElementById('kName').value.trim() || 'web-surface';
  const depth = parseInt(document.getElementById('kDepth').value || '3');
  const with_ai = document.getElementById('kAi').value === 'yes';
  const with_nuclei = document.getElementById('kNuclei') ? document.getElementById('kNuclei').checked : true;
  if(!url.startsWith('http')) return alert('Vui lòng nhập URL hợp lệ bắt đầu bằng http:// hoặc https://');
  const r = await fetch('/api/katana-scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({url,name,depth,with_ai,with_nuclei, audit_model:(document.getElementById('auditModelSel')||{}).value||'qwen3-vl:8b'})});
  const d = await r.json();
  if(d.job_id){ activeJobId = d.job_id; showTab('jobs', document.querySelectorAll('.nav button')[3]); loadJobs(); loadJobLog(d.job_id); }
}
init();
</script></body></html>"""

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return LOGIN_HTML.replace("{ERR}", "")

@app.post("/login")
def do_login(username: str = Form(...), password: str = Form(...)):
    if verify_password(username, password):
        resp = RedirectResponse(url="/", status_code=303)
        resp.set_cookie("ace_audit_session", SERIALIZER.dumps({"u": username}), httponly=True, samesite="lax", max_age=86400 * 7)
        return resp
    return HTMLResponse(LOGIN_HTML.replace("{ERR}", '<div class="err">Sai tài khoản hoặc mật khẩu!</div>'), status_code=401)

@app.get("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("ace_audit_session")
    return resp

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if not get_current_user(request):
        return RedirectResponse(url="/login", status_code=303)
    return MAIN_HTML

@app.get("/api/status")
def api_status(request: Request):
    require_auth(request)
    try:
        d = json.loads(urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=4).read())
        ms = d.get("models", [])
        return {
            "ollama_ok": True,
            "models": [m["name"] for m in ms],
            "model_details": [{"name": m["name"], "size_gb": round(m.get("size", 0) / (1024**3), 1)} for m in ms],
        }
    except Exception:
        return {"ollama_ok": False, "models": []}

@app.get("/api/telemetry")
def api_telemetry(request: Request):
    require_auth(request)
    gpu = {"gpu_ok": False, "gpu_util": 0, "vram_used_mib": 0, "vram_total_mib": 0, "gpu_temp": 0}
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu", "--format=csv,noheader,nounits"],
            timeout=2, text=True, stderr=subprocess.DEVNULL
        ).strip().splitlines()[0]
        parts = [int(float(x.strip())) for x in out.split(",")]
        gpu = {"gpu_ok": True, "gpu_util": parts[0], "vram_used_mib": parts[1], "vram_total_mib": parts[2], "gpu_temp": parts[3]}
    except Exception:
        pass
    loaded = []
    try:
        ps = json.loads(urllib.request.urlopen(f"{OLLAMA_URL}/api/ps", timeout=1.5).read())
        for m in ps.get("models", []):
            sz = max(1, m.get("size", 0))
            sv = m.get("size_vram", 0)
            loaded.append({"name": m.get("name", ""), "gpu_pct": round((sv / sz) * 100)})
    except Exception:
        pass
    active_job = None
    now_ts = time.time()
    for j in sorted(JOBS.values(), key=lambda x: x.get("started", ""), reverse=True):
        if j.get("status") == "RUNNING":
            active_job = {
                "id": j["id"], "title": j["title"],
                "step_label": j.get("step_label", ""),
                "progress": j.get("progress", 5),
                "elapsed_sec": int(now_ts - j.get("started_ts", now_ts)),
            }
            break
    return {**gpu, "loaded_models": loaded, "active_job": active_job}

@app.get("/api/collector-info")
def api_collector_info(request: Request):
    require_auth(request)
    return {"public_key": PUB_KEY_STR, "token": AUTH_CFG["collector_token"]}

@app.post("/api/collector/rotate-token")
def api_rotate_token(request: Request):
    require_auth(request)
    AUTH_CFG["collector_token"] = secrets.token_hex(20)
    AUTH_FILE.write_text(json.dumps(AUTH_CFG, indent=2), encoding="utf-8")
    return {"ok": True}

@app.get("/download/win-collector", response_class=PlainTextResponse)
def download_win_collector(request: Request, token: str = "", dl: int = 0):
    verify_collector_token(token)
    server_base = str(request.base_url).rstrip("/")
    script = f"""# AI Security Audit v3.0 — Windows CIS & MITRE ATT&CK Deep Collector (100% Read-Only)
$ErrorActionPreference = 'SilentlyContinue'
$hostName = $env:COMPUTERNAME
$work = Join-Path $env:TEMP ("ace_audit_" + $hostName + "_" + (Get-Random))
New-Item -ItemType Directory -Force -Path $work | Out-Null

$sb = New-Object System.Text.StringBuilder
$cv = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
[void]$sb.AppendLine("# Báo Cáo Hiện Trạng Windows & CIS/MITRE Audit ($hostName — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))")
[void]$sb.AppendLine("`n## 1. Hệ Điều Hành & Bản Vá (Hotfixes)")
[void]$sb.AppendLine("| Thông số | Giá trị |")
[void]$sb.AppendLine("|---|---|")
[void]$sb.AppendLine("| **Hostname** | ``$hostName`` |")
[void]$sb.AppendLine("| **OS** | $($cv.ProductName) (Build $($cv.CurrentBuild).$($cv.UBR)) |")
[void]$sb.AppendLine("`n``````text")
[void]$sb.AppendLine((Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID, Description, InstalledOn | Format-Table -AutoSize | Out-String))
[void]$sb.AppendLine("``````")

[void]$sb.AppendLine("`n## 2. Windows Firewall, Defender & Exclusions (MITRE Defense Evasion)")
[void]$sb.AppendLine("``````text")
[void]$sb.AppendLine((Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize | Out-String))
[void]$sb.AppendLine((Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, AntivirusSignatureLastUpdated | Format-List | Out-String))
$mp = Get-MpPreference
[void]$sb.AppendLine("Defender ExclusionPath: " + (($mp.ExclusionPath) -join ', '))
[void]$sb.AppendLine("Defender ExclusionProcess: " + (($mp.ExclusionProcess) -join ', '))
[void]$sb.AppendLine("``````")

[void]$sb.AppendLine("`n## 3. CIS Hardening (RDP / NLA / SMBv1 / LSA / WDigest / UAC / PS Logging)")
$rdp = (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -EA 0).fDenyTSConnections
$nla = (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -EA 0).UserAuthentication
$smb1 = (Get-SmbServerConfiguration -EA 0).EnableSMB1Protocol
$ppl = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -EA 0).RunAsPPL
$wdig = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -EA 0).UseLogonCredential
$uac = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -EA 0).EnableLUA
$pslog = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -EA 0).EnableScriptBlockLogging
[void]$sb.AppendLine("| Kiểm tra CIS | Giá trị thực tế | Chuẩn khuyến nghị |")
[void]$sb.AppendLine("|---|---|---|")
[void]$sb.AppendLine("| **RDP Disabled** | ``$rdp`` | 1 (hoặc bật NLA) |")
[void]$sb.AppendLine("| **RDP NLA** | ``$nla`` | 1 (Bắt buộc NLA) |")
[void]$sb.AppendLine("| **SMBv1 Enabled** | ``$smb1`` | False |")
[void]$sb.AppendLine("| **LSA Protection (RunAsPPL)** | ``$ppl`` | 1 |")
[void]$sb.AppendLine("| **WDigest Plaintext** | ``$wdig`` | 0 hoặc trống |")
[void]$sb.AppendLine("| **UAC (EnableLUA)** | ``$uac`` | 1 |")
[void]$sb.AppendLine("| **PS ScriptBlock Logging** | ``$pslog`` | 1 |")

[void]$sb.AppendLine("`n## 4. Cổng Mạng Đang Mở (Listening TCP Ports)")
[void]$sb.AppendLine("``````text")
[void]$sb.AppendLine((Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort | Sort-Object LocalPort -Unique | Format-Table -AutoSize | Out-String))
[void]$sb.AppendLine("``````")

[void]$sb.AppendLine("`n## 5. MITRE ATT&CK — Unquoted Service Paths, Local Admins & Scheduled Tasks")
[void]$sb.AppendLine("``````text")
[void]$sb.AppendLine("[Local Administrators]")
[void]$sb.AppendLine((Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, ObjectClass | Format-Table -AutoSize | Out-String))
[void]$sb.AppendLine("[Unquoted Service Paths]")
[void]$sb.AppendLine((Get-CimInstance Win32_Service | Where-Object {{ $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -notmatch '^C:\\Windows\\' -and $_.PathName -match ' ' }} | Select-Object Name, State, PathName | Format-Table -AutoSize | Out-String))
[void]$sb.AppendLine("[Non-Microsoft Active Scheduled Tasks (Temp/AppData/Shell)]")
Get-ScheduledTask | Where-Object {{ $_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -ne 'Disabled' }} | ForEach-Object {{
  $act = ($_.Actions | ForEach-Object {{ "$($_.Execute) $($_.Arguments)" }}) -join '; '
  if ($act -match 'Temp|AppData|Users|powershell|cmd\.exe|wscript|mshta') {{ [void]$sb.AppendLine("$($_.TaskName) -> $act") }}
}}
[void]$sb.AppendLine("``````")

[void]$sb.AppendLine("`n## 6. IIS, DB Services, SQL Server & Top 40 Phần Mềm Đã Cài")
[void]$sb.AppendLine("``````text")
Import-Module WebAdministration -EA 0
[void]$sb.AppendLine((Get-Website -EA 0 | Select-Object Name, State, PhysicalPath | Format-Table -AutoSize | Out-String))
[void]$sb.AppendLine((Get-Service | Where-Object {{ $_.Name -match 'SQL|Mongo|Postgres|MySQL|W3SVC|Docker|Redis|Wazuh' }} | Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String))
Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server' -EA 0 | ForEach-Object {{
  $setup = Join-Path $_.PSPath 'Setup'
  if (Test-Path $setup) {{
    $p = Get-ItemProperty $setup
    [void]$sb.AppendLine("SQL Instance=$($_.PSChildName) Edition=$($p.Edition) Version=$($p.Version) PatchLevel=$($p.PatchLevel)")
  }}
}}
[void]$sb.AppendLine((Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -EA 0 | Where-Object {{ $_.DisplayName }} | Select-Object -First 40 DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName | Format-Table -AutoSize | Out-String))
[void]$sb.AppendLine("``````")

Set-Content -Path (Join-Path $work 'live_system_audit.md') -Value $sb.ToString() -Encoding UTF8
if (Test-Path 'C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config') {{
  Copy-Item 'C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config' (Join-Path $work 'applicationHost.config') -Force
}}
$zip = "$work.zip"
Compress-Archive -Path "$work\\*" -DestinationPath $zip -Force
Write-Host "[AI Security Audit v3.0] Uploading CIS/MITRE snapshot for $hostName to {server_base}..." -ForegroundColor Cyan
$resp = Invoke-RestMethod -Uri "{server_base}/api/collector/upload?token={token}&host=$hostName&os=windows" -Method Post -InFile $zip -ContentType "application/zip" -TimeoutSec 120
Write-Host ("[AI Security Audit v3.0] DONE! Job ID: " + $resp.job_id + " | Report: " + $resp.report_tag) -ForegroundColor Green
Remove-Item $work, $zip -Recurse -Force -ErrorAction SilentlyContinue
"""
    hdrs = {"Content-Disposition": "attachment; filename=win_collector.ps1"} if dl else {}
    return PlainTextResponse(script, headers=hdrs)

@app.get("/download/linux-collector", response_class=PlainTextResponse)
def download_linux_collector(request: Request, token: str = "", dl: int = 0):
    verify_collector_token(token)
    server_base = str(request.base_url).rstrip("/")
    script = f"""#!/usr/bin/env bash
set -euo pipefail
HOST=$(hostname)
NOW=$(date -Iseconds)
OS_VER=$(lsb_release -ds 2>/dev/null || grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"')
KERNEL=$(uname -sr)
REBOOT=$([ -f /var/run/reboot-required ] && echo "CẦN REBOOT (YES)" || echo "Không (NO)")
WORK="/tmp/ace_audit_${{HOST}}_$$"
mkdir -p "$WORK/configs"
{{
  echo "# Báo Cáo Hiện Trạng Linux & CIS/MITRE Audit ($HOST — $NOW)"
  echo ""
  echo "## 1. Hệ Điều Hành, Kernel & Gói Chờ Cập Nhật"
  echo "| Thông số | Giá trị |"
  echo "|---|---|"
  echo "| **Hostname** | `$HOST` |"
  echo "| **Hệ điều hành** | $OS_VER |"
  echo "| **Kernel** | `$KERNEL` |"
  echo "| **Trạng thái Reboot** | **$REBOOT** |"
  echo ""
  echo '```text'
  apt list --upgradable 2>/dev/null | grep -v '^Listing' | head -n 40 || true
  echo '```'
  echo "## 2. Cổng Mạng Đang Mở (ss -tulpn)"
  echo '```text'
  ss -tulpn 2>/dev/null || true
  echo '```'
  echo "## 3. Tường Lửa & CIS SSH/Sysctl"
  echo '```text'
  ufw status verbose 2>/dev/null || true
  iptables -S DOCKER-USER 2>/dev/null || true
  grep -iE '^\s*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
  echo "ASLR=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo N/A) | SYNCOOKIES=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo N/A)"
  echo '```'
  echo "## 4. MITRE ATT&CK — UID0, Sudoers NOPASSWD & SUID"
  echo '```text'
  awk -F: '$3 == 0 {{print "UID0:", $1}}' /etc/passwd
  grep -rn "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | head -n 15 || true
  find /usr/local /opt /tmp /var /home -perm -4000 -type f 2>/dev/null | head -n 15 || true
  echo '```'
  echo "## 5. Docker Security Audit"
  echo '```text'
  if command -v docker >/dev/null 2>&1; then
    docker ps --format "table {{{{.Names}}}}\t{{{{.Image}}}}\t{{{{.Status}}}}\t{{{{.Ports}}}}" || true
    for cid in $(docker ps -q 2>/dev/null); do
      docker inspect "$cid" --format '{{{{.Name}}}} | Privileged={{{{.HostConfig.Privileged}}}} | NetMode={{{{.HostConfig.NetworkMode}}}} | User={{{{.Config.User}}}}' || true
    done
  else
    echo "Docker not installed."
  fi
  echo '```'
}} > "$WORK/live_system_audit.md"

for p in /etc/nginx /etc/haproxy /etc/postgresql /etc/mysql /etc/mongod.conf /etc/redis /etc/ssh/sshd_config; do
  [ -e "$p" ] && cp -rL "$p" "$WORK/configs/" 2>/dev/null || true
done

TGZ="${{WORK}}.tar.gz"
tar -czf "$TGZ" -C "$WORK" .
echo "[AI Security Audit v3.0] Uploading CIS/MITRE snapshot for $HOST to {server_base}..."
curl -fsS -X POST --data-binary @"$TGZ" -H "Content-Type: application/gzip" "{server_base}/api/collector/upload?token={token}&host=${{HOST}}&os=linux"
echo ""
rm -rf "$WORK" "$TGZ"
"""
    hdrs = {"Content-Disposition": "attachment; filename=linux_collector.sh"} if dl else {}
    return PlainTextResponse(script, headers=hdrs)

@app.post("/api/collector/upload")
async def api_collector_upload(request: Request, token: str = "", host: str = "unknown", os: str = "windows"):
    verify_collector_token(token)
    safe_host = re.sub(r"[^a-zA-Z0-9_-]+", "-", host.lower()).strip("-") or "host"
    pid = f"push-{safe_host}"
    dest = TARGETS_DIR / pid
    dest.mkdir(parents=True, exist_ok=True)
    raw = await request.body()
    if len(raw) > 80 * 1024 * 1024:
        raise HTTPException(413, "Payload too large")

    if request.headers.get("content-type", "").startswith("application/gzip") or os == "linux":
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
            for m in tf.getmembers():
                if not m.isfile() or m.size > 3 * 1024 * 1024:
                    continue
                rel = m.name.lstrip("/").replace("..", "__")
                t = dest / rel
                t.parent.mkdir(parents=True, exist_ok=True)
                f = tf.extractfile(m)
                if f:
                    t.write_bytes(f.read())
    else:
        with zipfile.ZipFile(io.BytesIO(raw), "r") as zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size > 3 * 1024 * 1024:
                    continue
                rel = info.filename.replace("\\", "/").lstrip("/").replace("..", "__")
                t = dest / rel
                t.parent.mkdir(parents=True, exist_ok=True)
                t.write_bytes(zf.read(info))

    projs = load_projects()
    if not any(p["id"] == pid for p in projs):
        stacks = ["owasp", "api", "dotnet", "mssql"] if os == "windows" else ["owasp", "ubuntu", "nginx", "docker", "mongodb", "postgresql", "mysql"]
        projs.append({
            "id": pid, "name": f"{host} (1-Line {os.upper()} Collector)", "mode": "push",
            "path": str(dest), "stacks": stacks, "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
        })
        save_projects(projs)

    tag = f"{datetime.now().strftime('%Y-%m-%d_%H%M')}_{pid}"
    wsl_src = win_to_wsl(str(dest))
    wsl_rep = f"/mnt/f/ERP-Audit-Lab/reports/{tag}"
    bash_cmd = (
        f"mkdir -p '{wsl_rep}' && "
        f"([ -f '{wsl_src}/live_system_audit.md' ] && cp '{wsl_src}/live_system_audit.md' '{wsl_rep}/00_live_system_audit.md' || true) && "
        f"gitleaks detect --source '{wsl_src}' --no-git --report-format json --report-path '{wsl_rep}/01_gitleaks_secrets.json' --exit-code 0 || true; "
        f"trivy fs --timeout 5m --skip-dirs '**/node_modules,node_modules,**/.next,.next,**/vendor,vendor,**/.git,.git,**/uploads,uploads,**/cache,cache,**/wp-content/uploads' --skip-files '**/*.min.js,**/*.map' --scanners vuln,misconfig --misconfig-scanners dockerfile,terraform,kubernetes --format json --output '{wsl_rep}/02_trivy_sca.json' '{wsl_src}' || true; "
        f"semgrep scan --timeout 300 --config /mnt/f/ERP-Audit-Lab/rules --json --output '{wsl_rep}/03_semgrep_sast.json' '{wsl_src}' || true; "
        f"echo 'PUSH AUDIT COMPLETE -> F:\\ERP-Audit-Lab\\reports\\{tag}'"
    )
    jid = start_job(f"1-Line Push Audit: {host}", [
        ("SAST + Secret + SCA (15 Stacks)", ["wsl", "-u", "root", "bash", "-c", bash_cmd]),
        ("AI System Security Audit (qwen3-vl:8b)", [WIN_PY, r"F:\ERP-Audit-Lab\scripts\ai_auditor.py", "--mode", "system", "--repo", str(dest), "--reports", rf"F:\ERP-Audit-Lab\reports\{tag}", "--audit-model", "qwen3-vl:8b"]),
    ])
    return {"ok": True, "project_id": pid, "job_id": jid, "report_tag": tag}

@app.get("/api/projects")
def api_list_projects(request: Request):
    require_auth(request)
    return load_projects()

@app.post("/api/projects")
async def api_save_project(request: Request):
    require_auth(request)
    body = await request.json()
    projs = load_projects()
    edit_id = (body.get("edit_id") or "").strip()
    mode = body.get("mode", "local")
    pid = edit_id if edit_id else (re.sub(r"[^a-z0-9-]+", "-", body["name"].lower()).strip("-") or secrets.token_hex(4))
    if not edit_id and any(p["id"] == pid for p in projs):
        pid = f"{pid}-{secrets.token_hex(2)}"

    entry = {
        "id": pid, "name": body["name"], "mode": mode,
        "stacks": body.get("stacks", ALL_STACKS),
        "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
    if mode == "ssh":
        entry.update({
            "os_type": body.get("os_type", "linux"),
            "ssh_host": body["ssh_host"],
            "ssh_port": int(body.get("ssh_port", 22)),
            "ssh_user": body["ssh_user"],
            "ssh_auth": body.get("ssh_auth", "key"),
            "remote_paths": body.get("remote_paths", ""),
            "path": str(TARGETS_DIR / pid),
        })
        secs = load_secrets()
        if body.get("ssh_password"):
            secs.setdefault(pid, {})["ssh_password"] = body["ssh_password"]
        if body.get("custom_key", "").strip():
            ck = KEYS_DIR / f"custom_{pid}.key"
            ck.write_text(body["custom_key"].strip() + "\n", encoding="utf-8")
            secs.setdefault(pid, {})["custom_key_path"] = str(ck)
        save_secrets(secs)
    else:
        entry["path"] = body["path"].rstrip("<>\"' ")

    if edit_id:
        projs = [entry if p["id"] == edit_id else p for p in projs]
    else:
        projs.append(entry)
    save_projects(projs)
    return {"ok": True, "id": pid}

@app.delete("/api/projects/{pid}")
def api_del_project(pid: str, request: Request):
    require_auth(request)
    pass
    save_projects([p for p in load_projects() if p["id"] != pid])
    secs = load_secrets()
    if pid in secs:
        del secs[pid]
        save_secrets(secs)
    return {"ok": True}

@app.post("/api/projects/{pid}/test-ssh")
def api_test_ssh(pid: str, request: Request):
    require_auth(request)
    proj = next((p for p in load_projects() if p["id"] == pid), None)
    if not proj or proj.get("mode") != "ssh":
        raise HTTPException(404, "SSH project not found")
    secs = load_secrets().get(pid, {})
    try:
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        auth = proj.get("ssh_auth", "key")
        if auth == "key":
            cli.connect(proj["ssh_host"], port=int(proj.get("ssh_port", 22)), username=proj["ssh_user"], pkey=load_pkey_any(str(KEY_PRIV)), timeout=10, look_for_keys=False, allow_agent=False)
        elif auth == "custom_key":
            cli.connect(proj["ssh_host"], port=int(proj.get("ssh_port", 22)), username=proj["ssh_user"], pkey=load_pkey_any(secs.get("custom_key_path", "")), timeout=10, look_for_keys=False, allow_agent=False)
        else:
            pwd = secs.get("ssh_password", "")
            try:
                cli.connect(proj["ssh_host"], port=int(proj.get("ssh_port", 22)), username=proj["ssh_user"], password=pwd, timeout=10, look_for_keys=False, allow_agent=False)
            except paramiko.AuthenticationException:
                tr = paramiko.Transport((proj["ssh_host"], int(proj.get("ssh_port", 22))))
                tr.connect()
                tr.auth_interactive(proj["ssh_user"], lambda t, i, pr: [pwd for _ in pr])
                cli._transport = tr
        cmd = "hostname && uname -sr" if proj.get("os_type", "linux") == "linux" else "hostname"
        _, o, _ = cli.exec_command(cmd, timeout=10)
        info = o.read().decode("utf-8", "ignore").strip()
        cli.close()
        return {"ok": True, "info": info}
    except Exception as ex:
        return {"ok": False, "error": str(ex)}

@app.post("/api/scan")
async def api_scan(request: Request):
    require_auth(request)
    body = await request.json()
    pid = body.get("project_id")
    mode = body.get("mode", "quick")
    proj = next((p for p in load_projects() if p["id"] == pid), None)
    if not proj:
        raise HTTPException(404, "Project not found")

    tag = f"{datetime.now().strftime('%Y-%m-%d_%H%M')}_{pid}"
    wsl_src = win_to_wsl(proj["path"])
    wsl_rep = f"/mnt/f/ERP-Audit-Lab/reports/{tag}"
    steps = []

    if proj.get("mode") == "ssh":
        secs = load_secrets().get(pid, {})
        cfg_file = JOBS_DIR / f"sync_{pid}_{secrets.token_hex(3)}.json"
        key_path = secs.get("custom_key_path", str(KEY_PRIV)) if proj.get("ssh_auth") == "custom_key" else str(KEY_PRIV)
        cfg_data = {
            "os_type": proj.get("os_type", "linux"),
            "ssh_host": proj["ssh_host"],
            "ssh_port": proj.get("ssh_port", 22),
            "ssh_user": proj["ssh_user"],
            "ssh_auth": proj.get("ssh_auth", "key"),
            "key_path": key_path,
            "ssh_password": secs.get("ssh_password", ""),
            "remote_paths": proj.get("remote_paths", ""),
            "local_path": proj["path"],
        }
        cfg_file.write_text(json.dumps(cfg_data), encoding="utf-8")
        steps.append((
            f"Agentless SSH Sync ({proj['ssh_user']}@{proj['ssh_host']})",
            [WIN_PY, r"F:\ERP-Audit-Lab\scripts\agentless_collector.py", "--config-json", str(cfg_file)]
        ))

    bash_sast = (
        f"mkdir -p '{wsl_rep}' && "
        f"([ -f '{wsl_src}/live_system_audit.md' ] && cp '{wsl_src}/live_system_audit.md' '{wsl_rep}/00_live_system_audit.md' || true) && "
        f"echo '[1/3] Gitleaks Secret Scan...' && "
        f"gitleaks detect --source '{wsl_src}' --no-git --report-format json --report-path '{wsl_rep}/01_gitleaks_secrets.json' --exit-code 0 || true; "
        f"echo '[2/3] Trivy SCA & Misconfig...' && "
        f"trivy fs --timeout 5m --skip-dirs '**/node_modules,node_modules,**/.next,.next,**/vendor,vendor,**/.git,.git,**/uploads,uploads,**/cache,cache,**/wp-content/uploads' --skip-files '**/*.min.js,**/*.map' --scanners vuln,misconfig --misconfig-scanners dockerfile,terraform,kubernetes --format json --output '{wsl_rep}/02_trivy_sca.json' '{wsl_src}' || true; "
        f"echo '[3/3] Semgrep SAST (15 Stacks)...' && "
        f"semgrep scan --timeout 300 --config /mnt/f/ERP-Audit-Lab/rules --json --output '{wsl_rep}/03_semgrep_sast.json' '{wsl_src}' || true; "
        f"echo 'SCAN COMPLETE -> F:\\ERP-Audit-Lab\\reports\\{tag}'"
    )
    steps.append(("SAST + Secret + SCA (15 Stacks)", ["wsl", "-u", "root", "bash", "-c", bash_sast]))
    if mode == "full":
        steps.append((
            "AI 3-Agent Deep Audit (Ollama Local)",
            [WIN_PY, r"F:\ERP-Audit-Lab\scripts\ai_auditor.py", "--mode", "full", "--repo", proj["path"], "--reports", rf"F:\ERP-Audit-Lab\reports\{tag}", "--audit-model", body.get("audit_model", "qwen3-vl:8b"), "--critic-model", body.get("critic_model", "deepseek-r1:14b")]
        ))
        jid = start_job(f"Full AI Audit: {proj['name']}", steps)
    else:
        jid = start_job(f"Quick Scan: {proj['name']}", steps)
    return {"job_id": jid, "report_tag": tag}

@app.post("/api/patch-diff")
async def api_patch_diff(request: Request):
    require_auth(request)
    body = await request.json()
    name = re.sub(r"[^a-zA-Z0-9_-]+", "_", body.get("name", "patch_diff"))
    model = body.get("model", "qwen3:30b-a3b")
    diff_text = body.get("diff_text", "")
    tag = f"{datetime.now().strftime('%Y-%m-%d_%H%M')}_{name}"
    rep_dir = REPORTS_ROOT / tag
    rep_dir.mkdir(parents=True, exist_ok=True)
    diff_file = rep_dir / "input.diff"
    diff_file.write_text(diff_text, encoding="utf-8")
    py_code = (
        f"import json, re, urllib.request; from pathlib import Path; "
        f"diff = Path(r'{diff_file}').read_text(encoding='utf-8', errors='ignore'); "
        f"payload = {{'model':'{model}','stream':False,'options':{{'temperature':0.1,'num_ctx':16384}},'messages':["
        f"{{'role':'system','content':'Ban la Chuyen gia Patch-Diff & Variant Analysis. Phan tich Security Regression va Variant Analysis bang tieng Viet, kem de xuat sua code & ModSecurity rule.'}},"
        f"{{'role':'user','content':'Phan tich ban diff sau:\\n```diff\\n'+diff[:26000]+'\\n```'}}]}}; "
        f"req = urllib.request.Request('{OLLAMA_URL}/api/chat', data=json.dumps(payload).encode(), headers={{'Content-Type':'application/json'}}, method='POST'); "
        f"res = json.loads(urllib.request.urlopen(req, timeout=900).read())['message']['content']; "
        f"res = re.sub(r'<think>[\\s\\S]*?</think>','',res).strip(); "
        f"Path(r'{rep_dir}\\06_patch_diff_audit.md').write_text('# Bao cao Patch-Diff & Variant Analysis\\n\\n'+res, encoding='utf-8'); "
        f"print('SAVED 06_patch_diff_audit.md OK')"
    )
    jid = start_job(f"Patch-Diff AI: {name}", [("AI Patch-Diff & Variant Analysis", [WIN_PY, "-c", py_code])])
    return {"job_id": jid, "report_tag": tag}

@app.get("/api/jobs")
def api_jobs(request: Request):
    require_auth(request)
    return sorted(JOBS.values(), key=lambda x: x["started"], reverse=True)[:30]

@app.get("/api/jobs/{jid}/log")
def api_job_log(jid: str, request: Request):
    require_auth(request)
    j = JOBS.get(jid)
    if not j:
        raise HTTPException(404, "Job not found")
    lp = Path(j["log_file"])
    return {"status": j["status"], "log": lp.read_text(encoding="utf-8", errors="ignore")[-25000:] if lp.exists() else ""}

@app.get("/api/reports")
def api_reports(request: Request):
    require_auth(request)
    return sorted([d.name for d in REPORTS_ROOT.iterdir() if d.is_dir()], reverse=True) if REPORTS_ROOT.exists() else []

@app.get("/api/reports/{folder}")
def api_report_files(folder: str, request: Request):
    require_auth(request)
    d = (REPORTS_ROOT / folder).resolve()
    if not str(d).startswith(str(REPORTS_ROOT.resolve())) or not d.exists():
        raise HTTPException(404, "Not found")
    return sorted([f.name for f in d.iterdir() if f.is_file()])

@app.get("/api/reports/{folder}/{filename}")
def api_report_content(folder: str, filename: str, request: Request):
    require_auth(request)
    fp = (REPORTS_ROOT / folder / filename).resolve()
    if not str(fp).startswith(str(REPORTS_ROOT.resolve())) or not fp.exists():
        raise HTTPException(404, "Not found")
    raw = fp.read_text(encoding="utf-8", errors="ignore")
    if fp.suffix.lower() == ".md":
        return {"html": markdown.markdown(raw, extensions=["fenced_code", "tables"])}
    if fp.suffix.lower() == ".json":
        try:
            data = json.loads(raw)
            if "01_gitleaks" in fp.name and isinstance(data, list):
                sol = report_exporter.REMEDIATION_KB["hardcoded"]
                rows = "".join(
                    f"<tr><td><span class='sev-CRITICAL'>CRITICAL</span></td><td>{x.get('RuleID','')}</td><td><code>{x.get('File','')}</code>:{x.get('StartLine','')}</td><td>***REDACTED***</td><td>{sol}</td></tr>"
                    for x in data[:100]
                )
                return {"html": f"<h3>Gitleaks — Lộ Thông Tin Nhạy Cảm ({len(data)} phát hiện — đã che giá trị)</h3><table><tr><th>Mức độ</th><th>Loại Secret</th><th>Vị trí</th><th>Giá trị</th><th>Giải pháp khắc phục (Solution)</th></tr>{rows}</table>"}
            if "02_trivy" in fp.name and isinstance(data, dict):
                v_rows, m_rows = [], []
                for res in data.get("Results", []) or []:
                    tgt = res.get("Target", "")
                    for v in res.get("Vulnerabilities", []) or []:
                        sv = report_exporter.normalize_severity(v.get("Severity", "MEDIUM"))
                        fx = v.get("FixedVersion", "")
                        pkg = v.get("PkgName", "")
                        sol = f"Nâng cấp gói <code>{pkg}</code> lên <code>{fx}</code>." if fx else f"Áp dụng WAF/Virtual Patch & theo dõi bản vá cho <code>{pkg}</code>."
                        v_rows.append(f"<tr><td><span class='sev-{sv}'>{sv}</span></td><td><code>{v.get('VulnerabilityID','')}</code></td><td><code>{pkg}</code> ({v.get('InstalledVersion','')})</td><td><code>{fx or 'Chưa có'}</code></td><td>{sol}</td></tr>")
                    for m in res.get("Misconfigurations", []) or []:
                        sv = report_exporter.normalize_severity(m.get("Severity", "MEDIUM"), m.get("ID", ""))
                        sol = m.get("Resolution", "") or report_exporter.get_solution(m.get("ID", ""), m.get("Title", ""))
                        m_rows.append(f"<tr><td><span class='sev-{sv}'>{sv}</span></td><td><code>{m.get('ID','')}</code></td><td>{m.get('Title','')} (<code>{tgt}</code>)</td><td>{sol}</td></tr>")
                html_out = f"<h3>Trivy SCA — Lỗ hổng thư viện (CVE): {len(v_rows)} phát hiện</h3>"
                if v_rows:
                    html_out += f"<table><tr><th>Mức độ</th><th>CVE</th><th>Gói thư viện</th><th>Bản vá</th><th>Giải pháp khắc phục (Solution)</th></tr>{''.join(v_rows[:200])}</table>"
                else:
                    html_out += "<p style='color:#4ade80'>Không phát hiện lỗ hổng CVE thư viện nào.</p>"
                if m_rows:
                    html_out += f"<h3 style='margin-top:18px'>Trivy Misconfiguration — Lỗi cấu hình: {len(m_rows)} phát hiện</h3><table><tr><th>Mức độ</th><th>Mã lỗi</th><th>Mô tả</th><th>Giải pháp khắc phục (Solution)</th></tr>{''.join(m_rows[:150])}</table>"
                return {"html": html_out}
            if "03_semgrep" in fp.name and isinstance(data, dict):
                res = data.get("results", [])
                sev_ord = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                items = []
                for r in res[:150]:
                    cid = r.get("check_id", "").split(".")[-1]
                    msg = r.get("extra", {}).get("message", "")
                    sv = report_exporter.normalize_severity(r.get("extra", {}).get("severity", "INFO"), cid)
                    sol = report_exporter.get_solution(cid, msg)
                    loc = f"{r.get('path','')}:{r.get('start',{}).get('line','')}"
                    items.append((sev_ord.get(sv, 9), f"<tr><td><span class='sev-{sv}'>{sv}</span></td><td><code>{cid}</code></td><td><code>{loc}</code></td><td>{msg}</td><td>{sol}</td></tr>"))
                items.sort(key=lambda x: x[0])
                rows = "".join(x[1] for x in items)
                return {"html": f"<h3>Semgrep SAST — Phân tích mã nguồn tĩnh ({len(res)} phát hiện)</h3><table><tr><th>Mức độ</th><th>Quy tắc</th><th>Vị trí</th><th>Mô tả</th><th>Giải pháp khắc phục (Solution)</th></tr>{rows}</table>"}
        except Exception:
            pass
    return {"html": f"<pre>{raw[:30000]}</pre>"}


@app.post("/api/katana-scan")
async def api_katana_scan(request: Request):
    require_auth(request)
    body = await request.json()
    url = (body.get("url") or "").strip()
    if not re.match(r"^https?://[^\s'\"`;&|<>]+$", url):
        raise HTTPException(400, "Invalid URL")
    name = re.sub(r"[^a-zA-Z0-9_-]+", "_", body.get("name", "web_surface"))
    depth = max(1, min(5, int(body.get("depth", 3))))
    with_ai = bool(body.get("with_ai", False))
    with_nuclei = bool(body.get("with_nuclei", True))
    tag = f"{datetime.now().strftime('%Y-%m-%d_%H%M')}_katana_{name}"
    wsl_rep = f"/mnt/f/ERP-Audit-Lab/reports/{tag}"
    nuc_part = (
        f"echo '[3/3] Running Nuclei Safe Profile (CVE / Misconfig / Exposure, -rl 10)...' && "
        f"if command -v nuclei >/dev/null 2>&1; then "
        f"nuclei -u '{url}' -severity critical,high,medium -tags cve,misconfig,exposure,panel,default-login -rl 10 -c 5 -timeout 8 -silent -nc -o '{wsl_rep}/nuclei.txt' 2>/dev/null || true; "
        f"else echo 'Nuclei chưa cài đặt' > '{wsl_rep}/nuclei.txt'; fi; "
    ) if with_nuclei else ""
    bash_cmd = (
        f"mkdir -p '{wsl_rep}' && "
        f"echo '[1/3] Running httpx fingerprint & TLS/Header probe...' && "
        f"echo '{url}' | httpx -title -status-code -tech-detect -server -tls-grab -silent > '{wsl_rep}/httpx.txt' 2>&1 || true; "
        f"echo '[2/3] Running Katana safe crawl (depth={depth}, rate-limit=10/s)...' && "
        f"katana -u '{url}' -d {depth} -c 3 -rl 10 -jc -kf all -silent -o '{wsl_rep}/katana_urls.txt' 2>/dev/null || true; "
        f"{nuc_part}"
        f"{{ echo '# Báo Cáo Khám Phá Bề Mặt Web & Nuclei Safe Scan ({url})'; echo ''; "
        f"echo '## 1. HTTPX Fingerprint (Tech Stack / Server / TLS / Status)'; echo '```text'; cat '{wsl_rep}/httpx.txt'; echo '```'; "
        f"echo '## 2. Nuclei Safe Vulnerability Scan (Critical / High / Medium)'; echo '```text'; ([ -s '{wsl_rep}/nuclei.txt' ] && cat '{wsl_rep}/nuclei.txt' || echo 'Không phát hiện lỗ hổng Nuclei (Safe Profile).'); echo '```'; "
        f"echo '## 3. Discovered Endpoints & JS Routes (Katana — top 200)'; echo '```text'; head -n 200 '{wsl_rep}/katana_urls.txt' 2>/dev/null || true; echo '```'; "
        f"}} > '{wsl_rep}/07_web_surface_katana.md'; "
        f"echo \"DISCOVERED_URLS=$(wc -l < '{wsl_rep}/katana_urls.txt' 2>/dev/null || echo 0)\""
    )
    steps = [(f"Katana + httpx + Nuclei Safe Scan ({url})", ["wsl", "-u", "root", "bash", "-c", bash_cmd])]
    if with_ai:
        k_model = re.sub(r"[^a-zA-Z0-9_.:-]+", "", body.get("audit_model", "qwen3-vl:8b")) or "qwen3-vl:8b"
        py_ai = (
            f"import json, re, urllib.request; from pathlib import Path; "
            f"rep = Path(r'F:\\ERP-Audit-Lab\\reports\\{tag}'); "
            f"surf = (rep / '07_web_surface_katana.md').read_text(encoding='utf-8', errors='ignore'); "
            f"payload = {{'model':'{k_model}','stream':False,'options':{{'temperature':0.1,'num_ctx':16384}},'messages':["
            f"{{'role':'system','content':'Ban la Chuyen gia AppSec. Phan tich danh sach endpoint & fingerprint tu Katana/httpx de chi ra Shadow API, duong dan quan tri/nhay cam lo ra ngoai, thieu security header, va de xuat hardening/ModSecurity rule bang tieng Viet.'}},"
            f"{{'role':'user','content':surf[:24000]}}]}}; "
            f"req = urllib.request.Request('{OLLAMA_URL}/api/chat', data=json.dumps(payload).encode(), headers={{'Content-Type':'application/json'}}, method='POST'); "
            f"res = json.loads(urllib.request.urlopen(req, timeout=900).read())['message']['content']; "
            f"res = re.sub(r'<think>[\\s\\S]*?</think>','',res).strip(); "
            f"(rep / '05_ai_deep_audit_report.md').write_text('# Phan Tich AI — Web Surface & Shadow API ({url})\\n\\n'+res, encoding='utf-8'); "
            f"print('AI_SURFACE_ANALYSIS_OK')"
        )
        steps.append(("AI Shadow API & Exposure Analysis (Ollama Local)", [WIN_PY, "-c", py_ai]))
    jid = start_job(f"Web Surface (Katana): {url}", steps)
    return {"job_id": jid, "report_tag": tag}

@app.get("/api/reports/{folder}/export/{fmt}")
def api_export_report(folder: str, fmt: str, request: Request):
    require_auth(request)
    d = (REPORTS_ROOT / folder).resolve()
    if not str(d).startswith(str(REPORTS_ROOT.resolve())) or not d.exists():
        raise HTTPException(404, "Report folder not found")
    safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "_", folder)
    if fmt == "excel":
        out = d / f"AI_Security_Audit_Report_{safe_name}.xlsx"
        report_exporter.export_excel(d, out)
        return FileResponse(str(out), filename=out.name, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    if fmt == "pdf":
        out = d / f"AI_Security_Audit_Report_{safe_name}.pdf"
        report_exporter.export_pdf(d, out)
        return FileResponse(str(out), filename=out.name, media_type="application/pdf")
    raise HTTPException(400, "Format must be pdf or excel")


@app.post("/api/jobs/{jid}/stop")
def api_stop_job(jid: str, request: Request):
    require_auth(request)
    j = JOBS.get(jid)
    if not j:
        raise HTTPException(404, "Job not found")
    j["stop_requested"] = True
    proc = JOB_PROCS.get(jid)
    if proc and proc.poll() is None:
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        except Exception:
            proc.terminate()
    j["status"] = "FAILED"
    j["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    j["finished_ts"] = time.time()
    save_jobs_store()
    return {"ok": True}


@app.delete("/api/jobs")
def api_clear_jobs(request: Request):
    require_auth(request)
    for jid in list(JOBS.keys()):
        if JOBS[jid].get("status") != "RUNNING":
            lp = Path(JOBS[jid].get("log_file", ""))
            if lp.exists():
                lp.unlink(missing_ok=True)
            del JOBS[jid]
    save_jobs_store()
    return {"ok": True}

@app.delete("/api/jobs/{jid}")
def api_delete_job(jid: str, request: Request):
    require_auth(request)
    j = JOBS.get(jid)
    if not j:
        raise HTTPException(404, "Job not found")
    if j.get("status") == "RUNNING":
        raise HTTPException(400, "Stop the running job before deleting")
    lp = Path(j.get("log_file", ""))
    if lp.exists():
        lp.unlink(missing_ok=True)
    del JOBS[jid]
    save_jobs_store()
    return {"ok": True}

@app.post("/api/jobs/{jid}/retry")
def api_retry_job(jid: str, request: Request):
    require_auth(request)
    j = JOBS.get(jid)
    if not j or not j.get("steps"):
        raise HTTPException(404, "Job steps not available for retry")
    new_jid = start_job(j["title"] + " (Retry)", j["steps"])
    return {"ok": True, "job_id": new_jid}

@app.delete("/api/reports/{folder}")
def api_delete_report(folder: str, request: Request):
    require_auth(request)
    d = (REPORTS_ROOT / folder).resolve()
    if not str(d).startswith(str(REPORTS_ROOT.resolve())) or d == REPORTS_ROOT.resolve() or not d.exists():
        raise HTTPException(404, "Report folder not found")
    shutil.rmtree(d)
    return {"ok": True}
