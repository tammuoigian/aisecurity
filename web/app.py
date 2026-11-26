import hashlib
import hmac
import io
import json
import os
import re
import secrets
import subprocess
import tarfile
import threading
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

JOBS = {}

def start_job(title: str, steps: list):
    jid = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    log_path = JOBS_DIR / f"{jid}.log"
    JOBS[jid] = {
        "id": jid, "title": title, "status": "RUNNING",
        "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "finished": "", "log_file": str(log_path), "rc": None,
    }
    def runner():
        rc = 0
        with open(log_path, "w", encoding="utf-8", errors="replace") as lf:
            lf.write(f"[{datetime.now().strftime('%H:%M:%S')}] START: {title}\n")
            lf.flush()
            try:
                for step_name, cmd_list in steps:
                    lf.write(f"\n>>> {step_name}\n")
                    lf.flush()
                    proc = subprocess.Popen(
                        cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, encoding="utf-8", errors="replace"
                    )
                    for line in proc.stdout:
                        lf.write(line)
                        lf.flush()
                    rc = proc.wait()
                    if rc != 0:
                        lf.write(f"\n[STOPPED] Step '{step_name}' exited with code {rc}\n")
                        break
                JOBS[jid]["rc"] = rc
                JOBS[jid]["status"] = "COMPLETED" if rc == 0 else "FAILED"
                lf.write(f"\n[{datetime.now().strftime('%H:%M:%S')}] FINAL EXIT CODE: {rc}\n")
            except Exception as ex:
                JOBS[jid]["status"] = "FAILED"
                lf.write(f"\nERROR: {ex}\n")
            JOBS[jid]["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    threading.Thread(target=runner, daemon=True).start()
    return jid

app = FastAPI(title="AI Security Audit Platform v2.2")

LOGIN_HTML = """<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><title>AI Security Audit v2.2</title>
<style>
body{margin:0;background:#0b1120;color:#e2e8f0;font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh}
.card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:32px;width:360px;box-shadow:0 20px 50px rgba(0,0,0,.5)}
h1{font-size:20px;margin:0 0 8px;color:#38bdf8} p{color:#94a3b8;font-size:13px;margin:0 0 20px}
label{display:block;font-size:12px;color:#94a3b8;margin:12px 0 4px}
input{width:100%;box-sizing:border-box;padding:10px 12px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#f8fafc;font-size:14px}
button{margin-top:20px;width:100%;padding:11px;background:#0284c7;border:none;border-radius:8px;color:#fff;font-weight:600;cursor:pointer;font-size:14px}
.err{color:#f87171;font-size:13px;margin-top:10px}
</style></head><body><div class="card">
<h1>AI Security Audit v2.2</h1>
<p>15 Ecosystems · Agentless SSH · 1-Line Push Collector (Port 2810)</p>
<form method="post" action="/login">
<label>Username</label><input name="username" value="admin" required>
<label>Password</label><input name="password" type="password" required autofocus>
<button type="submit">Đăng nhập</button>{ERR}
</form></div></body></html>"""

MAIN_HTML = r"""<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><title>AI Security Audit v2.2 — Port 2810</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0b1120;color:#e2e8f0;font-family:system-ui,-apple-system,sans-serif;font-size:14px}
header{background:#0f172a;border-bottom:1px solid #1e293b;padding:14px 24px;display:flex;align-items:center;justify-content:space-between}
header h1{margin:0;font-size:18px;color:#38bdf8}
.badge{display:inline-block;padding:3px 9px;border-radius:999px;font-size:11px;font-weight:600;background:#1e293b;color:#38bdf8;margin-left:6px}
.badge-ssh{background:#064e3b;color:#34d399} .badge-local{background:#1e3a8a;color:#93c5fd} .badge-push{background:#581c87;color:#d8b4fe}
.nav{display:flex;gap:8px;padding:12px 24px;background:#0f172a;border-bottom:1px solid #1e293b;flex-wrap:wrap}
.nav button{background:#1e293b;color:#cbd5e1;border:1px solid #334155;padding:8px 16px;border-radius:8px;cursor:pointer;font-weight:600}
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
.st-RUNNING{color:#facc15;font-weight:700} .st-COMPLETED{color:#4ade80;font-weight:700} .st-FAILED{color:#f87171;font-weight:700}
.hidden{display:none}
.keybox{background:#020617;border:1px solid #1e293b;border-radius:8px;padding:10px 12px;font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all;color:#34d399;margin:6px 0}
</style></head><body>
<header>
  <div><h1>AI Security Audit v2.2 <span class="badge badge-ssh">Agentless SSH</span><span class="badge badge-push">1-Line Collector</span><span class="badge">15 Stacks</span></h1></div>
  <div><span id="ollamaBadge" class="badge">Checking Ollama...</span> <a href="/logout" style="color:#94a3b8;margin-left:14px;text-decoration:none;font-size:13px">Đăng xuất</a></div>
</header>
<div class="nav">
  <button class="active" onclick="showTab('projects',this)">1. Dự án &amp; Quét Agentless</button>
  <button onclick="showTab('sshkey',this)">2. SSH Key &amp; 1-Line Collector (Win/Linux)</button>
  <button onclick="showTab('diff',this)">3. Patch-Diff &amp; Variant Analysis</button>
  <button onclick="showTab('jobs',this)">4. Tiến trình &amp; Live Log</button>
  <button onclick="showTab('katana',this)">5. Web Surface (Katana + httpx)</button>
  <button onclick="showTab('reports',this)">6. Báo cáo &amp; Xuất PDF/Excel</button>
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
      <h2>Danh sách Dự án &amp; Máy chủ (1-Click Agentless Audit)</h2>
      <table><thead><tr><th>Dự án / Chế độ</th><th>Kết nối / Nguồn</th><th>Hệ sinh thái</th><th>Hành động</th></tr></thead><tbody id="projTable"></tbody></table>
    </div>
    <div class="card">
      <h2 id="formTitle">+ Thêm Máy chủ (Agentless SSH) hoặc Thư mục Local</h2>
      <input type="hidden" id="editId" value="">
      <div class="row">
        <div><label>Tên dự án / Máy chủ</label><input id="pName" placeholder="VD: My-Server-01"></div>
        <div><label>Chế độ quét</label>
          <select id="pMode" onchange="toggleMode()">
            <option value="ssh">Agentless Remote Server (SSH — Tự động quét toàn bộ hệ thống)</option>
            <option value="local">Local Folder trên <AUDIT_SERVER></option>
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
          <label>Dán nội dung Private Key (OpenSSH / RSA / ECDSA):</label>
          <textarea id="sCustomKey" placeholder="Paste SSH Private Key here..."></textarea>
        </div>
        <div style="margin-bottom:12px">
          <label>Đường dẫn mã nguồn cụ thể (<b>ĐỂ TRỐNG = MẶC ĐỊNH TỰ ĐỘNG QUÉT TOÀN BỘ HỆ THỐNG</b>: OS + Firewall + Docker + Nginx/DB/MongoDB + Tự dò toàn bộ app trong /var/www, /opt, /srv, /home, /root):</label>
          <input id="sPaths" placeholder="Để trống để Auto-Discover toàn hệ thống — hoặc nhập đường dẫn cụ thể VD: /var/www/app1, /opt/mcp">
        </div>
      </div>

      <div id="box-local" class="hidden" style="margin-bottom:12px">
        <label>Đường dẫn thư mục có sẵn trên <AUDIT_SERVER></label>
        <input id="pPath" placeholder="VD: F:\ERP-Audit-Lab\repo">
      </div>

      <label>Chọn hệ sinh thái cần quét (15 hệ sinh thái):</label>
      <div class="stacks" id="stackBoxes"></div>
      <button class="btn btn-green" onclick="saveProject()">Lưu Dự án / Máy chủ</button>
      <button class="btn btn-gray hidden" id="btnCancelEdit" onclick="resetForm()">Hủy sửa</button>
    </div>
  </div>

  <div id="tab-sshkey" class="hidden">
    <div class="card">
      <h2>A. 1-Line Push Collector cho Windows Server (PowerShell — KHÔNG cần SSH / Agent)</h2>
      <p style="color:#94a3b8">Chạy 1 dòng dưới đây trong PowerShell (Administrator) trên bất kỳ máy Windows Server nào trong VPN <code>10.7.0.0/24</code>. Script tự thu thập chỉ-đọc OS/Hotfix, Firewall, Defender, Ports, IIS, <b>MS SQL Server</b>, MongoDB/Docker, gửi về <code><AUDIT_SERVER>:2810</code>, tự dọn file tạm và <b>tự động chạy quét ngay!</b></p>
      <div class="keybox" id="winColCmd">Đang tải...</div>
      <button class="btn btn-primary" onclick="copyText('winColCmd')">Copy lệnh Windows PowerShell</button>
      <button class="btn btn-danger" onclick="rotateToken()">Xoay vòng Token bảo mật</button>
    </div>
    <div class="card">
      <h2>B. 1-Line Push Collector cho Linux / VPS (khi VPS chặn SSH từ ngoài)</h2>
      <div class="keybox" id="linColCmd">Đang tải...</div>
      <button class="btn btn-primary" onclick="copyText('linColCmd')">Copy lệnh Linux Bash</button>
    </div>
    <div class="card">
      <h2>C. SSH Public Key chuyên dụng của AI Audit Lab (ed25519)</h2>
      <div class="keybox" id="pubKeyBox">Đang tải...</div>
      <label style="margin-top:10px">Lệnh cài nhanh 1 dòng trên máy chủ Linux đích:</label>
      <div class="keybox" id="pubCmdBox">Đang tải...</div>
      <button class="btn btn-primary" onclick="copyText('pubCmdBox')">Copy lệnh cài SSH Key</button>
    </div>
  </div>

  <div id="tab-diff" class="hidden">
    <div class="card">
      <h2>Patch-Diff &amp; Variant Analysis (Săn lỗ hổng chưa biết từ bản vá)</h2>
      <div class="row">
        <div><label>Tên đợt phân tích</label><input id="diffName" value="patch-diff-manual"></div>
        <div><label>Model AI phân tích</label><select id="diffModel"><option value="qwen3:30b-a3b">qwen3:30b-a3b (Nhanh, đọc code mạnh)</option><option value="deepseek-r1:14b">deepseek-r1:14b (Suy luận sâu)</option></select></div>
      </div>
      <label>Dán nội dung Patch / Git Diff:</label>
      <textarea id="diffText" style="min-height:180px" placeholder="diff --git a/... b/..."></textarea>
      <div style="margin-top:12px"><button class="btn btn-ai" onclick="runManualDiff()">Chạy AI Patch-Diff &amp; Variant Analysis</button></div>
    </div>
  </div>

  <div id="tab-jobs" class="hidden">
    <div class="card">
      <h2>Lịch sử Tác vụ &amp; Live Log</h2>
      <table><thead><tr><th>Job ID</th><th>Tên tác vụ</th><th>Trạng thái</th><th>Bắt đầu</th><th>Kết thúc</th><th>Log</th></tr></thead><tbody id="jobsTable"></tbody></table>
    </div>
    <div class="card"><h2>Live Terminal Output</h2><pre id="jobLog">Chọn một tác vụ để xem log trực tiếp...</pre></div>
  </div>

  <div id="tab-katana" class="hidden">
    <div class="card">
      <h2>Web Surface &amp; SPA/Next.js Endpoint Discovery (ProjectDiscovery Katana + httpx)</h2>
      <p style="color:#94a3b8">Quét bề mặt ngoài vào (<b>Outside-In</b>) ở chế độ an toàn giới hạn tốc độ (<code>-rl 10 req/s</code>) cho các domain/URL thuộc quyền sở hữu: tự động tìm API ẩn trong JS bundle (Next.js/React/WordPress), kiểm tra TLS, Security Headers và Tech Stack.</p>
      <div class="row">
        <div><label>URL mục tiêu được phép quét (VD: https://app.domain.vn)</label><input id="kUrl" placeholder="https://..."></div>
        <div><label>Tên đợt quét</label><input id="kName" value="web-surface"></div>
      </div>
      <div class="row">
        <div><label>Độ sâu crawl (mặc định 3)</label><input id="kDepth" value="3"></div>
        <div><label>Phân tích chéo bằng AI Local (Shadow API / Exposure)?</label><select id="kAi"><option value="yes">Có — Phân tích bằng Ollama Local (qwen3:30b-a3b)</option><option value="no">Không — Chỉ chạy Katana + httpx (~20 giây)</option></select></div>
      </div>
      <button class="btn btn-ai" onclick="runKatanaScan()">Chạy Web Surface Discovery (Katana + httpx)</button>
    </div>
  </div>

  <div id="tab-reports" class="hidden">
    <div class="card">
      <h2>Danh sách Báo cáo Kiểm toán (F:\ERP-Audit-Lab\reports\)</h2>
      <div class="row">
        <div><label>Chọn đợt báo cáo</label><select id="repFolder" onchange="loadReportFiles()"></select></div>
        <div><label>Chọn file báo cáo</label><select id="repFile" onchange="viewReportFile()"></select></div>
      </div>
      <div style="margin-top:10px">
        <button class="btn btn-danger" onclick="exportReport('pdf')">Xuất Báo Cáo PDF (Gửi Lãnh Đạo)</button>
        <button class="btn btn-green" onclick="exportReport('excel')">Xuất Báo Cáo Excel (.xlsx — 5 Sheet)</button>
      </div>
    </div>
    <div class="card"><div id="repContent" class="md">Chọn báo cáo để xem chi tiết...</div></div>
  </div>
</div>
<script>
const ALL_STACKS = ["owasp","api","dotnet","mssql","nginx","haproxy","ubuntu","postgresql","mysql","mongodb","docker","mcp","nextjs","nodejs","wordpress"];
let activeJobId = null;
let cachedProjects = [];

function copyText(id){ navigator.clipboard.writeText(document.getElementById(id).textContent); alert('Đã copy!'); }
function showTab(name, btn){
  document.querySelectorAll('[id^="tab-"]').forEach(el=>el.classList.add('hidden'));
  document.getElementById('tab-'+name).classList.remove('hidden');
  document.querySelectorAll('.nav button').forEach(b=>b.classList.remove('active'));
  if(btn) btn.classList.add('active');
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
  document.getElementById('formTitle').textContent = '+ Thêm Máy chủ (Agentless SSH) hoặc Thư mục Local';
  document.getElementById('btnCancelEdit').classList.add('hidden');
  document.getElementById('pName').value = '';
  document.getElementById('sHost').value = '';
  document.getElementById('sPort').value = '22';
  document.getElementById('sUser').value = 'ubuntu';
  document.getElementById('sPass').value = '';
  document.getElementById('sCustomKey').value = '';
  document.getElementById('sPaths').value = '';
  document.getElementById('pPath').value = '';
}
function editProject(pid){
  const p = cachedProjects.find(x=>x.id===pid); if(!p) return;
  document.getElementById('editId').value = p.id;
  document.getElementById('formTitle').textContent = 'Sửa Dự án: ' + p.name;
  document.getElementById('btnCancelEdit').classList.remove('hidden');
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
  document.getElementById('formTitle').scrollIntoView({behavior:'smooth'});
}

async function init(){
  document.getElementById('stackBoxes').innerHTML = ALL_STACKS.map(s=>`<label><input type="checkbox" value="${s}" checked> ${s}</label>`).join('');
  toggleMode(); toggleAuth();
  loadStatus(); loadProjects(); loadReportFolders(); loadCollectorInfo();
  setInterval(()=>{ loadJobs(); if(activeJobId) loadJobLog(activeJobId); }, 4000);
}
async function loadStatus(){
  const r = await fetch('/api/status'); const d = await r.json();
  document.getElementById('ollamaBadge').textContent = d.ollama_ok ? `Ollama Ready (${d.models.length} models)` : 'Ollama Offline';
}
async function loadCollectorInfo(){
  const r = await fetch('/api/collector-info'); const d = await r.json();
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
        ${isSsh ? `<button class="btn btn-gray" onclick="testSsh('${p.id}')">Test SSH</button>` : ''}
        <button class="btn btn-primary" onclick="triggerScan('${p.id}','quick')">${isSsh?'SSH Sync + ':''}Quick Scan</button>
        <button class="btn btn-ai" onclick="triggerScan('${p.id}','full')">${isSsh?'SSH Sync + ':''}Full AI Audit</button>
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
  if(r.ok){ resetForm(); loadProjects(); alert('Đã lưu thành công!'); } else { alert('Lỗi lưu dự án!'); }
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
  const r = await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({project_id:projectId, mode})});
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
async function loadJobs(){
  const r = await fetch('/api/jobs'); const list = await r.json();
  document.getElementById('kpiJobs').textContent = list.filter(j=>j.status==='RUNNING').length;
  document.getElementById('jobsTable').innerHTML = list.map(j=>`
    <tr><td><code>${j.id}</code></td><td>${j.title}</td><td class="st-${j.status}">${j.status}</td>
    <td>${j.started}</td><td>${j.finished||'-'}</td>
    <td><button class="btn btn-primary" onclick="activeJobId='${j.id}';loadJobLog('${j.id}')">Xem Log</button></td></tr>`).join('');
}
async function loadJobLog(jid){
  const r = await fetch('/api/jobs/'+jid+'/log'); const d = await r.json();
  const pre = document.getElementById('jobLog'); pre.textContent = d.log || '(Chưa có output)'; pre.scrollTop = pre.scrollHeight;
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
  if(!url.startsWith('http')) return alert('Vui lòng nhập URL hợp lệ bắt đầu bằng http:// hoặc https://');
  const r = await fetch('/api/katana-scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({url,name,depth,with_ai})});
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
        return {"ollama_ok": True, "models": [m["name"] for m in d.get("models", [])]}
    except Exception:
        return {"ollama_ok": False, "models": []}

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
def download_win_collector(request: Request, token: str = ""):
    verify_collector_token(token)
    server_base = str(request.base_url).rstrip("/")
    script = f"""# AI Security Audit — Agentless Windows Security Collector (100% Read-Only)
$ErrorActionPreference = 'SilentlyContinue'
$hostName = $env:COMPUTERNAME
$work = Join-Path $env:TEMP ("ace_audit_" + $hostName + "_" + (Get-Random))
New-Item -ItemType Directory -Force -Path $work | Out-Null

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("# Windows Live Security Audit Snapshot ($hostName - $(Get-Date -Format 's'))")
[void]$sb.AppendLine("`n## 1. OS Build & Recent Hotfixes")
$cv = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
[void]$sb.AppendLine("OS: $($cv.ProductName) Build=$($cv.CurrentBuild).$($cv.UBR)")
[void]$sb.AppendLine((Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID, InstalledOn | Out-String))

[void]$sb.AppendLine("`n## 2. Windows Firewall & Defender")
[void]$sb.AppendLine((Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Out-String))
[void]$sb.AppendLine((Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated | Out-String))

[void]$sb.AppendLine("`n## 3. Listening TCP Ports")
[void]$sb.AppendLine((Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort | Sort-Object LocalPort -Unique | Out-String))

[void]$sb.AppendLine("`n## 4. Local Administrators & Running DB/Web Services")
[void]$sb.AppendLine((Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, ObjectClass | Out-String))
[void]$sb.AppendLine((Get-Service | Where-Object {{ $_.Name -match 'SQL|Mongo|Postgres|MySQL|W3SVC|Docker|Redis' }} | Select-Object Name, Status, StartType | Out-String))

[void]$sb.AppendLine("`n## 5. IIS Websites & AppPools")
Import-Module WebAdministration -ErrorAction SilentlyContinue
[void]$sb.AppendLine((Get-Website | Select-Object Name, State, PhysicalPath | Out-String))

[void]$sb.AppendLine("`n## 6. Microsoft SQL Server Version & PatchLevel")
Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server' -ErrorAction SilentlyContinue | ForEach-Object {{
  $setup = Join-Path $_.PSPath 'Setup'
  if (Test-Path $setup) {{
    $p = Get-ItemProperty $setup
    [void]$sb.AppendLine("Instance=$($_.PSChildName) Edition=$($p.Edition) Version=$($p.Version) PatchLevel=$($p.PatchLevel)")
  }}
}}

Set-Content -Path (Join-Path $work 'live_system_audit.md') -Value $sb.ToString() -Encoding UTF8
if (Test-Path 'C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config') {{
  Copy-Item 'C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config' (Join-Path $work 'applicationHost.config') -Force
}}

$zip = "$work.zip"
Compress-Archive -Path "$work\\*" -DestinationPath $zip -Force
Write-Host "[AI Security Audit] Uploading snapshot for $hostName to {server_base}..." -ForegroundColor Cyan
$resp = Invoke-RestMethod -Uri "{server_base}/api/collector/upload?token={token}&host=$hostName&os=windows" -Method Post -InFile $zip -ContentType "application/zip" -TimeoutSec 120
Write-Host ("[AI Security Audit] DONE! Job ID: " + $resp.job_id + " | Report: " + $resp.report_tag) -ForegroundColor Green
Remove-Item $work, $zip -Recurse -Force -ErrorAction SilentlyContinue
"""
    return script

@app.get("/download/linux-collector", response_class=PlainTextResponse)
def download_linux_collector(request: Request, token: str = ""):
    verify_collector_token(token)
    server_base = str(request.base_url).rstrip("/")
    script = f"""#!/usr/bin/env bash
set -euo pipefail
HOST=$(hostname)
WORK="/tmp/ace_audit_${{HOST}}_$$"
mkdir -p "$WORK/configs"
{{
  echo "# Linux Live Security Snapshot ($HOST - $(date -Iseconds))"
  echo "## 1. OS & Updates"
  (lsb_release -ds 2>/dev/null || cat /etc/os-release | head -n 4); uname -a
  apt list --upgradable 2>/dev/null | head -n 40 || true
  echo "## 2. Listening Ports"
  ss -tulpn 2>/dev/null || true
  echo "## 3. Firewall"
  ufw status verbose 2>/dev/null || true
  iptables -S DOCKER-USER 2>/dev/null || true
  echo "## 4. Docker Security"
  if command -v docker >/dev/null 2>&1; then
    docker ps --format "table {{{{.Names}}}}\\t{{{{.Image}}}}\\t{{{{.Status}}}}\\t{{{{.Ports}}}}" || true
    for cid in $(docker ps -q 2>/dev/null); do
      docker inspect "$cid" --format '{{{{.Name}}}} | Privileged={{{{.HostConfig.Privileged}}}} | NetMode={{{{.HostConfig.NetworkMode}}}} | User={{{{.Config.User}}}}' || true
    done
  fi
}} > "$WORK/live_system_audit.md"

for p in /etc/nginx /etc/haproxy /etc/postgresql /etc/mysql /etc/mongod.conf /etc/redis /etc/ssh/sshd_config; do
  [ -e "$p" ] && cp -rL "$p" "$WORK/configs/" 2>/dev/null || true
done

TGZ="${{WORK}}.tar.gz"
tar -czf "$TGZ" -C "$WORK" .
echo "[AI Security Audit] Uploading snapshot for $HOST to {server_base}..."
curl -fsS -X POST --data-binary @"$TGZ" -H "Content-Type: application/gzip" "{server_base}/api/collector/upload?token={token}&host=${{HOST}}&os=linux"
echo ""
rm -rf "$WORK" "$TGZ"
"""
    return script

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
        f"trivy fs --scanners vuln,misconfig --format json --output '{wsl_rep}/02_trivy_sca.json' '{wsl_src}' || true; "
        f"semgrep scan --config /mnt/f/ERP-Audit-Lab/rules --json --output '{wsl_rep}/03_semgrep_sast.json' '{wsl_src}' || true; "
        f"echo 'PUSH AUDIT COMPLETE -> F:\\ERP-Audit-Lab\\reports\\{tag}'"
    )
    jid = start_job(f"1-Line Push Audit: {host}", [("SAST + Secret + SCA (15 Stacks)", ["wsl", "-u", "root", "bash", "-c", bash_cmd])])
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
        f"trivy fs --scanners vuln,misconfig --format json --output '{wsl_rep}/02_trivy_sca.json' '{wsl_src}' || true; "
        f"echo '[3/3] Semgrep SAST (15 Stacks)...' && "
        f"semgrep scan --config /mnt/f/ERP-Audit-Lab/rules --json --output '{wsl_rep}/03_semgrep_sast.json' '{wsl_src}' || true; "
        f"echo 'SCAN COMPLETE -> F:\\ERP-Audit-Lab\\reports\\{tag}'"
    )
    steps.append(("SAST + Secret + SCA (15 Stacks)", ["wsl", "-u", "root", "bash", "-c", bash_sast]))
    if mode == "full":
        steps.append((
            "AI 3-Agent Deep Audit (Ollama Local)",
            [WIN_PY, r"F:\ERP-Audit-Lab\scripts\ai_auditor.py", "--mode", "full", "--repo", proj["path"], "--reports", rf"F:\ERP-Audit-Lab\reports\{tag}"]
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
                rows = "".join(
                    f"<tr><td>{x.get('RuleID','')}</td><td><code>{x.get('File','')}</code></td><td>{x.get('StartLine','')}</td><td>***REDACTED***</td></tr>"
                    for x in data[:100]
                )
                return {"html": f"<h3>Gitleaks Findings ({len(data)} total — secrets masked)</h3><table><tr><th>Rule</th><th>File</th><th>Line</th><th>Match</th></tr>{rows}</table>"}
            if "03_semgrep" in fp.name and isinstance(data, dict):
                res = data.get("results", [])
                rows = "".join(
                    f"<tr><td><b>{r.get('extra',{}).get('severity','')}</b></td><td><code>{r.get('check_id','').split('.')[-1]}</code></td><td><code>{r.get('path','')}:{r.get('start',{}).get('line','')}</code></td><td>{r.get('extra',{}).get('message','')}</td></tr>"
                    for r in res[:150]
                )
                return {"html": f"<h3>Semgrep SAST Findings ({len(res)} total)</h3><table><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th></tr>{rows}</table>"}
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
    tag = f"{datetime.now().strftime('%Y-%m-%d_%H%M')}_katana_{name}"
    wsl_rep = f"/mnt/f/ERP-Audit-Lab/reports/{tag}"
    bash_cmd = (
        f"mkdir -p '{wsl_rep}' && "
        f"echo '[1/2] Running httpx fingerprint & TLS/Header probe...' && "
        f"echo '{url}' | httpx -title -status-code -tech-detect -server -tls-grab -silent > '{wsl_rep}/httpx.txt' 2>&1 || true; "
        f"echo '[2/2] Running Katana safe crawl (depth={depth}, rate-limit=10/s)...' && "
        f"katana -u '{url}' -d {depth} -c 3 -rl 10 -jc -kf all -silent -o '{wsl_rep}/katana_urls.txt' 2>/dev/null || true; "
        f"{{ echo '# Web Surface Discovery Report ({url})'; echo ''; "
        f"echo '## 1. HTTPX Fingerprint (Tech Stack / Server / Status)'; echo '```'; cat '{wsl_rep}/httpx.txt'; echo '```'; "
        f"echo '## 2. Discovered Endpoints & JS Routes (Katana — top 200)'; echo '```'; head -n 200 '{wsl_rep}/katana_urls.txt' 2>/dev/null || true; echo '```'; "
        f"}} > '{wsl_rep}/07_web_surface_katana.md'; "
        f"echo \"DISCOVERED_URLS=$(wc -l < '{wsl_rep}/katana_urls.txt' 2>/dev/null || echo 0)\""
    )
    steps = [(f"Katana + httpx Safe Discovery ({url})", ["wsl", "-u", "root", "bash", "-c", bash_cmd])]
    if with_ai:
        py_ai = (
            f"import json, re, urllib.request; from pathlib import Path; "
            f"rep = Path(r'F:\\ERP-Audit-Lab\\reports\\{tag}'); "
            f"surf = (rep / '07_web_surface_katana.md').read_text(encoding='utf-8', errors='ignore'); "
            f"payload = {{'model':'qwen3:30b-a3b','stream':False,'options':{{'temperature':0.1,'num_ctx':16384}},'messages':["
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
