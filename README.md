# AI Security Audit Platform (v2.2.1)

**Nền tảng Kiểm Toán Bảo Mật Ứng Dụng & Hạ Tầng Độc Lập — 100% On-Premise (White-Box Code Audit + Patch-Diff + Agentless SSH/Push + Outside-In Web Discovery + Local AI Multi-Agent).**

Được thiết kế theo chuẩn **CTEM (Continuous Threat Exposure Management)** & **Grey-Box Security Assessment ("Trong soi ra — Ngoài soi vào")**, giúp phát hiện các **lỗ hổng chưa biết tới (0-day, lỗi logic nghiệp vụ, IDOR, SQLi sâu trong mã nguồn/DLL, NoSQLi, Shadow API, sai cấu hình hạ tầng)** mà WAF hay máy quét lỗ hổng truyền thống thường bỏ sót — **0 byte mã nguồn rời khỏi mạng nội bộ**.

---

## 1. Tính Năng Cốt Lõi

### A. Bao phủ **15 Hệ Sinh Thái** (35 Custom Semgrep Rules + AI Playbooks)
| Nhóm | Hệ sinh thái hỗ trợ |
|---|---|
| **Chuẩn bảo mật quốc tế** | `owasp` (OWASP Top 10 A01–A10), `api` (OWASP API Top 10: BOLA/IDOR, CORS, SSRF, Mass Assignment) |
| **Web & Backend** | `dotnet` (.NET / ASP.NET WebForms + Decompile DLL bằng `ilspycmd`), `nextjs`, `nodejs`, `wordpress` (PHP) |
| **Cơ sở dữ liệu** | `mssql` (MS SQL Server), `postgresql`, `mysql`, `mongodb` (NoSQLi & `mongod.conf`) |
| **Hạ tầng & AI** | `nginx`, `haproxy`, `ubuntu` (Linux Hardening), `docker` (Docker/Compose), `mcp` (Model Context Protocol) |

### B. Quy Trình Kiểm Toán 4 Lớp + AI 3-Agent (100% Local Ollama)
1. **Lớp 1 — Secret Scanning (`Gitleaks`):** Quét lộ mật khẩu, API key, JWT secret, private key, chuỗi kết nối DB.
2. **Lớp 2 — SCA & Misconfiguration (`Trivy`):** Quét CVE thư viện, package lỗi thời và sai cấu hình hạ tầng/Docker.
3. **Lớp 3 — Static Application Security Testing (`Semgrep`):** Quét mã nguồn (kể cả `.NET` DLL đã tự động giải biên dịch) theo bộ rule chuyên sâu 15 hệ sinh thái.
4. **Lớp 4 — AI 3-Agent Reasoning (Ollama Local):**
   - **Agent 1 (Attack Surface Mapper):** Lập bản đồ toàn bộ endpoint API, `.asmx`/`.ashx`, SQL sinks, File Upload, Nginx/HAProxy routes.
   - **Agent 2 (Deep Audit & Variant Hunter):** Suy luận sâu các lỗi logic/0-day theo từng Playbook chuyên biệt; hỗ trợ chọn linh hoạt model nhẹ nhanh (`qwen3-vl:8b` cho GPU 8 GB VRAM) hoặc model sâu (`qwen3:30b-a3b`, `gemma3:27b`).
   - **Agent 3 (Critic / False-Positive Filter):** Tự phản biện lọc cảnh báo giả (dùng `deepseek-r1:14b`), đề xuất cách vá code và sinh **ModSecurity Virtual Patch** chặn tạm.

### C. Thu Thập Không Cài Agent (Agentless) & Soi Bề Mặt Ngoài Vào
- **Agentless SSH (Linux / Windows OpenSSH):** Hỗ trợ SSH Key `ed25519` chuyên dụng, Custom Private Key hoặc Password (`keyboard-interactive`). Mặc định **Auto-Discovery toàn bộ hệ thống** (OS, Firewall, Ports, Docker, cấu hình Nginx/HAProxy/DB/MongoDB và tự dò toàn bộ mã nguồn sạch, tự loại trừ `node_modules`, `.next`, `vendor`, `uploads`, `.cache`, ảnh/video/log).
- **1-Line Push Collector (Token-Protected):** Chạy đúng 1 dòng lệnh PowerShell (`irm ... | iex`) trên Windows Server hoặc Bash (`curl ... | sudo bash`) trên Linux khi không mở cổng SSH vào $\rightarrow$ tự thu thập chỉ-đọc, upload về trung tâm, tự dọn file tạm và **tự động chạy AI System Audit**.
- **Patch-Diff & Variant Analysis:** So sánh `git diff` giữa 2 phiên bản để phát hiện lỗi hồi quy bảo mật (**Security Regression**) và truy vết các biến thể chưa vá trên toàn codebase.
- **Outside-In Web Surface Discovery (`ProjectDiscovery Katana` + `httpx`):** Crawl an toàn có giới hạn tốc độ (`-rl 10 req/s`) để tìm API ẩn trong JavaScript bundle (Next.js/React/WordPress), kiểm tra TLS/Headers và ghép chéo **Shadow API** bằng AI.
- **Xuất Báo Cáo Lãnh Đạo 1-Click:** Xuất trực tiếp **PDF khổ A4** (tiếng Việt UTF-8 sắc nét) và **Excel `.xlsx` 5 Sheet** có KPI, màu mức độ rủi ro và bộ lọc sẵn.

---

## 2. Yêu Cầu Phần Cứng & Phần Mềm

| Thành phần | Tối thiểu (Quick Scan + AI nhẹ 8B) | Khuyến nghị (Full AI 14B–30B MoE) |
|---|---|---|
| **CPU** | 4–8 vCPU | 8–16 Cores (VD: Intel i7 / Xeon) |
| **RAM** | 16 GB | 32–64 GB |
| **GPU (tùy chọn)** | NVIDIA 8 GB VRAM (chạy mượt `qwen3-vl:8b`) | NVIDIA 16–24 GB VRAM (chạy mượt `14B–30B`) |
| **Ổ cứng** | 50 GB trống | 100+ GB SSD trống |
| **Hệ điều hành** | Windows 11 / Windows Server 2022–2025 (**WSL2 Ubuntu**) hoặc **Ubuntu 22.04/24.04 LTS** | Windows 11/Server + WSL2 Ubuntu hoặc Ubuntu 24.04 LTS |

---

## 3. Hướng Dẫn Cài Đặt & Deploy Trên Hệ Thống Mới (Từ Đầu)

### Bước 1: Clone mã nguồn về máy chủ Audit
```bash
# Trên Ubuntu Linux:
git clone https://github.com/tammuoigian/aisecurity.git /opt/ai-security-audit

# Trên Windows (khuyến nghị đặt tại F:\ERP-Audit-Lab hoặc C:\AI-Security-Audit):
git clone https://github.com/tammuoigian/aisecurity.git F:\ERP-Audit-Lab
```

### Bước 2: Cài đặt bộ công cụ quét trong Ubuntu (hoặc WSL2 Ubuntu)
Chạy các lệnh sau với quyền `root` (`sudo -i` hoặc `wsl -u root`):

```bash
# 1. Cài gói nền tảng
apt-get update && apt-get install -y git curl jq unzip ripgrep python3-venv python3-pip ca-certificates gnupg

# 2. Cài .NET 8 SDK & ilspycmd (để decompile DLL .NET sang C#)
curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
bash /tmp/dotnet-install.sh --channel 8.0 --install-dir /usr/local/dotnet
ln -sf /usr/local/dotnet/dotnet /usr/local/bin/dotnet
export DOTNET_ROOT=/usr/local/dotnet
dotnet tool install --tool-path /usr/local/bin ilspycmd --version 9.1.0.7988

# 3. Cài Gitleaks (Quét Secret)
GL_VER=$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r '.tag_name' | sed 's/^v//')
curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GL_VER}/gitleaks_${GL_VER}_linux_x64.tar.gz" | tar -xz -C /usr/local/bin gitleaks

# 4. Cài Trivy (Quét SCA & Misconfiguration)
TR_VER=$(curl -fsSL https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r '.tag_name' | sed 's/^v//')
curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TR_VER}/trivy_${TR_VER}_Linux-64bit.tar.gz" | tar -xz -C /usr/local/bin trivy

# 5. Cài Semgrep (SAST Engine) trong venv riêng
python3 -m venv /opt/audit-semgrep-venv
/opt/audit-semgrep-venv/bin/pip install --upgrade pip semgrep requests
ln -sf /opt/audit-semgrep-venv/bin/semgrep /usr/local/bin/semgrep

# 6. Cài ProjectDiscovery Katana & httpx (Web Surface Discovery)
KV=$(curl -fsSL https://api.github.com/repos/projectdiscovery/katana/releases/latest | jq -r '.tag_name' | sed 's/^v//')
curl -fsSL "https://github.com/projectdiscovery/katana/releases/download/v${KV}/katana_${KV}_linux_amd64.zip" -o /tmp/katana.zip && unzip -qo /tmp/katana.zip katana -d /usr/local/bin/ && rm -f /tmp/katana.zip

HV=$(curl -fsSL https://api.github.com/repos/projectdiscovery/httpx/releases/latest | jq -r '.tag_name' | sed 's/^v//')
curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HV}/httpx_${HV}_linux_amd64.zip" -o /tmp/httpx.zip && unzip -qo /tmp/httpx.zip httpx -d /usr/local/bin/ && rm -f /tmp/httpx.zip

chmod +x /usr/local/bin/{gitleaks,trivy,katana,httpx}
```

### Bước 3: Cài đặt Ollama & Tải Model AI Cục Bộ (100% On-Premise)
Cài Ollama tại [https://ollama.com/download](https://ollama.com/download) và tải model phù hợp với GPU:
```bash
# GPU 8 GB VRAM (nhanh, nhẹ — khuyến nghị mặc định):
ollama pull qwen3-vl:8b
ollama pull deepseek-r1:14b

# GPU 16–24 GB VRAM hoặc RAM 32 GB+ (phân tích sâu):
ollama pull qwen3:30b-a3b
ollama pull gemma3:27b
```

### Bước 4: Cài đặt môi trường Web Portal (Python) & Tạo Tài Khoản Đăng Nhập
```powershell
cd F:\ERP-Audit-Lab
python -m venv web-venv
.\web-venv\Scripts\pip.exe install -r requirements.txt

# Tạo tài khoản admin & mật khẩu ngẫu nhiên an toàn (lưu tại web\auth.json & web\admin_credentials.txt)
.\web-venv\Scripts\python.exe -c "
import hashlib, json, secrets
from pathlib import Path
pwd = 'Audit@' + secrets.token_hex(5)
salt = secrets.token_bytes(16)
h = hashlib.pbkdf2_hmac('sha256', pwd.encode(), salt, 120000).hex()
Path('web/auth.json').write_text(json.dumps({'username':'admin','salt':salt.hex(),'password_hash':h,'session_secret':secrets.token_hex(32),'collector_token':secrets.token_hex(20)}, indent=2))
Path('web/admin_credentials.txt').write_text(f'Username: admin\nPassword: {pwd}\n')
print('Created web/admin_credentials.txt')
"
```

### Bước 5: Khởi Chạy Web Portal (Port `2810`) & Cấu Hình Firewall
- **Chạy thử trực tiếp:**
  ```powershell
  cd F:\ERP-Audit-Lab\web
  ..\web-venv\Scripts\uvicorn.exe app:app --host 0.0.0.0 --port 2810
  ```
- **Chạy nền tự động cùng Windows (Scheduled Task) & chỉ mở cổng `2810` cho dải VPN/LAN nội bộ:**
  ```powershell
  # Chỉ cho phép dải mạng quản trị / VPN truy cập cổng 2810
  New-NetFirewallRule -DisplayName 'AI-Security-Audit-Web-2810' -Direction Inbound -Protocol TCP -LocalPort 2810 -RemoteAddress '10.7.0.0/24','127.0.0.1' -Action Allow

  # Đăng ký tự khởi động cùng hệ thống
  $act = New-ScheduledTaskAction -Execute 'F:\ERP-Audit-Lab\web-venv\Scripts\uvicorn.exe' -Argument 'app:app --host 0.0.0.0 --port 2810' -WorkingDirectory 'F:\ERP-Audit-Lab\web'
  $trig = New-ScheduledTaskTrigger -AtStartup
  $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName 'AI-Security-Audit-Web-2810' -Action $act -Trigger $trig -Settings $set -Force
  Start-ScheduledTask -TaskName 'AI-Security-Audit-Web-2810'
  ```
- Truy cập trình duyệt tại **`http://<IP-SERVER>:2810`** và đăng nhập bằng thông tin trong `web\admin_credentials.txt`.

---

## 4. Hướng Dẫn Sử Dụng Nhanh (6 Tab Trên Web Portal)

1. **Tab 1 — Dự án & Quét Agentless:** Chọn Model AI (`qwen3-vl:8b` nhanh / `qwen3:30b-a3b` sâu), thêm máy chủ từ xa qua **Agentless SSH** (để trống đường dẫn = tự động quét toàn bộ hệ thống) hoặc thư mục Local $\rightarrow$ bấm **`Test SSH`**, **`Quick Scan`** hoặc **`Full AI Audit`**.
2. **Tab 2 — SSH Key & 1-Line Collector:** Copy lệnh cài SSH Public Key (`ed25519`), hoặc copy lệnh **1-dòng PowerShell (`irm ... | iex`)** / **Linux (`curl ... | sudo bash`)** cho các máy không mở SSH vào.
3. **Tab 3 — Patch-Diff & Variant Analysis:** Dán `git diff` giữa 2 phiên bản để AI tìm lỗi hồi quy và săn biến thể chưa vá.
4. **Tab 4 — Tiến trình & Live Log:** Theo dõi log trực tiếp theo thời gian thực và chủ động bấm **`Dừng (Stop)`** nếu cần.
5. **Tab 5 — Web Surface (`Katana + httpx`):** Nhập URL thuộc quyền sở hữu để crawl tìm endpoint ẩn trong JS/SPA và phân tích Shadow API bằng AI.
6. **Tab 6 — Báo cáo & Xuất PDF/Excel:** Xem trực tiếp báo cáo Markdown/JSON và bấm **`Xuất Báo Cáo PDF (Gửi Lãnh Đạo)`** hoặc **`Xuất Báo Cáo Excel (.xlsx)`**.

---

## 5. Lưu Ý Bảo Mật Vận Hành
- **Tuyệt đối không expose cổng `2810` trực tiếp ra Internet công cộng** — luôn giới hạn qua VPN nội bộ hoặc Reverse Proxy có xác thực.
- **Chỉ quét các hệ thống, máy chủ và tên miền thuộc quyền sở hữu hợp pháp hoặc được cấp phép bằng văn bản.**
- File `.gitignore` đã cấu hình sẵn loại trừ toàn bộ `auth.json`, `admin_credentials.txt`, `project_secrets.json`, `keys/`, `repo/`, `targets/`, `reports/` để tránh lộ thông tin nhạy cảm khi đồng bộ Git.
