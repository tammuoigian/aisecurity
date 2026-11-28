# AI Security Audit Platform (v4.4 — Expert SecOps & MCP Edition)

**Nền tảng Kiểm Toán Bảo Mật Ứng Dụng, Hạ Tầng & Hệ Thống AI — 100% On-Premise (MCP Server `mcp-aisecurityaudit` + Cross-Agent `SKILL.md` + 52 Semgrep/Taint/OWASP-LLM Rules + OS CVE & SBOM CycloneDX + CWE/CVSS v3.1 + CIS Scorecard 0–100 + Wiz Attack Paths + CrowdStrike IOCs + 7-Question Gate + Katana/httpx/Nuclei/Nmap TLS).**

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
2. **Lớp 2 — SCA & Misconfiguration (`Trivy`):** Quét CVE thư viện, package lỗi thời và sai cấu hình hạ tầng/Docker (có tự động loại trừ thư mục nặng & giới hạn timeout an toàn).
3. **Lớp 3 — Static Application Security Testing (`Semgrep`):** Quét mã nguồn (kể cả `.NET` DLL đã tự động giải biên dịch) theo bộ rule chuyên sâu 15 hệ sinh thái.
4. **Lớp 4 — AI 3-Agent Reasoning (Ollama Local):**
   - **Agent 1 (Attack Surface Mapper):** Lập bản đồ toàn bộ endpoint API, `.asmx`/`.ashx`, SQL sinks, File Upload, Nginx/HAProxy routes.
   - **Agent 2 (Deep Audit & Variant Hunter):** Suy luận sâu các lỗi logic/0-day theo từng Playbook chuyên biệt; chọn linh hoạt model AI ngay trước khi chạy qua **Hộp thoại Chọn Model** (tự động đọc dung lượng thực tế từ Ollama và gắn nhãn `100% GPU` hoặc `GPU + RAM`).
   - **Agent 3 (Critic / False-Positive Filter):** Tự phản biện lọc cảnh báo giả (mặc định `deepseek-r1:14b`), đề xuất cách vá code và sinh **ModSecurity Virtual Patch** chặn tạm.

### C. Thu Thập Không Cài Agent (Agentless) & Soi Bề Mặt Ngoài Vào
- **Agentless SSH (Linux / Windows OpenSSH):** Hỗ trợ SSH Key `ed25519` chuyên dụng, Custom Private Key hoặc Password (`keyboard-interactive`). Mặc định **Auto-Discovery toàn bộ hệ thống** (OS, Firewall, Ports, Docker, cấu hình Nginx/HAProxy/DB/MongoDB và tự dò toàn bộ mã nguồn sạch, tự loại trừ `*/node_modules`, `*/.next`, `*/vendor`, `*/uploads`, `*/.cache`, ảnh/video/log với ngưỡng an toàn `15,000 files / 150 MB`).
- **Thu thập nhanh 1-Dòng (Token-Protected + Tải trực tiếp `.ps1` / `.sh`):** Chạy 1 dòng lệnh PowerShell / Bash hoặc bấm tải trực tiếp file `win_collector.ps1` / `linux_collector.sh` (tránh cảnh báo ClickFix trên trình duyệt) cho máy không mở cổng SSH vào $\rightarrow$ tự thu thập chỉ-đọc, upload về trung tâm, tự dọn file tạm và **tự động chạy AI System Audit**.
- **Patch-Diff & Variant Analysis:** So sánh `git diff` giữa 2 phiên bản để phát hiện lỗi hồi quy bảo mật (**Security Regression**) và truy vết các biến thể chưa vá trên toàn codebase.
- **Outside-In Web Surface Discovery (`ProjectDiscovery Katana` + `httpx`):** Crawl an toàn có giới hạn tốc độ (`-rl 10 req/s`) để tìm API ẩn trong JavaScript bundle (Next.js/React/WordPress), kiểm tra TLS/Headers và phân tích chéo **Shadow API** bằng Model AI tự chọn.

### D. Tinh Hoa Bảo Mật Chuyên Gia (v4.0 — Full Power Expert Edition)
- **Qualys VMDR / Tenable Nessus — OS-Level CVE Engine + SBOM CycloneDX + Nmap TLS Cipher Audit:** Tự động kéo `/var/lib/dpkg/status` & chạy `trivy rootfs` quét **100% CVE mọi gói hệ điều hành Linux** (`OpenSSL`, `OpenSSH`, `Nginx`, `Kernel`, `PostgreSQL`, `Docker`...), gắn cờ **`CISA KEV`**, soi hạn chứng chỉ SSL/TLS, xuất **SBOM CycloneDX (`08_sbom_cyclonedx.json`)** tải 1-click trên Tab 6, và tích hợp **`Nmap -sV --script=ssl-enum-ciphers`** tại Tab 5.
- **Săn "Lỗ hổng chưa biết đến" & OWASP LLM/MCP Top 10 (BugHunter + AIGoat):** **52 rule Semgrep** (35 Multi-Stack + 9 Dataflow Taint-Mode + 8 OWASP LLM/Agentic/MCP Top 10), **Scope Guardrail (Deny-Wins)** & **High-Value Target Ranking** tại Tab 5, tự động gắn **`CWE-xxx` + điểm `CVSS v3.1`** trên Web/PDF/Excel, **Sink-Centered Context ±22 dòng**, **14 Auto-Adaptive AI Playbooks** và **7-Question Validation Gate** gắn nhãn **`[CONFIRMED]` / `[NEEDS-REVIEW]`**.
- **Wiz — Deep Container Inspection & Attack Paths:** Kiểm tra sâu Docker `Capabilities` (`SYS_ADMIN`, `SYS_PTRACE`), `PidMode`, `ReadonlyRootfs`, phát hiện tên biến môi trường `ENV` chứa bí mật (che giá trị), và nối chuỗi tấn công ghép (**Toxic Combinations**).
- **CrowdStrike / Rapid7 — Expert Threat Hunting & IOCs:** Săn **Deleted-but-Running Binaries** (`/proc/*/exe (deleted)`), rootkit **`/etc/ld.so.preload`**, **Webshell PHP/ASPX**, **WMI Persistence**, **Registry Run Keys**, **SMB Shares `Everyone`**, kết nối `ESTABLISHED` và lịch sử đăng nhập.
- **Lynis / CIS-CAT / DefectDojo:** Chấm điểm **CIS Scorecard `0–100` (Hạng A–F)**, so sánh biến động **`+N mới / -M đã vá`**, quản trị vòng đời lỗ hổng (Triage Dropdown), và **Live GPU Telemetry (`/api/telemetry`)**.

---

## 2. Yêu Cầu Phần Cứng & Tư Vấn Chọn Model AI (GPU VRAM vs RAM)

| Thành phần | Tối thiểu (Quick Scan + AI nhẹ 7B–8B) | Khuyến nghị (Full AI 14B–30B MoE) |
|---|---|---|
| **CPU** | 4–8 vCPU | 8–16 Cores (VD: Intel i7 / Xeon) |
| **RAM hệ thống** | 16 GB | 32–64 GB |
| **GPU (tùy chọn)** | NVIDIA 8 GB VRAM (chạy 100% GPU với model 7B–8B) | NVIDIA 16–24 GB VRAM (chạy 100% GPU với 14B–30B) |
| **Ổ cứng** | 50 GB trống | 100+ GB SSD trống |
| **Hệ điều hành** | Windows 11 / Windows Server 2022–2025 (**WSL2 Ubuntu**) hoặc **Ubuntu 22.04/24.04 LTS** | Windows 11/Server + WSL2 Ubuntu hoặc Ubuntu 24.04 LTS |

### Hiểu đúng về GPU VRAM (8 GB) vs RAM hệ thống (32 GB) khi chạy Ollama
- Ollama luôn ưu tiên nạp model vào **VRAM của GPU** để đạt tốc độ cao nhất.
- **Model < 8 GB** (VD: `qwen3-vl:8b`, `qwen2.5vl:7b`): nạp **100% vào GPU VRAM** $\rightarrow$ phản hồi rất nhanh.
- **Model > 8 GB** (VD: `deepseek-r1:14b`, `qwen3:30b-a3b`, `gemma3:27b`, `qwen3-vl:30b`): khi vượt quá dung lượng VRAM, Ollama tự động **chạy lai (Hybrid GPU + RAM)** — nạp tối đa vào GPU VRAM và tràn phần còn lại sang **32 GB RAM hệ thống** (CPU xử lý phần tràn). Nhờ đó máy vẫn chạy được đầy đủ các model lớn mà không bị thiếu bộ nhớ, nhưng phần chạy qua RAM sẽ chậm hơn 100% GPU.

| Model AI (Ollama Local) | Dung lượng | Cách chạy trên GPU 8 GB VRAM + 32 GB RAM | Khuyến nghị sử dụng |
|---|---:|---|---|
| `qwen3-vl:8b` | ~6.2 GB | **100% GPU (VRAM)** — Rất nhanh | **Mặc định hằng ngày** cho Kiểm toán sâu, 1-Line Push Audit & Katana AI |
| `qwen2.5vl:7b` | ~6.0 GB | **100% GPU (VRAM)** — Rất nhanh | Model nhẹ dự phòng, phản hồi tức thì |
| `deepseek-r1:14b` | ~9.0 GB | **~75% GPU + ~25% RAM** — Khá nhanh | **Model Phản biện (Critic)** lọc báo động giả & So sánh Bản vá |
| `qwen3:30b-a3b` (MoE) | ~18.0 GB | **~35% GPU + ~65% RAM** — Trung bình | Kiến trúc MoE (chỉ kích hoạt 3B/token) — Kiểm toán sâu mã nguồn lõi |
| `gemma3:27b` (Dense) | ~17.0 GB | **~35% GPU + ~65% RAM** — Chậm | Kiến trúc Dense (kích hoạt đủ 27B/token) — Chạy sâu qua đêm |
| `qwen3-vl:30b` (MoE+VL) | ~19.0 GB | **~35% GPU + ~65% RAM** — Trung bình | Bản 30B đa phương thức (code + hình ảnh) |

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
Cài Ollama tại [https://ollama.com/download](https://ollama.com/download) và tải model phù hợp phần cứng:
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
  New-NetFirewallRule -DisplayName 'AI-Security-Audit-Web-2810' -Direction Inbound -Protocol TCP -LocalPort 2810 -RemoteAddress '10.x.x.0/24','127.0.0.1' -Action Allow

  # Đăng ký tự khởi động cùng hệ thống
  $act = New-ScheduledTaskAction -Execute 'F:\ERP-Audit-Lab\web-venv\Scripts\uvicorn.exe' -Argument 'app:app --host 0.0.0.0 --port 2810' -WorkingDirectory 'F:\ERP-Audit-Lab\web'
  $trig = New-ScheduledTaskTrigger -AtStartup
  $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName 'AI-Security-Audit-Web-2810' -Action $act -Trigger $trig -Settings $set -Force
  Start-ScheduledTask -TaskName 'AI-Security-Audit-Web-2810'
  ```
- Truy cập trình duyệt tại **`http://<IP-SERVER>:2810`** và đăng nhập bằng thông tin trong `web\admin_credentials.txt`.

---

## 4. Hướng Dẫn Sử Dụng Nhanh (7 Tab Trên Web Portal v2.5)

1. **`1. Dự án & Quét`:** Bấm nút **`+ Tạo dự án mới`** để thêm máy chủ qua **Agentless SSH** (để trống đường dẫn = tự động dò toàn bộ hệ thống) hoặc thư mục Local $\rightarrow$ bấm **`Kiểm tra SSH`**, **`Quét nhanh`** (~30–60 giây) hoặc **`Kiểm toán AI sâu`** (mở hộp thoại chọn Model AI ngay trước khi quét).
2. **`2. Kết nối & Collector`:** Sao chép lệnh cài SSH Public Key (`ed25519`), hoặc sao chép lệnh **1-dòng** / bấm **`Tải file win_collector.ps1`** / **`Tải file linux_collector.sh`** cho các máy không mở SSH vào.
3. **`3. So sánh Bản vá`:** Dán `git diff` giữa 2 phiên bản để AI tìm lỗi hồi quy bảo mật (**Security Regression**) và săn biến thể chưa vá.
4. **`4. Tiến trình & Log`:** Theo dõi thanh tiến độ `%`, bộ đếm thời gian `mm:ss`, nhật ký chạy trực tiếp (Smart Auto-Scroll + nút **`Xuống cuối log`**), cùng các nút **`Dừng`**, **`Chạy lại`**, **`Xóa`** và **`Xóa toàn bộ lịch sử đã xong/lỗi`**.
5. **`5. Bề mặt Web`:** Nhập URL thuộc quyền sở hữu để chạy `Katana + httpx` tìm endpoint ẩn trong JS/SPA và chọn Model AI phân tích **Shadow API**.
6. **`6. Báo cáo & Xuất file`:** Xem trực tiếp báo cáo Markdown, bảng Enterprise Intelligence (CIS `0–100`, Wiz Attack Paths, CISA KEV, DefectDojo Delta), bảng lỗi kèm **Giải pháp vá chuẩn Nessus/Qualys + link NVD/CWE/OWASP**, bấm **`Xuất Báo cáo PDF (.pdf)`**, **`Xuất Báo cáo Excel (.xlsx — 5 Sheet)`**, **`Tải SBOM (CycloneDX JSON)`** hoặc **`Xóa đợt báo cáo này`**.
7. **`7. Hướng dẫn`:** Tài liệu quy trình 4 bước chuẩn, bảng tư vấn chọn 6 Model AI theo GPU VRAM + RAM và lưu ý bảo mật tích hợp ngay trên Web Portal.

---

## 5. Tích Hợp MCP Server (`mcp-aisecurityaudit`) & Bộ Skill Cho Mọi AI Agent

### A. Cài bộ Skill `ai-security-audit` (Claude Code, Codex, Antigravity, OpenCode, Cursor, Windsurf, Freebuf)
```bash
# Cài tự động 1-dòng (chuẩn agentskills.io):
npx skills add tammuoigian/aisecurity
```
Chi tiết cài đặt thủ công từng AI Agent xem tại [skills/ai-security-audit/references/install-all-agents.md](skills/ai-security-audit/references/install-all-agents.md).

### B. Kết nối MCP Server `mcp-aisecurityaudit` (11 MCP Tools)
```bash
pip install -r mcp/requirements-mcp.txt
```
Thêm vào cấu hình MCP (`mcp_config.json`, `claude_desktop_config.json`, `.mcp.json`, `.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "mcp-aisecurityaudit": {
      "command": "python",
      "args": ["/path/to/aisecurity/mcp/server.py"],
      "env": {
        "AISEC_URL": "http://<AUDIT_SERVER>:2810",
        "AISEC_API_KEY": "aisec_your_api_key_from_web_auth_json"
      }
    }
  }
}
```
- Hỗ trợ cả **`stdio`** (mặc định) và **`--transport streamable-http --port 2811`** cho team dùng chung qua VPN.

---

## 6. Lưu Ý Bảo Mật Vận Hành
- **Tuyệt đối không expose cổng `2810` trực tiếp ra Internet công cộng** — luôn giới hạn qua VPN nội bộ hoặc Reverse Proxy có xác thực.
- **Chỉ quét các hệ thống, máy chủ và tên miền thuộc quyền sở hữu hợp pháp hoặc được cấp phép bằng văn bản.**
- File `.gitignore` đã cấu hình sẵn loại trừ toàn bộ `auth.json`, `admin_credentials.txt`, `project_secrets.json`, `keys/`, `repo/`, `targets/`, `reports/` để tránh lộ thông tin nhạy cảm khi đồng bộ Git.
