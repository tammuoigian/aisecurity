# Hướng Dẫn Cài Đặt `ai-security-audit` Skill & `mcp-aisecurityaudit` Trên Mọi Hệ AI Agent

## 1. Cài đặt Bộ Skill (`SKILL.md`) 1-Dòng cho mọi AI Agent

### Cách A — Tự động bằng `npx skills` (Khuyến nghị — giống `cloudflare/security-audit-skill`)
```bash
npx skills add tammuoigian/aisecurity
```
Lệnh trên tự động phát hiện và cài skill `ai-security-audit` vào **Claude Code, Codex, Antigravity, OpenCode, Cursor, Windsurf**.

### Cách B — Cài thủ công theo từng môi trường AI Agent
Copy thư mục `skills/ai-security-audit/` vào đường dẫn tương ứng:
- **Claude Code:** `~/.claude/skills/ai-security-audit/` (hoặc `.claude/skills/` trong dự án)
- **Antigravity (AGY):** `~/.gemini/config/skills/ai-security-audit/` (Windows: `C:\Users\<USER>\.gemini\config\skills\ai-security-audit\`)
- **OpenAI Codex CLI:** `~/.codex/skills/ai-security-audit/`
- **OpenCode:** `~/.config/opencode/skills/ai-security-audit/`
- **Cursor / Windsurf / Cline / Freebuf:** Copy `SKILL.md` vào thư mục Rules/Skills của ứng dụng tương ứng.

---

## 2. Cài đặt MCP Server (`mcp-aisecurityaudit`)

### Bước 1: Chuẩn bị môi trường Python & Lấy `AISEC_API_KEY`
```bash
git clone https://github.com/tammuoigian/aisecurity.git
cd aisecurity/mcp
pip install -r requirements-mcp.txt
```
Lấy giá trị `mcp_api_key` trong file `web/auth.json` trên máy chủ AI Security Audit (ví dụ `http://<AUDIT_SERVER>:2810`).

### Bước 2: Khai báo MCP trên từng AI Agent

#### A. Antigravity / Claude Desktop / Cursor / Windsurf / Freebuf (JSON chuẩn MCP)
Thêm vào file cấu hình MCP (`mcp_config.json`, `claude_desktop_config.json`, `.mcp.json`, hoặc `.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "mcp-aisecurityaudit": {
      "command": "python",
      "args": ["/path/to/aisecurity/mcp/server.py"],
      "env": {
        "AISEC_URL": "http://<AUDIT_SERVER>:2810",
        "AISEC_API_KEY": "aisec_your_api_key_here"
      }
    }
  }
}
```

#### B. Claude Code (CLI 1 dòng)
```bash
claude mcp add mcp-aisecurityaudit \
  -e AISEC_URL="http://<AUDIT_SERVER>:2810" \
  -e AISEC_API_KEY="aisec_your_api_key_here" \
  -- python /path/to/aisecurity/mcp/server.py
```

#### C. OpenAI Codex (`~/.codex/config.toml`)
```toml
[mcp_servers.mcp-aisecurityaudit]
command = "python"
args = ["/path/to/aisecurity/mcp/server.py"]
[mcp_servers.mcp-aisecurityaudit.env]
AISEC_URL = "http://<AUDIT_SERVER>:2810"
AISEC_API_KEY = "aisec_your_api_key_here"
```

#### D. OpenCode (`opencode.json`)
```json
{
  "mcp": {
    "mcp-aisecurityaudit": {
      "type": "local",
      "command": ["python", "/path/to/aisecurity/mcp/server.py"],
      "environment": {
        "AISEC_URL": "http://<AUDIT_SERVER>:2810",
        "AISEC_API_KEY": "aisec_your_api_key_here"
      }
    }
  }
}
```

#### E. Chế độ Remote Streamable HTTP (Dùng chung cho cả team qua VPN)
```bash
AISEC_URL="http://127.0.0.1:2810" AISEC_API_KEY="aisec_..." \
  python mcp/server.py --transport streamable-http --host 0.0.0.0 --port 2811
```
Sau đó trỏ các client hỗ trợ Remote MCP vào `http://<AUDIT_SERVER>:2811/mcp`.
