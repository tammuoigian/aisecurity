# AI Security Audit Platform (v2.2)

**100% On-Premise White-Box Code Audit, Patch-Diff & Agentless Security Assessment Platform** powered by deterministic SAST/SCA/Secret engines + Local LLM Multi-Agent Reasoning (Ollama) + Outside-In Web Surface Discovery (Katana & httpx).

## Key Features
- **15 Security Ecosystems:** `owasp` (OWASP Top 10 A01–A10), `api` (OWASP API Top 10), `dotnet`, `mssql`, `nginx`, `haproxy`, `ubuntu`, `postgresql`, `mysql`, `mongodb`, `docker`, `mcp` (Model Context Protocol), `nextjs`, `nodejs`, `wordpress`.
- **4-Layer Deterministic + AI Pipeline:**
  1. **Secret Scanning:** Gitleaks
  2. **SCA & Misconfiguration:** Trivy
  3. **SAST (35 Custom Multi-Stack Rules):** Semgrep
  4. **AI 3-Agent Deep Audit (100% Local Ollama):** Attack Surface Mapper $\rightarrow$ Playbook Auditor (`qwen3:30b-a3b`) $\rightarrow$ Critic False-Positive Filter (`deepseek-r1:14b`)
- **Automated `.NET` DLL Decompilation:** Uses `ilspycmd` to decompile compiled business `.NET` assemblies into C# for white-box auditing.
- **Patch-Diff & Variant Analysis:** Compares Git commits/patches to detect security regressions and hunt unpatched sibling variants.
- **Agentless Remote Server Auditing:**
  - **SSH Mode (Linux / Windows OpenSSH):** Supports dedicated `ed25519` SSH Key, Custom Private Key, or Password/Keyboard-Interactive; defaults to full system Auto-Discovery (OS, Firewall, Ports, Docker, DB/Web configs, and lightweight source code excluding `node_modules`/`uploads`/media).
  - **1-Line Push Collector (Token-Protected):** PowerShell (`irm ... | iex`) for Windows Server & Bash (`curl ... | sudo bash`) for Linux when inbound SSH is unavailable.
- **Outside-In Web Surface Discovery:** Safe rate-limited **ProjectDiscovery `katana` + `httpx`** to discover hidden JS/SPA/API endpoints and cross-check Shadow APIs with AI.
- **Executive Reporting (1-Click Export):** Export clean Vietnamese/UTF-8 **A4 PDF** and **5-Sheet Styled Excel (`.xlsx`)** reports for management.

## Quick Start
1. Install Python dependencies in a virtual environment:
   ```bash
   python -m venv web-venv
   web-venv/Scripts/pip install -r requirements.txt
   ```
2. Install WSL2/Linux audit tools: `git`, `ripgrep`, `jq`, `.NET 8 SDK` + `ilspycmd`, `gitleaks`, `trivy`, `semgrep`, `katana`, `httpx`.
3. Ensure local **Ollama** is running (`http://127.0.0.1:11434`) with `qwen3:30b-a3b` and `deepseek-r1:14b`.
4. Start the Web Portal on port `2810`:
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 2810 --app-dir web
   ```
