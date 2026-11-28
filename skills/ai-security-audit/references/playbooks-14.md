# 14 Auto-Adaptive Security Audit Playbooks & 52 Validation Rules

## Semgrep Rule Suites (52 Validated Rules — 0 Errors)
1. `01_dotnet_owasp_api_rules.yaml` — .NET / ASP.NET WebForms, OWASP Top 10 & API Top 10 (SQLi, BinaryFormatter, Auth, CORS, SSRF, Path Traversal).
2. `02_infra_db_nginx_rules.yaml` — Nginx, HAProxy, Ubuntu, MSSQL, PostgreSQL, MySQL.
3. `03_multistack_rules.yaml` — MongoDB NoSQLi, Docker/Compose (`privileged`, `docker.sock`, `network_mode: host`), Next.js, Node.js, WordPress.
4. `04_mcp_ai_rules.yaml` — Baseline MCP & AI configuration hygiene.
5. `05_taint_zeroday_rules.yaml` — **9 Dataflow Taint-Mode (`mode: taint`)** rules tracking `Source -> Sink` across JS/TS, Python, PHP, and C#.
6. `06_owasp_llm_mcp_rules.yaml` — **8 OWASP LLM Top 10 & OWASP MCP Top 10** rules (Prompt Injection `LLM01`, Insecure Output Handling `LLM02`, Excessive Agency `LLM06`, RAG Poisoning `LLM07`, MCP Hardcoded Secret `MCP01`, Exposed `0.0.0.0` `MCP02`, Shell Exec `MCP03`).

## 14 Auto-Adaptive AI Playbooks (Sink-Centered ±22-Line Context)
1. **Playbook 1:** Auth, Session, JWT, RBAC & IDOR/BOLA
2. **Playbook 2:** Injection (SQLi, NoSQLi MongoDB, Command Injection, SSTI)
3. **Playbook 3:** File Upload, Path Traversal, SSRF & XXE
4. **Playbook 4:** Deserialization, XSS, Prototype Pollution & Supply-Chain
5. **Playbook 5:** Reverse Proxy, WAF, TLS & CORS (`Nginx`, `HAProxy`, `IIS`)
6. **Playbook 6:** Container, Docker Compose & Secrets Hygiene (`CapAdd`, `ENV`, `docker.sock`)
7. **Playbook 7:** Database & Cache Hardening (`MSSQL`, `PostgreSQL`, `MySQL`, `MongoDB`, `Redis`)
8. **Playbook 8:** OS, CIS Benchmark (`0–100`) & CrowdStrike/MITRE Threat Hunting IOCs
9. **Playbook 9:** OWASP LLM Top 10, Agentic AI, RAG Poisoning & MCP Top 10 (`AIGoat`)
10. **Playbook 10:** WordPress / CMS & Next.js Specific Security
11. **Playbook 11:** Zero-Day Business Logic, IDOR/BOLA, Auth Bypass & Race Condition Hunter (fed with `04b_auth_matrix_zeroday.md`)
12. **Playbook 12:** Modern API, OAuth2/JWT, Webhook HMAC & Anti-Bruteforce
13. **Playbook 13:** CI/CD, GitHub Actions & Supply-Chain Poisoning
14. **Playbook 14:** Windows Enterprise, IIS ViewState `machineKey` & SMB/WinRM Hardening
