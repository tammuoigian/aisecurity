---
name: ai-security-audit
description: Defensive White-Box, Grey-Box, and On-Premise Infrastructure Security Audit skill powered by AI Security Audit Platform (v4.3) & mcp-aisecurityaudit. Use when auditing codebases, servers, containers, web surfaces, git diffs, CVEs/SBOMs, or OWASP LLM/MCP systems with zero source-code leakage.
---

# AI Security Audit Skill (v4.3 — Full-Power On-Premise)

Use this skill to perform **defensive, evidence-based security audits** across application source code, Linux/Windows servers, Docker containers, external web surfaces, and AI/LLM/MCP systems — either directly through the **`mcp-aisecurityaudit`** MCP server or via manual white-box methodology when offline.

> **Authorization & Scope Rule (Deny-Wins):** ONLY scan, crawl, or probe systems, domains, repositories, and IP addresses explicitly owned or authorized by the user. Never fabricate findings without direct file/line or command-output evidence.

---

## 6-Phase Audit Workflow

Follow these phases in order (adapted from CTEM + Claude-BugHunter + AIGoat):

1. **Phase 1 — Scope & Health Check**
   - If `mcp-aisecurityaudit` is connected, call `aisec_status()` to verify Ollama local models and GPU/VRAM availability, and `aisec_list_projects()` to identify target projects.
   - Verify the target is inside the authorized scope before running any outside-in scan.

2. **Phase 2 — Multi-Layer Automated Discovery**
   - **Code & Infrastructure (`aisec_start_scan`):**
     - `mode="quick"` (~30–60s): Gitleaks (secrets) + Trivy Fast Staging (App SCA + Linux OS `dpkg` CVE + CISA KEV + SBOM CycloneDX) + **52 Semgrep rules** (35 Multi-Stack + 9 Dataflow Taint-Mode + 8 OWASP LLM/Agentic/MCP Top 10).
     - `mode="full"`: Adds **14 Auto-Adaptive AI Playbooks** with Sink-Centered ±22-line context, Zero-Day Auth Matrix, and **7-Question Validation Gate** Critic.
     - *GPU Model Rule:* Default to `qwen3-vl:8b` (`100% GPU` on 8 GB VRAM) for daily scans; use `qwen3:30b-a3b` or `deepseek-r1:14b` for deep core code audits.
   - **Outside-In Web Surface (`aisec_web_surface_scan`):**
     - Runs `Katana + httpx + Nuclei (Safe Profile -rl 10) + Nmap TLS Cipher Audit` + High-Value Target Ranking (`/graphql`, `/swagger`, `/admin`, `/.env`, `/.git`, `/mcp`).
   - **Pre-Merge Patch-Diff (`aisec_patch_diff_audit`):**
     - Pass `git diff` directly to catch **Security Regressions** and **Variant Analysis** before merging PRs.

3. **Phase 3 — Enterprise Intelligence & Cross-Layer Triage**
   - Call `aisec_get_report_summary(folder)` to inspect:
     - **CIS Compliance Scorecard (`0–100`, Grade `A–F`)** (Lynis / CIS-CAT / HardeningKitty)
     - **Wiz Attack Paths / Toxic Combinations** (cross-layer chains: exposed ports + critical SAST/KEV + container privilege + leaked secrets)
     - **CISA KEV CVEs** (actively exploited vulnerabilities requiring P0 patching)
     - **DefectDojo Delta (`+N new / -M fixed`)** vs. the previous scan

4. **Phase 4 — 7-Question Validation Gate (Zero False Positives)**
   - Before reporting any vulnerability as **`[CONFIRMED]`**, validate all 7 criteria in `references/7-question-gate.md`: exact `File:Line` evidence, reproducibility, auth/WAF reachability, non-test code, CIA impact, root cause, and accurate **CWE + CVSS v3.1** score.

5. **Phase 5 — Remediation & Virtual Patching**
   - Always deliver actionable fixes ranked **P0 (24h) / P1 (7d) / P2 (30d)**:
     - Exact code diff / config fix (Parameterized Query, Least Privilege, CIS hardening command)
     - **ModSecurity Virtual Patch** rule when immediate WAF mitigation is needed before a code release
     - Update finding status with `aisec_triage_finding(fingerprint, status)` (`FIXED`, `IN_PROGRESS`, `FALSE_POSITIVE`, `RISK_ACCEPTED`).

6. **Phase 6 — Executive Reporting**
   - Direct the user to 1-click **PDF A4**, **Excel 5-Sheet**, and **SBOM CycloneDX** exports in Tab 6 (`Báo cáo & Xuất file`) of the Web Portal.

---

## References
- `references/playbooks-14.md` — Full matrix of all 14 Playbooks & 52 Semgrep/Taint/OWASP-LLM rules.
- `references/7-question-gate.md` — 7-Question Validation Gate & CWE/CVSS v3.1 mapping table.
- `references/install-all-agents.md` — Setup guide for Claude Code, Codex, Antigravity, OpenCode, Cursor, Windsurf & Freebuf.
