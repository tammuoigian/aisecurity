# 7-Question Validation Gate & CWE / CVSS v3.1 Reference

## 7-Question Validation Gate (Adapted from Claude-BugHunter)
Every candidate finding must pass all 7 checks before receiving the **`[CONFIRMED]`** label:
1. **Direct Evidence:** Is there an exact `File:Line` snippet or verified command output proving the issue?
2. **Reproducibility:** Can the flaw be triggered realistically with attacker-controlled input?
3. **Reachability & Mitigations:** Is it blocked upstream by authentication, RBAC, or ModSecurity WAF?
4. **Production Scope:** Is it active production code/config (not dead code, mocks, or unit tests)?
5. **CIA Impact:** What is the concrete Confidentiality, Integrity, or Availability impact?
6. **Root Cause vs. Symptom:** Is this a standalone bug or a symptom of a deeper architectural issue?
7. **Standard Rating:** What are the exact **CWE ID**, **CVSS v3.1 score**, and **P0/P1/P2** priority?

## Standard CWE & CVSS v3.1 Mapping
| Vulnerability Class | CWE | Base CVSS v3.1 | Severity |
|---|---:|---:|---|
| SQL Injection (`SqlCommand`, dynamic SQL) | `CWE-89` | `9.8` | `CRITICAL` |
| Command Injection / RCE / LLM Output-to-Exec | `CWE-78` | `9.8` | `CRITICAL` |
| Insecure Deserialization (`BinaryFormatter`) | `CWE-502` | `9.8` | `CRITICAL` |
| Hardcoded Secret / Private Key / MCP Token | `CWE-798` | `9.1` | `CRITICAL` |
| Docker `privileged: true` / `docker.sock` mount | `CWE-250` | `8.8` | `CRITICAL` |
| NoSQL Injection (`$where`) | `CWE-943` | `8.6` | `HIGH` |
| SSRF / Untrusted RAG URL Loader | `CWE-918` | `8.2` | `HIGH` |
| Path Traversal / LFI | `CWE-22` | `8.1` | `HIGH` |
| IDOR / BOLA / Broken Auth | `CWE-639` | `8.1` | `HIGH` |
| Prompt Injection (`OWASP LLM01`) | `CWE-77` | `8.1` | `HIGH` |
| XSS / `dangerouslySetInnerHTML` | `CWE-79` | `6.8` | `MEDIUM` |
| CORS Wildcard (`*`) | `CWE-942` | `6.5` | `MEDIUM` |
| Docker `network_mode: host` / Exposed MCP `0.0.0.0` | `CWE-284` | `6.5` | `MEDIUM` |
| Weak TLS / Disabled Cert Verification | `CWE-327` | `5.9` | `MEDIUM` |
