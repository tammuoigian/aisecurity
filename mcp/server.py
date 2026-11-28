"""
mcp-aisecurityaudit — Model Context Protocol (MCP) Server for AI Security Audit Platform (v4.3)
Connects Claude Code, Antigravity, Codex, OpenCode, Cursor, Windsurf, Cline, Freebuf/Cherry Studio
directly to your 100% On-Premise AI Security Audit server (Port 2810).

Environment variables:
  AISEC_URL      Base URL of AI Security Audit Web Portal (default: http://127.0.0.1:2810)
  AISEC_API_KEY  MCP API Key from web/auth.json ("mcp_api_key")
"""
import argparse
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from mcp.server.fastmcp import FastMCP

AISEC_URL = os.environ.get("AISEC_URL", "http://127.0.0.1:2810").rstrip("/")
AISEC_API_KEY = os.environ.get("AISEC_API_KEY", "").strip()

mcp = FastMCP(
    "mcp-aisecurityaudit",
    instructions=(
        "MCP Server for AI Security Audit Platform (100% On-Premise). "
        "Use these tools to run authorized Agentless SSH/Local SAST+Taint+SCA+OS-CVE audits, "
        "Katana/httpx/Nuclei/Nmap web surface scans (with Scope Guardrail), Patch-Diff regression analysis, "
        "read CIS Scorecards & Wiz Attack Paths, and triage findings."
    ),
)

def _api(method: str, path: str, body: Optional[dict] = None, timeout: int = 30) -> dict:
    if not AISEC_API_KEY:
        return {"error": "Missing AISEC_API_KEY environment variable. Set AISEC_API_KEY from web/auth.json."}
    url = f"{AISEC_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"X-API-Key": AISEC_API_KEY, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:500]
        return {"error": f"HTTP {e.code}: {detail}"}
    except Exception as ex:
        return {"error": f"{type(ex).__name__}: {ex}"}

@mcp.tool()
def aisec_status() -> dict:
    """Check AI Security Audit server health, installed Ollama models (with sizes), and live GPU/VRAM telemetry."""
    st = _api("GET", "/api/status")
    tel = _api("GET", "/api/telemetry")
    return {"server": AISEC_URL, "ollama": st, "telemetry": tel}

@mcp.tool()
def aisec_list_projects() -> dict:
    """List all configured projects and remote servers (Agentless SSH, 1-Line Push, Local) on the audit server."""
    res = _api("GET", "/api/projects")
    return {"projects": res} if isinstance(res, list) else res

@mcp.tool()
def aisec_test_ssh(project_id: str) -> dict:
    """Test read-only Agentless SSH connectivity to a configured project_id."""
    return _api("POST", f"/api/projects/{urllib.parse.quote(project_id)}/test-ssh", timeout=25)

@mcp.tool()
def aisec_start_scan(
    project_id: str,
    mode: str = "quick",
    audit_model: str = "qwen3-vl:8b",
    critic_model: str = "deepseek-r1:14b",
) -> dict:
    """Start a security audit job on a project. mode='quick' runs Gitleaks + Trivy (App+OS CVE+SBOM) + 52 Semgrep/Taint/OWASP-LLM rules; mode='full' also runs 14 AI Playbooks + 7-Question Critic."""
    return _api("POST", "/api/scan", {
        "project_id": project_id,
        "mode": mode,
        "audit_model": audit_model,
        "critic_model": critic_model,
    })

@mcp.tool()
def aisec_web_surface_scan(
    url: str,
    name: str = "web-surface",
    depth: int = 3,
    with_nuclei: bool = True,
    with_nmap: bool = True,
    with_ai: bool = True,
    audit_model: str = "qwen3-vl:8b",
) -> dict:
    """Run an authorized outside-in web surface scan (Katana + httpx + Nuclei Safe Profile + Nmap TLS Cipher Audit + AI Shadow API analysis). Enforces Allowed Scope Guardrail."""
    return _api("POST", "/api/katana-scan", {
        "url": url,
        "name": name,
        "depth": depth,
        "with_nuclei": with_nuclei,
        "with_nmap": with_nmap,
        "with_ai": with_ai,
        "audit_model": audit_model,
    })

@mcp.tool()
def aisec_patch_diff_audit(
    diff_text: str,
    name: str = "patch-diff-mcp",
    model: str = "qwen3-vl:8b",
) -> dict:
    """Analyze a unified git diff for Security Regressions and Variant Analysis using local Ollama AI before merging."""
    return _api("POST", "/api/patch-diff", {"name": name, "model": model, "diff_text": diff_text})

@mcp.tool()
def aisec_job_status(job_id: str) -> dict:
    """Get live progress %, status, elapsed time, and recent terminal log output for an audit job."""
    jobs = _api("GET", "/api/jobs")
    meta = next((j for j in jobs if j.get("id") == job_id), {}) if isinstance(jobs, list) else {}
    log_data = _api("GET", f"/api/jobs/{urllib.parse.quote(job_id)}/log")
    return {
        "id": job_id,
        "status": meta.get("status", log_data.get("status")),
        "progress": meta.get("progress"),
        "step_label": meta.get("step_label"),
        "started": meta.get("started"),
        "finished": meta.get("finished"),
        "log_tail": (log_data.get("log") or "")[-4000:],
    }

@mcp.tool()
def aisec_list_reports() -> dict:
    """List all saved audit report folders (newest first)."""
    res = _api("GET", "/api/reports")
    return {"reports": res[:30]} if isinstance(res, list) else res

@mcp.tool()
def aisec_get_report_summary(folder: str) -> dict:
    """Get Enterprise Intelligence summary for a report folder: CIS Scorecard (0-100), Wiz Attack Paths, CISA KEV CVEs, DefectDojo Delta (+new/-fixed), and KPI counts."""
    return _api("GET", f"/api/reports/{urllib.parse.quote(folder)}/summary")

@mcp.tool()
def aisec_read_report(folder: str, filename: str = "05_ai_deep_audit_report.md") -> dict:
    """List files in a report folder (if filename='') or read a specific report file (e.g., 05_ai_deep_audit_report.md, 00_live_system_audit.md, 04b_auth_matrix_zeroday.md, 03_semgrep_sast.json)."""
    if not filename:
        return {"files": _api("GET", f"/api/reports/{urllib.parse.quote(folder)}")}
    res = _api("GET", f"/api/reports/{urllib.parse.quote(folder)}/{urllib.parse.quote(filename)}")
    if isinstance(res, dict) and "html" in res:
        return {"folder": folder, "filename": filename, "content_preview": res["html"][:12000]}
    return res

@mcp.tool()
def aisec_triage_finding(fingerprint: str, status: str) -> dict:
    """Update DefectDojo finding lifecycle status. status must be one of: OPEN, IN_PROGRESS, FIXED, FALSE_POSITIVE, RISK_ACCEPTED."""
    return _api("POST", "/api/triage", {"fingerprint": fingerprint, "status": status.upper()})

def main():
    ap = argparse.ArgumentParser(description="mcp-aisecurityaudit MCP Server")
    ap.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2811)
    args = ap.parse_args()
    if args.transport == "streamable-http":
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
