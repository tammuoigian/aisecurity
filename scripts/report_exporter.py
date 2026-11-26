import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import markdown
import openpyxl
from openpyxl.styles import Alignment, Font, PatternFill

def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return default

def _gather_report_data(report_dir: Path):
    gl = _load_json(report_dir / "01_gitleaks_secrets.json", [])
    if not isinstance(gl, list):
        gl = []
    sg_raw = _load_json(report_dir / "03_semgrep_sast.json", {})
    sg = sg_raw.get("results", []) if isinstance(sg_raw, dict) else []
    tr_raw = _load_json(report_dir / "02_trivy_sca.json", {})
    tr_items = []
    if isinstance(tr_raw, dict):
        for res in tr_raw.get("Results", []) or []:
            tgt = res.get("Target", "")
            for v in res.get("Vulnerabilities", []) or []:
                tr_items.append({
                    "severity": v.get("Severity", "UNKNOWN"),
                    "id": v.get("VulnerabilityID", ""),
                    "target": f"{tgt} ({v.get('PkgName', '')})",
                    "installed": v.get("InstalledVersion", ""),
                    "fixed": v.get("FixedVersion", ""),
                    "desc": v.get("Title") or v.get("Description", "")[:180],
                })
            for m in res.get("Misconfigurations", []) or []:
                tr_items.append({
                    "severity": m.get("Severity", "UNKNOWN"),
                    "id": m.get("ID", ""),
                    "target": tgt,
                    "installed": "-",
                    "fixed": m.get("Resolution", "")[:100],
                    "desc": m.get("Title", ""),
                })

    md_sections = []
    for fname, label in [
        ("05_ai_deep_audit_report.md", "Phân Tích Chuyên Sâu AI 3-Agent & Đề Xuất Khắc Phục"),
        ("06_patch_diff_audit.md", "Phân Tích Patch-Diff & Variant Analysis"),
        ("07_web_surface_katana.md", "Khám Phá Bề Mặt Web / SPA (Katana & httpx)"),
        ("00_live_system_audit.md", "Hiện Trạng Hệ Thống Thực Tế (Live System Snapshot)"),
    ]:
        fp = report_dir / fname
        if fp.exists():
            md_sections.append((label, fp.read_text(encoding="utf-8", errors="ignore")))

    sast_err = sum(1 for r in sg if r.get("extra", {}).get("severity", "").upper() == "ERROR")
    sast_warn = sum(1 for r in sg if r.get("extra", {}).get("severity", "").upper() == "WARNING")
    tr_crit = sum(1 for x in tr_items if x["severity"].upper() in ("CRITICAL", "HIGH"))

    return {
        "folder": report_dir.name,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "gitleaks": gl,
        "semgrep": sg,
        "trivy": tr_items,
        "md_sections": md_sections,
        "kpi": {
            "sast_total": len(sg),
            "sast_critical_error": sast_err,
            "sast_warning": sast_warn,
            "secrets_total": len(gl),
            "sca_total": len(tr_items),
            "sca_crit_high": tr_crit,
        },
    }

def export_excel(report_dir: Path, out_xlsx: Path) -> Path:
    d = _gather_report_data(report_dir)
    wb = openpyxl.Workbook()

    hdr_fill = PatternFill("solid", fgColor="0F172A")
    hdr_font = Font(bold=True, color="FFFFFF", name="Calibri", size=11)
    title_font = Font(bold=True, color="0F172A", name="Calibri", size=15)
    red_fill = PatternFill("solid", fgColor="FEE2E2")
    yel_fill = PatternFill("solid", fgColor="FEF3C7")
    grn_fill = PatternFill("solid", fgColor="DCFCE7")

    # Sheet 1: Tong_Quan
    ws1 = wb.active
    ws1.title = "Tong_Quan"
    ws1["A1"] = "BÁO CÁO KIỂM TOÁN BẢO MẬT HỆ THỐNG — AI SECURITY AUDIT"
    ws1["A1"].font = title_font
    ws1["A2"] = f"Đợt kiểm toán: {d['folder']}"
    ws1["A3"] = f"Ngày xuất báo cáo: {d['generated_at']}"

    ws1.append([])
    ws1.append(["Hạng mục kiểm toán", "Số lượng phát hiện", "Mức độ ưu tiên / Ghi chú"])
    for cell in ws1[5]:
        cell.fill = hdr_fill; cell.font = hdr_font

    rows_summary = [
        ("Lỗ hổng Mã nguồn SAST mức Nghiêm trọng (ERROR)", d["kpi"]["sast_critical_error"], "P0 - Cần vá ngay / Virtual Patch"),
        ("Cảnh báo Mã nguồn SAST (WARNING)", d["kpi"]["sast_warning"], "P1 - Cần rà soát & khắc phục"),
        ("Lộ thông tin nhạy cảm / Secrets (Gitleaks)", d["kpi"]["secrets_total"], "P0 - Xoay vòng mật khẩu / dọn file thừa"),
        ("Lỗ hổng Thư viện & Cấu hình (Trivy Critical/High)", d["kpi"]["sca_crit_high"], "P1 - Lên kế hoạch cập nhật gói/config"),
        ("Tổng số phát hiện Trivy SCA & Misconfig", d["kpi"]["sca_total"], "Theo dõi định kỳ"),
    ]
    for r in rows_summary:
        ws1.append(list(r))
    for row in ws1.iter_rows(min_row=6, max_row=10):
        if row[1].value and int(row[1].value) > 0:
            row[1].fill = red_fill if "P0" in str(row[2].value) else yel_fill
        else:
            row[1].fill = grn_fill
    ws1.column_dimensions["A"].width = 48
    ws1.column_dimensions["B"].width = 22
    ws1.column_dimensions["C"].width = 42

    # Sheet 2: Lo_Hong_SAST
    ws2 = wb.create_sheet("Lo_Hong_SAST")
    ws2.append(["STT", "Mức độ", "Mã Rule", "Đường dẫn File", "Dòng", "Mô tả chi tiết"])
    for cell in ws2[1]:
        cell.fill = hdr_fill; cell.font = hdr_font
    for idx, r in enumerate(d["semgrep"], 1):
        sev = r.get("extra", {}).get("severity", "INFO")
        cid = r.get("check_id", "").split(".")[-1]
        fp = r.get("path", "").replace("/mnt/f/ERP-Audit-Lab/repo/", "")
        ln = r.get("start", {}).get("line", "")
        msg = r.get("extra", {}).get("message", "")
        ws2.append([idx, sev, cid, fp, ln, msg])
        if sev.upper() == "ERROR":
            ws2.cell(idx + 1, 2).fill = red_fill
        elif sev.upper() == "WARNING":
            ws2.cell(idx + 1, 2).fill = yel_fill
    ws2.auto_filter.ref = f"A1:F{max(1, len(d['semgrep'])+1)}"
    for col, w in [("A", 7), ("B", 13), ("C", 34), ("D", 55), ("E", 8), ("F", 65)]:
        ws2.column_dimensions[col].width = w

    # Sheet 3: Lo_Secret
    ws3 = wb.create_sheet("Lo_Secret")
    ws3.append(["STT", "Loại Secret", "File", "Dòng", "Giá trị (Đã che bảo mật)"])
    for cell in ws3[1]:
        cell.fill = hdr_fill; cell.font = hdr_font
    for idx, g in enumerate(d["gitleaks"], 1):
        ws3.append([idx, g.get("RuleID", ""), g.get("File", "").replace("/mnt/f/ERP-Audit-Lab/repo/", ""), g.get("StartLine", ""), "***REDACTED***"])
    ws3.auto_filter.ref = f"A1:E{max(1, len(d['gitleaks'])+1)}"
    for col, w in [("A", 7), ("B", 24), ("C", 60), ("D", 8), ("E", 24)]:
        ws3.column_dimensions[col].width = w

    # Sheet 4: Lo_Hong_Thu_Vien
    ws4 = wb.create_sheet("Lo_Hong_Thu_Vien")
    ws4.append(["STT", "Mức độ", "CVE / Rule ID", "Gói / File", "Phiên bản hiện tại", "Phiên bản vá", "Mô tả"])
    for cell in ws4[1]:
        cell.fill = hdr_fill; cell.font = hdr_font
    for idx, t in enumerate(d["trivy"], 1):
        ws4.append([idx, t["severity"], t["id"], t["target"], t["installed"], t["fixed"], t["desc"]])
    ws4.auto_filter.ref = f"A1:G{max(1, len(d['trivy'])+1)}"
    for col, w in [("A", 7), ("B", 13), ("C", 22), ("D", 38), ("E", 18), ("F", 22), ("G", 55)]:
        ws4.column_dimensions[col].width = w

    # Sheet 5: Phan_Tich_AI
    ws5 = wb.create_sheet("Phan_Tich_AI")
    ws5.append(["Chuyên mục", "Nội dung phân tích chi tiết"])
    for cell in ws5[1]:
        cell.fill = hdr_fill; cell.font = hdr_font
    for label, txt in d["md_sections"]:
        ws5.append([label, txt[:32000]])
    for row in ws5.iter_rows(min_row=2):
        row[1].alignment = Alignment(wrap_text=True, vertical="top")
    ws5.column_dimensions["A"].width = 36
    ws5.column_dimensions["B"].width = 110

    wb.save(str(out_xlsx))
    return out_xlsx

def _find_edge():
    for p in (
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ):
        if Path(p).exists():
            return p
    return shutil.which("msedge") or shutil.which("chrome")

def export_pdf(report_dir: Path, out_pdf: Path) -> Path:
    d = _gather_report_data(report_dir)
    sast_rows = "".join(
        f"<tr><td><span class='sev-{r.get('extra',{}).get('severity','INFO').upper()}'>{r.get('extra',{}).get('severity','')}</span></td>"
        f"<td><code>{r.get('check_id','').split('.')[-1]}</code></td>"
        f"<td><code>{r.get('path','').replace('/mnt/f/ERP-Audit-Lab/repo/','')}:{r.get('start',{}).get('line','')}</code></td>"
        f"<td>{r.get('extra',{}).get('message','')}</td></tr>"
        for r in d["semgrep"][:60]
    ) or "<tr><td colspan='4'>Không có phát hiện SAST.</td></tr>"

    sec_rows = "".join(
        f"<tr><td>{g.get('RuleID','')}</td><td><code>{g.get('File','').replace('/mnt/f/ERP-Audit-Lab/repo/','')}</code></td><td>{g.get('StartLine','')}</td></tr>"
        for g in d["gitleaks"][:40]
    ) or "<tr><td colspan='3'>Không phát hiện lộ thông tin bí mật.</td></tr>"

    ai_html = ""
    for label, txt in d["md_sections"]:
        rendered = markdown.markdown(txt[:35000], extensions=["fenced_code", "tables"])
        ai_html += f"<div class='page-break'></div><h2>{label}</h2><div class='md-body'>{rendered}</div>"

    html = f"""<!doctype html>
<html lang="vi"><head><meta charset="utf-8">
<title>Báo Cáo Kiểm Toán Bảo Mật — {d['folder']}</title>
<style>
@page {{ size: A4; margin: 16mm 14mm; }}
body {{ font-family: 'Segoe UI', Arial, sans-serif; color: #0f172a; font-size: 11px; line-height: 1.5; margin: 0; }}
.cover {{ border-bottom: 3px solid #0284c7; padding-bottom: 12px; margin-bottom: 16px; }}
.cover h1 {{ margin: 0; font-size: 20px; color: #0f172a; }}
.cover .sub {{ color: #475569; font-size: 12px; margin-top: 4px; }}
.kpis {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 14px 0 18px; }}
.kpi {{ border: 1px solid #cbd5e1; border-radius: 8px; padding: 10px; background: #f8fafc; }}
.kpi .num {{ font-size: 22px; font-weight: 700; color: #0284c7; }}
.kpi .num.red {{ color: #dc2626; }} .kpi .num.org {{ color: #d97706; }}
.kpi .lbl {{ font-size: 10px; color: #475569; margin-top: 2px; }}
h2 {{ font-size: 14px; color: #0369a1; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; margin-top: 18px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 10px; }}
th, td {{ border: 1px solid #cbd5e1; padding: 5px 6px; text-align: left; vertical-align: top; word-break: break-word; }}
th {{ background: #0f172a; color: #ffffff; }}
.sev-ERROR {{ background: #fee2e2; color: #b91c1c; padding: 2px 5px; border-radius: 4px; font-weight: 700; }}
.sev-WARNING {{ background: #fef3c7; color: #b45309; padding: 2px 5px; border-radius: 4px; font-weight: 700; }}
code {{ background: #f1f5f9; padding: 1px 3px; border-radius: 3px; font-family: Consolas, monospace; font-size: 9.5px; }}
pre {{ background: #f8fafc; border: 1px solid #e2e8f0; padding: 8px; border-radius: 6px; overflow: hidden; white-space: pre-wrap; font-size: 9px; }}
.page-break {{ page-break-before: always; }}
</style></head><body>
<div class="cover">
  <h1>BÁO CÁO KIỂM TOÁN BẢO MẬT HỆ THỐNG (AI SECURITY AUDIT)</h1>
  <div class="sub">Đợt kiểm toán: <b>{d['folder']}</b> &nbsp;|&nbsp; Ngày xuất báo cáo: <b>{d['generated_at']}</b> &nbsp;|&nbsp; Phân loại: Nội bộ — Bảo mật</div>
</div>
<div class="kpis">
  <div class="kpi"><div class="num red">{d['kpi']['sast_critical_error']}</div><div class="lbl">SAST Nghiêm trọng (ERROR)</div></div>
  <div class="kpi"><div class="num org">{d['kpi']['sast_warning']}</div><div class="lbl">SAST Cảnh báo (WARNING)</div></div>
  <div class="kpi"><div class="num red">{d['kpi']['secrets_total']}</div><div class="lbl">Lộ Secret / Key (Gitleaks)</div></div>
  <div class="kpi"><div class="num">{d['kpi']['sca_crit_high']} / {d['kpi']['sca_total']}</div><div class="lbl">Trivy Critical-High / Tổng SCA</div></div>
</div>
<h2>1. Tổng Hợp Phát Hiện Mã Nguồn &amp; Cấu Hình (Semgrep SAST)</h2>
<table><thead><tr><th style="width:10%">Mức độ</th><th style="width:24%">Mã Rule</th><th style="width:30%">Vị trí</th><th>Mô tả</th></tr></thead><tbody>{sast_rows}</tbody></table>
<h2>2. Phát Hiện Thông Tin Nhạy Cảm (Gitleaks — Đã Che Giá Trị)</h2>
<table><thead><tr><th style="width:22%">Loại Secret</th><th>File</th><th style="width:10%">Dòng</th></tr></thead><tbody>{sec_rows}</tbody></table>
{ai_html}
</body></html>"""

    tmp_html = out_pdf.with_suffix(".tmp.html")
    tmp_html.write_text(html, encoding="utf-8")
    browser = _find_edge()
    if not browser:
        raise RuntimeError("Microsoft Edge/Chrome not found for PDF rendering")
    try:
        subprocess.run(
            [browser, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-pdf-header-footer",
             f"--print-to-pdf={out_pdf}", tmp_html.as_uri()],
            check=True, timeout=60, capture_output=True
        )
    finally:
        if tmp_html.exists():
            tmp_html.unlink(missing_ok=True)
    return out_pdf
