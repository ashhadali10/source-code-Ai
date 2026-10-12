import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict

from utils import mask_secrets

logger = logging.getLogger(__name__)


class ReportGenerator:
    @staticmethod
    def generate(scan_data: Dict, output_dir: str, prefix: str = "report"):
        Path(output_dir).mkdir(exist_ok=True)
        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        base_path = Path(output_dir) / f"{prefix}_{now}"
        base_path.mkdir(exist_ok=True)

        # JSON
        with open(base_path / "findings.json", 'w', encoding='utf-8') as f:
            json.dump(scan_data, f, indent=2, default=str)

        # CSV
        with open(base_path / "findings.csv", 'w', encoding='utf-8') as f:
            f.write("Finding ID,Severity,Verdict,Confidence,File,Line,Rule,Message\n")
            for fn in scan_data.get("findings", []):
                msg = mask_secrets(fn.get("description", "") or "").replace('"', '""').replace('\n', ' ')
                f.write(
                    f'"{fn.get("finding_id","")}","{fn.get("severity","")}",'
                    f'"{fn.get("ai_verdict", "N/A")}","{fn.get("ai_confidence", "N/A")}",'
                    f'"{fn.get("relative_path","")}",{fn.get("line",0)},"{fn.get("rule_id","")}",'
                    f'"{msg}"\n'
                )

        # HTML
        html_content = ReportGenerator._build_html(scan_data)
        with open(base_path / "index.html", 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"Reports generated: {base_path}")
        return str(base_path)

    @staticmethod
    def _esc(s):
        import html as html_lib
        return html_lib.escape(str(s or ""), quote=True)

    @staticmethod
    def _build_html(scan_data: Dict) -> str:
        stats = scan_data.get("stats", {}) or {}
        scan_info = scan_data.get("scan_info", {}) or {}
        ai_stats = scan_data.get("ai_review_stats", {}) or {}

        findings = scan_data.get("findings", []) or []
        if findings:
            rows_html = ""
            for f in findings:
                sev = (f.get("severity") or "LOW").lower()
                sev_upper = (f.get("severity") or "").upper()
                verdict = f.get("ai_verdict") or "NEEDS_REVIEW"
                verdict_class = verdict.lower().replace("_", "-")
                fid = ReportGenerator._esc(f.get("finding_id", ""))
                rel = ReportGenerator._esc(f.get("relative_path", ""))
                line = f.get("line", 0)
                rule = ReportGenerator._esc(f.get("rule_id", ""))
                desc = ReportGenerator._esc((f.get("description") or f.get("title") or "")[:120])
                reason = ReportGenerator._esc(f.get("ai_reason", "") or "")
                remediation = ReportGenerator._esc(f.get("ai_remediation", "") or "")
                evidence = ReportGenerator._esc((f.get("evidence") or "No context")[:15000])

                # LOW/INFO = no AI details
                is_low_priority = sev_upper in ("LOW", "INFO")

                if is_low_priority:
                    details_html = f"""
                        <details>
                            <summary><strong>{rule}</strong> — {desc}</summary>
                            <pre class="code-block">{evidence}</pre>
                        </details>
                    """
                else:
                    details_html = f"""
                        <details>
                            <summary>{desc}...</summary>
                            <p><strong>AI Reason:</strong> {reason or 'N/A'}</p>
                            <p><strong>Remediation:</strong> {remediation or 'N/A'}</p>
                            <pre class="code-block">{evidence}</pre>
                        </details>
                    """

                rows_html += f"""
                <tr>
                    <td>{fid}</td>
                    <td><span class="badge {sev}">{ReportGenerator._esc(f.get('severity',''))}</span></td>
                    <td><span class="badge {verdict_class}">{ReportGenerator._esc(verdict)}</span></td>
                    <td>{rel}</td>
                    <td>{line}</td>
                    <td>{rule}</td>
                    <td>{details_html}</td>
                </tr>
                """
        else:
            rows_html = '<tr><td colspan="7" style="text-align:center;color:#888;">No findings</td></tr>'

        history = scan_data.get("history", []) or []
        if history:
            hist_rows = ""
            for h in history:
                hist_rows += f"""
                <tr>
                    <td>{ReportGenerator._esc(h.get('finding_id',''))}</td>
                    <td>{ReportGenerator._esc(h.get('event_type',''))}</td>
                    <td>{ReportGenerator._esc(h.get('old_status','N/A') or 'N/A')}</td>
                    <td>{ReportGenerator._esc(h.get('new_status','N/A') or 'N/A')}</td>
                    <td>{ReportGenerator._esc(h.get('timestamp',''))}</td>
                    <td>{ReportGenerator._esc(h.get('details','') or '')}</td>
                </tr>
                """
        else:
            hist_rows = '<tr><td colspan="6" style="text-align:center;color:#888;">No history</td></tr>'

        # AI Review Stats HTML Block
        ai_review_html = ""
        if ai_stats and ai_stats.get("selected", 0) > 0:
            priority_list = "".join([f"<li>{f}</li>" for f in ai_stats.get("highest_priority", [])])
            ai_review_html = f"""
            <div class="stat-card" style="grid-column: 1 / -1; text-align: left; padding: 20px;">
                <h4 style="margin-top:0; color:#055160;">AI File Review Summary</h4>
                <p style="margin: 0 0 10px 0; font-size: 0.9rem;">
                    <strong>Files eligible:</strong> {ai_stats.get('eligible', 0)} |
                    <strong>Selected:</strong> {ai_stats.get('selected', 0)} |
                    <strong>Lines reviewed:</strong> {ai_stats.get('total_lines_reviewed', 0)} / {ai_stats.get('max_budget', 600)} budget |
                    <strong>Skipped:</strong> {ai_stats.get('skipped', 0)}
                </p>
                <p style="margin: 0; font-size: 0.9rem;"><strong>Highest-priority files reviewed:</strong></p>
                <ul style="margin: 5px 0 0 20px; font-size: 0.9rem; color: #495057;">{priority_list}</ul>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8f9fa; color: #212529; margin: 0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: #fff; padding: 24px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ margin-top: 0; }}
        .tabs {{ display: flex; border-bottom: 2px solid #dee2e6; margin-bottom: 20px; }}
        .tab {{ padding: 10px 20px; cursor: pointer; border: 1px solid transparent; border-bottom: none; border-radius: 4px 4px 0 0; user-select: none; }}
        .tab.active {{ background: #fff; border-color: #dee2e6; border-bottom-color: #fff; font-weight: bold; }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; display: inline-block; }}
        .critical {{ background: #f8d7da; color: #842029; }}
        .high {{ background: #fff3cd; color: #664d03; }}
        .medium {{ background: #cff4fc; color: #055160; }}
        .low {{ background: #d1e7dd; color: #0f5132; }}
        .info {{ background: #e2e3e5; color: #41464b; }}
        .true-positive {{ background: #f8d7da; color: #842029; }}
        .false-positive {{ background: #d1e7dd; color: #0f5132; }}
        .needs-review {{ background: #fff3cd; color: #664d03; }}
        .fixed {{ background: #d1e7dd; color: #0f5132; }}
        .skipped {{ background: #e2e3e5; color: #41464b; }}
        .not-fixed {{ background: #f8d7da; color: #842029; }}
        .partially-fixed {{ background: #fff3cd; color: #664d03; }}
        .code-block {{ background: #212529; color: #f8f9fa; padding: 12px; border-radius: 6px; overflow-x: auto; font-family: "Courier New", monospace; font-size: 0.85rem; white-space: pre-wrap; word-break: break-word; max-height: 600px; overflow-y: auto; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #dee2e6; vertical-align: top; font-size: 0.92rem; }}
        th {{ background: #e9ecef; font-weight: 600; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 14px; margin-bottom: 24px; }}
        .stat-card {{ background: #f8f9fa; padding: 14px; border-radius: 8px; text-align: center; border: 1px solid #dee2e6; }}
        .stat-card h3 {{ margin: 0; font-size: 1.8rem; }}
        .stat-card p {{ margin: 4px 0 0; color: #6c757d; font-size: 0.85rem; }}
        .meta {{ color: #6c757d; font-size: 0.9rem; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Source-Code Security Report</h1>
        <p class="meta">
            Scan ID: <strong>{ReportGenerator._esc(scan_info.get('scan_id', 'N/A'))}</strong> |
            Date: <strong>{ReportGenerator._esc(scan_info.get('started_at', 'N/A'))}</strong> |
            Project: <strong>{ReportGenerator._esc(scan_info.get('project_path', 'N/A'))}</strong> |
            Model: <strong>{ReportGenerator._esc(scan_info.get('model_name', 'N/A'))}</strong>
        </p>

        <div class="stats-grid">
            {ai_review_html}
            <div class="stat-card"><h3>{stats.get('total', 0)}</h3><p>Total Findings</p></div>
            <div class="stat-card"><h3 style="color:#842029">{stats.get('critical', 0)}</h3><p>Critical</p></div>
            <div class="stat-card"><h3 style="color:#664d03">{stats.get('high', 0)}</h3><p>High</p></div>
            <div class="stat-card"><h3 style="color:#055160">{stats.get('medium', 0)}</h3><p>Medium</p></div>
            <div class="stat-card"><h3 style="color:#0f5132">{stats.get('low', 0)}</h3><p>Low</p></div>
            <div class="stat-card"><h3 style="color:#842029">{stats.get('true_positives', 0)}</h3><p>True Positives</p></div>
        </div>

        <div class="tabs">
            <div class="tab active" data-tab="findings">Findings</div>
            <div class="tab" data-tab="history">History</div>
        </div>

        <div id="findings" class="tab-content active">
            <table>
                <thead>
                    <tr>
                        <th>ID</th><th>Severity</th><th>Verdict</th>
                        <th>File</th><th>Line</th><th>Rule</th><th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>

        <div id="history" class="tab-content">
            <table>
                <thead>
                    <tr>
                        <th>Finding ID</th><th>Event</th><th>Old Status</th>
                        <th>New Status</th><th>Date</th><th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {hist_rows}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        document.querySelectorAll('.tab').forEach(t => {{
            t.addEventListener('click', () => {{
                document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
                t.classList.add('active');
                document.getElementById(t.dataset.tab).classList.add('active');
            }});
        }});
    </script>
</body>
</html>"""
