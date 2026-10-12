"""validate command — revalidation with old + new code comparison."""

import sys
import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List
from html import escape as html_escape

from database import DatabaseManager
from ai_validator import AIValidator
from utils import run_command, tool_installed

logger = logging.getLogger(__name__)


def extract_code_window(file_path: str, center_line: int, window: int = 50) -> str:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        start = max(0, center_line - window - 1)
        end = min(len(lines), center_line + window)
        numbered = []
        for i in range(start, end):
            marker = ">>>" if (i + 1) == center_line else "   "
            numbered.append(f"{marker} {i+1:4d} | {lines[i].rstrip()}")
        return "\n".join(numbered)
    except Exception as e:
        return f"[Error: {e}]"


def run_semgrep_on_file(file_path: str, line_start: int, line_end: int) -> List[Dict]:
    if not tool_installed("semgrep"):
        return []
    cmd = [
        "semgrep", "scan",
        "--config", "p/owasp-top-ten",
        "--config", "p/secrets",
        "--json", "--quiet",
        "--no-git-ignore", "--disable-version-check",
        file_path,
    ]
    result = run_command(cmd, timeout=300)
    if not result or result["returncode"] not in (0, 1):
        return []
    try:
        data = json.loads(result["stdout"])
    except json.JSONDecodeError:
        return []
    findings = []
    for f in data.get("results", []):
        start = f.get("start", {}).get("line", 0)
        if not (line_start - 10 <= start <= line_end + 10):
            continue
        extra = f.get("extra", {}) or {}
        findings.append({
            "rule_id": f.get("check_id", ""),
            "severity": extra.get("severity", "INFO"),
            "message": extra.get("message", ""),
            "line": start,
        })
    return findings


def validate_single_finding(finding, validator, use_semgrep=True):
    file_path = finding.get("absolute_path", "")
    line = finding.get("line", 0)
    if not Path(file_path).exists():
        return {
            "verdict": "NEEDS_REVIEW", "confidence": "LOW",
            "reason": f"File not found: {file_path}",
            "old_code": finding.get("evidence", ""),
            "new_code": "", "changes_detected": [], "semgrep_findings": [],
        }
    new_code = extract_code_window(file_path, line, window=50)
    semgrep_result = run_semgrep_on_file(file_path, line - 10, line + 10) if use_semgrep else []
    old_code = finding.get("evidence", "No historical code")
    static_still = len(semgrep_result) > 0
    result = validator.validate_fix(finding, old_code, new_code, static_still_vulnerable=static_still)
    return {
        "verdict": result.get("result", "NEEDS_REVIEW"),
        "confidence": result.get("confidence", "LOW"),
        "reason": result.get("reason", ""),
        "changes_detected": result.get("changes_detected", []),
        "old_code": old_code,
        "new_code": new_code,
        "semgrep_findings": semgrep_result,
    }


def cmd_validate(args, config: Dict):
    db = DatabaseManager(config["database"]["path"])
    validator = AIValidator(config["llm"])
    targets = args.target if isinstance(args.target, list) else [args.target]

    finding_ids, file_paths = [], []
    for t in targets:
        for p in [x.strip() for x in t.replace(",", " ").split() if x.strip()]:
            (finding_ids if p.startswith("FIND-") else file_paths).append(p)

    findings = []
    if finding_ids:
        findings.extend(db.get_findings_for_validation(finding_ids=finding_ids))
    for fp in file_paths:
        findings.extend(db.get_findings_for_validation(file_path=fp))

    if not findings:
        logger.warning("No open findings found.")
        sys.exit(0)

    # Deduplicate
    seen, unique = set(), []
    for f in findings:
        fid = f.get("finding_id")
        if fid and fid not in seen:
            seen.add(fid); unique.append(f)
    findings = unique

    logger.info(f"Validating {len(findings)} finding(s)...\n")
    results = []
    for i, f in enumerate(findings, 1):
        fid = f.get("finding_id", "?")
        print(f"[{i}/{len(findings)}] {fid}")
        print(f"    File: {f.get('relative_path','')}:{f.get('line',0)}")
        result = validate_single_finding(f, validator, use_semgrep=True)

        validation_data = {
            "old_code": str(f.get("evidence", ""))[:5000],
            "new_code": str(result.get("new_code", ""))[:5000],
            "old_hash": str(f.get("version_hash", "")),
            "new_hash": hashlib.sha256(result.get("new_code", "").encode()).hexdigest(),
            "result": result["verdict"],
            "confidence": result["confidence"],
            "reason": result["reason"],
        }
        db.record_validation(fid, validation_data)
        print(f"    → {result['verdict']} ({result['confidence']})")
        print(f"    Reason: {result['reason'][:180]}...\n")

        results.append({
            **f,
            "validation_result": result["verdict"],
            "validation_confidence": result["confidence"],
            "validation_reason": result["reason"],
            "old_code": result.get("old_code", ""),
            "new_code": result.get("new_code", ""),
            "changes_detected": result.get("changes_detected", []),
            "semgrep_findings": result.get("semgrep_findings", []),
            "ai_verdict": result["verdict"],
            "ai_confidence": result["confidence"],
            "ai_reason": result["reason"],
        })

    fixed = sum(1 for r in results if r["validation_result"] == "FIXED")
    partial = sum(1 for r in results if r["validation_result"] == "PARTIALLY_FIXED")
    not_fixed = sum(1 for r in results if r["validation_result"] == "NOT_FIXED")
    regr = sum(1 for r in results if r["validation_result"] == "REGRESSION")

    print("=" * 60)
    print(f"FIXED:          {fixed}")
    print(f"PARTIALLY:      {partial}")
    print(f"NOT FIXED:      {not_fixed}")
    print(f"REGRESSION:     {regr}")
    print("=" * 60 + "\n")

    # Build report
    out_dir = Path(config["reporting"]["output_dir"])
    out_dir.mkdir(exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_path = out_dir / f"VALIDATION_{now}"
    base_path.mkdir(exist_ok=True)

    with open(base_path / "index.html", 'w', encoding='utf-8') as f:
        f.write(_build_validation_html(results, targets))
    with open(base_path / "validation.json", 'w', encoding='utf-8') as f:
        json.dump({"targets": targets, "results": results}, f, indent=2, default=str)

    print(f"✅ Validation complete. Report: {base_path}/index.html")


def _build_validation_html(results, targets):
    def esc(s):
        return html_escape(str(s or ""), quote=True)

    rows = ""
    for i, r in enumerate(results, 1):
        verdict = r.get("validation_result", "NEEDS_REVIEW")
        vclass = verdict.lower().replace("_", "-")
        sev = (r.get("severity") or "LOW").lower()
        fid = esc(r.get("finding_id", ""))
        rel = esc(r.get("relative_path", ""))
        line = r.get("line", 0)
        rule = esc(r.get("rule_id", ""))
        reason = esc(r.get("validation_reason", "") or "")
        old_code = esc((r.get("old_code") or "No historical code")[:5000])
        new_code = esc((r.get("new_code") or "No current code")[:5000])
        changes = r.get("changes_detected") or []
        changes_html = "".join(f"<li>{esc(c)}</li>" for c in changes) if changes else "<li>—</li>"

        rows += f"""
        <div style="border:1px solid #dee2e6; border-radius:8px; padding:16px; margin-bottom:16px; background:#fff;">
            <div style="margin-bottom:10px;">
                <span class="badge {vclass}">{esc(verdict)}</span>
                <span class="badge {sev}">{esc(r.get('severity',''))}</span>
                <strong>{fid}</strong> | {rel}:{line} | <code>{rule}</code>
            </div>
            <p><strong>AI Reason:</strong> {reason or 'N/A'}</p>
            <p><strong>Changes Detected:</strong></p>
            <ul>{changes_html}</ul>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px; margin-top:12px;">
                <div>
                    <h4 style="color:#842029; margin:0 0 6px 0;">OLD Code (Vulnerable)</h4>
                    <pre class="code-block" style="background:#2b1a1a;">{old_code}</pre>
                </div>
                <div>
                    <h4 style="color:#0f5132; margin:0 0 6px 0;">NEW Code (Current)</h4>
                    <pre class="code-block" style="background:#1a2b1a;">{new_code}</pre>
                </div>
            </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Revalidation Report</title>
<style>
body {{ font-family: -apple-system, sans-serif; background:#f8f9fa; margin:0; padding:20px; }}
.container {{ max-width:1600px; margin:0 auto; background:#fff; padding:24px; border-radius:8px; }}
h1 {{ margin-top:0; }}
.badge {{ padding:4px 8px; border-radius:4px; font-size:0.8rem; font-weight:600; text-transform:uppercase; margin-right:6px; }}
.critical {{ background:#f8d7da; color:#842029; }}
.high {{ background:#fff3cd; color:#664d03; }}
.medium {{ background:#cff4fc; color:#055160; }}
.low {{ background:#d1e7dd; color:#0f5132; }}
.fixed {{ background:#d1e7dd; color:#0f5132; }}
.not-fixed {{ background:#f8d7da; color:#842029; }}
.partially-fixed {{ background:#fff3cd; color:#664d03; }}
.needs-review {{ background:#e2e3e5; color:#41464b; }}
.regression {{ background:#f8d7da; color:#842029; }}
.code-block {{ padding:12px; border-radius:6px; overflow:auto; font-family:"Courier New",monospace; font-size:0.8rem; color:#f8f9fa; white-space:pre-wrap; max-height:500px; }}
</style></head>
<body><div class="container">
<h1>Revalidation Report</h1>
<p><strong>Targets:</strong> {', '.join(esc(t) for t in targets)}</p>
<p><strong>Generated:</strong> {datetime.now().isoformat()}</p>
<h2>Findings ({len(results)})</h2>
{rows}
</div></body></html>"""


