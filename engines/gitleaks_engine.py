# secscanner/engines/gitleaks_engine.py
"""Gitleaks engine."""

import json
import logging
from pathlib import Path
from typing import List, Dict

from utils import run_command, tool_installed

logger = logging.getLogger(__name__)


class GitleaksEngine:
    def __init__(self, target_dir: str):
        self.target_dir = target_dir

    def run(self) -> List[Dict]:
        if not tool_installed("gitleaks"):
            logger.warning("[!] Gitleaks not installed. Skipping secret detection.")
            return []

        logger.info("Running Gitleaks...")
        report_file = Path(".scanner_cache/gitleaks.json")

        run_command(
            ["gitleaks", "dir", self.target_dir,
             "--report-format", "json",
             "--report-path", str(report_file),
             "--no-banner", "--exit-code", "0"],
            timeout=300
        )

        findings = []
        if report_file.exists():
            try:
                for leak in json.loads(report_file.read_text(encoding='utf-8')):
                    secret = str(leak.get("Secret", "") or leak.get("Match", ""))
                    findings.append({
                        "tool": "gitleaks",
                        "language": "generic",
                        "relative_path": leak["File"],
                        "absolute_path": str(Path(leak["File"]).resolve()),
                        "line": leak.get("StartLine", 0),
                        "column": leak.get("StartColumn", 0),
                        "rule_id": f"gitleaks.{leak.get('RuleID', 'secret')}",
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "message": f"Hardcoded secret: {leak.get('Description', 'Secret')} "
                                   f"(value starts: {secret[:4]}..., masked)",
                        "cwe": "CWE-798",
                        "owasp": "A07:2021",
                    })
            except Exception as e:
                logger.error(f"Gitleaks parse error: {e}")
        return findings
