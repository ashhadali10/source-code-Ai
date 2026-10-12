# secscanner/engines/trivy_engine.py
"""Trivy engine (misconfigurations)."""

import json
import logging
from pathlib import Path
from typing import List, Dict

from utils import run_command, tool_installed

logger = logging.getLogger(__name__)


class TrivyEngine:
    def __init__(self, target_dir: str):
        self.target_dir = target_dir

    def run(self) -> List[Dict]:
        if not tool_installed("trivy"):
            logger.warning("[!] Trivy not installed. Skipping misconfiguration scan.")
            return []

        logger.info("Running Trivy (misconfig only)...")
        result = run_command(
            ["trivy", "config", "--scanners", "misconfig",
             "--format", "json", "--quiet", self.target_dir],
            timeout=300
        )
        findings = []
        if result and result["returncode"] in (0, 1):
            try:
                for res in json.loads(result["stdout"]).get("Results", []):
                    for misconfig in res.get("Misconfigurations", []):
                        cause = misconfig.get("CauseMetadata", {}) or {}
                        lines = cause.get("Lines", []) or []
                        line = lines[0].get("Number", 0) if lines else cause.get("StartLine", 0)
                        findings.append({
                            "tool": "trivy",
                            "language": "config",
                            "relative_path": res["Target"],
                            "absolute_path": str(Path(res["Target"]).resolve()),
                            "line": line,
                            "column": 0,
                            "rule_id": misconfig.get("ID", "TRIVY-MISC"),
                            "severity": misconfig.get("Severity", "MEDIUM").upper(),
                            "confidence": "MEDIUM",
                            "message": misconfig.get("Title", "Misconfiguration"),
                            "cwe": (misconfig.get("CweIDs") or ["Unknown"])[0],
                            "owasp": "Unknown",
                        })
            except json.JSONDecodeError:
                pass
        return findings
