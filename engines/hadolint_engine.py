# secscanner/engines/hadolint_engine.py
"""Hadolint engine (Dockerfile linting)."""

import json
import logging
from pathlib import Path
from typing import List, Dict

from utils import run_command, tool_installed
from constants import HADOLINT_SEV_MAP

logger = logging.getLogger(__name__)


class HadolintEngine:
    def __init__(self, target_files: List[Path]):
        self.dockerfiles = [
            str(f) for f in target_files
            if f.name.lower().startswith("dockerfile")
        ]

    def run(self) -> List[Dict]:
        if not self.dockerfiles:
            return []
        if not tool_installed("hadolint"):
            logger.warning("[!] Hadolint not installed. Skipping Dockerfile linting.")
            return []

        logger.info("Running Hadolint...")
        findings = []
        for df in self.dockerfiles:
            result = run_command(["hadolint", "-f", "json", df], timeout=120)
            if result and result["returncode"] in (0, 1):
                try:
                    for issue in json.loads(result["stdout"]):
                        level = str(issue.get("level", "info")).lower()
                        if level == "style":
                            continue
                        findings.append({
                            "tool": "hadolint",
                            "language": "docker",
                            "relative_path": df,
                            "absolute_path": str(Path(df).resolve()),
                            "line": issue.get("line", 0),
                            "column": issue.get("column", 0),
                            "rule_id": issue.get("code", "DL3000"),
                            "severity": HADOLINT_SEV_MAP.get(level, "LOW"),
                            "confidence": "HIGH" if level == "error" else "MEDIUM",
                            "message": issue.get("message", "Dockerfile issue"),
                            "cwe": "CWE-1104",
                            "owasp": "A08:2021",
                        })
                except json.JSONDecodeError:
                    pass
        return findings
