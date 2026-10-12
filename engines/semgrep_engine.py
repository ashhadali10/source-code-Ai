# secscanner/engines/semgrep_engine.py
import json
import logging
import time
from pathlib import Path
from typing import List, Dict
from collections import defaultdict

from utils import run_command

logger = logging.getLogger(__name__)


class SemgrepEngine:
    def __init__(self, target_files: List[Path]):
        self.target_files = [str(f) for f in target_files]
        self.rules_dir = Path("rules").resolve()

    def run(self) -> List[Dict]:
        logger.info("[2/5] Semgrep Analysis")
        logger.info("-" * 40)

        if not self.target_files:
            logger.info("Status: SKIPPED (No eligible files found)")
            return []

        # Analyze files by language
        lang_counts = defaultdict(int)
        for f in self.target_files:
            ext = Path(f).suffix.lower()
            if ext == '.java': lang_counts['Java'] += 1
            elif ext in ['.js', '.ts']: lang_counts['JavaScript/TypeScript'] += 1
            elif ext == '.vue': lang_counts['Vue'] += 1
            elif ext == '.esql': lang_counts['ESQL'] += 1
            elif Path(f).name.lower().startswith('dockerfile'): lang_counts['Docker'] += 1
            else: lang_counts['Other'] += 1

        logger.info(f"Files to scan: {len(self.target_files)}")
        for lang, count in lang_counts.items():
            logger.info(f"  - {lang}: {count} files")

        # ═══ MAXIMUM RULESETS ═══
        registry_rules = [
            "p/owasp-top-ten",
            "p/secrets",
            "p/security-audit",
            "p/command-injection",
            "p/dockerfile",
            "p/java",
            "p/javascript",
            "p/php",
            "p/python",
        ]
        custom_rules = []
        for lang_dir in ["java", "javascript", "vue", "docker", "esql"]:
            lang_path = self.rules_dir / lang_dir
            if lang_path.exists():
                custom_rules.extend([str(f) for f in lang_path.rglob("*.yml")])

        logger.info(f"Rulesets loaded:")
        logger.info(f"  - Registry: {', '.join(registry_rules)}")
        logger.info(f"  - Custom: {len(custom_rules)} files")
        logger.info("Status: RUNNING...")

        # ═══ BUILD COMMAND WITH ALL RULESETS ═══
        cmd = ["semgrep", "scan"]
        for rule in registry_rules:
            cmd.extend(["--config", rule])
        cmd.extend([
            "--json", "--quiet", "--no-git-ignore",
            "--disable-version-check",
            "--exclude", "node_modules",
            "--exclude", "target",
            "--exclude", "build",
            "--exclude", "dist",
            *self.target_files
        ])

        # Add custom rules if they exist
        for rule in custom_rules:
            cmd.extend(["--config", rule])

        start_time = time.time()
        result = run_command(cmd, timeout=600)
        elapsed = time.time() - start_time

        if not result or result["returncode"] not in (0, 1):
            logger.error(f"Status: FAILED")
            logger.error(f"Error: {result['stderr'][:500] if result else 'Unknown'}")
            return []

        findings = []
        try:
            data = json.loads(result["stdout"])
            raw_findings = data.get("results", [])

            for f in raw_findings:
                extra = f.get("extra", {}) or {}
                meta = extra.get("metadata", {}) or {}
                start = f.get("start", {}) or {}

                # Normalize severity
                sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
                raw_sev = str(extra.get("severity", "INFO")).upper()
                sev = str(meta.get("severity") or sev_map.get(raw_sev, "LOW")).upper()

                # Normalize cwe/owasp (may be list)
                cwe = meta.get("cwe", "Unknown")
                if isinstance(cwe, list):
                    cwe = ", ".join(str(c) for c in cwe)
                owasp = meta.get("owasp", "Unknown")
                if isinstance(owasp, list):
                    owasp = ", ".join(str(o) for o in owasp)

                findings.append({
                    "tool": "semgrep",
                    "language": meta.get("language", "unknown"),
                    "relative_path": f["path"],
                    "absolute_path": str(Path(f["path"]).resolve()),
                    "line": start.get("line", 0),
                    "column": start.get("col", 0),
                    "rule_id": f["check_id"],
                    "severity": sev,
                    "confidence": str(meta.get("confidence", "MEDIUM")).upper(),
                    "message": extra.get("message", ""),
                    "cwe": cwe,
                    "owasp": owasp,
                })

            logger.info(f"Status: COMPLETED in {elapsed:.2f}s")
            logger.info(f"Findings: {len(findings)}")

        except json.JSONDecodeError:
            logger.error("Status: FAILED (JSON parsing error)")

        logger.info("-" * 40)
        return findings
