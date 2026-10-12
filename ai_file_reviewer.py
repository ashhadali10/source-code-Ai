# secscanner/ai_file_reviewer.py
"""AI File Reviewer — verifies Semgrep findings + adds missing issues.

Workflow:
  1. Semgrep + other tools generate findings
  2. AI reviews findings to classify TRUE/FALSE positive
  3. AI additionally reviews small files (< max_file_lines) holistically
     to catch what static tools missed
  4. Merges everything into a consolidated view
"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Tuple

from ai_validator import AIValidator

logger = logging.getLogger(__name__)


PRIORITY_KEYWORDS = [
    (r'(?i)\bdockerfile\b', 100),
    (r'(?i)(auth|authentication|login|jwt|session|token|password|credential)', 90),
    (r'(?i)\b(server|app|main|index)\b', 80),
    (r'(?i)(route|routes|controller|controllers|api|endpoint)', 70),
    (r'(?i)(middleware|middlewares)', 60),
    (r'(?i)(db|database|query|model|models|repository)', 50),
    (r'(?i)(config|settings|env|dotenv)', 40),
    (r'(?i)(upload|file|attachment)', 40),
    (r'(?i)(exec|spawn|child_process|system)', 30),
    (r'(?i)(util|utils|helper|helpers|common)', 10),
]


def calculate_priority(file_path: str) -> int:
    score = 0
    name = Path(file_path).name
    for pattern, pts in PRIORITY_KEYWORDS:
        if re.search(pattern, name):
            score += pts
    parent = Path(file_path).parent.name
    for pattern, pts in PRIORITY_KEYWORDS:
        if re.search(pattern, parent):
            score += pts // 2
    return score


def count_lines(file_path: str) -> int:
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for _ in f)
    except Exception:
        return 9999


class AIFileReviewer:
    """AI reviewer that:
       - Reviews small files holistically (files <= max_file_lines)
       - Works alongside Semgrep findings for verification
    """

    def __init__(self, config: Dict):
        ai_cfg = config.get("ai_code_review", {}) or {}
        self.config = ai_cfg
        self.enabled = ai_cfg.get("enabled", False)
        self.max_file_lines = int(ai_cfg.get("max_file_lines", 150))
        self.max_total_lines = int(ai_cfg.get("max_total_lines", 600))
        self.ai_validator = AIValidator(config.get("llm", {}))

    @staticmethod
    def count_lines(file_path: str) -> int:
        return count_lines(file_path)

    def select_files(self, files: List[Path]) -> List[Tuple[Path, int, int]]:
        """Select files under max_file_lines for holistic AI review."""
        if not self.enabled:
            return []

        candidates = []
        for f in files:
            lines = count_lines(str(f))
            if lines <= self.max_file_lines:
                score = calculate_priority(str(f))
                candidates.append((f, lines, score))

        candidates.sort(key=lambda x: x[2], reverse=True)

        selected = []
        current_total = 0
        for f, lines, score in candidates:
            if current_total + lines <= self.max_total_lines:
                selected.append((f, lines, score))
                current_total += lines

        return selected

    def review_files(self, selected_files: List[Tuple[Path, int, int]]) -> List[Dict]:
        """Run holistic AI review on selected files."""
        findings = []
        for f, lines, score in selected_files:
            logger.info(f"AI Reviewing: {f.name} ({lines} lines, priority: {score})")
            try:
                with open(f, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()

                result = self.ai_validator.review_whole_file(str(f), content)

                if result and result.get("findings"):
                    for finding in result["findings"]:
                        findings.append({
                            "tool": "ai_file_review",
                            "language": "unknown",
                            "relative_path": str(f),
                            "absolute_path": str(f.resolve()),
                            "line": finding.get("line", 1),
                            "column": 0,
                            "rule_id": finding.get("rule_id", "ai-whole-file"),
                            "severity": finding.get("severity", "MEDIUM").upper(),
                            "message": finding.get("message", "AI detected potential issue"),
                            "cwe": finding.get("cwe", "Unknown"),
                            "owasp": finding.get("owasp", "Unknown"),
                            "evidence": content,
                            "ai_verdict": "TRUE_POSITIVE",
                            "ai_confidence": finding.get("confidence", "MEDIUM"),
                            "ai_reason": finding.get("reason", ""),
                            "ai_remediation": finding.get("remediation", ""),
                            "review_priority_score": score,
                            "review_lines": lines,
                        })
            except Exception as e:
                logger.error(f"Failed to review {f}: {e}")

        return findings
