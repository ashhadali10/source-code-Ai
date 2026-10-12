# secscanner/rules_loader.py
"""Default rules and environment setup."""

import logging
from pathlib import Path
import yaml

from constants import SEMGREP_LANGS

logger = logging.getLogger(__name__)

# (Same DEFAULT_RULES dict as your original — copy it as-is)
DEFAULT_RULES = {
    "esql/custom.yml": r"""rules:
  - id: esql-dynamic-sql-concatenation
    ...
""",
    # ... keep all rules as they were
}


def setup_environment() -> None:
    """Create directories and write default rules if missing/invalid."""
    Path("rules").mkdir(exist_ok=True)
    for lang in ["java", "javascript", "vue", "docker", "esql"]:
        Path(f"rules/{lang}").mkdir(exist_ok=True)

    # Write config.yaml
    from config import load_config
    # Only create config.yaml if it doesn't exist — never overwrite user settings
    if not Path("config.yaml").exists():
        cfg = load_config("config.yaml")
        Path("config.yaml").write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False),
            encoding="utf-8"
        )
        logger.info("config.yaml created")

    # Write rule files if missing or invalid
    for filepath, content in DEFAULT_RULES.items():
        fpath = Path(f"rules/{filepath}")
        needs_write = not fpath.exists()

        if not needs_write:
            try:
                existing = yaml.safe_load(fpath.read_text(encoding="utf-8")) or {}
                for rule in (existing.get("rules") or []):
                    if str(rule.get("severity", "")).upper() not in ("ERROR", "WARNING", "INFO"):
                        needs_write = True
                        break
                    for lang in (rule.get("languages") or []):
                        if str(lang).lower() not in SEMGREP_LANGS:
                            needs_write = True
                            break
            except Exception:
                needs_write = True

        if needs_write:
            fpath.write_text(content, encoding="utf-8")
            logger.info(f"wrote valid rule file: {filepath}")

    Path(".scanner_cache").mkdir(exist_ok=True)
