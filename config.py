# secscanner/config.py
"""Configuration loading with defaults merge."""

import yaml
import logging
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

# secscanner/config.py
# ... (keep imports and deep_merge exactly as they are) ...

DEFAULT_CONFIG = """
scanner:
  target_languages: ["java", "javascript", "vue", "esql", "docker"]
  exclude_dirs: ["node_modules", "target", "build", "dist", "coverage", "vendor", "venv", ".git", "__pycache__", ".scanner_cache"]

llm:
  provider: ollama
  url: http://localhost:11434/api/generate
  model: qwen2.5-coder:14b-instruct-q5_1
  models:
    - qwen2.5-coder:14b-instruct-q5_1
    - qwen2.5-coder:14b
  timeout: 180
  max_workers: 4

ai_code_review:
  enabled: true
  max_file_lines: 150
  max_total_lines: 600

database:
  path: .scanner_data/scanner.db

reporting:
  output_dir: ./reports
  mask_secrets: true

tools:
  semgrep: true
  gitleaks: true
  hadolint: true
  trivy: true
"""
# ... (keep the rest of load_config exactly as it is) ...


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge override onto base."""
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    """Load config, merging user config over defaults."""
    defaults = yaml.safe_load(DEFAULT_CONFIG) or {}
    user_cfg: Dict[str, Any] = {}

    p = Path(path)
    if p.exists():
        try:
            user_cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if not isinstance(user_cfg, dict):
                logger.warning(f"{path} is not a mapping - using defaults")
                user_cfg = {}
        except Exception as exc:
            logger.warning(f"could not parse {path}: {exc} - using defaults")
            user_cfg = {}

    merged = deep_merge(defaults, user_cfg)

    # LLM model list normalization
    user_llm = user_cfg.get("llm") or {}
    models: Any = user_llm.get("models")
    if isinstance(models, str):
        models = [m.strip() for m in models.split(",") if m.strip()]
    if not models:
        single = user_llm.get("model")
        models = [single] if single else (
            merged.get("llm", {}).get("models") or ["qwen2.5-coder:14b"]
        )

    merged["llm"]["models"] = models
    merged["llm"]["model"] = models[0]
    return merged
