import re
import os
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────
# CONSTANTS
# ────────────────────────────────────────────────────

ALLOWED_EXTENSIONS = {'.java', '.js', '.vue', '.esql', '.ts'}
ALLOWED_FILENAMES = {'dockerfile'}
EXCLUDED_DIRS = {
    'node_modules', 'target', 'build', 'dist', 'coverage',
    'vendor', 'venv', '.venv', '.git', '__pycache__',
    '.scanner_cache', '.scanner_data'
}


# ────────────────────────────────────────────────────
# SECRET MASKING
# ────────────────────────────────────────────────────

def mask_secrets(text: str) -> str:
    """Mask secret-like values in text."""
    if not text:
        return ""
    patterns = [
        (r'(AKIA)[A-Z0-9]{16}', r'\1****************'),
        (r'(ghp_)[a-zA-Z0-9]{36}', r'\1************************************'),
        (r'([pP]assword["\']?\s*[:=]\s*["\'])([^"\']{4,})', r'\1********'),
        (r'([tT]oken["\']?\s*[:=]\s*["\'])([^"\']{4,})', r'\1********'),
        (r'(api[_-]?key["\']?\s*[:=]\s*["\'])([^"\']{4,})', r'\1********'),
    ]
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text


# ────────────────────────────────────────────────────
# CODE CONTEXT EXTRACTION
# ────────────────────────────────────────────────────

def extract_security_context(file_path: str, line: int, context_lines: int = 100) -> Dict[str, Any]:
    """Extract code context around a finding line."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        if not lines:
            return {"snippet": "Empty file", "function_start": line, "line": line}

        line = max(1, min(line, len(lines)))

        start = max(0, line - context_lines - 1)
        end = min(len(lines), line + context_lines)

        # Try to find enclosing function
        func_start = start
        func_pattern = re.compile(
            r'^\s*(def |async def |function |func |class |public |private |protected |\w+\s*\([^)]*\)\s*\{)'
        )
        for i in range(line - 1, max(0, line - 100), -1):
            if func_pattern.match(lines[i]):
                func_start = i
                break

        snippet_lines = lines[func_start:end]
        numbered = []
        for idx, txt in enumerate(snippet_lines, start=func_start + 1):
            prefix = ">>>" if idx == line else "   "
            numbered.append(f"{prefix} {idx:4d} | {txt.rstrip()}")

        return {
            "snippet": "\n".join(numbered),
            "function_start": func_start + 1,
            "line": line
        }
    except Exception as e:
        return {
            "snippet": f"No context available: {e}",
            "function_start": line,
            "line": line
        }


# ────────────────────────────────────────────────────
# FILE DISCOVERY
# ────────────────────────────────────────────────────

def get_target_files(target_dir: str) -> List[Path]:
    """Find files eligible for scanning."""
    target = Path(target_dir).resolve()
    files = []

    if not target.exists():
        return files

    if target.is_file():
        if (target.suffix.lower() in ALLOWED_EXTENSIONS
                or target.name.lower() in ALLOWED_FILENAMES
                or target.name.lower().startswith("dockerfile")):
            return [target]
        return []

    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for fname in filenames:
            fpath = Path(root) / fname
            ext = fpath.suffix.lower()
            name_lower = fname.lower()
            if (ext in ALLOWED_EXTENSIONS
                    or name_lower in ALLOWED_FILENAMES
                    or name_lower.startswith("dockerfile")):
                files.append(fpath)
    return files


# ────────────────────────────────────────────────────
# COMMAND EXECUTION
# ────────────────────────────────────────────────────

def run_command(cmd: List[str], timeout: int = 300) -> Optional[Dict[str, Any]]:
    """Run a subprocess command safely."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out: {' '.join(cmd[:3])}")
        return None
    except FileNotFoundError:
        logger.warning(f"Command not found: {cmd[0]}")
        return None
    except Exception as e:
        logger.error(f"Command execution error: {e}")
        return None


def tool_installed(name: str) -> bool:
    """Check if a CLI tool is available."""
    try:
        return subprocess.run(
            ["which", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        ).returncode == 0
    except Exception:
        return False


# ────────────────────────────────────────────────────
# PATH HELPERS
# ────────────────────────────────────────────────────

def normalize_path(path: str, base: str = "") -> str:
    """Normalize a file path."""
    if not path:
        return ""
    p = Path(path)
    if p.is_absolute():
        return str(p.resolve())
    if base:
        return str((Path(base) / p).resolve())
    return str(p.resolve())
