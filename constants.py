# secscanner/constants.py
"""Constants and severity mappings."""

ALLOWED_EXTENSIONS = {'.java', '.js', '.vue', '.esql'}
ALLOWED_FILENAMES = {'dockerfile'}
EXCLUDED_DIRS = {
    'node_modules', 'target', 'build', 'dist', 'coverage',
    'vendor', 'venv', '.git', '__pycache__', '.scanner_cache'
}

SEMGREP_SEV_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
HADOLINT_SEV_MAP = {"error": "HIGH", "warning": "MEDIUM", "info": "LOW", "style": "INFO"}

SEMGREP_LANGS = {
    "apex", "bash", "c", "c++", "csharp", "dart", "dockerfile",
    "elixir", "go", "hack", "html", "java", "javascript", "json",
    "julia", "kotlin", "lua", "ocaml", "php", "promql", "protobuf",
    "python", "r", "ruby", "rust", "scala", "sh", "solidity",
    "swift", "terraform", "tsx", "typescript", "yaml", "generic", "regex"
}
