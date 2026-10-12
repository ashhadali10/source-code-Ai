# commands/tools.py
"""tools command — check installed security tools + Ollama."""

import json
import urllib.request

from utils import tool_installed


def cmd_tools(args, config):
    tools = ["semgrep", "gitleaks", "hadolint", "trivy"]

    print("\nTool Status:")
    for tool in tools:
        status = "✅ OK" if tool_installed(tool) else "❌ MISSING"
        print(f"  {tool.capitalize():<10} : {status}")

    # Ollama check
    models = config["llm"].get("models") or []
    try:
        req = urllib.request.Request("http://localhost:11434/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            tags = json.loads(resp.read().decode())

        available = [m.get("name", "") for m in tags.get("models", [])]
        print("  Ollama     : ✅ reachable")

        for m in models:
            mark = "✅ loaded" if m in available else f"⚠️  not pulled (run: ollama pull {m})"
            print(f"      {m:<40} {mark}")

        if not models:
            print("      (no models configured)")

    except Exception as e:
        print(f"  Ollama     : ❌ UNAVAILABLE ({e})")
        print("               ensure 'ollama serve' is running")
