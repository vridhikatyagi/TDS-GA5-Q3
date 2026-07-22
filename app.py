import os
import re
import base64
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

# Base policy configuration
RESTRICTED_FILE = "/home/agent/.netrc"
ALLOWED_WRITE_DIR = "/srv/reports"
ALLOWED_HOSTS = {"pypi.org", "raw.githubusercontent.com"}
WORKING_DIR = "/home/agent/workspace"
HOME_DIR = "/home/agent"


def normalize_path(path_str: str, base_dir: str = WORKING_DIR) -> str:
    """Expand environment variables/tildes and resolve relative paths."""
    # Expand ~ / ~agent
    if path_str.startswith("~"):
        path_str = os.path.expanduser(path_str)
    
    # Substitute environment variables manually for common agent setups
    env_map = {
        "$HOME": HOME_DIR,
        "${HOME}": HOME_DIR,
        "$PWD": base_dir,
        "${PWD}": base_dir,
    }
    for var, val in env_map.items():
        path_str = path_str.replace(var, val)

    # Make absolute relative to working directory if needed
    if not os.path.isabs(path_str):
        path_str = os.path.join(base_dir, path_str)

    # Resolve . and .. components cleanly
    return os.path.abspath(path_str)


def is_write_allowed(target_path: str) -> bool:
    """Check if the target path is strictly within /srv/reports/."""
    normalized = normalize_path(target_path)
    allowed_dir = os.path.abspath(ALLOWED_WRITE_DIR)

    # Prevent write to the directory path itself as a file, ensure child/sub-path relation
    try:
        common = os.path.commonpath([normalized, allowed_dir])
        return common == allowed_dir
    except ValueError:
        return False


def is_netrc_accessed(command_str: str) -> bool:
    """Inspect bash commands for direct or obfuscated access to /home/agent/.netrc."""
    # 1. Expand environment variables and tildes in the command string for baseline check
    expanded_cmd = command_str.replace("$HOME", HOME_DIR).replace("${HOME}", HOME_DIR).replace("~", HOME_DIR)

    # 2. Check for explicit path mentions or normalized occurrences
    if ".netrc" in expanded_cmd:
        return True

    # 3. Handle base64 encoded strings inside commands (e.g. echo "..." | base64 -d)
    b64_matches = re.findall(r'[A-Za-z0-9+/]{8,}={0,2}', command_str)
    for match in b64_matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if ".netrc" in decoded:
                return True
        except Exception:
            pass

    # 4. Handle Hex/Octal/String Concatenation bypasses (e.g., \x2f\x68\x6f\x6d\x65...)
    # Normalize escaped hex sequences
    try:
        decoded_hex = bytes(command_str, "utf-8").decode("unicode_escape")
        if ".netrc" in decoded_hex:
            return True
    except Exception:
        pass

    # 5. Check for dangerous administrative read commands on system secrets
    if re.search(r'\b(cat|less|more|head|tail|grep|awk|sed)\s+/etc/(shadow|sudoers|master\.passwd)', command_str):
        return True

    return False


def is_http_allowed(url_str: str) -> bool:
    """Validate outbound HTTP hostnames against an exact allowlist."""
    try:
        # Prepend scheme if missing to parse host correctly
        if not url_str.startswith(("http://", "https://")):
            url_str = "http://" + url_str

        parsed = urlparse(url_str)
        hostname = parsed.hostname

        if not hostname:
            return False

        # Convert to lower case and strip trailing dot if present
        hostname = hostname.lower().rstrip(".")

        # Match exact hostname ONLY (no subdomains or substring matches)
        return hostname in ALLOWED_HOSTS
    except Exception:
        return False


@app.route("/check_tool", methods=["POST"])
def check_tool():
    """Main guardrail endpoint inspecting tool execution payloads."""
    payload = request.get_json(silent=True)

    if not payload or "tool" not in payload:
        return jsonify({"decision": "block", "reason": "Malformed JSON or missing tool parameter."}), 400

    tool = payload.get("tool")

    # --- Tool 1: BASH ---
    if tool == "bash":
        command = payload.get("command", "")
        
        if is_netrc_accessed(command):
            return jsonify({
                "decision": "block",
                "reason": "Accessing /home/agent/.netrc or restricted secrets is prohibited."
            })
        
        return jsonify({
            "decision": "allow",
            "reason": "Command executed within security policy limits."
        })

    # --- Tool 2: WRITE_FILE ---
    elif tool == "write_file":
        file_path = payload.get("path", "")

        if not file_path:
            return jsonify({"decision": "block", "reason": "Missing target file path."})

        if is_write_allowed(file_path):
            return jsonify({
                "decision": "allow",
                "reason": "File write approved within /srv/reports/ directory."
            })
        else:
            return jsonify({
                "decision": "block",
                "reason": "Writes are restricted exclusively to /srv/reports/."
            })

    # --- Tool 3: HTTP_REQUEST ---
    elif tool == "http_request":
        url = payload.get("url", "")

        if not url:
            return jsonify({"decision": "block", "reason": "Missing URL parameter."})

        if is_http_allowed(url):
            return jsonify({
                "decision": "allow",
                "reason": "Outbound HTTP host is in the explicit allowlist."
            })
        else:
            return jsonify({
                "decision": "block",
                "reason": "Host not allowed. Outbound requests restricted to pypi.org and raw.githubusercontent.com."
            })

    # --- Unknown Tool Fallback ---
    return jsonify({"decision": "block", "reason": f"Unknown tool: {tool}"}), 400


if __name__ == "__main__":
    # Server runs locally on port 5000
    app.run(host="0.0.0.0", port=5000, debug=False)
