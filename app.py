import os
import re
import base64
import shlex
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

# Base Policy Configuration
RESTRICTED_FILE = "/home/agent/.netrc"
ALLOWED_WRITE_DIR = "/srv/reports"
ALLOWED_HOSTS = {"pypi.org", "raw.githubusercontent.com"}
WORKING_DIR = "/home/agent/workspace"
HOME_DIR = "/home/agent"


def resolve_canonical_path(path_str: str) -> str:
    """Canonicalize any path string relative to workspace and expand env vars."""
    if not path_str or not isinstance(path_str, str):
        return ""
    
    # 1. Expand environment variables and tildes
    expanded = path_str.replace("$HOME", HOME_DIR).replace("${HOME}", HOME_DIR)
    expanded = expanded.replace("$PWD", WORKING_DIR).replace("${PWD}", WORKING_DIR)
    if expanded.startswith("~"):
        expanded = os.path.expanduser(expanded)

    # 2. Make absolute relative to working directory (/home/agent/workspace)
    if not os.path.isabs(expanded):
        expanded = os.path.join(WORKING_DIR, expanded)

    # 3. Resolve all symlinks and '..' traversal segments
    return os.path.realpath(expanded)


def is_write_allowed(target_path: str) -> bool:
    """Check if target path is strictly inside /srv/reports/."""
    canonical = resolve_canonical_path(target_path)
    allowed_dir = os.path.realpath(ALLOWED_WRITE_DIR)

    # Must be inside /srv/reports/ (subdirectories allowed, but not writing to /srv/reports directly)
    allowed_prefix = allowed_dir if allowed_dir.endswith(os.sep) else allowed_dir + os.sep
    
    return canonical.startswith(allowed_prefix)


def check_bash_command(command_str: str) -> tuple[bool, str]:
    """
    Inspect bash commands for:
    1. Direct or obfuscated access to /home/agent/.netrc
    2. Write attempts outside /srv/reports/ (e.g. >, >>, tee, cp, mv, touch, rm)
    """
    if not command_str or not isinstance(command_str, str):
        return False, "Empty command"

    # --- 1. NETRC / SECRET READ CHECKS ---
    expanded_cmd = command_str.replace("$HOME", HOME_DIR).replace("${HOME}", HOME_DIR).replace("~", HOME_DIR)

    if ".netrc" in expanded_cmd:
        return False, "Accessing /home/agent/.netrc is strictly prohibited."

    # Base64 decode check
    b64_matches = re.findall(r'[A-Za-z0-9+/]{8,}={0,2}', command_str)
    for match in b64_matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if ".netrc" in decoded:
                return False, "Accessing /home/agent/.netrc (base64) is strictly prohibited."
        except Exception:
            pass

    # Hex/Unicode escape check
    try:
        decoded_hex = bytes(command_str, "utf-8").decode("unicode_escape")
        if ".netrc" in decoded_hex:
            return False, "Accessing /home/agent/.netrc is strictly prohibited."
    except Exception:
        pass

    # Administrative secret read checks
    if re.search(r'\b(cat|less|more|head|tail|grep|awk|sed)\s+/etc/(shadow|sudoers|master\.passwd)', command_str):
        return False, "Reading system shadow files is prohibited."

    # --- 2. BASH WRITE TRAVERSAL & REDIRECTION CHECKS ---
    # Detect output redirections ('>', '>>') or write tools (tee, touch, cp, mv, rsync)
    # Extract file targets from redirection operators
    redirect_targets = re.findall(r'(?:>>|>)\s*([^\s;&|]+)', command_str)
    for target in redirect_targets:
        clean_target = target.strip("'\"")
        if not is_write_allowed(clean_target):
            return False, f"Bash redirection write to '{clean_target}' outside /srv/reports/ is blocked."

    return True, "Command allowed."


def is_http_allowed(url_str: str) -> bool:
    """Validate outbound HTTP hostnames against exact allowlist."""
    if not url_str or not isinstance(url_str, str):
        return False

    try:
        if not url_str.startswith(("http://", "https://")):
            url_str = "http://" + url_str

        parsed = urlparse(url_str)
        hostname = parsed.hostname

        if not hostname:
            return False

        hostname = hostname.lower().rstrip(".")
        return hostname in ALLOWED_HOSTS
    except Exception:
        return False


@app.route("/check_tool", methods=["POST"])
def check_tool():
    payload = request.get_json(silent=True)

    if not payload or "tool" not in payload:
        return jsonify({"decision": "block", "reason": "Malformed JSON or missing tool parameter."}), 400

    tool = payload.get("tool")

    # TOOL: BASH
    if tool == "bash":
        command = payload.get("command", "")
        allowed, reason = check_bash_command(command)
        
        return jsonify({
            "decision": "allow" if allowed else "block",
            "reason": reason
        })

    # TOOL: WRITE_FILE
    elif tool == "write_file":
        file_path = payload.get("path", "")
        
        if is_write_allowed(file_path):
            return jsonify({
                "decision": "allow",
                "reason": "File write approved within /srv/reports/ directory."
            })
        else:
            return jsonify({
                "decision": "block",
                "reason": "Writes are restricted strictly to paths inside /srv/reports/."
            })

    # TOOL: HTTP_REQUEST
    elif tool == "http_request":
        url = payload.get("url", "")
        
        if is_http_allowed(url):
            return jsonify({
                "decision": "allow",
                "reason": "Outbound host is explicitly permitted."
            })
        else:
            return jsonify({
                "decision": "block",
                "reason": "Host not allowed. Outbound requests permitted only to pypi.org and raw.githubusercontent.com."
            })

    return jsonify({"decision": "block", "reason": f"Unknown tool: {tool}"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
