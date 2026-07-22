import os
import re
import base64
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

# Security Policy Configuration
RESTRICTED_FILE = "/home/agent/.netrc"
ALLOWED_WRITE_DIR = "/srv/reports"
ALLOWED_HOSTS = {"pypi.org", "raw.githubusercontent.com"}
WORKING_DIR = "/home/agent/workspace"
HOME_DIR = "/home/agent"


def is_write_allowed(target_path: str) -> bool:
    """Check if the target path is strictly inside /srv/reports/."""
    if not target_path or not isinstance(target_path, str):
        return False

    # 1. Expand environment variables and ~
    expanded_path = target_path.replace("$HOME", HOME_DIR).replace("${HOME}", HOME_DIR)
    if expanded_path.startswith("~"):
        expanded_path = os.path.expanduser(expanded_path)

    # 2. Handle relative paths against agent working directory
    if not os.path.isabs(expanded_path):
        expanded_path = os.path.join(WORKING_DIR, expanded_path)

    # 3. Canonicalize path fully (resolves '..' traversals and symlinks)
    try:
        normalized_target = os.path.realpath(expanded_path)
        allowed_dir = os.path.realpath(ALLOWED_WRITE_DIR)
    except Exception:
        return False

    # Add trailing separator to prevent matching /srv/reports-evil or /srv/reports directory itself
    allowed_dir_slash = allowed_dir if allowed_dir.endswith(os.sep) else allowed_dir + os.sep

    # Must be strictly inside /srv/reports/
    return normalized_target.startswith(allowed_dir_slash)


def is_netrc_accessed(command_str: str) -> bool:
    """Inspect bash commands for direct or obfuscated access to /home/agent/.netrc."""
    if not command_str or not isinstance(command_str, str):
        return False

    # 1. Expand environment variables and tildes in command
    expanded_cmd = command_str.replace("$HOME", HOME_DIR).replace("${HOME}", HOME_DIR).replace("~", HOME_DIR)

    # 2. Direct string match on filename or path
    if ".netrc" in expanded_cmd:
        return True

    # 3. Base64 decoded check
    b64_matches = re.findall(r'[A-Za-z0-9+/]{8,}={0,2}', command_str)
    for match in b64_matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if ".netrc" in decoded:
                return True
        except Exception:
            pass

    # 4. Hex/Octal/Unicode escape check
    try:
        decoded_hex = bytes(command_str, "utf-8").decode("unicode_escape")
        if ".netrc" in decoded_hex:
            return True
    except Exception:
        pass

    # 5. Administrative reads on sensitive system files
    if re.search(r'\b(cat|less|more|head|tail|grep|awk|sed)\s+/etc/(shadow|sudoers|master\.passwd)', command_str):
        return True

    return False


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
        return jsonify({"decision": "block", "reason": "Malformed request or missing tool name."}), 400

    tool = payload.get("tool")

    # BASH
    if tool == "bash":
        command = payload.get("command", "")
        if is_netrc_accessed(command):
            return jsonify({
                "decision": "block",
                "reason": "Accessing /home/agent/.netrc or restricted system secrets is prohibited."
            })
        return jsonify({
            "decision": "allow",
            "reason": "Command approved within execution boundaries."
        })

    # WRITE_FILE
    elif tool == "write_file":
        file_path = payload.get("path", "")
        if is_write_allowed(file_path):
            return jsonify({
                "decision": "allow",
                "reason": "Write approved within /srv/reports/ directory."
            })
        return jsonify({
            "decision": "block",
            "reason": "Writes are restricted strictly to subpaths inside /srv/reports/."
        })

    # HTTP_REQUEST
    elif tool == "http_request":
        url = payload.get("url", "")
        if is_http_allowed(url):
            return jsonify({
                "decision": "allow",
                "reason": "Hostname is in the explicit allowlist."
            })
        return jsonify({
            "decision": "block",
            "reason": "Outbound host blocked. Permitted hosts: pypi.org and raw.githubusercontent.com."
        })

    return jsonify({"decision": "block", "reason": f"Unknown tool: {tool}"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
