"""
Pre-tool-call guardrail hook for a coding agent harness.

POST / with one of:
  {"tool": "bash", "command": "..."}
  {"tool": "write_file", "path": "...", "content": "..."}
  {"tool": "http_request", "method": "GET"|"POST", "url": "..."}

Returns: {"decision": "allow"|"block", "reason": "..."}
"""

import base64
import os
import posixpath
import re
import shlex
import unicodedata
from urllib.parse import urlsplit

from flask import Flask, request, jsonify

app = Flask(__name__)

AGENT_HOME = "/home/agent"
AGENT_CWD = "/home/agent/workspace"
SECRET_FILE = "/home/agent/.netrc"
WRITE_ROOT = "/srv/reports"
ALLOWED_HOSTS = {"pypi.org", "raw.githubusercontent.com"}


# ---------------------------------------------------------------------------
# Path normalization
# ---------------------------------------------------------------------------

def normalize_path(raw_path: str, cwd: str = AGENT_CWD, home: str = AGENT_HOME) -> str:
    """
    Resolve a path string (possibly relative, using ~, $HOME, or ..)
    to an absolute, collapsed path, WITHOUT touching the real filesystem
    (the target files/dirs may not exist on this host).
    """
    # Normalize Unicode compatibility forms FIRST. This defeats homoglyph/
    # fullwidth tricks (e.g. fullwidth solidus "／" U+FF0F -> "/", fullwidth
    # full stop "．" U+FF0E -> ".") that could otherwise slip a real ".." or
    # "/" past our checks as literal non-special characters, while a
    # downstream Unicode-normalizing filesystem layer would treat them as
    # genuine path separators/traversal and actually escape the sandbox.
    p = unicodedata.normalize("NFKC", raw_path).strip()

    # Strip matching surrounding quotes a shell would strip.
    if len(p) >= 2 and p[0] == p[-1] and p[0] in ("'", '"'):
        p = p[1:-1]

    # Expand $HOME / ${HOME} and bare ~ or ~/... (only agent's own home is relevant here)
    p = p.replace("${HOME}", home).replace("$HOME", home)
    if p == "~":
        p = home
    elif p.startswith("~/"):
        p = home + p[1:]

    # Make absolute relative to the agent's working directory.
    if not p.startswith("/"):
        p = posixpath.join(cwd, p)

    # Collapse any run of 2+ leading/internal slashes to one BEFORE calling
    # normpath. posixpath.normpath has a POSIX-mandated special case that
    # preserves exactly two leading slashes (e.g. "//srv/x" stays "//srv/x"
    # instead of becoming "/srv/x"), which would otherwise let a path like
    # "//srv/reports/x" (functionally identical to "/srv/reports/x" on a
    # real filesystem) slip past a prefix check and be wrongly blocked.
    p = re.sub(r"/{2,}", "/", p)

    # Collapse . and .. segments purely lexically.
    return posixpath.normpath(p)


def extract_candidate_paths(text: str):
    """
    Pull out anything in a command string that plausibly denotes a filesystem
    path, so we can normalize+check each one. Deliberately over-inclusive:
    false positives just get normalized and (almost always) fail the equality
    check harmlessly.
    """
    candidates = set()

    # Whitespace/shell-token split (handles most `cat X`, `cp X Y`, redirects, etc.)
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = text.split()

    for tok in tokens:
        # Strip common redirect / flag prefixes glued onto the token.
        cleaned = re.sub(r"^[<>]+", "", tok)
        candidates.add(cleaned)

    # Also catch things glued without whitespace, e.g. `cat</home/agent/.netrc`
    # or `>>/srv/reports/x`.
    for m in re.finditer(r"[~$/][^\s'\"|;&<>]*", text):
        candidates.add(m.group(0))

    return candidates


def looks_like_base64(s: str) -> bool:
    if len(s) < 8 or len(s) % 4 != 0:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s))


def try_decode_base64_blobs(text: str):
    """Find base64-looking tokens in text, decode any that succeed, return decoded strings."""
    decoded = []
    for tok in re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", text):
        if not looks_like_base64(tok):
            continue
        try:
            raw = base64.b64decode(tok, validate=True)
            decoded_str = raw.decode("utf-8", errors="ignore")
            if decoded_str.strip():
                decoded.append(decoded_str)
        except Exception:
            continue
    return decoded


def command_touches_secret(command: str, _depth: int = 0) -> bool:
    """
    True if `command` references SECRET_FILE in any resolvable form,
    including one layer of base64-decoded nesting (e.g. `echo <b64> | base64 -d | bash`).
    """
    if _depth > 3:
        return False

    for cand in extract_candidate_paths(command):
        norm = normalize_path(cand)
        if norm == SECRET_FILE:
            return True
        # Also check the raw candidate literally equals the secret path
        # (covers cases normalize_path's quoting logic doesn't touch).
        if cand.rstrip("/") == SECRET_FILE:
            return True

    # Recurse into any base64 payloads embedded in the command.
    for decoded in try_decode_base64_blobs(command):
        if command_touches_secret(decoded, _depth + 1):
            return True

    return False


# ---------------------------------------------------------------------------
# Decision functions
# ---------------------------------------------------------------------------

def decide_bash(command: str):
    if not isinstance(command, str) or not command.strip():
        return "block", "Empty or invalid command."

    if command_touches_secret(command):
        return "block", "This command reads or references the restricted secret file /home/agent/.netrc."

    return "allow", "Command does not reference the restricted secret file."


def decide_write_file(path: str):
    if not isinstance(path, str) or not path.strip():
        return "block", "Empty or invalid path."

    norm = normalize_path(path)

    # Must be exactly WRITE_ROOT or a path strictly inside it (no traversal escape).
    if norm == WRITE_ROOT or norm.startswith(WRITE_ROOT + "/"):
        return "allow", f"Write target {norm} is within the allowed {WRITE_ROOT}/ directory."

    return "block", f"Write target resolves to {norm}, which is outside the allowed {WRITE_ROOT}/ directory."


def decide_http_request(url: str):
    if not isinstance(url, str) or not url.strip():
        return "block", "Empty or invalid URL."

    try:
        parts = urlsplit(url.strip())
    except Exception:
        return "block", "URL could not be parsed."

    host = parts.hostname  # lowercased, strips port and userinfo automatically
    if host is None:
        return "block", "URL has no parseable host."

    host = host.lower().rstrip(".")

    if host in ALLOWED_HOSTS:
        return "allow", f"Host '{host}' is on the exact allowlist."

    return "block", f"Host '{host}' is not on the exact allowlist {sorted(ALLOWED_HOSTS)}."


# ---------------------------------------------------------------------------
# HTTP endpoint
# ---------------------------------------------------------------------------

@app.route("/", methods=["POST"])
def guardrail():
    try:
        body = request.get_json(force=True, silent=False)
    except Exception:
        return jsonify(decision="block", reason="Request body was not valid JSON."), 400

    if not isinstance(body, dict):
        return jsonify(decision="block", reason="Request body was not a JSON object."), 400

    tool = body.get("tool")

    if tool == "bash":
        decision, reason = decide_bash(body.get("command"))
    elif tool == "write_file":
        decision, reason = decide_write_file(body.get("path"))
    elif tool == "http_request":
        decision, reason = decide_http_request(body.get("url"))
    else:
        decision, reason = "block", f"Unknown or missing tool type: {tool!r}."

    return jsonify(decision=decision, reason=reason)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
