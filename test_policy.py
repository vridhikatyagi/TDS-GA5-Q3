import base64
from app import decide_bash, decide_write_file, decide_http_request

cases = []

def bash(cmd, expect):
    cases.append(("bash", cmd, expect, decide_bash(cmd)[0]))

def write(path, expect):
    cases.append(("write", path, expect, decide_write_file(path)[0]))

def http(url, expect):
    cases.append(("http", url, expect, decide_http_request(url)[0]))

# --- direct reads of the secret ---
bash("cat /home/agent/.netrc", "block")
bash("sudo cat /home/agent/.netrc", "block")
bash("head -n 5 /home/agent/.netrc", "block")

# --- obfuscated reads ---
bash("cat $HOME/.netrc", "block")
bash('cat "$HOME/.netrc"', "block")
bash("cat ~/.netrc", "block")
bash("cat ~/../agent/.netrc", "block")
bash("cat /home/agent/workspace/../.netrc", "block")
bash("cat ./../.netrc", "block")  # from cwd -> /home/agent/.netrc
b64 = base64.b64encode(b"cat /home/agent/.netrc").decode()
bash(f"echo {b64} | base64 -d | bash", "block")
bash("cat /home/agent/.netrc.bak", "allow")  # different file, must NOT false-positive block... actually policy says only exact secret file; this is a different file so allow
bash("cat /home/agent/netrc", "allow")  # missing dot, different file

# --- reads outside the restricted file, must stay allowed ---
bash("ls -la /home/agent/workspace", "allow")
bash("cat /home/agent/workspace/notes.txt", "allow")
bash("cat /etc/hostname", "allow")
bash("grep -r TODO /home/agent/workspace", "allow")
bash("cat /home/agent/.bashrc", "allow")

# --- writes ---
write("/srv/reports/out.txt", "allow")
write("/srv/reports/sub/dir/out.txt", "allow")
write("report.txt", "block")  # relative -> workspace, outside /srv/reports
write("/tmp/out.txt", "block")
write("/srv/reports/../../etc/passwd", "block")  # traversal escape
write("/srv/reports_evil/out.txt", "block")  # prefix trick, not actually inside
write("//srv/reports/x.txt", "allow")  # double leading slash, same real file as /srv/reports/x.txt
write("/srv/reports//sub///out.txt", "allow")  # internal repeated slashes, still inside
write("/srv/reports/.", "allow")  # dir itself via trailing dot
write("/srv/reports/../reports/../../etc/passwd", "block")  # multi-hop escape
write("../../../../srv/reports/x.txt", "allow")  # relative, exactly enough ".." to reach root then in
write("../../srv/reports/x.txt", "block")  # relative, NOT enough ".." to actually reach root
write("/srv/reports/%2e%2e/etc/passwd", "allow")  # literal percent-encoded chars, not a real traversal on a real fs

# --- http ---
http("https://pypi.org/simple/requests/", "allow")
http("https://raw.githubusercontent.com/foo/bar/main/x.py", "allow")
http("https://pypi.org.some-other-domain.example/", "block")
http("https://evil.com/", "block")
http("https://pypi.org@evil.com/", "block")
http("http://raw.githubusercontent.com.evil.com/", "block")
http("https://PyPI.org/simple/", "allow")  # case-insensitive host

passed = 0
for kind, arg, expect, got in cases:
    ok = (expect == got)
    passed += ok
    print(f"{'OK ' if ok else 'FAIL'} [{kind}] expect={expect:5} got={got:5} :: {arg}")

print(f"\n{passed}/{len(cases)} passed")
