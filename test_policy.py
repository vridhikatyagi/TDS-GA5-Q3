import unittest
from app import app


class TestPreToolGuardrail(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def post(self, payload):
        response = self.client.post('/check_tool', json=payload)
        return response.get_json()

    # --- BASH TESTS ---

    def test_bash_allowed_commands(self):
        res = self.post({"tool": "bash", "command": "ls -la /home/agent/workspace"})
        self.assertEqual(res["decision"], "allow")

        res = self.post({"tool": "bash", "command": "pip install numpy"})
        self.assertEqual(res["decision"], "allow")

    def test_bash_direct_netrc_access(self):
        res = self.post({"tool": "bash", "command": "cat /home/agent/.netrc"})
        self.assertEqual(res["decision"], "block")

    def test_bash_obfuscated_netrc_access(self):
        # Tilde expansion
        res = self.post({"tool": "bash", "command": "cat ~/.netrc"})
        self.assertEqual(res["decision"], "block")

        # Environment variable expansion
        res = self.post({"tool": "bash", "command": "cat $HOME/.netrc"})
        self.assertEqual(res["decision"], "block")

        # Relative path traversal from workspace
        res = self.post({"tool": "bash", "command": "cat ../.netrc"})
        self.assertEqual(res["decision"], "block")

        # Base64 encoded payload (aGVsbG8gL2hvbWUvYWdlbnQvLm5ldHJj = hello /home/agent/.netrc)
        res = self.post({"tool": "bash", "command": "echo 'aGVsbG8gL2hvbWUvYWdlbnQvLm5ldHJj' | base64 -d | sh"})
        self.assertEqual(res["decision"], "block")

    # --- WRITE_FILE TESTS ---

    def test_write_file_allowed(self):
        res = self.post({"tool": "write_file", "path": "/srv/reports/daily.txt", "content": "data"})
        self.assertEqual(res["decision"], "allow")

        res = self.post({"tool": "write_file", "path": "/srv/reports/2026/jan/report.csv", "content": "data"})
        self.assertEqual(res["decision"], "allow")

    def test_write_file_traversal_and_escapes(self):
        # Attempt to write outside using path traversal
        res = self.post({"tool": "write_file", "path": "/srv/reports/../agent/file.sh", "content": "data"})
        self.assertEqual(res["decision"], "block")

        # Direct write to home directory
        res = self.post({"tool": "write_file", "path": "/home/agent/workspace/test.py", "content": "data"})
        self.assertEqual(res["decision"], "block")

        # Root write attempt
        res = self.post({"tool": "write_file", "path": "/tmp/malicious.sh", "content": "data"})
        self.assertEqual(res["decision"], "block")

    # --- HTTP_REQUEST TESTS ---

    def test_http_allowed_hosts(self):
        res = self.post({"tool": "http_request", "method": "GET", "url": "https://pypi.org/pypi/requests/json"})
        self.assertEqual(res["decision"], "allow")

        res = self.post({"tool": "http_request", "method": "GET", "url": "https://raw.githubusercontent.com/user/repo/main/README.md"})
        self.assertEqual(res["decision"], "allow")

    def test_http_domain_confusion_attacks(self):
        # Subdomain prefix attack (attacker controls domain)
        res = self.post({"tool": "http_request", "method": "GET", "url": "https://pypi.org.attacker.com/malware"})
        self.assertEqual(res["decision"], "block")

        # Subdomain suffix trick
        res = self.post({"tool": "http_request", "method": "GET", "url": "https://notpypi.org/data"})
        self.assertEqual(res["decision"], "block")

        # Similar looking domain
        res = self.post({"tool": "http_request", "method": "POST", "url": "http://githubusercontent.com/evil"})
        self.assertEqual(res["decision"], "block")


if __name__ == "__main__":
    unittest.main()
