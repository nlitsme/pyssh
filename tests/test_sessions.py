# written by chatgpt GPT-6
"""Real encrypted session tests; commands run only on loopback/socketpairs."""

import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

import ssh


class SessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.host = ed25519.Ed25519PrivateKey.generate()
        self.pinned = ssh.HostKey("ssh-ed25519", self.host.public_key().public_bytes_raw())
        self.credentials = ssh.Credentials("testuser", "test-password")

    def serve_socket(self, sock: socket.socket, curve: bool = False) -> None:
        ssh.SSHServer(self.host, self.credentials, curve).serve(sock)

    def check_command(self, command: str | None, data: bytes = b"", curve: bool = False) -> ssh.CommandResult:
        left, right = socket.socketpair()
        left.settimeout(10)
        right.settimeout(10)
        with left, right, ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.serve_socket, left, curve)
            client = ssh.SSHClient(right, self.pinned, curve)
            try:
                client.authenticate("testuser", "test-password")
                result = client.run(command, data)
                pending.result(timeout=10)
                return result
            finally:
                client.close()

    def test_stdout_stderr_and_exit_status(self) -> None:
        for curve in (False, True):
            with self.subTest(curve=curve):
                result = self.check_command("printf out; printf err >&2; exit 7", curve=curve)
                self.assertEqual(result, ssh.CommandResult(b"out", b"err", 7))

    def test_non_pty_shell(self) -> None:
        result = self.check_command(None, b"printf shell; exit 3\n")
        self.assertEqual(result.stdout, b"shell")
        self.assertEqual(result.exit_status, 3)

    def test_flow_control_beyond_initial_window(self) -> None:
        data = bytes(range(256)) * (3 * 1024 * 1024 // 256 + 1)
        result = self.check_command("cat", data)
        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.exit_status, 0)

    def test_failed_password_can_retry(self) -> None:
        left, right = socket.socketpair()
        left.settimeout(10)
        right.settimeout(10)
        with left, right, ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.serve_socket, left)
            client = ssh.SSHClient(right, self.pinned)
            try:
                with self.assertRaises(ssh.AuthenticationError):
                    client.authenticate("testuser", "wrong")
                client.authenticate("testuser", "test-password")
                self.assertEqual(client.run("printf retry").stdout, b"retry")
                pending.result(timeout=10)
            finally:
                client.close()

    def test_host_key_mismatch_prevents_authentication(self) -> None:
        left, right = socket.socketpair()
        left.settimeout(3)
        right.settimeout(3)
        other = ed25519.Ed25519PrivateKey.generate()
        wrong = ssh.HostKey("ssh-ed25519", other.public_key().public_bytes_raw())
        with left, right, ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.serve_socket, left)
            try:
                with self.assertRaises(ssh.HostKeyError):
                    ssh.SSHClient(right, wrong)
            finally:
                right.close()
            with self.assertRaises((EOFError, OSError)):
                pending.result(timeout=5)

    @unittest.skipUnless(shutil.which("ssh"), "OpenSSH client unavailable")
    def test_openssh_client_to_python_server(self) -> None:
        for curve in (False, True):
            with self.subTest(curve=curve), tempfile.TemporaryDirectory() as directory:
                self.check_openssh_client(Path(directory), curve)

    def check_openssh_client(self, directory: Path, curve: bool) -> None:
        askpass = directory / "askpass.py"
        askpass.write_text("#!/usr/bin/env python3\n# written by chatgpt GPT-6\nimport os\nprint(os.environ['SSH_TEST_PASSWORD'])\n")
        askpass.chmod(0o700)
        environment = os.environ.copy()
        environment.update(SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE="force", SSH_TEST_PASSWORD="test-password", DISPLAY=":0")
        with socket.create_server(("127.0.0.1", 0)) as listener:
            port = listener.getsockname()[1]
            known = directory / "known_hosts"
            known.write_bytes(f"[127.0.0.1]:{port} ".encode() + self.pinned.openssh() + b"\n")
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.accept_one, listener, curve)
                command = [
                    "ssh",
                    "-F",
                    "/dev/null",
                    "-p",
                    str(port),
                    "-o",
                    "StrictHostKeyChecking=yes",
                    "-o",
                    f"UserKnownHostsFile={known}",
                    "-o",
                    "PreferredAuthentications=password",
                    "-o",
                    "PubkeyAuthentication=no",
                    "-o",
                    "NumberOfPasswordPrompts=1",
                    "testuser@127.0.0.1",
                    "cat; printf error >&2; exit 9",
                ]
                result = subprocess.run(command, input=b"openssh input\n", capture_output=True, env=environment, timeout=20)
                pending.result(timeout=10)
                self.assertEqual(result.returncode, 9, result.stderr.decode(errors="replace"))
                self.assertEqual(result.stdout, b"openssh input\n")
                self.assertIn(b"error", result.stderr)

    def accept_one(self, listener: socket.socket, curve: bool) -> None:
        sock, _ = listener.accept()
        sock.settimeout(10)
        self.serve_socket(sock, curve)


if __name__ == "__main__":
    unittest.main()
