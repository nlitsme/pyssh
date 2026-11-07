# written by chatgpt GPT-6
"""Independent interoperability tests against installed OpenSSH."""

import contextlib
import getpass
import shutil
import socket
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Iterator

import ssh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class OpenSSHTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.host = ed25519.Ed25519PrivateKey.generate()
        self.identity = ed25519.Ed25519PrivateKey.generate()
        self.pinned = ssh.HostKey(
            "ssh-ed25519", self.host.public_key().public_bytes_raw()
        )
        self.user_key = ssh.HostKey(
            "ssh-ed25519", self.identity.public_key().public_bytes_raw()
        )
        self.save_key("host", self.host)
        self.save_key("user", self.identity)

    def save_key(self, name: str, key: ed25519.Ed25519PrivateKey) -> None:
        path = self.root / name
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption(),
            )
        )
        path.chmod(0o600)
        public = ssh.HostKey(
            "ssh-ed25519", key.public_key().public_bytes_raw()
        )
        (self.root / (name + ".pub")).write_bytes(public.openssh() + b"\n")

    @contextlib.contextmanager
    def openssh_server(
        self, curve: bool, rekey: bool = False
    ) -> Iterator[ssh.SSHClient]:
        config = self.root / "sshd_config"
        method = ssh.KEX_CURVE if curve else ssh.KEX_HYBRID
        config.write_text(
            f"HostKey {self.root / 'host'}\n"
            "UsePAM no\nPasswordAuthentication no\n"
            "PubkeyAuthentication yes\n"
            f"AuthorizedKeysFile {self.root / 'user.pub'}\n"
            "StrictModes no\nUseDNS no\nPrintMotd no\n"
            f"KexAlgorithms {method}\n"
            f"Ciphers {ssh.CIPHER}\nLogLevel DEBUG2\n"
            + ("RekeyLimit 64K\n" if rekey else ""),
        )
        left, right = socket.socketpair()
        right.settimeout(10)
        with (self.root / "sshd.log").open("wb") as log:
            process = subprocess.Popen(
                [
                    shutil.which("sshd") or "/usr/sbin/sshd",
                    "-i",
                    "-e",
                    "-f",
                    str(config),
                ],
                stdin=left,
                stdout=left,
                stderr=log,
            )
            left.close()
            try:
                client = ssh.SSHClient(right, self.pinned, curve)
                client.authenticate_publickey(getpass.getuser(), self.identity)
                yield client
            except Exception as exc:
                diagnostic = (self.root / "sshd.log").read_text()
                raise AssertionError(
                    f"OpenSSH integration failed: {exc}\n{diagnostic[-6000:]}"
                ) from exc
            finally:
                right.close()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=5)

    @unittest.skipUnless(shutil.which("sshd"), "OpenSSH server unavailable")
    def test_python_client_to_openssh_server(self) -> None:
        for curve in (False, True):
            with (
                self.subTest(curve=curve),
                self.openssh_server(curve) as client,
            ):
                self.assertEqual(
                    client.run(
                        "cat; printf error >&2; exit 4", b"client data"
                    ),
                    ssh.CommandResult(b"client data", b"error", 4),
                )

    @unittest.skipUnless(shutil.which("sshd"), "OpenSSH server unavailable")
    def test_openssh_initiated_rekey_with_live_data(self) -> None:
        for curve in (False, True):
            with (
                self.subTest(curve=curve),
                self.openssh_server(curve, rekey=True) as client,
            ):
                original_session_id = client.connection.session_id
                data = bytes(range(256)) * 2048
                result = client.run("cat", data)
                self.assertEqual(result.stdout, data)
                self.assertEqual(result.exit_status, 0)
                self.assertEqual(
                    client.connection.session_id, original_session_id
                )

    @unittest.skipUnless(shutil.which("sshd"), "OpenSSH server unavailable")
    def test_python_initiated_rekey_after_authentication(self) -> None:
        with self.openssh_server(False) as client:
            original_session_id = client.connection.session_id
            client.connection.key_exchange()
            self.assertTrue(client.connection.suite.strict)
            self.assertEqual(client.connection.session_id, original_session_id)
            self.assertEqual(client.run("printf rekey").stdout, b"rekey")

    @unittest.skipUnless(shutil.which("ssh"), "OpenSSH client unavailable")
    def test_openssh_publickey_probe_and_signed_request(self) -> None:
        credentials = ssh.Credentials(
            "testuser", authorized_keys=(self.user_key,)
        )
        server = ssh.SSHServer(self.host, credentials)
        with socket.create_server(("127.0.0.1", 0)) as listener:
            listener.settimeout(10)
            port = listener.getsockname()[1]
            known = self.root / "known_hosts"
            known.write_bytes(
                f"[127.0.0.1]:{port} ".encode() + self.pinned.openssh() + b"\n"
            )
            command = [
                "ssh",
                "-F",
                "/dev/null",
                "-p",
                str(port),
                "-i",
                str(self.root / "user"),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"UserKnownHostsFile={known}",
                "testuser@127.0.0.1",
                "printf pubkey",
            ]
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.accept_one, listener, server)
                result = subprocess.run(
                    command, capture_output=True, timeout=15
                )
                future.result(timeout=10)
            self.assertEqual(
                result.returncode, 0, result.stderr.decode(errors="replace")
            )
            self.assertEqual(result.stdout, b"pubkey")

    @staticmethod
    def accept_one(listener: socket.socket, server: ssh.SSHServer) -> None:
        sock, _ = listener.accept()
        sock.settimeout(10)
        server.serve(sock)


if __name__ == "__main__":
    unittest.main()
