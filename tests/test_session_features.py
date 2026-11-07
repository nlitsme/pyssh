# written by chatgpt GPT-6
"""PTY semantics and real OpenSSH SFTP file operations over encrypted channels."""

import contextlib
import io
import os
import pty
import shlex
import shutil
import socket
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import ssh


class PythonSessionFeatureTests(unittest.TestCase):
    @contextlib.contextmanager
    def connected(self, config: ssh.SessionConfig | None = None, log: io.StringIO | None = None) -> Iterator[ssh.SSHClient]:
        host = ed25519.Ed25519PrivateKey.generate()
        pinned = ssh.HostKey(key=host.public_key().public_bytes_raw())
        server = ssh.SSHServer(host, ssh.Credentials("test", "secret"), session_config=config, verbose=2 if log else 0, trace_stream=log)
        left, right = socket.socketpair()
        left.settimeout(10)
        right.settimeout(10)
        with left, right, ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(server.serve, left)
            client = ssh.SSHClient(right, pinned)
            client.authenticate("test", "secret")
            try:
                yield client
            finally:
                client.close()
                try:
                    future.result(timeout=10)
                except EOFError:
                    pass  # Tests rejecting a request intentionally disconnect before starting a process.

    def test_pty_dimensions_controlling_terminal_and_merged_stderr(self) -> None:
        program = "import os; fd = os.open('/dev/tty', os.O_RDWR); print(os.tcgetpgrp(fd) == os.getpgrp())"
        command = "test -t 0 && test -t 1 && test -t 2 && stty size; printf '%s\\n' \"$TERM\"; "
        command += "python3 -c " + shlex.quote(program) + "; printf merged >&2; exit 7"
        with self.connected() as client:
            result = client.run(command, terminal=ssh.PtyRequest(b"xterm-kitty", 190, 27, 1710, 486))
        self.assertEqual(result.exit_status, 7)
        self.assertIn(b"27 190\r\n", result.stdout)
        self.assertIn(b"xterm-kitty\r\nTrue\r\n", result.stdout)
        self.assertIn(b"merged", result.stdout)
        self.assertEqual(result.stderr, b"")

    def test_canonical_pty_input_and_ssh_eof(self) -> None:
        modes = ssh.TerminalModes((ssh.TerminalMode(53, 0), ssh.TerminalMode(0)))
        with self.connected() as client:
            result = client.run("cat", b"hello\n", terminal=ssh.PtyRequest(b"xterm", 80, 24, modes=modes))
        self.assertEqual(result, ssh.CommandResult(b"hello\r\n", b"", 0))

    def test_raw_pty_binary_flow_control(self) -> None:
        data = bytes(range(256)) * (3 * 1024 * 1024 // 256)
        modes = ssh.TerminalModes(tuple(ssh.TerminalMode(opcode, 0) for opcode in (36, 38, 50, 51, 53, 70)) + (ssh.TerminalMode(0),))
        program = (
            "import os\n"
            f"remaining = {len(data)}\n"
            "while remaining:\n"
            "    data = os.read(0, min(remaining, 16384))\n"
            "    remaining -= len(data)\n"
            "    while data:\n"
            "        data = data[os.write(1, data):]\n"
        )
        with self.connected() as client:
            result = client.run("python3 -c " + shlex.quote(program), data, terminal=ssh.PtyRequest(b"xterm", 80, 24, modes=modes))
        self.assertEqual(result, ssh.CommandResult(data, b"", 0))

    @staticmethod
    def request(channel: ssh.Channel, body: ssh.RequestBody) -> bool:
        channel.request(body)
        while channel.request_reply is None:
            channel.handle(channel.connection.receive())
        return channel.request_reply

    def test_window_change_and_environment_before_exec(self) -> None:
        with self.connected() as client:
            channel = ssh.Channel.open_client(client.connection)
            self.assertTrue(self.request(channel, ssh.PtyRequest(b"xterm", 80, 24)))
            self.assertTrue(self.request(channel, ssh.WindowChangeRequest(132, 43)))
            self.assertTrue(self.request(channel, ssh.WindowChangeRequest()))  # Zero dimensions retain the existing size.
            self.assertTrue(self.request(channel, ssh.EnvRequest(b"COLORTERM", b"truecolor")))
            self.assertFalse(self.request(channel, ssh.EnvRequest(b"LD_PRELOAD", b"unwanted")))
            self.assertFalse(self.request(channel, ssh.EnvRequest(b"LANG", b"bad\x00value")))
            output = io.BytesIO()
            status = ssh.ClientSession(channel, io.BytesIO(), output, io.BytesIO()).run("stty size; printf '%s' \"$COLORTERM\"")
        self.assertEqual(status, 0)
        self.assertIn(b"43 132\r\ntruecolor", output.getvalue())

    def test_window_change_signals_running_foreground_process(self) -> None:
        program = (
            "import os, signal\n"
            "def resized(number, frame):\n"
            "    size = os.get_terminal_size(0)\n"
            "    print(size.columns, size.lines, flush=True)\n"
            "    raise SystemExit(0)\n"
            "signal.signal(signal.SIGWINCH, resized)\n"
            "print('READY', flush=True)\n"
            "while True:\n"
            "    signal.pause()\n"
        )
        output = bytearray()
        resized = False
        with self.connected() as client:
            channel = ssh.Channel.open_client(client.connection)
            self.assertTrue(self.request(channel, ssh.PtyRequest(b"xterm", 80, 24)))
            self.assertTrue(self.request(channel, ssh.ExecRequest("python3 -c " + shlex.quote(program))))
            while not channel.peer_closed:
                event = channel.handle(client.connection.receive())
                if isinstance(event, ssh.ChannelData):
                    output.extend(event.data)
                    channel.acknowledge(len(event.data))
                    if b"READY" in output and not resized:
                        channel.request(ssh.WindowChangeRequest(101, 31), want_reply=False)
                        resized = True
                elif isinstance(event, ssh.Msg98_ChannelRequest):
                    channel.handle_client_request(event)
        self.assertIn(b"101 31\r\n", output)
        self.assertEqual(channel.exit_status, 0)

    def test_local_terminal_restored_after_error(self) -> None:
        master, slave = pty.openpty()
        try:
            with os.fdopen(slave, "rb", buffering=0) as source:
                original = ssh.TerminalAttributes.read(source.fileno())
                with self.assertRaisesRegex(RuntimeError, "test restore"):
                    with ssh.local_terminal(True, source) as request:
                        self.assertIsNotNone(request)
                        self.assertNotEqual(ssh.TerminalAttributes.read(source.fileno()), original)
                        raise RuntimeError("test restore")
                self.assertEqual(ssh.TerminalAttributes.read(source.fileno()), original)
        finally:
            os.close(master)

    @unittest.skipUnless(ssh.find_sftp_server(), "OpenSSH sftp-server unavailable")
    def test_sftp_subsystem_initialization_and_trace(self) -> None:
        output, errors, log = io.BytesIO(), io.BytesIO(), io.StringIO()
        with self.connected(log=log) as client:
            channel = ssh.Channel.open_client(client.connection)
            self.assertTrue(self.request(channel, ssh.SubsystemRequest("sftp")))
            channel.send_data(bytes.fromhex("000000050100000003"))
            decoder = ssh.SftpStream()
            frames: tuple[ssh.SftpFrame, ...] = ()
            while not frames:
                event = channel.handle(client.connection.receive())
                if isinstance(event, ssh.ChannelData):
                    output.write(event.data)
                    frames = decoder.feed(event.data)
                    channel.acknowledge(len(event.data))
            channel.eof()
            while not channel.peer_closed:
                event = channel.handle(client.connection.receive())
                if isinstance(event, ssh.Msg98_ChannelRequest):
                    channel.handle_client_request(event)
            status = channel.exit_status
        self.assertEqual(status, 0)
        frames = ssh.SftpStream().feed(output.getvalue())
        self.assertEqual(len(frames), 1)
        self.assertIsInstance(frames[0].packet, ssh.Sftp2_Version)
        self.assertEqual(frames[0].packet.version, 3)
        self.assertEqual(errors.getvalue(), b"")
        self.assertIn("SSH_FXP_INIT", log.getvalue())
        self.assertIn("SSH_FXP_VERSION", log.getvalue())

    def test_unavailable_or_unknown_subsystem_is_rejected(self) -> None:
        config = ssh.SessionConfig(Path("/nonexistent/sftp-server"))
        for name in ("sftp", "unconfigured"):
            with self.subTest(name=name), self.connected(config) as client:
                with self.assertRaisesRegex(ssh.ProtocolError, "rejected subsystem"):
                    client.run_subsystem(name, io.BytesIO(), io.BytesIO(), io.BytesIO())


@dataclass
class ExternalEndpoint:
    port: int
    identity: Path
    known_hosts: Path

    def options(self) -> list[str]:
        return [
            "-F",
            "/dev/null",
            "-o",
            f"Port={self.port}",
            "-i",
            str(self.identity),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
        ]


class OpenSSHSessionFeatureTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.host = ed25519.Ed25519PrivateKey.generate()
        self.identity = ed25519.Ed25519PrivateKey.generate()
        self.identity_path = self.root / "identity"
        self.identity_path.write_bytes(
            self.identity.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
        )
        self.identity_path.chmod(0o600)

    @contextlib.contextmanager
    def endpoint(self, log: io.StringIO | None = None) -> Iterator[ExternalEndpoint]:
        user_key = ssh.HostKey(key=self.identity.public_key().public_bytes_raw())
        server = ssh.SSHServer(self.host, ssh.Credentials("test", authorized_keys=(user_key,)), verbose=2 if log else 0, trace_stream=log)
        with socket.create_server(("127.0.0.1", 0)) as listener:
            listener.settimeout(10)
            port = listener.getsockname()[1]
            known = self.root / "known_hosts"
            pinned = ssh.HostKey(key=self.host.public_key().public_bytes_raw())
            known.write_bytes(f"[127.0.0.1]:{port} ".encode() + pinned.openssh() + b"\n")
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.accept_one, listener, server)
                yield ExternalEndpoint(port, self.identity_path, known)
                future.result(timeout=10)

    @staticmethod
    def accept_one(listener: socket.socket, server: ssh.SSHServer) -> None:
        sock, _ = listener.accept()
        sock.settimeout(10)
        server.serve(sock)

    @unittest.skipUnless(shutil.which("ssh"), "OpenSSH ssh unavailable")
    def test_openssh_forced_pty(self) -> None:
        with self.endpoint() as endpoint:
            command = ["ssh", *endpoint.options(), "-tt", "test@127.0.0.1", "test -t 0 && test -t 1 && stty size; printf terminal; exit 6"]
            result = subprocess.run(command, input=b"", capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 6, result.stderr.decode(errors="replace"))
        self.assertIn(b"terminal", result.stdout)
        self.assertNotIn(b"allocation request failed", result.stderr)

    @unittest.skipUnless(shutil.which("sftp") and ssh.find_sftp_server(), "OpenSSH SFTP unavailable")
    def test_openssh_sftp_put_get_list_rename_symlink_remove(self) -> None:
        original = self.root / "original.bin"
        downloaded = self.root / "downloaded.bin"
        remote = self.root / "remote"
        data = bytes(range(256)) * 1200
        original.write_bytes(data)
        batch = (
            f"mkdir {remote}\ncd {remote}\nput {original} upload.bin\nls -l\nget upload.bin {downloaded}\n"
            f"rename upload.bin renamed.bin\nln -s renamed.bin link.bin\nrm link.bin\nrm renamed.bin\ncd /\nrmdir {remote}\nbye\n"
        )
        log = io.StringIO()
        with self.endpoint(log) as endpoint:
            command = ["sftp", *endpoint.options(), "-b", "-", "test@127.0.0.1"]
            result = subprocess.run(command, input=batch.encode(), capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(downloaded.read_bytes(), data)
        self.assertFalse(remote.exists())
        self.assertIn(b"upload.bin", result.stdout)
        for name in ("SSH_FXP_OPEN", "SSH_FXP_WRITE", "SSH_FXP_READ", "SSH_FXP_NAME", "SSH_FXP_STATUS", "SSH_FXP_SYMLINK"):
            self.assertIn(name, log.getvalue())


if __name__ == "__main__":
    unittest.main()
