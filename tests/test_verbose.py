# written by chatgpt GPT-6
"""Protocol trace formatting and live encrypted transport coverage."""

import io
import socket
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519

import ssh


class ProtocolTraceTests(unittest.TestCase):
    def setUp(self) -> None:
        clock = patch("ssh.ProtocolTrace.timestamp", return_value="12:34:56.123456")
        clock.start()
        self.addCleanup(clock.stop)

    def test_verbose_argument_count(self) -> None:
        parser = ssh.build_parser()
        for flag, expected in (([], 0), (["-v"], 1), (["-vv"], 2), (["--verbose", "--verbose"], 2)):
            for mode in ("client", "server"):
                arguments = [mode, "-u", "testuser", *flag]
                arguments.extend(["host"] if mode == "client" else ["-k", "hostkey"])
                self.assertEqual(parser.parse_args(arguments).verbose, expected)

    def test_hex_is_one_complete_line(self) -> None:
        output = io.StringIO()
        packet = ssh.Msg94_ChannelData(7, bytes(range(256)) * 32)
        payload = ssh.encode_message(packet)
        ssh.ProtocolTrace(1, output).message("send", packet, payload)
        self.assertEqual(output.getvalue(), f"12:34:56.123456 send SSH_MSG_CHANNEL_DATA {payload.hex()}\n")
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertGreater(len(output.getvalue()), 160)

    def test_zero_verbosity_is_silent(self) -> None:
        output = io.StringIO()
        trace = ssh.ProtocolTrace(0, output)
        packet = ssh.Msg21_NewKeys()
        trace.message("send", packet, ssh.encode_message(packet))
        trace.identification("send", ssh.Hello())
        self.assertEqual(output.getvalue(), "")

    def test_decoded_nested_fields_include_all_bytes(self) -> None:
        output = io.StringIO()
        method = ssh.PasswordAuth(password=b"secret")
        packet = ssh.Msg50_UserAuthRequest("itsme", method=method)
        ssh.ProtocolTrace(2, output).message("recv", packet, ssh.encode_message(packet))
        text = output.getvalue()
        self.assertIn("recv SSH_MSG_USERAUTH_REQUEST", text)
        self.assertIn("username: 'itsme'", text)
        self.assertIn("method: PasswordAuth (password)", text)
        self.assertIn("password: 6 bytes", text)
        self.assertIn("text: 'secret'", text)
        self.assertIn("73 65 63 72 65 74", text)

    def test_algorithm_lists_are_readable_and_control_characters_escaped(self) -> None:
        output = io.StringIO()
        trace = ssh.ProtocolTrace(2, output)
        packet = ssh.Msg20_KexInit(cookie=bytes(16))
        trace.message("send", packet, ssh.encode_message(packet))
        self.assertIn("  kex_algorithms:\n    mlkem768x25519-sha256\n    curve25519-sha256", output.getvalue())
        output.seek(0)
        output.truncate()
        banner = ssh.Msg53_UserAuthBanner("message\n\x1b[31m")
        trace.message("recv", banner, ssh.encode_message(banner))
        self.assertIn("message\\n\\x1b[31m", output.getvalue())
        self.assertNotIn("\x1b", output.getvalue())

    def test_empty_unknown_hybrid_and_identification_names(self) -> None:
        output = io.StringIO()
        trace = ssh.ProtocolTrace(1, output)
        trace.kex_algorithm = ssh.KEX_HYBRID
        packets: tuple[ssh.SshPacket, ...] = (ssh.Msg21_NewKeys(), ssh.RawPacket(254, b"opaque"), ssh.Msg30_ECDHInit(bytes(1216)))
        for packet in packets:
            trace.message("send", packet, ssh.encode_message(packet))
        trace.identification("recv", ssh.Hello())
        lines = output.getvalue().splitlines()
        self.assertEqual(lines[0], "12:34:56.123456 send SSH_MSG_NEWKEYS 15")
        self.assertTrue(lines[1].startswith("12:34:56.123456 send SSH_MSG_UNKNOWN_254 fe"))
        self.assertTrue(lines[2].startswith("12:34:56.123456 send SSH_MSG_KEX_HYBRID_INIT 1e"))
        self.assertEqual(lines[3], f"12:34:56.123456 recv SSH_IDENTIFICATION {ssh.encode_object(ssh.Hello()).hex()}")

    def test_live_client_and_server_trace_encrypted_messages(self) -> None:
        for level in (1, 2):
            with self.subTest(level=level):
                self.check_live_trace(level)

    def check_live_trace(self, level: int) -> None:
        host = ed25519.Ed25519PrivateKey.generate()
        pinned = ssh.HostKey("ssh-ed25519", host.public_key().public_bytes_raw())
        client_log, server_log = io.StringIO(), io.StringIO()
        server = ssh.SSHServer(host, ssh.Credentials("testuser", "secret"), verbose=level, trace_stream=server_log)
        left, right = socket.socketpair()
        left.settimeout(5)
        right.settimeout(5)
        with left, right, ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(server.serve, left)
            client = ssh.SSHClient(right, pinned, verbose=level, trace_stream=client_log)
            client.authenticate("testuser", "secret")
            self.assertEqual(client.run("cat; exit 7", b"trace-input"), ssh.CommandResult(b"trace-input", b"", 7))
            pending.result(timeout=5)
        for log in (client_log.getvalue(), server_log.getvalue()):
            self.assertIn("SSH_MSG_KEX_HYBRID_INIT", log)
            self.assertIn("SSH_MSG_KEX_HYBRID_REPLY", log)
            self.assertIn("SSH_MSG_USERAUTH_REQUEST", log)
            self.assertIn("SSH_MSG_CHANNEL_DATA", log)
            self.assertIn("SSH_MSG_CHANNEL_CLOSE", log)
        if level == 1:
            sent: list[bytes] = []
            received: list[bytes] = []
            for line in client_log.getvalue().splitlines():
                timestamp, direction, name, data = line.split(" ", 3)
                if name.startswith("SSH_MSG_"):
                    (sent if direction == "send" else received).append(bytes.fromhex(data))
            peer_sent: list[bytes] = []
            peer_received: list[bytes] = []
            for line in server_log.getvalue().splitlines():
                timestamp, direction, name, data = line.split(" ", 3)
                if name.startswith("SSH_MSG_"):
                    (peer_sent if direction == "send" else peer_received).append(bytes.fromhex(data))
            self.assertEqual(sent, peer_received)
            self.assertEqual(received, peer_sent)
        else:
            self.assertIn("request: ExecRequest (exec)", server_log.getvalue())
            self.assertIn("command: 'cat; exit 7'", server_log.getvalue())
            self.assertIn("text: 'trace-input'", client_log.getvalue())


if __name__ == "__main__":
    unittest.main()
