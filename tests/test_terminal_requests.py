# written by chatgpt GPT-6
"""Captured PTY/environment requests and lossless terminal-mode decoding."""

import io
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import ssh


def captured_request(name: str, want_reply: bool) -> bytes:
    fixture = "pty_capture.hex" if name == "pty-req" else "env_capture.hex"
    writer = ssh.SSHWriter()
    writer.writebyte(98)
    writer.write32be(0)
    writer.writelstr(name)
    writer.writeboolean(want_reply)
    writer.write(bytes.fromhex(Path(__file__).with_name(fixture).read_text()))
    return writer.getvalue()


class TerminalRequestTests(unittest.TestCase):
    def test_captured_pty_fields_and_roundtrip(self) -> None:
        payload = captured_request("pty-req", True)
        packet = ssh.decode_message(ssh.SSHReader(payload))
        self.assertEqual(len(payload), 313)
        self.assertIsInstance(packet.request, ssh.PtyRequest)
        self.assertEqual(packet.recipient, 0)
        self.assertTrue(packet.want_reply)
        request = packet.request
        self.assertEqual(request.terminal, b"xterm-kitty")
        self.assertEqual((request.columns, request.rows, request.width_pixels, request.height_pixels), (190, 27, 1710, 486))
        self.assertEqual(len(request.modes.entries), 53)  # 52 settings and TTY_OP_END.
        self.assertEqual(request.modes.entries[0], ssh.TerminalMode(129, 38400))
        self.assertEqual(request.modes.entries[1], ssh.TerminalMode(128, 38400))
        self.assertIn(ssh.TerminalMode(1, 3), request.modes.entries)
        self.assertIn(ssh.TerminalMode(3, 127), request.modes.entries)
        self.assertIn(ssh.TerminalMode(42, 1), request.modes.entries)
        self.assertIn(ssh.TerminalMode(53, 1), request.modes.entries)
        self.assertEqual(request.modes.entries[-1], ssh.TerminalMode(0))
        self.assertEqual(request.modes.undecoded, b"")
        self.assertEqual(ssh.encode_message(packet), payload)

    def test_captured_env_fields_and_roundtrip(self) -> None:
        payload = captured_request("env", False)
        packet = ssh.decode_message(ssh.SSHReader(payload))
        self.assertEqual(len(payload), 39)
        self.assertIsInstance(packet.request, ssh.EnvRequest)
        self.assertFalse(packet.want_reply)
        self.assertEqual(packet.request.variable, b"COLORTERM")
        self.assertEqual(packet.request.value, b"truecolor")
        self.assertEqual(ssh.encode_message(packet), payload)

    def test_terminal_mode_unknown_arguments_stops_and_trailing_bytes(self) -> None:
        for stop in (0, 160, 255):
            data = bytes.fromhex("9f010203040100000003") + bytes([stop]) + b"remaining\xff"
            modes = ssh.decode_object(ssh.TerminalModes(), data)
            self.assertEqual(modes.entries[0], ssh.TerminalMode(159, 0x01020304))
            self.assertEqual(modes.entries[1], ssh.TerminalMode(1, 3))
            self.assertEqual(modes.entries[2], ssh.TerminalMode(stop))
            self.assertEqual(modes.undecoded, b"remaining\xff")
            self.assertEqual(ssh.encode_object(modes), data)
            output = io.StringIO()
            packet = ssh.Msg98_ChannelRequest(request=ssh.PtyRequest(modes=modes))
            ssh.ProtocolTrace(2, output).message("recv", packet, ssh.encode_message(packet))
            self.assertIn("UNKNOWN_TERMINAL_MODE_159", output.getvalue())
            self.assertIn("undecoded: 10 bytes", output.getvalue())
            if stop:
                self.assertIn(f"UNKNOWN_STOP_OPCODE_{stop}", output.getvalue())

    def test_modes_preserve_duplicates_and_empty_string(self) -> None:
        for data in (b"", b"\x00", bytes.fromhex("3500000001350000000000")):
            modes = ssh.decode_object(ssh.TerminalModes(), data)
            self.assertEqual(ssh.encode_object(modes), data)
        self.assertEqual(len(modes.entries), 3)
        self.assertEqual(modes.entries[:2], (ssh.TerminalMode(53, 1), ssh.TerminalMode(53, 0)))

    def test_truncated_fields_arguments_and_missing_stop_are_rejected(self) -> None:
        for name in ("pty-req", "env"):
            payload = captured_request(name, True)
            for length in range(len(payload)):
                with self.subTest(name=name, length=length), self.assertRaises((EOFError, ssh.ProtocolError)):
                    ssh.decode_message(ssh.SSHReader(payload[:length]))
            with self.assertRaises(ssh.ProtocolError):
                ssh.decode_message(ssh.SSHReader(payload + b"\x00"))
        for data in (b"\x01", bytes.fromhex("01000000"), bytes.fromhex("0100000003")):
            with self.subTest(data=data), self.assertRaises((EOFError, ssh.ProtocolError)):
                ssh.decode_object(ssh.TerminalModes(), data)

    def test_terminal_and_environment_strings_retain_binary_bytes(self) -> None:
        requests: tuple[ssh.RequestBody, ...] = (
            ssh.EnvRequest(b"EXAMPLE", "café".encode()),
            ssh.EnvRequest(b"\xff\x00", b"\xfe\x00\n"),
            ssh.PtyRequest(terminal=b"\xff\x00"),
        )
        for request in requests:
            packet = ssh.Msg98_ChannelRequest(request=request)
            payload = ssh.encode_message(packet)
            self.assertEqual(ssh.decode_message(ssh.SSHReader(payload)), packet)

    def test_verbose_output_names_modes_and_environment(self) -> None:
        output = io.StringIO()
        with patch("ssh.ProtocolTrace.timestamp", return_value="20:15:44.140694"):
            for name in ("pty-req", "env"):
                payload = captured_request(name, name == "pty-req")
                packet = ssh.decode_message(ssh.SSHReader(payload))
                ssh.ProtocolTrace(2, output).message("recv", packet, payload)
        text = output.getvalue()
        for label in ("PtyRequest (pty-req)", "EnvRequest (env)", "xterm-kitty", "columns: 190", "rows: 27", "COLORTERM", "truecolor"):
            self.assertIn(label, text)
        for label in ("TTY_OP_OSPEED", "38400", "VINTR", "^C", "ICANON", "ECHO", "IUTF8", "TTY_OP_END"):
            self.assertIn(label, text)
        self.assertNotIn("OpaqueRequest", text)
        self.assertTrue(text.startswith("20:15:44.140694 recv SSH_MSG_CHANNEL_REQUEST"))

    def test_pty_and_environment_requests_are_applied_before_start(self) -> None:
        channel = Mock(spec=ssh.Channel)
        session = ssh.ServerSession(channel)
        try:
            for name in ("pty-req", "env"):
                channel.reply.reset_mock()
                packet = ssh.decode_message(ssh.SSHReader(captured_request(name, True)))
                session._request(packet)
                self.assertIsNone(session.process)
                channel.reply.assert_called_once_with(True)
            self.assertIsNotNone(session.terminal)
            self.assertEqual(session.environment["COLORTERM"], "truecolor")
        finally:
            session._cleanup()


if __name__ == "__main__":
    unittest.main()
