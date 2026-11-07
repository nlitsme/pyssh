# written by chatgpt GPT-6
"""Captured subsystem packets, lossless SFTP framing, and compact tracing."""

import inspect
import io
import unittest

import ssh


class SubsystemDecodingTests(unittest.TestCase):
    def test_cli_pty_subsystem_and_sftp_server_short_options(self) -> None:
        parser = ssh.build_parser()
        arguments = parser.parse_args(["client", "-u", "test", "-T", "host"])
        self.assertTrue(arguments.pty)
        arguments = parser.parse_args(["client", "-u", "test", "-s", "sftp", "host"])
        self.assertEqual(arguments.subsystem, "sftp")
        arguments = parser.parse_args(["server", "-u", "test", "-k", "hostkey", "-s", "/usr/lib/ssh/sftp-server"])
        self.assertEqual(str(arguments.sftp_server), "/usr/lib/ssh/sftp-server")

    def test_all_sftp_messages_share_the_instance_interface(self) -> None:
        self.assertEqual(len(ssh.SFTP_CLASSES), 27)
        for message_type in ssh.SFTP_CLASSES:
            packet = message_type()
            with self.subTest(message=message_type.__name__):
                for method in ("encode", "decode"):
                    self.assertNotIsInstance(inspect.getattr_static(message_type, method), (classmethod, staticmethod))
                data = ssh.encode_object(ssh.SftpFrame(packet))
                self.assertEqual(ssh.decode_object(ssh.SftpFrame(), data), ssh.SftpFrame(packet))

    def test_captured_subsystem_request(self) -> None:
        payload = bytes.fromhex("62000000000000000973756273797374656d010000000473667470")
        packet = ssh.decode_message(ssh.SSHReader(payload))
        self.assertEqual(len(payload), 27)
        self.assertIsInstance(packet.request, ssh.SubsystemRequest)
        self.assertEqual(packet.request.subsystem, "sftp")
        self.assertEqual(ssh.encode_message(packet), payload)

    def test_captured_sftp_init_fragmentation_and_coalescing(self) -> None:
        captured = bytes.fromhex("000000050100000003")
        for split in range(1, len(captured)):
            stream = ssh.SftpStream()
            self.assertEqual(stream.feed(captured[:split]), ())
            frames = stream.feed(captured[split:] + captured)
            self.assertEqual(len(frames), 2)
            self.assertEqual(frames[0].packet, ssh.Sftp1_Init(3))
            self.assertEqual(ssh.encode_object(frames[0]), captured)
            self.assertEqual(stream.pending, b"")

    def test_sftp_attributes_and_requests_roundtrip(self) -> None:
        attributes = ssh.SftpAttributes(flags=15, size=123, uid=1000, gid=1000, permissions=0o100644, atime=12, mtime=13)
        packets: tuple[ssh.SftpPacket, ...] = (
            ssh.Sftp3_Open(7, b"file.txt", 26, attributes),
            ssh.Sftp5_Read(8, b"handle", 2**40, 65536),
            ssh.Sftp6_Write(9, b"handle", 8, b"\x00\xff"),
            ssh.Sftp104_Name(10, (ssh.SftpName(b"file.txt", b"long name", attributes),)),
            ssh.Sftp101_Status(11, 2, b"No such file", b""),
        )
        for packet in packets:
            frame = ssh.SftpFrame(packet)
            data = ssh.encode_object(frame)
            self.assertEqual(ssh.SftpStream().feed(data), (frame,))

    def test_sftp_unknown_and_malformed_data_remain_explicit(self) -> None:
        unknown = bytes.fromhex("00000004fe010203")
        frame = ssh.SftpStream().feed(unknown)[0]
        self.assertIsInstance(frame.packet, ssh.SftpUnknown)
        self.assertEqual(frame.packet.undecoded, b"\x01\x02\x03")
        self.assertEqual(ssh.encode_object(frame), unknown)
        with self.assertRaises(ssh.ProtocolError):
            ssh.SftpStream().feed(bytes(4))
        with self.assertRaises(ssh.ProtocolError):
            ssh.SftpStream().feed(bytes.fromhex("ffffffff"))
        malformed = bytes.fromhex("00000003040000")
        frame = ssh.SftpStream().feed(malformed)[0]
        self.assertIsInstance(frame.packet, ssh.SftpUnknown)
        self.assertIn("malformed", frame.packet.reason)
        self.assertEqual(ssh.encode_object(frame), malformed)

    def test_non_v3_data_and_extended_bodies_are_explicitly_undecoded(self) -> None:
        decoder = ssh.SftpStream()
        decoder.feed(ssh.encode_object(ssh.SftpFrame(ssh.Sftp2_Version(6))))
        data = ssh.encode_object(ssh.SftpFrame(ssh.Sftp4_Close(7, b"handle")))
        frame = decoder.feed(data)[0]
        self.assertIsInstance(frame.packet, ssh.SftpUnknown)
        self.assertIn("version 6", frame.packet.reason)
        self.assertEqual(ssh.encode_object(frame), data)
        packet = ssh.Sftp200_Extended(4, b"unknown@example.org", b"opaque extension parameters")
        data = ssh.encode_object(ssh.SftpFrame(packet))
        self.assertEqual(ssh.SftpStream().feed(data)[0].packet, packet)

    def test_sftp_attributes_extended_values_and_unknown_flags(self) -> None:
        attributes = ssh.SftpAttributes(flags=0x80000000, extensions=(ssh.SftpExtension(b"name", b"value"),))
        data = ssh.encode_object(attributes)
        self.assertEqual(ssh.decode_object(ssh.SftpAttributes(), data), attributes)
        with self.assertRaises(ssh.ProtocolError):
            ssh.decode_object(ssh.SftpAttributes(), bytes.fromhex("40000000"))

    def test_pure_text_fields_are_compact_and_binary_stays_hex(self) -> None:
        output = io.StringIO()
        trace = ssh.ProtocolTrace(2, output)
        packet = ssh.Msg98_ChannelRequest(request=ssh.EnvRequest(b"COLORTERM", b"truecolor"))
        trace.message("recv", packet, ssh.encode_message(packet))
        self.assertIn("variable: 'COLORTERM'", output.getvalue())
        self.assertIn("value: 'truecolor'", output.getvalue())
        self.assertNotIn("text:", output.getvalue())
        output.seek(0)
        output.truncate()
        packet = ssh.Msg94_ChannelData(data=b"\x00\xff")
        trace.message("recv", packet, ssh.encode_message(packet))
        self.assertIn("data: 2 bytes", output.getvalue())
        self.assertIn("00 ff", output.getvalue())

    def test_text_formatting_keeps_unicode_newlines_and_controls_lossless(self) -> None:
        for data in ("café\n\t".encode(), b"", b"line\r\n"):
            output = io.StringIO()
            packet = ssh.Msg94_ChannelData(data=data)
            ssh.ProtocolTrace(2, output).message("recv", packet, ssh.encode_message(packet))
            self.assertIn(f"data: {data.decode()!r}", output.getvalue())
        for data in (b"\xff", b"\x00", b"\x1b[31m"):
            self.assertIsNone(ssh.ProtocolTrace._text(data))

    def test_sftp_trace_requires_subsystem_context_and_keeps_hex_mode(self) -> None:
        output = io.StringIO()
        trace = ssh.ProtocolTrace(2, output)
        request = ssh.Msg98_ChannelRequest(request=ssh.SubsystemRequest("sftp"))
        trace.message("recv", request, ssh.encode_message(request))
        packet = ssh.Msg94_ChannelData(data=bytes.fromhex("000000050100000003"))
        trace.message("recv", packet, ssh.encode_message(packet))
        self.assertIn("SSH_FXP_INIT", output.getvalue())
        self.assertIn("version: 3", output.getvalue())
        self.assertNotIn("undecoded", output.getvalue())
        plain = io.StringIO()
        ssh.ProtocolTrace(2, plain).message("recv", packet, ssh.encode_message(packet))
        self.assertNotIn("SSH_FXP_INIT", plain.getvalue())
        verbose = io.StringIO()
        ssh.ProtocolTrace(1, verbose).message("recv", packet, ssh.encode_message(packet))
        self.assertTrue(verbose.getvalue().endswith(ssh.encode_message(packet).hex() + "\n"))


if __name__ == "__main__":
    unittest.main()
