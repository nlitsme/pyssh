# written by chatgpt GPT-6
"""Uniform wire interfaces, explicit layouts, and CLI policy regression tests."""

import inspect
import os
import socket
import unittest
import warnings
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519

import ssh


class WireInterfaceTests(unittest.TestCase):
    def test_ssh_reader_writer_extensions(self) -> None:
        writer = ssh.SSHWriter()
        writer.write32be(0x12345678)
        writer.writeldata(b"\x00\xff")
        writer.writelstr("café\x00")
        writer.writeldata(b"")
        reader = ssh.SSHReader(writer.getvalue())
        self.assertEqual(reader.read32be(), 0x12345678)
        self.assertEqual(reader.readldata(), b"\x00\xff")
        self.assertEqual(reader.readlstr(), "café\x00")
        self.assertEqual(reader.readldata(), b"")
        reader.finish()

    def test_reader_rejects_invalid_strings(self) -> None:
        with self.assertRaises(EOFError):
            ssh.SSHReader(bytes.fromhex("0000000261")).readldata()
        with self.assertRaises(UnicodeDecodeError):
            ssh.SSHReader(bytes.fromhex("00000001ff")).readlstr()
        with self.assertRaises(ssh.ProtocolError):
            ssh.SSHReader(bytes.fromhex("ffffffff")).readldata()

    def test_all_registered_messages_share_the_instance_interface(self) -> None:
        samples: dict[int, ssh.SshPacket] = {31: ssh.Msg31_ECDHReply(ssh.HostKey(key=bytes(32)), bytes(32), ssh.Signature(data=bytes(64)))}
        for message_type in ssh.MESSAGE_CLASSES:
            packet = samples.get(message_type.msgtype, message_type())
            with self.subTest(message=message_type.__name__):
                for name in ("encode", "decode"):
                    self.assertTrue(inspect.ismethod(getattr(packet, name)))
                    self.assertNotIsInstance(inspect.getattr_static(message_type, name), (classmethod, staticmethod))
                writer = ssh.SSHWriter()
                self.assertIsNone(packet.encode(writer))
                reader = ssh.SSHReader(writer.getvalue())
                other = message_type()
                self.assertIsNone(other.decode(reader))
                reader.finish()
                self.assertEqual(ssh.encode_message(other), ssh.encode_message(packet))
                self.assertEqual(ssh.encode_object(ssh.decode_message(ssh.SSHReader(ssh.encode_message(packet)))), writer.getvalue())

    def test_authentication_variants_and_signature_input(self) -> None:
        signature = ssh.Signature(data=bytes(64))
        key = ssh.encode_object(ssh.HostKey(key=bytes(32)))
        methods: tuple[ssh.AuthMethod, ...] = (
            ssh.NoneAuth(),
            ssh.PasswordAuth(password=b"secret"),
            ssh.PasswordAuth(True, b"old", b"new"),
            ssh.PublicKeyAuth(public_key=key),
            ssh.PublicKeyAuth(True, "ssh-ed25519", key, signature),
            ssh.UnknownAuth("unsupported", b"opaque"),
        )
        for method in methods:
            packet = ssh.Msg50_UserAuthRequest("itsme", method=method)
            encoded = ssh.encode_message(packet)
            decoded = ssh.decode_message(ssh.SSHReader(encoded))
            self.assertEqual(ssh.encode_message(decoded), encoded)
        request = ssh.Msg50_UserAuthRequest("itsme", method=ssh.PublicKeyAuth(True, "ssh-ed25519", key, signature))
        writer = ssh.SSHWriter()
        writer.writeldata(b"session-id")
        writer.write(ssh.encode_message(request)[: -4 - len(ssh.encode_object(signature))])
        self.assertEqual(request.signature_input(b"session-id"), writer.getvalue())

    def test_channel_request_variants_roundtrip(self) -> None:
        requests: tuple[ssh.RequestBody, ...] = (
            ssh.ShellRequest(),
            ssh.ExecRequest("cat"),
            ssh.SignalRequest("INT"),
            ssh.ExitStatusRequest(7),
            ssh.ExitSignalRequest("TERM", False, "terminated", ""),
            ssh.PtyRequest(b"xterm-kitty", 190, 27, 1710, 486),
            ssh.EnvRequest(b"COLORTERM", b"truecolor"),
            ssh.SubsystemRequest("sftp"),
            ssh.WindowChangeRequest(132, 43, 0, 0),
            ssh.OpaqueRequest("unknown@example.org", b"retained opaque body"),
        )
        for request in requests:
            packet = ssh.Msg98_ChannelRequest(3, request, False)
            encoded = ssh.encode_message(packet)
            decoded = ssh.decode_message(ssh.SSHReader(encoded))
            self.assertEqual(ssh.encode_message(decoded), encoded)
            self.assertIsInstance(decoded, ssh.Msg98_ChannelRequest)
            self.assertIs(type(decoded.request), type(request))

    def test_channel_data_wire_layout(self) -> None:
        packet = ssh.Msg95_ChannelExtendedData(recipient=3, stream=1, data=b"err")
        self.assertEqual(ssh.encode_message(packet), bytes.fromhex("5f000000030000000100000003657272"))
        decoded = ssh.decode_message(ssh.SSHReader(ssh.encode_message(packet)))
        self.assertEqual(decoded, packet)

    def test_frame_encode_decode_can_share_a_reader(self) -> None:
        first = ssh.SSH2Frame(ssh.Msg21_NewKeys(), bytes(10))
        second = ssh.SSH2Frame(ssh.Msg52_UserAuthSuccess(), bytes(10))
        reader = ssh.SSHReader(ssh.encode_object(first) + ssh.encode_object(second))
        a, b = ssh.SSH2Frame(), ssh.SSH2Frame()
        a.decode(reader)
        b.decode(reader)
        reader.finish()
        self.assertEqual(a.packet.msgtype, 21)
        self.assertEqual(b.packet.msgtype, 52)


class CLIPolicyTests(unittest.TestCase):
    def test_short_options_and_default_port(self) -> None:
        parser = ssh.build_parser()
        args = parser.parse_args(["client", "-u", "itsme", "-P", "secret", "host"])
        self.assertEqual(args.port, 22)
        self.assertEqual(args.password, "secret")
        self.assertIsNone(args.host_key)
        args = parser.parse_args(["client", "-u", "itsme", "-p", "2222", "-k", "host.pub", "-i", "identity", "-c", "-t", "10", "host"])
        self.assertEqual(args.port, 2222)
        self.assertEqual(args.host_key, Path("host.pub"))
        self.assertEqual(args.identity, Path("identity"))
        self.assertTrue(args.curve25519)
        self.assertEqual(args.timeout, 10)
        args = parser.parse_args(["server", "-u", "itsme", "-k", "host", "-l", "127.0.0.1", "-a", "user.pub", "-o"])
        self.assertEqual(args.port, 22)
        self.assertTrue(args.once)

    def test_password_argument_environment_prompt_precedence(self) -> None:
        with patch.dict(os.environ, {"SSH_PASSWORD": "environment"}, clear=True):
            self.assertEqual(ssh.read_password("explicit"), "explicit")
            self.assertEqual(ssh.read_password(""), "")
            self.assertEqual(ssh.read_password(None), "environment")
        with patch.dict(os.environ, {}, clear=True), patch("ssh.getpass.getpass", return_value="prompted") as prompt:
            self.assertEqual(ssh.read_password(None), "prompted")
            prompt.assert_called_once()

    def test_unpinned_host_is_accepted_and_warned_once(self) -> None:
        host = ed25519.Ed25519PrivateKey.generate()
        left, right = socket.socketpair()
        left.settimeout(5)
        right.settimeout(5)
        with left, right, ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(ssh.Connection, left, True, host)
            with warnings.catch_warnings(record=True) as emitted:
                warnings.simplefilter("always")
                client = ssh.Connection(right)
                server = future.result(timeout=5)
                pending = pool.submit(client.key_exchange)
                server.key_exchange(server.transport.receive())
                pending.result(timeout=5)
            self.assertEqual(len(emitted), 1)
            self.assertIn("host key is not verified", str(emitted[0].message))
            self.assertIn("SHA256:", str(emitted[0].message))
            self.assertEqual(client.session_id, server.session_id)


if __name__ == "__main__":
    unittest.main()
