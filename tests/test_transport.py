# written by chatgpt GPT-6
"""Cryptographic framing, key exchange, and hostile-input regression tests."""

import socket
import struct
import unittest
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric import ed25519

import ssh


class TransportTests(unittest.TestCase):
    def test_padding(self) -> None:
        for size in range(1, 1000):
            for block in (8, 16):
                for header in (1, 5):
                    pad = ssh.padding_size(size, block, header)
                    self.assertGreaterEqual(pad, 4)
                    self.assertLess(pad, block + 4)
                    self.assertEqual((size + header + pad) % block, 0)

    def test_cipher_authenticates_header_body_and_tag(self) -> None:
        cipher = ssh.ChaChaPoly(bytes(range(64)))
        payload = ssh.encode_message(ssh.Msg5_ServiceRequest("ssh-userauth"))
        data = cipher.seal(7, payload)
        self.assertEqual(ssh.encode_message(cipher.open(7, data).packet), payload)
        for offset in (0, 4, 8, len(data) - 1):
            corrupted = bytearray(data)
            corrupted[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ssh.ProtocolError):
                cipher.open(7, bytes(corrupted))
        with self.assertRaises(ssh.ProtocolError):
            cipher.open(8, data)

    def test_reject_malformed_plaintext_packets(self) -> None:
        valid = ssh.encode_object(ssh.SSH2Frame(ssh.Msg21_NewKeys(), bytes(10)))
        for data in (valid[:-1], valid + b"\x00", valid[:4] + b"\x03" + valid[5:], struct.pack(">I", ssh.MAX_PACKET + 1) + valid[4:]):
            with self.subTest(data=data), self.assertRaises(ssh.ProtocolError):
                ssh.decode_object(ssh.SSH2Frame(), data)

    def test_no_silent_trailing_bytes(self) -> None:
        with self.assertRaises(ssh.ProtocolError):
            ssh.decode_message(ssh.SSHReader(b"\x15\x00"))
        raw = ssh.decode_message(ssh.SSHReader(b"\xfeunknown"))
        self.assertIsInstance(raw, ssh.RawPacket)
        self.assertEqual(ssh.encode_message(raw), b"\xfeunknown")

    def test_both_kex_methods_and_rekey(self) -> None:
        for curve_only in (False, True):
            with self.subTest(curve_only=curve_only):
                self.check_exchange(curve_only)

    def check_exchange(self, curve_only: bool) -> None:
        host = ed25519.Ed25519PrivateKey.generate()
        pinned = ssh.HostKey("ssh-ed25519", host.public_key().public_bytes_raw())
        left, right = socket.socketpair()
        left.settimeout(5)
        right.settimeout(5)
        with left, right, ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(ssh.Connection, left, True, host, None, curve_only)
            client = ssh.Connection(right, pinned_key=pinned, curve_only=curve_only)
            server = pending.result(timeout=5)
            self.assertEqual(client.session_id, server.session_id)
            self.assertEqual(client.transport.send_sequence, 0)
            self.assertEqual(server.transport.recv_sequence, 0)
            original_session = client.session_id
            client.send(ssh.Msg5_ServiceRequest("ssh-userauth"))
            self.assertEqual(server.expect(5).msgtype, 5)
            pending_rekey = pool.submit(client.key_exchange)
            # receive() handles the rekey, then waits for application data.
            server_kex = server.transport.receive()
            server.key_exchange(server_kex)
            pending_rekey.result(timeout=5)
            self.assertEqual(client.session_id, original_session)
            self.assertEqual(server.session_id, original_session)
            server.send(ssh.Msg6_ServiceAccept("ssh-userauth"))
            self.assertEqual(client.expect(6).msgtype, 6)


if __name__ == "__main__":
    unittest.main()
