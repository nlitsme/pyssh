# written by chatgpt GPT-6
"""Golden decoding tests, written before the SSH implementation."""

import hashlib
import unittest
from pathlib import Path

import ssh

CAPTURE = Path(__file__).with_name("capture.txt").read_text()


class CaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = ssh.decode_transcript(CAPTURE)
        self.frames = tuple(
            event.value
            for event in self.events
            if isinstance(event.value, ssh.SSH2Frame)
        )

    def test_versions(self) -> None:
        versions = tuple(
            event.value.version
            for event in self.events
            if isinstance(event.value, ssh.Hello)
        )
        self.assertEqual(
            versions,
            (
                "SSH-2.0-OpenSSH_10.6p1 Debian-1",
                "SSH-2.0-OpenSSH_10.6",
            ),
        )

    def test_frame_boundaries(self) -> None:
        self.assertEqual(
            tuple(frame.packet.msgtype for frame in self.frames),
            (20, 20, 30, 31, 21, 21),
        )
        self.assertEqual(
            tuple(frame.packet_length for frame in self.frames),
            (1052, 1708, 1228, 1276, 12, 12),
        )
        self.assertEqual(
            tuple(len(frame.padding) for frame in self.frames),
            (5, 6, 6, 8, 10, 10),
        )

    def test_kexinit_fields_and_negotiation(self) -> None:
        server = self.frames[0].packet
        client = self.frames[1].packet
        self.assertIsInstance(server, ssh.Msg20_KexInit)
        self.assertIsInstance(client, ssh.Msg20_KexInit)
        self.assertEqual(
            server.cookie.hex(), "82fd05571cb725f5e4b11d6590ef521e"
        )
        self.assertEqual(
            client.cookie.hex(), "2a0ad294d9c24cd86c99a03944345ae2"
        )
        self.assertEqual(len(server.kex_algorithms.split(",")), 10)
        self.assertIn("ssh-ed25519", server.hostkey_algorithms.split(","))
        self.assertEqual(server.c2s_comp, "none,zlib@openssh.com")
        self.assertEqual(server.c2s_lang, "")
        self.assertEqual(server.reserved, 0)
        self.assertFalse(server.kexfollows)
        selected = ssh.Algorithms.negotiate(client, server)
        self.assertEqual(selected.kex, "mlkem768x25519-sha256")
        self.assertEqual(selected.hostkey, "ssh-ed25519")
        self.assertEqual(selected.c2s_cipher, "chacha20-poly1305@openssh.com")
        self.assertEqual(selected.s2c_cipher, selected.c2s_cipher)
        self.assertTrue(selected.strict)

    def test_hybrid_client_key(self) -> None:
        packet = self.frames[2].packet
        self.assertIsInstance(packet, ssh.Msg30_ECDHInit)
        parts = ssh.HybridInit.decode(packet.pubkey)
        self.assertEqual(len(parts.kem_public), 1184)
        self.assertEqual(len(parts.x25519_public), 32)
        self.assertEqual(packet.pubkey[:8].hex(), "4f1b15959755f6f6")
        self.assertEqual(packet.pubkey[-8:].hex(), "afedac570de1ab44")

    def test_hybrid_server_key_and_signature(self) -> None:
        packet = self.frames[3].packet
        self.assertIsInstance(packet, ssh.Msg31_ECDHReply)
        self.assertEqual(packet.hostkey.algorithm, "ssh-ed25519")
        self.assertEqual(
            packet.hostkey.key.hex(),
            (
                "f857812148d5e9063e229cf0144e797248df5243a5af54ff673d0f6bd7b6054f"
            ),
        )
        parts = ssh.HybridReply.decode(packet.pubkey)
        self.assertEqual(len(parts.kem_ciphertext), 1088)
        self.assertEqual(len(parts.x25519_public), 32)
        self.assertEqual(packet.signature.algorithm, "ssh-ed25519")
        self.assertEqual(len(packet.signature.data), 64)
        self.assertEqual(packet.signature.data[:8].hex(), "a7883a2f683ed75f")

    def test_encrypted_tails_are_explicit_and_lossless(self) -> None:
        tails = tuple(
            event
            for event in self.events
            if isinstance(event.value, ssh.EncryptedData)
        )
        self.assertEqual(tuple(event.direction for event in tails), ("<", ">"))
        self.assertEqual(
            tuple(len(event.value.data) for event in tails), (364, 68)
        )
        self.assertEqual(tails[0].value.data[:8].hex(), "4e5c3e0deb9a48f5")
        self.assertEqual(tails[1].value.data[:8].hex(), "6c1368b20d01f71e")
        for direction in ("<", ">"):
            original = b"".join(
                bytes.fromhex(line[1:])
                for line in CAPTURE.splitlines()
                if line.startswith(direction)
            )
            reconstructed = b"".join(
                event.value.to_bytes()
                for event in self.events
                if event.direction == direction
            )
            self.assertEqual(reconstructed, original)

    def test_round_trip_captured_frames(self) -> None:
        expected = (
            "c6f4d216d0113ff710666359264e8d0740dd4cd3090f576d0babe05d8bc223ba",
            "5572eca704249fe9ef9e7866860ec510fc9dfc43cb49631ca9022438a4fa9f3f",
            "6291b3525144387e5ad72e801b7b50740b59ab25f81702cf9eae9d6ebc9d1b67",
        )
        for frame, digest in zip(self.frames, expected):
            self.assertEqual(
                hashlib.sha256(frame.to_bytes()).hexdigest(), digest
            )
        for frame in self.frames:
            self.assertEqual(
                ssh.SSH2Frame.from_bytes(frame.to_bytes()).to_bytes(),
                frame.to_bytes(),
            )

    def test_fragmentation_at_every_byte(self) -> None:
        for direction in ("<", ">"):
            stream = ssh.TranscriptStream(direction)
            values: list[ssh.TranscriptEvent] = []
            for line in CAPTURE.splitlines():
                if line.startswith(direction):
                    for byte in bytes.fromhex(line[1:]):
                        values.extend(stream.feed(bytes([byte])))
            stream.finish()
            # Ciphertext chunking may differ; the stream stays identical.
            self.assertEqual(
                b"".join(event.value.to_bytes() for event in values),
                b"".join(
                    event.value.to_bytes()
                    for event in self.events
                    if event.direction == direction
                ),
            )
            self.assertEqual(
                sum(
                    isinstance(event.value, ssh.SSH2Frame) for event in values
                ),
                3,
            )

    def test_truncated_capture_is_an_error(self) -> None:
        stream = ssh.TranscriptStream(">")
        stream.feed(b"SSH-2.0-test\n\x00\x00\x00\x0c\x0a\x15")
        with self.assertRaises(ssh.ProtocolError):
            stream.finish()


if __name__ == "__main__":
    unittest.main()
