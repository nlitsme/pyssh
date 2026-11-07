# written by chatgpt GPT-6
"""Captured OpenSSH host-key advertisements and their nested public parameters."""

import base64
import io
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ssh

CAPTURE = bytes.fromhex(Path(__file__).with_name("hostkeys_capture.hex").read_text())


def captured_message() -> bytes:
    writer = ssh.SSHWriter()
    writer.writebyte(80)
    writer.writelstr("hostkeys-00@openssh.com")
    writer.writeboolean(False)
    writer.write(CAPTURE)
    return writer.getvalue()


class HostKeyAdvertisementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = captured_message()
        self.packet = ssh.decode_message(ssh.SSHReader(self.payload))
        assert isinstance(self.packet, ssh.Msg80_GlobalRequest)
        assert isinstance(self.packet.data, ssh.HostKeysRequestData)
        self.keys = self.packet.data.keys

    def test_captured_boundaries_and_exact_roundtrip(self) -> None:
        self.assertEqual(len(CAPTURE), 574)
        self.assertEqual(len(self.payload), 603)
        self.assertEqual(self.packet.name, "hostkeys-00@openssh.com")
        self.assertFalse(self.packet.want_reply)
        self.assertEqual(len(self.keys), 3)
        self.assertEqual(tuple(len(ssh.encode_object(key)) for key in self.keys), (407, 104, 51))
        self.assertEqual(ssh.encode_message(self.packet), self.payload)

    def test_rsa_parameters(self) -> None:
        key = self.keys[0]
        self.assertEqual(key.algorithm, "ssh-rsa")
        self.assertIsInstance(key.parameters, ssh.RSAPublicKeyFields)
        self.assertEqual(key.parameters.exponent, 65537)
        self.assertEqual(key.parameters.modulus.bit_length(), 3072)
        self.assertEqual(key.parameters.modulus.to_bytes(384, "big")[:8].hex(), "eb0fed9c68ad8ae8")
        self.assertEqual(key.bits(), 3072)
        self.assertEqual(key.fingerprint(), "SHA256:NtiLpAzKx1Fro5mbun6N+knJVbU50QUz3+VXkJRCUWo")

    def test_ecdsa_and_ed25519_parameters(self) -> None:
        ecdsa, ed25519 = self.keys[1:]
        self.assertEqual(ecdsa.algorithm, "ecdsa-sha2-nistp256")
        self.assertIsInstance(ecdsa.parameters, ssh.ECDSAPublicKeyFields)
        self.assertEqual(ecdsa.parameters.curve, "nistp256")
        self.assertEqual(len(ecdsa.parameters.point), 65)
        numbers = ecdsa.parameters.public_numbers()
        self.assertEqual(f"{numbers.x:064x}", "5dd0e6b9891127dd7d767254d96f06d2c549488392fbbb0acea4dd98775a9073")
        self.assertEqual(f"{numbers.y:064x}", "5aa314233bcd1de2e4737defc5d20cf559f588790fc67f4e121de6a767140465")
        self.assertEqual(ecdsa.fingerprint(), "SHA256:EW+azFri4e2MfWXuNgXCEBgif6dgt10opMvbhlLrutE")
        self.assertEqual(ed25519.algorithm, "ssh-ed25519")
        self.assertIsInstance(ed25519.parameters, ssh.Ed25519PublicKeyFields)
        self.assertEqual(ed25519.parameters.key.hex(), "c0e97e70fd7a40bdd1de4b382648f63d71b3d725a7c8a4f42b36821b931554f8")
        self.assertEqual(ed25519.fingerprint(), "SHA256:/ZUfC4weoZjzDz7MT2y+B+tTbpqt4l2WqGMy7621i9s")

    @unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen unavailable")
    def test_fingerprints_agree_with_openssh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for index, key in enumerate(self.keys):
                path = Path(directory) / f"host{index}.pub"
                blob = base64.b64encode(ssh.encode_object(key))
                path.write_bytes(key.algorithm.encode("ascii") + b" " + blob + b"\n")
                result = subprocess.run(["ssh-keygen", "-lf", str(path), "-E", "sha256"], capture_output=True, check=True, timeout=5)
                self.assertIn(key.fingerprint().encode("ascii"), result.stdout)

    def test_unknown_key_and_global_request_preserve_undecoded_data(self) -> None:
        writer = ssh.SSHWriter()
        writer.writelstr("unknown-key@example.org")
        writer.write(b"opaque key parameters")
        unknown_blob = writer.getvalue()
        key = ssh.decode_object(ssh.AdvertisedHostKey(), unknown_blob)
        self.assertIsInstance(key.parameters, ssh.OpaquePublicKeyFields)
        self.assertEqual(key.parameters.undecoded, b"opaque key parameters")
        self.assertEqual(ssh.encode_object(key), unknown_blob)
        self.assertIsNone(key.bits())
        request = ssh.Msg80_GlobalRequest("unknown@example.org", False, b"opaque global request")
        encoded = ssh.encode_message(request)
        decoded = ssh.decode_message(ssh.SSHReader(encoded))
        self.assertIsInstance(decoded.data, ssh.OpaqueGlobalRequestData)
        self.assertEqual(decoded.data.undecoded, b"opaque global request")
        self.assertEqual(ssh.encode_message(decoded), encoded)

    def test_truncated_advertisement_and_invalid_key_are_errors(self) -> None:
        for data in (CAPTURE[:-1], CAPTURE[:20], CAPTURE + b"\x00"):
            with self.subTest(length=len(data)), self.assertRaises((EOFError, ssh.ProtocolError)):
                ssh.decode_object(ssh.HostKeysRequestData(), data)
        point = bytearray(self.keys[1].parameters.point)
        point[0] = 0xFF
        bad_key = ssh.AdvertisedHostKey("ecdsa-sha2-nistp256", ssh.ECDSAPublicKeyFields("nistp256", bytes(point)))
        with self.assertRaises(ssh.ProtocolError):
            ssh.decode_object(ssh.AdvertisedHostKey(), ssh.encode_object(bad_key))

    def test_mpint_signed_values_and_minimal_encoding(self) -> None:
        values = (0, 1, 127, 128, 255, 256, -1, -127, -128, -129, -256, 2**3071, -(2**3071))
        for value in values:
            writer = ssh.SSHWriter()
            writer.writempint(value)
            reader = ssh.SSHReader(writer.getvalue())
            self.assertEqual(reader.readmpint(), value)
            reader.finish()
        for data in (b"\x00", b"\x00\x01", b"\xff\x80"):
            writer = ssh.SSHWriter()
            writer.writeldata(data)
            with self.assertRaises(ssh.ProtocolError):
                ssh.SSHReader(writer.getvalue()).readmpint()

    def test_timestamp_and_verbose_output_decode_all_three_keys(self) -> None:
        log = io.StringIO()
        with patch("ssh.ProtocolTrace.timestamp", return_value="20:12:34.123456"):
            ssh.ProtocolTrace(2, log).message("recv", self.packet, self.payload)
        text = log.getvalue()
        self.assertTrue(text.startswith("20:12:34.123456 recv SSH_MSG_GLOBAL_REQUEST"))
        self.assertIn("keys: 3 entries", text)
        self.assertIn("bits: 3072", text)
        self.assertIn("exponent: 65537 (0x10001)", text)
        self.assertIn("curve: 'nistp256'", text)
        for key in self.keys:
            self.assertIn(key.fingerprint(), text)
        self.assertNotIn("undecoded", text)
        self.assertRegex(ssh.ProtocolTrace.timestamp(), r"^\d{2}:\d{2}:\d{2}\.\d{6}$")
        self.assertIsNotNone(re.match(r"^20:12:34\.123456 recv", text))


if __name__ == "__main__":
    unittest.main()
