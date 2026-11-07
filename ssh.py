# written by chatgpt GPT-6
"""Small, inspectable SSH-2 client/server and lossless handshake decoder.

Suite: ML-KEM-768/X25519 (or Curve25519), Ed25519, OpenSSH ChaCha20/
Poly1305, no compression. Authentication: password and Ed25519 user key.
One shell, exec, PTY, or SFTP session per connection.
"""

from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import getpass
import hashlib
import hmac
import io
import os
import pty
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
import tty
import warnings
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field, fields, is_dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import IO, BinaryIO, ClassVar, Iterator, TextIO, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mlkem, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305

from datareader import DataReader
from datawriter import DataWriter

MAX_PACKET = 256 * 1024
CHANNEL_PACKET = 32768
CHANNEL_WINDOW = 2 * 1024 * 1024
KEX_HYBRID = "mlkem768x25519-sha256"
KEX_CURVE = "curve25519-sha256"
CIPHER = "chacha20-poly1305@openssh.com"
VERSION = "SSH-2.0-python_ssh"


class ProtocolError(ValueError):
    """Malformed, out-of-order, or unsupported SSH protocol data."""


class AuthenticationError(ProtocolError):
    """The server rejected the credentials."""


class HostKeyError(ProtocolError):
    """The server host key did not match the explicitly pinned key."""


def roundup(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


def padding_size(payload_size: int, block_size: int = 8, header_size: int = 5) -> int:
    """Include the message type in payload_size; ChaCha uses header_size=1."""
    if payload_size < 1 or block_size < 8 or block_size > 128:
        raise ValueError("invalid payload size or block size")
    padding = -(header_size + payload_size) % block_size
    return padding if padding >= 4 else padding + block_size


class SSHReader(DataReader):
    """The supplied reader, extended with SSH's length-prefixed values."""

    def readldata(self) -> bytes:
        length = self.read32be()
        if length > MAX_PACKET:
            raise ProtocolError(f"SSH string too long: {length}")
        return self.read(length)

    def readlstr(self, encoding: str = "utf-8") -> str:
        return self.readldata().decode(encoding)

    def readmpint(self) -> int:
        data = self.readldata()
        if data == b"\x00":
            raise ProtocolError("mpint zero must have zero length")
        if len(data) > 1:
            if data[0] == 0 and not data[1] & 0x80:
                raise ProtocolError("redundant positive mpint sign byte")
            if data[0] == 0xFF and data[1] & 0x80:
                raise ProtocolError("redundant negative mpint sign byte")
        return int.from_bytes(data, "big", signed=True)

    def readboolean(self) -> bool:
        value = self.readbyte()
        if value not in (0, 1):
            raise ProtocolError("noncanonical boolean")
        return bool(value)

    def finish(self) -> None:
        if self.remaining():
            raise ProtocolError(f"{self.remaining()} unexpected trailing bytes")


class SSHWriter(DataWriter):
    """The supplied writer, extended with SSH's length-prefixed values."""

    def write(self, data: bytes) -> None:
        # The supplied DataWriter grows by one byte on an empty write.
        if data:
            super().write(data)

    def writeldata(self, data: bytes) -> None:
        self.write32be(len(data))
        self.write(data)

    def writelstr(self, text: str, encoding: str = "utf-8") -> None:
        self.writeldata(text.encode(encoding))

    def writempint(self, value: int) -> None:
        if value == 0:
            self.writeldata(b"")
            return
        length = (value.bit_length() + 8) // 8
        data = value.to_bytes(length, "big", signed=True)
        while len(data) > 1 and ((data[0] == 0 and not data[1] & 0x80) or (data[0] == 0xFF and data[1] & 0x80)):
            data = data[1:]
        self.writeldata(data)

    def writeboolean(self, value: bool) -> None:
        self.writebyte(int(value))


class WireObject:
    """All wire objects encode into and decode from a reader/writer instance."""

    def encode(self, writer: SSHWriter) -> None:
        raise NotImplementedError

    def decode(self, reader: SSHReader) -> None:
        raise NotImplementedError


WireType = TypeVar("WireType", bound=WireObject)


def encode_object(value: WireObject) -> bytes:
    writer = SSHWriter()
    value.encode(writer)
    return writer.getvalue()


def decode_object(value: WireType, data: bytes) -> WireType:
    reader = SSHReader(data)
    value.decode(reader)
    reader.finish()
    return value


@dataclass
class Hello(WireObject):
    version: str = VERSION
    ending: bytes = b"\r\n"

    def validate(self) -> None:
        if "\r" in self.version or "\n" in self.version:
            raise ProtocolError("newline in identification")
        parts = self.version.split("-", 2)
        if len(parts) != 3 or parts[0] != "SSH" or parts[1] not in ("2.0", "1.99"):
            raise ProtocolError("invalid SSH-2 identification")
        software = parts[2].split(" ", 1)[0]
        if not software or any(ord(c) < 33 or ord(c) > 126 or c == "-" for c in software):
            raise ProtocolError("invalid software identifier")
        if self.ending not in (b"\n", b"\r\n"):
            raise ProtocolError("invalid identification terminator")
        if len(self.version.encode("ascii")) + len(self.ending) > 255:
            raise ProtocolError("identification exceeds 255 bytes")

    def encode(self, writer: SSHWriter) -> None:
        self.validate()
        writer.writestr(self.version, "ascii")
        writer.write(self.ending)

    def decode(self, reader: SSHReader) -> None:
        line = reader.readline()
        if not line.endswith("\n"):
            raise ProtocolError("unterminated identification")
        self.ending = b"\r\n" if line.endswith("\r\n") else b"\n"
        self.version = line[: -len(self.ending)]
        self.validate()


class SshPacket(WireObject):
    """encode/decode handle the body; the envelope owns the message-type byte."""

    @property
    def msgtype(self) -> int:
        raise NotImplementedError


class EmptyMessage(SshPacket):
    def encode(self, writer: SSHWriter) -> None:
        pass

    def decode(self, reader: SSHReader) -> None:
        pass


@dataclass
class RawPacket(SshPacket):
    """An unknown message type; its complete body remains explicitly opaque."""

    type_code: int = 0
    body: bytes = b""

    @property
    def msgtype(self) -> int:
        return self.type_code

    def encode(self, writer: SSHWriter) -> None:
        writer.write(self.body)

    def decode(self, reader: SSHReader) -> None:
        self.body = reader.read(reader.remaining())


@dataclass
class Msg1_Disconnect(SshPacket):
    msgtype: ClassVar[int] = 1
    reason: int = 0
    description: str = ""
    language: str = ""

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.reason)
        writer.writelstr(self.description)
        writer.writelstr(self.language)

    def decode(self, reader: SSHReader) -> None:
        self.reason = reader.read32be()
        self.description = reader.readlstr()
        self.language = reader.readlstr()


@dataclass
class Msg2_Ignore(SshPacket):
    msgtype: ClassVar[int] = 2
    data: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.writeldata(self.data)

    def decode(self, reader: SSHReader) -> None:
        self.data = reader.readldata()


@dataclass
class Msg3_Unimplemented(SshPacket):
    msgtype: ClassVar[int] = 3
    sequence: int = 0

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.sequence)

    def decode(self, reader: SSHReader) -> None:
        self.sequence = reader.read32be()


@dataclass
class Msg4_Debug(SshPacket):
    msgtype: ClassVar[int] = 4
    always_display: bool = False
    message: str = ""
    language: str = ""

    def encode(self, writer: SSHWriter) -> None:
        writer.writeboolean(self.always_display)
        writer.writelstr(self.message)
        writer.writelstr(self.language)

    def decode(self, reader: SSHReader) -> None:
        self.always_display = reader.readboolean()
        self.message = reader.readlstr()
        self.language = reader.readlstr()


@dataclass
class ServiceMessage(SshPacket):
    service: str = "ssh-userauth"

    def encode(self, writer: SSHWriter) -> None:
        writer.writelstr(self.service)

    def decode(self, reader: SSHReader) -> None:
        self.service = reader.readlstr()


class Msg5_ServiceRequest(ServiceMessage):
    msgtype: ClassVar[int] = 5


class Msg6_ServiceAccept(ServiceMessage):
    msgtype: ClassVar[int] = 6


@dataclass
class Msg20_KexInit(SshPacket):
    msgtype: ClassVar[int] = 20
    cookie: bytes = field(default_factory=lambda: os.urandom(16))
    kex_algorithms: str = KEX_HYBRID + "," + KEX_CURVE
    hostkey_algorithms: str = "ssh-ed25519"
    c2s_encryption: str = CIPHER
    s2c_encryption: str = CIPHER
    c2s_mac: str = "hmac-sha2-256"
    s2c_mac: str = "hmac-sha2-256"
    c2s_comp: str = "none"
    s2c_comp: str = "none"
    c2s_lang: str = ""
    s2c_lang: str = ""
    kexfollows: bool = False
    reserved: int = 0
    list_fields: ClassVar[tuple[str, ...]] = (
        "kex_algorithms",
        "hostkey_algorithms",
        "c2s_encryption",
        "s2c_encryption",
        "c2s_mac",
        "s2c_mac",
        "c2s_comp",
        "s2c_comp",
        "c2s_lang",
        "s2c_lang",
    )

    def encode(self, writer: SSHWriter) -> None:
        if len(self.cookie) != 16:
            raise ProtocolError("KEXINIT cookie must have 16 bytes")
        writer.write(self.cookie)
        writer.writelstr(self.kex_algorithms, "ascii")
        writer.writelstr(self.hostkey_algorithms, "ascii")
        writer.writelstr(self.c2s_encryption, "ascii")
        writer.writelstr(self.s2c_encryption, "ascii")
        writer.writelstr(self.c2s_mac, "ascii")
        writer.writelstr(self.s2c_mac, "ascii")
        writer.writelstr(self.c2s_comp, "ascii")
        writer.writelstr(self.s2c_comp, "ascii")
        writer.writelstr(self.c2s_lang, "ascii")
        writer.writelstr(self.s2c_lang, "ascii")
        writer.writeboolean(self.kexfollows)
        writer.write32be(self.reserved)

    def decode(self, reader: SSHReader) -> None:
        self.cookie = reader.read(16)
        self.kex_algorithms = reader.readlstr("ascii")
        self.hostkey_algorithms = reader.readlstr("ascii")
        self.c2s_encryption = reader.readlstr("ascii")
        self.s2c_encryption = reader.readlstr("ascii")
        self.c2s_mac = reader.readlstr("ascii")
        self.s2c_mac = reader.readlstr("ascii")
        self.c2s_comp = reader.readlstr("ascii")
        self.s2c_comp = reader.readlstr("ascii")
        self.c2s_lang = reader.readlstr("ascii")
        self.s2c_lang = reader.readlstr("ascii")
        self.kexfollows = reader.readboolean()
        self.reserved = reader.read32be()
        for name in self.list_fields:
            value: str = getattr(self, name)
            if value and any(not item or any(ord(c) < 33 or ord(c) > 126 for c in item) for item in value.split(",")):
                raise ProtocolError("malformed algorithm name-list")

    @classmethod
    def proposal(cls, server: bool, curve_only: bool = False) -> Msg20_KexInit:
        result = cls()
        if curve_only:
            result.kex_algorithms = KEX_CURVE
        side = "s" if server else "c"
        result.kex_algorithms += f",kex-strict-{side}-v00@openssh.com"
        return result


class Msg21_NewKeys(EmptyMessage):
    msgtype: ClassVar[int] = 21


@dataclass
class Msg30_ECDHInit(SshPacket):
    """Also the outer format of SSH_MSG_KEX_HYBRID_INIT."""

    msgtype: ClassVar[int] = 30
    pubkey: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.writeldata(self.pubkey)

    def decode(self, reader: SSHReader) -> None:
        self.pubkey = reader.readldata()


@dataclass
class HostKey(WireObject):
    algorithm: str = "ssh-ed25519"
    key: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.writelstr(self.algorithm)
        writer.writeldata(self.key)

    def decode(self, reader: SSHReader) -> None:
        self.algorithm = reader.readlstr()
        self.key = reader.readldata()
        if self.algorithm != "ssh-ed25519" or len(self.key) != 32:
            raise ProtocolError("only 32-byte ssh-ed25519 host keys supported")

    def fingerprint(self) -> str:
        digest = hashlib.sha256(encode_object(self)).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")

    def openssh(self) -> bytes:
        return b"ssh-ed25519 " + base64.b64encode(encode_object(self))

    @classmethod
    def from_public_file(cls, path: Path) -> HostKey:
        key = serialization.load_ssh_public_key(path.read_bytes())
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise HostKeyError("the pinned public key must be Ed25519")
        return cls("ssh-ed25519", key.public_bytes_raw())


@dataclass
class Signature(WireObject):
    algorithm: str = "ssh-ed25519"
    data: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.writelstr(self.algorithm)
        writer.writeldata(self.data)

    def decode(self, reader: SSHReader) -> None:
        self.algorithm = reader.readlstr()
        self.data = reader.readldata()

    def require_ed25519(self) -> None:
        if self.algorithm != "ssh-ed25519" or len(self.data) != 64:
            raise ProtocolError("invalid Ed25519 signature blob")


@dataclass
class Msg31_ECDHReply(SshPacket):
    """Three SSH strings; the host-key and signature strings have inner fields."""

    msgtype: ClassVar[int] = 31
    hostkey: HostKey = field(default_factory=HostKey)
    pubkey: bytes = b""
    signature: Signature = field(default_factory=Signature)

    def encode(self, writer: SSHWriter) -> None:
        writer.writeldata(encode_object(self.hostkey))
        writer.writeldata(self.pubkey)
        writer.writeldata(encode_object(self.signature))

    def decode(self, reader: SSHReader) -> None:
        self.hostkey = decode_object(HostKey(), reader.readldata())
        self.pubkey = reader.readldata()
        self.signature = decode_object(Signature(), reader.readldata())
        self.signature.require_ed25519()


@dataclass
class HybridInit(WireObject):
    kem_public: bytes = b""
    x25519_public: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        if len(self.kem_public) != 1184 or len(self.x25519_public) != 32:
            raise ProtocolError("invalid hybrid client key lengths")
        writer.write(self.kem_public)
        writer.write(self.x25519_public)

    def decode(self, reader: SSHReader) -> None:
        self.kem_public = reader.read(1184)
        self.x25519_public = reader.read(32)


@dataclass
class HybridReply(WireObject):
    kem_ciphertext: bytes = b""
    x25519_public: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        if len(self.kem_ciphertext) != 1088 or len(self.x25519_public) != 32:
            raise ProtocolError("invalid hybrid server key lengths")
        writer.write(self.kem_ciphertext)
        writer.write(self.x25519_public)

    def decode(self, reader: SSHReader) -> None:
        self.kem_ciphertext = reader.read(1088)
        self.x25519_public = reader.read(32)


class AuthMethod(WireObject):
    @property
    def name(self) -> str:
        raise NotImplementedError


class NoneAuth(AuthMethod):
    name = "none"

    def encode(self, writer: SSHWriter) -> None:
        pass

    def decode(self, reader: SSHReader) -> None:
        pass


@dataclass
class PasswordAuth(AuthMethod):
    name: ClassVar[str] = "password"
    change: bool = False
    password: bytes = field(default=b"", repr=False)
    new_password: bytes = field(default=b"", repr=False)

    def encode(self, writer: SSHWriter) -> None:
        writer.writeboolean(self.change)
        writer.writeldata(self.password)
        if self.change:
            writer.writeldata(self.new_password)

    def decode(self, reader: SSHReader) -> None:
        self.change = reader.readboolean()
        self.password = reader.readldata()
        self.new_password = reader.readldata() if self.change else b""


@dataclass
class PublicKeyAuth(AuthMethod):
    name: ClassVar[str] = "publickey"
    signed: bool = False
    algorithm: str = "ssh-ed25519"
    public_key: bytes = b""
    signature: Signature | None = None

    def encode_fields(self, writer: SSHWriter) -> None:
        writer.writeboolean(self.signed)
        writer.writelstr(self.algorithm)
        writer.writeldata(self.public_key)

    def encode(self, writer: SSHWriter) -> None:
        self.encode_fields(writer)
        if self.signed:
            if self.signature is None:
                raise ProtocolError("signed public-key request needs a signature")
            writer.writeldata(encode_object(self.signature))

    def decode(self, reader: SSHReader) -> None:
        self.signed = reader.readboolean()
        self.algorithm = reader.readlstr()
        self.public_key = reader.readldata()
        self.signature = decode_object(Signature(), reader.readldata()) if self.signed else None


@dataclass
class UnknownAuth(AuthMethod):
    """Unsupported method-specific fields are preserved and rejected."""

    name: str = ""
    data: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write(self.data)

    def decode(self, reader: SSHReader) -> None:
        self.data = reader.read(reader.remaining())


@dataclass
class Msg50_UserAuthRequest(SshPacket):
    msgtype: ClassVar[int] = 50
    username: str = ""
    service: str = "ssh-connection"
    method: AuthMethod = field(default_factory=NoneAuth)

    def encode_header(self, writer: SSHWriter) -> None:
        writer.writelstr(self.username)
        writer.writelstr(self.service)
        writer.writelstr(self.method.name)

    def encode(self, writer: SSHWriter) -> None:
        self.encode_header(writer)
        self.method.encode(writer)

    def decode(self, reader: SSHReader) -> None:
        self.username = reader.readlstr()
        self.service = reader.readlstr()
        name = reader.readlstr()
        methods: dict[str, type[AuthMethod]] = {"none": NoneAuth, "password": PasswordAuth, "publickey": PublicKeyAuth}
        self.method = methods[name]() if name in methods else UnknownAuth(name)
        self.method.decode(reader)

    def signature_input(self, session_id: bytes) -> bytes:
        if not isinstance(self.method, PublicKeyAuth) or not self.method.signed:
            raise ProtocolError("signature input requires a signed public-key request")
        writer = SSHWriter()
        writer.writeldata(session_id)
        writer.writebyte(self.msgtype)
        self.encode_header(writer)
        self.method.encode_fields(writer)
        return writer.getvalue()


@dataclass
class Msg51_UserAuthFailure(SshPacket):
    msgtype: ClassVar[int] = 51
    methods: str = ""
    partial: bool = False

    def encode(self, writer: SSHWriter) -> None:
        writer.writelstr(self.methods)
        writer.writeboolean(self.partial)

    def decode(self, reader: SSHReader) -> None:
        self.methods = reader.readlstr()
        self.partial = reader.readboolean()


class Msg52_UserAuthSuccess(EmptyMessage):
    msgtype: ClassVar[int] = 52


@dataclass
class Msg53_UserAuthBanner(SshPacket):
    msgtype: ClassVar[int] = 53
    message: str = ""
    language: str = ""

    def encode(self, writer: SSHWriter) -> None:
        writer.writelstr(self.message)
        writer.writelstr(self.language)

    def decode(self, reader: SSHReader) -> None:
        self.message = reader.readlstr()
        self.language = reader.readlstr()


@dataclass
class Msg60_UserAuthPKOK(SshPacket):
    msgtype: ClassVar[int] = 60
    algorithm: str = "ssh-ed25519"
    public_key: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.writelstr(self.algorithm)
        writer.writeldata(self.public_key)

    def decode(self, reader: SSHReader) -> None:
        self.algorithm = reader.readlstr()
        self.public_key = reader.readldata()


class PublicKeyFields(WireObject):
    """Public key parameters; decoding support does not enable authentication."""


@dataclass
class RSAPublicKeyFields(PublicKeyFields):
    exponent: int = 0
    modulus: int = 0

    def encode(self, writer: SSHWriter) -> None:
        writer.writempint(self.exponent)
        writer.writempint(self.modulus)

    def decode(self, reader: SSHReader) -> None:
        self.exponent = reader.readmpint()
        self.modulus = reader.readmpint()
        if self.exponent <= 0 or self.modulus <= 0:
            raise ProtocolError("RSA public parameters must be positive")


@dataclass
class ECDSAPublicKeyFields(PublicKeyFields):
    curve: str = "nistp256"
    point: bytes = b""
    curves: ClassVar[dict[str, type[ec.EllipticCurve]]] = {"nistp256": ec.SECP256R1, "nistp384": ec.SECP384R1, "nistp521": ec.SECP521R1}

    def encode(self, writer: SSHWriter) -> None:
        writer.writelstr(self.curve, "ascii")
        writer.writeldata(self.point)

    def decode(self, reader: SSHReader) -> None:
        self.curve = reader.readlstr("ascii")
        self.point = reader.readldata()
        self.public_numbers()  # Validate the named curve and SEC1 point encoding.

    def public_numbers(self) -> ec.EllipticCurvePublicNumbers:
        if self.curve not in self.curves:
            raise ProtocolError(f"unsupported ECDSA named curve: {self.curve}")
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(self.curves[self.curve](), self.point)
        except ValueError as exc:
            raise ProtocolError("invalid ECDSA public point") from exc
        return key.public_numbers()


@dataclass
class Ed25519PublicKeyFields(PublicKeyFields):
    key: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.writeldata(self.key)

    def decode(self, reader: SSHReader) -> None:
        self.key = reader.readldata()
        if len(self.key) != 32:
            raise ProtocolError("Ed25519 public key must have 32 bytes")


@dataclass
class OpaquePublicKeyFields(PublicKeyFields):
    """Unrecognized algorithm/certificate parameters, retained byte-for-byte."""

    undecoded: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write(self.undecoded)

    def decode(self, reader: SSHReader) -> None:
        self.undecoded = reader.read(reader.remaining())


@dataclass
class AdvertisedHostKey(WireObject):
    algorithm: str = ""
    parameters: PublicKeyFields = field(default_factory=OpaquePublicKeyFields)

    def encode(self, writer: SSHWriter) -> None:
        writer.writelstr(self.algorithm, "ascii")
        self.parameters.encode(writer)

    def decode(self, reader: SSHReader) -> None:
        self.algorithm = reader.readlstr("ascii")
        if self.algorithm == "ssh-rsa":
            self.parameters = RSAPublicKeyFields()
        elif self.algorithm in ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"):
            self.parameters = ECDSAPublicKeyFields()
        elif self.algorithm == "ssh-ed25519":
            self.parameters = Ed25519PublicKeyFields()
        else:
            self.parameters = OpaquePublicKeyFields()
        self.parameters.decode(reader)
        if isinstance(self.parameters, ECDSAPublicKeyFields) and self.algorithm != "ecdsa-sha2-" + self.parameters.curve:
            raise ProtocolError("ECDSA key algorithm and named curve do not match")

    def fingerprint(self) -> str:
        digest = hashlib.sha256(encode_object(self)).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")

    def bits(self) -> int | None:
        if isinstance(self.parameters, RSAPublicKeyFields):
            return self.parameters.modulus.bit_length()
        if isinstance(self.parameters, ECDSAPublicKeyFields):
            return self.parameters.curves[self.parameters.curve]().key_size
        if isinstance(self.parameters, Ed25519PublicKeyFields):
            return 256
        return None


class GlobalRequestData(WireObject):
    """Fields following the global-request name and want-reply flag."""


@dataclass
class HostKeysRequestData(GlobalRequestData):
    """A sequence of SSH strings extending to the end of the request; no count."""

    keys: tuple[AdvertisedHostKey, ...] = ()

    def encode(self, writer: SSHWriter) -> None:
        for key in self.keys:
            writer.writeldata(encode_object(key))

    def decode(self, reader: SSHReader) -> None:
        keys: list[AdvertisedHostKey] = []
        while reader.remaining():
            keys.append(decode_object(AdvertisedHostKey(), reader.readldata()))
        self.keys = tuple(keys)


@dataclass
class OpaqueGlobalRequestData(GlobalRequestData):
    """Unsupported request-specific payload, explicitly retained as undecoded."""

    undecoded: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write(self.undecoded)

    def decode(self, reader: SSHReader) -> None:
        self.undecoded = reader.read(reader.remaining())


@dataclass
class Msg80_GlobalRequest(SshPacket):
    msgtype: ClassVar[int] = 80
    name: str = ""
    want_reply: bool = False
    data: GlobalRequestData | bytes = field(default_factory=OpaqueGlobalRequestData)
    hostkey_requests: ClassVar[tuple[str, ...]] = ("hostkeys-00@openssh.com", "hostkeys-prove-00@openssh.com")

    def encode(self, writer: SSHWriter) -> None:
        writer.writelstr(self.name)
        writer.writeboolean(self.want_reply)
        if isinstance(self.data, bytes):
            writer.write(self.data)  # Compatibility for callers supplying an encoded body.
        else:
            self.data.encode(writer)

    def decode(self, reader: SSHReader) -> None:
        self.name = reader.readlstr()
        self.want_reply = reader.readboolean()
        self.data = HostKeysRequestData() if self.name in self.hostkey_requests else OpaqueGlobalRequestData()
        self.data.decode(reader)


@dataclass
class Msg81_RequestSuccess(SshPacket):
    """Success data depends on the originating global request; retained opaque."""

    msgtype: ClassVar[int] = 81
    data: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write(self.data)

    def decode(self, reader: SSHReader) -> None:
        self.data = reader.read(reader.remaining())


class Msg82_RequestFailure(EmptyMessage):
    msgtype: ClassVar[int] = 82


@dataclass
class Msg90_ChannelOpen(SshPacket):
    msgtype: ClassVar[int] = 90
    channel_type: str = "session"
    sender: int = 0
    window: int = CHANNEL_WINDOW
    max_packet: int = CHANNEL_PACKET
    extra: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.writelstr(self.channel_type)
        writer.write32be(self.sender)
        writer.write32be(self.window)
        writer.write32be(self.max_packet)
        writer.write(self.extra)

    def decode(self, reader: SSHReader) -> None:
        self.channel_type = reader.readlstr()
        self.sender = reader.read32be()
        self.window = reader.read32be()
        self.max_packet = reader.read32be()
        self.extra = reader.read(reader.remaining())
        if self.channel_type == "session" and self.extra:
            raise ProtocolError("unexpected session channel-open data")


@dataclass
class Msg91_ChannelOpenConfirmation(SshPacket):
    msgtype: ClassVar[int] = 91
    recipient: int = 0
    sender: int = 0
    window: int = CHANNEL_WINDOW
    max_packet: int = CHANNEL_PACKET
    extra: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.recipient)
        writer.write32be(self.sender)
        writer.write32be(self.window)
        writer.write32be(self.max_packet)
        writer.write(self.extra)

    def decode(self, reader: SSHReader) -> None:
        self.recipient = reader.read32be()
        self.sender = reader.read32be()
        self.window = reader.read32be()
        self.max_packet = reader.read32be()
        self.extra = reader.read(reader.remaining())


@dataclass
class Msg92_ChannelOpenFailure(SshPacket):
    msgtype: ClassVar[int] = 92
    recipient: int = 0
    reason: int = 1
    description: str = ""
    language: str = ""

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.recipient)
        writer.write32be(self.reason)
        writer.writelstr(self.description)
        writer.writelstr(self.language)

    def decode(self, reader: SSHReader) -> None:
        self.recipient = reader.read32be()
        self.reason = reader.read32be()
        self.description = reader.readlstr()
        self.language = reader.readlstr()


class ChannelMessage(SshPacket):
    recipient: int


@dataclass
class Msg93_ChannelWindowAdjust(ChannelMessage):
    msgtype: ClassVar[int] = 93
    recipient: int = 0
    adjustment: int = 0

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.recipient)
        writer.write32be(self.adjustment)

    def decode(self, reader: SSHReader) -> None:
        self.recipient = reader.read32be()
        self.adjustment = reader.read32be()


@dataclass
class Msg94_ChannelData(ChannelMessage):
    msgtype: ClassVar[int] = 94
    recipient: int = 0
    data: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.recipient)
        writer.writeldata(self.data)

    def decode(self, reader: SSHReader) -> None:
        self.recipient = reader.read32be()
        self.data = reader.readldata()


@dataclass
class Msg95_ChannelExtendedData(ChannelMessage):
    msgtype: ClassVar[int] = 95
    recipient: int = 0
    stream: int = 1
    data: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.recipient)
        writer.write32be(self.stream)
        writer.writeldata(self.data)

    def decode(self, reader: SSHReader) -> None:
        self.recipient = reader.read32be()
        self.stream = reader.read32be()
        self.data = reader.readldata()


@dataclass
class RecipientMessage(ChannelMessage):
    recipient: int = 0

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.recipient)

    def decode(self, reader: SSHReader) -> None:
        self.recipient = reader.read32be()


class Msg96_ChannelEOF(RecipientMessage):
    msgtype: ClassVar[int] = 96


class Msg97_ChannelClose(RecipientMessage):
    msgtype: ClassVar[int] = 97


class RequestBody(WireObject):
    @property
    def name(self) -> str:
        raise NotImplementedError


@dataclass
class TerminalMode(WireObject):
    """One terminal opcode and, for opcodes 1..159, its uint32 argument."""

    opcode: int = 0
    value: int | None = None
    names: ClassVar[dict[int, str]] = {
        0: "TTY_OP_END",
        1: "VINTR",
        2: "VQUIT",
        3: "VERASE",
        4: "VKILL",
        5: "VEOF",
        6: "VEOL",
        7: "VEOL2",
        8: "VSTART",
        9: "VSTOP",
        10: "VSUSP",
        11: "VDSUSP",
        12: "VREPRINT",
        13: "VWERASE",
        14: "VLNEXT",
        15: "VFLUSH",
        16: "VSWTCH",
        17: "VSTATUS",
        18: "VDISCARD",
        30: "IGNPAR",
        31: "PARMRK",
        32: "INPCK",
        33: "ISTRIP",
        34: "INLCR",
        35: "IGNCR",
        36: "ICRNL",
        37: "IUCLC",
        38: "IXON",
        39: "IXANY",
        40: "IXOFF",
        41: "IMAXBEL",
        42: "IUTF8",
        50: "ISIG",
        51: "ICANON",
        52: "XCASE",
        53: "ECHO",
        54: "ECHOE",
        55: "ECHOK",
        56: "ECHONL",
        57: "NOFLSH",
        58: "TOSTOP",
        59: "IEXTEN",
        60: "ECHOCTL",
        61: "ECHOKE",
        62: "PENDIN",
        70: "OPOST",
        71: "OLCUC",
        72: "ONLCR",
        73: "OCRNL",
        74: "ONOCR",
        75: "ONLRET",
        90: "CS7",
        91: "CS8",
        92: "PARENB",
        93: "PARODD",
        128: "TTY_OP_ISPEED",
        129: "TTY_OP_OSPEED",
    }

    @property
    def name(self) -> str:
        unknown = "UNKNOWN_STOP_OPCODE" if self.is_stop() else "UNKNOWN_TERMINAL_MODE"
        return self.names.get(self.opcode, f"{unknown}_{self.opcode}")

    def is_stop(self) -> bool:
        return self.opcode == 0 or self.opcode >= 160

    def encode(self, writer: SSHWriter) -> None:
        if not 0 <= self.opcode <= 255:
            raise ProtocolError("terminal opcode must fit in a byte")
        if self.is_stop() != (self.value is None):
            raise ProtocolError("terminal argument required only for opcodes 1..159")
        writer.writebyte(self.opcode)
        if self.value is not None:
            writer.write32be(self.value)

    def decode(self, reader: SSHReader) -> None:
        self.opcode = reader.readbyte()
        self.value = None if self.is_stop() else reader.read32be()

    def description(self) -> str:
        text = f"{self.name} (opcode={self.opcode})"
        if self.value is None:
            return text
        text += f" value={self.value} (0x{self.value:x})"
        if 1 <= self.opcode <= 18 and self.value <= 255:
            character = "disabled" if self.value == 255 else self._character(self.value)
            text += f" [{character}]"
        return text

    @staticmethod
    def _character(value: int) -> str:
        if value < 32:
            return "^" + chr(value + 64)
        return "^?" if value == 127 else repr(bytes([value]))


@dataclass
class TerminalModes(WireObject):
    """Ordered modes including the stop opcode; retain any bytes after it."""

    entries: tuple[TerminalMode, ...] = ()
    undecoded: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        if self.entries and not self.entries[-1].is_stop():
            raise ProtocolError("terminal modes missing stop opcode")
        if not self.entries and self.undecoded:
            raise ProtocolError("undecoded terminal bytes require a stop opcode")
        for index, entry in enumerate(self.entries):
            if entry.is_stop() and index != len(self.entries) - 1:
                raise ProtocolError("terminal entries after stop opcode")
            entry.encode(writer)
        writer.write(self.undecoded)

    def decode(self, reader: SSHReader) -> None:
        entries: list[TerminalMode] = []
        self.entries = ()
        self.undecoded = b""
        while reader.remaining():
            entry = TerminalMode()
            entry.decode(reader)
            entries.append(entry)
            if entry.is_stop():
                self.entries = tuple(entries)
                self.undecoded = reader.read(reader.remaining())
                return
        if entries:
            raise ProtocolError("terminal modes missing stop opcode")


@dataclass
class PtyRequest(RequestBody):
    name: ClassVar[str] = "pty-req"
    terminal: bytes = b""
    columns: int = 0
    rows: int = 0
    width_pixels: int = 0
    height_pixels: int = 0
    modes: TerminalModes = field(default_factory=TerminalModes)

    def encode(self, writer: SSHWriter) -> None:
        writer.writeldata(self.terminal)
        writer.write32be(self.columns)
        writer.write32be(self.rows)
        writer.write32be(self.width_pixels)
        writer.write32be(self.height_pixels)
        writer.writeldata(encode_object(self.modes))

    def decode(self, reader: SSHReader) -> None:
        self.terminal = reader.readldata()
        self.columns = reader.read32be()
        self.rows = reader.read32be()
        self.width_pixels = reader.read32be()
        self.height_pixels = reader.read32be()
        self.modes = decode_object(TerminalModes(), reader.readldata())


@dataclass
class EnvRequest(RequestBody):
    name: ClassVar[str] = "env"
    variable: bytes = b""
    value: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.writeldata(self.variable)
        writer.writeldata(self.value)

    def decode(self, reader: SSHReader) -> None:
        self.variable = reader.readldata()
        self.value = reader.readldata()


@dataclass
class SubsystemRequest(RequestBody):
    name: ClassVar[str] = "subsystem"
    subsystem: str = ""

    def encode(self, writer: SSHWriter) -> None:
        writer.writelstr(self.subsystem)

    def decode(self, reader: SSHReader) -> None:
        self.subsystem = reader.readlstr()


@dataclass
class WindowChangeRequest(RequestBody):
    name: ClassVar[str] = "window-change"
    columns: int = 0
    rows: int = 0
    width_pixels: int = 0
    height_pixels: int = 0

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.columns)
        writer.write32be(self.rows)
        writer.write32be(self.width_pixels)
        writer.write32be(self.height_pixels)

    def decode(self, reader: SSHReader) -> None:
        self.columns = reader.read32be()
        self.rows = reader.read32be()
        self.width_pixels = reader.read32be()
        self.height_pixels = reader.read32be()


class ShellRequest(RequestBody):
    name = "shell"

    def encode(self, writer: SSHWriter) -> None:
        pass

    def decode(self, reader: SSHReader) -> None:
        pass


@dataclass
class ExecRequest(RequestBody):
    name: ClassVar[str] = "exec"
    command: str = ""

    def encode(self, writer: SSHWriter) -> None:
        writer.writelstr(self.command)

    def decode(self, reader: SSHReader) -> None:
        self.command = reader.readlstr()


@dataclass
class SignalRequest(RequestBody):
    name: ClassVar[str] = "signal"
    signal: str = ""

    def encode(self, writer: SSHWriter) -> None:
        writer.writelstr(self.signal)

    def decode(self, reader: SSHReader) -> None:
        self.signal = reader.readlstr()


@dataclass
class ExitStatusRequest(RequestBody):
    name: ClassVar[str] = "exit-status"
    status: int = 0

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.status)

    def decode(self, reader: SSHReader) -> None:
        self.status = reader.read32be()


@dataclass
class ExitSignalRequest(RequestBody):
    name: ClassVar[str] = "exit-signal"
    signal: str = ""
    core_dumped: bool = False
    description: str = ""
    language: str = ""

    def encode(self, writer: SSHWriter) -> None:
        writer.writelstr(self.signal)
        writer.writeboolean(self.core_dumped)
        writer.writelstr(self.description)
        writer.writelstr(self.language)

    def decode(self, reader: SSHReader) -> None:
        self.signal = reader.readlstr()
        self.core_dumped = reader.readboolean()
        self.description = reader.readlstr()
        self.language = reader.readlstr()


@dataclass
class OpaqueRequest(RequestBody):
    """Unsupported request-specific fields, retained for explicit rejection."""

    name: str = ""
    data: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write(self.data)

    def decode(self, reader: SSHReader) -> None:
        self.data = reader.read(reader.remaining())


@dataclass
class Msg98_ChannelRequest(ChannelMessage):
    msgtype: ClassVar[int] = 98
    recipient: int = 0
    request: RequestBody = field(default_factory=ShellRequest)
    want_reply: bool = True

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.recipient)
        writer.writelstr(self.request.name)
        writer.writeboolean(self.want_reply)
        self.request.encode(writer)

    def decode(self, reader: SSHReader) -> None:
        self.recipient = reader.read32be()
        name = reader.readlstr()
        self.want_reply = reader.readboolean()
        requests: dict[str, type[RequestBody]] = {
            "pty-req": PtyRequest,
            "env": EnvRequest,
            "subsystem": SubsystemRequest,
            "window-change": WindowChangeRequest,
            "shell": ShellRequest,
            "exec": ExecRequest,
            "signal": SignalRequest,
            "exit-status": ExitStatusRequest,
            "exit-signal": ExitSignalRequest,
        }
        self.request = requests[name]() if name in requests else OpaqueRequest(name)
        self.request.decode(reader)


class Msg99_ChannelSuccess(RecipientMessage):
    msgtype: ClassVar[int] = 99


class Msg100_ChannelFailure(RecipientMessage):
    msgtype: ClassVar[int] = 100


MESSAGE_CLASSES: tuple[type[SshPacket], ...] = (
    Msg1_Disconnect,
    Msg2_Ignore,
    Msg3_Unimplemented,
    Msg4_Debug,
    Msg5_ServiceRequest,
    Msg6_ServiceAccept,
    Msg20_KexInit,
    Msg21_NewKeys,
    Msg30_ECDHInit,
    Msg31_ECDHReply,
    Msg50_UserAuthRequest,
    Msg51_UserAuthFailure,
    Msg52_UserAuthSuccess,
    Msg53_UserAuthBanner,
    Msg60_UserAuthPKOK,
    Msg80_GlobalRequest,
    Msg81_RequestSuccess,
    Msg82_RequestFailure,
    Msg90_ChannelOpen,
    Msg91_ChannelOpenConfirmation,
    Msg92_ChannelOpenFailure,
    Msg93_ChannelWindowAdjust,
    Msg94_ChannelData,
    Msg95_ChannelExtendedData,
    Msg96_ChannelEOF,
    Msg97_ChannelClose,
    Msg98_ChannelRequest,
    Msg99_ChannelSuccess,
    Msg100_ChannelFailure,
)
MESSAGE_TYPES: dict[int, type[SshPacket]] = {cls().msgtype: cls for cls in MESSAGE_CLASSES}


def encode_message(packet: SshPacket) -> bytes:
    writer = SSHWriter()
    writer.writebyte(packet.msgtype)
    packet.encode(writer)
    return writer.getvalue()


def decode_message(reader: SSHReader) -> SshPacket:
    msgtype = reader.readbyte()
    packet = MESSAGE_TYPES[msgtype]() if msgtype in MESSAGE_TYPES else RawPacket(msgtype)
    packet.decode(reader)
    reader.finish()
    return packet


@dataclass
class SSH2Frame(WireObject):
    """Transport header, message-type byte/body, and padding in wire order."""

    packet: SshPacket = field(default_factory=Msg21_NewKeys)
    padding: bytes = b""
    header_size: int = 5

    @property
    def packet_length(self) -> int:
        return 1 + len(encode_message(self.packet)) + len(self.padding)

    def encode(self, writer: SSHWriter) -> None:
        payload = encode_message(self.packet)
        if not self.padding:
            self.padding = os.urandom(padding_size(len(payload), header_size=self.header_size))
        writer.write32be(1 + len(payload) + len(self.padding))
        writer.writebyte(len(self.padding))
        writer.write(payload)
        writer.write(self.padding)

    def decode(self, reader: SSHReader) -> None:
        length = reader.read32be()
        padding_length = reader.readbyte()
        if length > MAX_PACKET or length < (12 if self.header_size == 5 else 8) or length - 1 > reader.remaining():
            raise ProtocolError("invalid or truncated SSH frame length")
        if (length + self.header_size - 1) % 8:
            raise ProtocolError("unaligned SSH frame")
        if padding_length < 4 or padding_length + 2 > length:
            raise ProtocolError("invalid SSH padding length")
        payload = reader.read(length - padding_length - 1)
        self.packet = decode_message(SSHReader(payload))
        self.padding = reader.read(padding_length)


@dataclass
class EncryptedData(WireObject):
    """Opaque ciphertext; encrypted message boundaries are unknown."""

    data: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write(self.data)

    def decode(self, reader: SSHReader) -> None:
        self.data = reader.read(reader.remaining())


@dataclass
class Banner(WireObject):
    """Preserved server pre-identification line; not part of the KEX hash."""

    data: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write(self.data)

    def decode(self, reader: SSHReader) -> None:
        self.data = reader.readuntil(b"\n")


@dataclass(frozen=True)
class Algorithms:
    kex: str
    hostkey: str
    c2s_cipher: str
    s2c_cipher: str
    c2s_mac: str
    s2c_mac: str
    c2s_comp: str
    s2c_comp: str
    strict: bool

    @staticmethod
    def choose(client: str, server: str) -> str:
        offered = server.split(",")
        for name in client.split(","):
            if name and not name.startswith(("ext-info-", "kex-strict-")):
                if name in offered:
                    return name
        raise ProtocolError("no mutually supported algorithm")

    @classmethod
    def negotiate(cls, client: Msg20_KexInit, server: Msg20_KexInit) -> Algorithms:
        choose = cls.choose
        c2s = choose(client.c2s_encryption, server.c2s_encryption)
        s2c = choose(client.s2c_encryption, server.s2c_encryption)
        return cls(
            choose(client.kex_algorithms, server.kex_algorithms),
            choose(client.hostkey_algorithms, server.hostkey_algorithms),
            c2s,
            s2c,
            "implicit" if c2s == CIPHER else choose(client.c2s_mac, server.c2s_mac),
            "implicit" if s2c == CIPHER else choose(client.s2c_mac, server.s2c_mac),
            choose(client.c2s_comp, server.c2s_comp),
            choose(client.s2c_comp, server.s2c_comp),
            "kex-strict-c-v00@openssh.com" in client.kex_algorithms.split(",") and "kex-strict-s-v00@openssh.com" in server.kex_algorithms.split(","),
        )

    def require_supported(self) -> None:
        if (
            self.kex not in (KEX_HYBRID, KEX_CURVE)
            or self.hostkey != "ssh-ed25519"
            or self.c2s_cipher != CIPHER
            or self.s2c_cipher != CIPHER
            or self.c2s_comp != "none"
            or self.s2c_comp != "none"
        ):
            raise ProtocolError(f"unsupported negotiated suite: {self}")


@dataclass(frozen=True)
class TranscriptEvent:
    direction: str
    offset: int
    value: Hello | SSH2Frame | EncryptedData | Banner


class TranscriptStream:
    def __init__(self, direction: str):
        if direction not in ("<", ">"):
            raise ValueError("direction must be < or >")
        self.direction = direction
        self.buffer = bytearray()
        self.offset = 0
        self.identified = False
        self.encrypted = False

    def _take(self, count: int) -> bytes:
        data = bytes(self.buffer[:count])
        del self.buffer[:count]
        self.offset += count
        return data

    def feed(self, data: bytes) -> tuple[TranscriptEvent, ...]:
        self.buffer.extend(data)
        events: list[TranscriptEvent] = []
        while self.buffer:
            start = self.offset
            value = self._next()
            if value is None:
                break
            events.append(TranscriptEvent(self.direction, start, value))
        return tuple(events)

    def _next(self) -> Hello | SSH2Frame | EncryptedData | Banner | None:
        if self.encrypted:
            return EncryptedData(self._take(len(self.buffer)))
        if not self.identified:
            end = self.buffer.find(b"\n")
            if end < 0:
                if len(self.buffer) > 255:
                    raise ProtocolError("identification line too long")
                return None
            line = self._take(end + 1)
            if not line.startswith(b"SSH-"):
                return Banner(line)
            self.identified = True
            return decode_object(Hello(), line)
        if len(self.buffer) < 4:
            return None
        length = SSHReader(bytes(self.buffer[:4])).read32be()
        if length < 12 or length > MAX_PACKET:
            raise ProtocolError("invalid plaintext frame length")
        if len(self.buffer) < length + 4:
            return None
        frame = decode_object(SSH2Frame(), self._take(length + 4))
        self.encrypted = frame.packet.msgtype == 21
        return frame

    def finish(self) -> None:
        if self.buffer or not self.identified:
            raise ProtocolError("truncated identification or plaintext packet")


def decode_transcript(text: str) -> tuple[TranscriptEvent, ...]:
    client, server = TranscriptStream(">"), TranscriptStream("<")
    result: list[TranscriptEvent] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0] not in ("<", ">"):
            raise ProtocolError(f"line {number}: expected a direction marker")
        stream = client if line[0] == ">" else server
        try:
            result.extend(stream.feed(bytes.fromhex(line[1:])))
        except (ValueError, EOFError) as exc:
            raise ProtocolError(f"line {number}: {exc}") from exc
    client.finish()
    server.finish()
    return tuple(result)


MESSAGE_NAMES: dict[int, str] = {
    1: "SSH_MSG_DISCONNECT",
    2: "SSH_MSG_IGNORE",
    3: "SSH_MSG_UNIMPLEMENTED",
    4: "SSH_MSG_DEBUG",
    5: "SSH_MSG_SERVICE_REQUEST",
    6: "SSH_MSG_SERVICE_ACCEPT",
    20: "SSH_MSG_KEXINIT",
    21: "SSH_MSG_NEWKEYS",
    30: "SSH_MSG_KEX_ECDH_INIT",
    31: "SSH_MSG_KEX_ECDH_REPLY",
    50: "SSH_MSG_USERAUTH_REQUEST",
    51: "SSH_MSG_USERAUTH_FAILURE",
    52: "SSH_MSG_USERAUTH_SUCCESS",
    53: "SSH_MSG_USERAUTH_BANNER",
    60: "SSH_MSG_USERAUTH_PK_OK",
    80: "SSH_MSG_GLOBAL_REQUEST",
    81: "SSH_MSG_REQUEST_SUCCESS",
    82: "SSH_MSG_REQUEST_FAILURE",
    90: "SSH_MSG_CHANNEL_OPEN",
    91: "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
    92: "SSH_MSG_CHANNEL_OPEN_FAILURE",
    93: "SSH_MSG_CHANNEL_WINDOW_ADJUST",
    94: "SSH_MSG_CHANNEL_DATA",
    95: "SSH_MSG_CHANNEL_EXTENDED_DATA",
    96: "SSH_MSG_CHANNEL_EOF",
    97: "SSH_MSG_CHANNEL_CLOSE",
    98: "SSH_MSG_CHANNEL_REQUEST",
    99: "SSH_MSG_CHANNEL_SUCCESS",
    100: "SSH_MSG_CHANNEL_FAILURE",
}


@dataclass
class SftpExtension(WireObject):
    name: bytes = b""
    data: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.writeldata(self.name)
        writer.writeldata(self.data)

    def decode(self, reader: SSHReader) -> None:
        self.name = reader.readldata()
        self.data = reader.readldata()


@dataclass
class SftpAttributes(WireObject):
    flags: int = 0
    size: int | None = None
    uid: int | None = None
    gid: int | None = None
    permissions: int | None = None
    atime: int | None = None
    mtime: int | None = None
    extensions: tuple[SftpExtension, ...] = ()
    flag_fields: ClassVar[tuple[tuple[int, str, bool], ...]] = (
        (1, "size", True),
        (2, "uid", False),
        (2, "gid", False),
        (4, "permissions", False),
        (8, "atime", False),
        (8, "mtime", False),
    )

    def encode(self, writer: SSHWriter) -> None:
        if self.flags & ~0x8000000F:
            raise ProtocolError("unknown SFTP attribute flags")
        writer.write32be(self.flags)
        for flag, name, wide in self.flag_fields:
            if self.flags & flag:
                value: int | None = getattr(self, name)
                if value is None:
                    raise ProtocolError(f"SFTP attributes missing {name}")
                if wide:
                    writer.write64be(value)
                else:
                    writer.write32be(value)
        if self.flags & 0x80000000:
            writer.write32be(len(self.extensions))
            for extension in self.extensions:
                extension.encode(writer)

    def decode(self, reader: SSHReader) -> None:
        self.flags = reader.read32be()
        if self.flags & ~0x8000000F:
            raise ProtocolError("unknown SFTP attribute flags; layout undecoded")
        for flag, name, wide in self.flag_fields:
            value = (reader.read64be() if wide else reader.read32be()) if self.flags & flag else None
            setattr(self, name, value)
        self.extensions = ()
        if self.flags & 0x80000000:
            count = reader.read32be()
            if count > reader.remaining() // 8:
                raise ProtocolError("truncated SFTP attribute extensions")
            self.extensions = tuple(self._extension(reader) for _ in range(count))

    @staticmethod
    def _extension(reader: SSHReader) -> SftpExtension:
        result = SftpExtension()
        result.decode(reader)
        return result


class SftpPacket(WireObject):
    @property
    def msgtype(self) -> int:
        raise NotImplementedError

    @property
    def name(self) -> str:
        return "SSH_FXP_" + type(self).__name__.split("_", 1)[1].upper()


@dataclass
class SftpVersionPacket(SftpPacket):
    version: int = 3
    extensions: tuple[SftpExtension, ...] = ()

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.version)
        for extension in self.extensions:
            extension.encode(writer)

    def decode(self, reader: SSHReader) -> None:
        self.version = reader.read32be()
        extensions: list[SftpExtension] = []
        while reader.remaining():
            extension = SftpExtension()
            extension.decode(reader)
            extensions.append(extension)
        self.extensions = tuple(extensions)


class Sftp1_Init(SftpVersionPacket):
    msgtype: ClassVar[int] = 1


class Sftp2_Version(SftpVersionPacket):
    msgtype: ClassVar[int] = 2


@dataclass
class SftpPathPacket(SftpPacket):
    request_id: int = 0
    path: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.request_id)
        writer.writeldata(self.path)

    def decode(self, reader: SSHReader) -> None:
        self.request_id = reader.read32be()
        self.path = reader.readldata()


@dataclass
class Sftp3_Open(SftpPathPacket):
    msgtype: ClassVar[int] = 3
    pflags: int = 0
    attributes: SftpAttributes = field(default_factory=SftpAttributes)

    def encode(self, writer: SSHWriter) -> None:
        super().encode(writer)
        writer.write32be(self.pflags)
        self.attributes.encode(writer)

    def decode(self, reader: SSHReader) -> None:
        super().decode(reader)
        self.pflags = reader.read32be()
        self.attributes.decode(reader)


@dataclass
class SftpHandlePacket(SftpPacket):
    request_id: int = 0
    handle: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.request_id)
        writer.writeldata(self.handle)

    def decode(self, reader: SSHReader) -> None:
        self.request_id = reader.read32be()
        self.handle = reader.readldata()


class Sftp4_Close(SftpHandlePacket):
    msgtype: ClassVar[int] = 4


@dataclass
class Sftp5_Read(SftpHandlePacket):
    msgtype: ClassVar[int] = 5
    offset: int = 0
    length: int = 0

    def encode(self, writer: SSHWriter) -> None:
        super().encode(writer)
        writer.write64be(self.offset)
        writer.write32be(self.length)

    def decode(self, reader: SSHReader) -> None:
        super().decode(reader)
        self.offset = reader.read64be()
        self.length = reader.read32be()


@dataclass
class Sftp6_Write(SftpHandlePacket):
    msgtype: ClassVar[int] = 6
    offset: int = 0
    data: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        super().encode(writer)
        writer.write64be(self.offset)
        writer.writeldata(self.data)

    def decode(self, reader: SSHReader) -> None:
        super().decode(reader)
        self.offset = reader.read64be()
        self.data = reader.readldata()


class Sftp7_Lstat(SftpPathPacket):
    msgtype: ClassVar[int] = 7


class Sftp8_Fstat(SftpHandlePacket):
    msgtype: ClassVar[int] = 8


@dataclass
class SftpPathAttributesPacket(SftpPathPacket):
    attributes: SftpAttributes = field(default_factory=SftpAttributes)

    def encode(self, writer: SSHWriter) -> None:
        super().encode(writer)
        self.attributes.encode(writer)

    def decode(self, reader: SSHReader) -> None:
        super().decode(reader)
        self.attributes.decode(reader)


class Sftp9_Setstat(SftpPathAttributesPacket):
    msgtype: ClassVar[int] = 9


@dataclass
class Sftp10_Fsetstat(SftpHandlePacket):
    msgtype: ClassVar[int] = 10
    attributes: SftpAttributes = field(default_factory=SftpAttributes)

    def encode(self, writer: SSHWriter) -> None:
        super().encode(writer)
        self.attributes.encode(writer)

    def decode(self, reader: SSHReader) -> None:
        super().decode(reader)
        self.attributes.decode(reader)


class Sftp11_Opendir(SftpPathPacket):
    msgtype: ClassVar[int] = 11


class Sftp12_Readdir(SftpHandlePacket):
    msgtype: ClassVar[int] = 12


class Sftp13_Remove(SftpPathPacket):
    msgtype: ClassVar[int] = 13


class Sftp14_Mkdir(SftpPathAttributesPacket):
    msgtype: ClassVar[int] = 14


class Sftp15_Rmdir(SftpPathPacket):
    msgtype: ClassVar[int] = 15


class Sftp16_Realpath(SftpPathPacket):
    msgtype: ClassVar[int] = 16


class Sftp17_Stat(SftpPathPacket):
    msgtype: ClassVar[int] = 17


@dataclass
class Sftp18_Rename(SftpPathPacket):
    msgtype: ClassVar[int] = 18
    new_path: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        super().encode(writer)
        writer.writeldata(self.new_path)

    def decode(self, reader: SSHReader) -> None:
        super().decode(reader)
        self.new_path = reader.readldata()


class Sftp19_Readlink(SftpPathPacket):
    msgtype: ClassVar[int] = 19


@dataclass
class Sftp20_Symlink(SftpPacket):
    """OpenSSH wire order is target followed by link, opposite draft-02."""

    msgtype: ClassVar[int] = 20
    request_id: int = 0
    target: bytes = b""
    link: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.request_id)
        writer.writeldata(self.target)
        writer.writeldata(self.link)

    def decode(self, reader: SSHReader) -> None:
        self.request_id = reader.read32be()
        self.target = reader.readldata()
        self.link = reader.readldata()


@dataclass
class Sftp101_Status(SftpPacket):
    msgtype: ClassVar[int] = 101
    request_id: int = 0
    status: int = 0
    message: bytes = b""
    language: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.request_id)
        writer.write32be(self.status)
        writer.writeldata(self.message)
        writer.writeldata(self.language)

    def decode(self, reader: SSHReader) -> None:
        self.request_id = reader.read32be()
        self.status = reader.read32be()
        self.message = reader.readldata()
        self.language = reader.readldata()


class Sftp102_Handle(SftpHandlePacket):
    msgtype: ClassVar[int] = 102


@dataclass
class Sftp103_Data(SftpPacket):
    msgtype: ClassVar[int] = 103
    request_id: int = 0
    data: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.request_id)
        writer.writeldata(self.data)

    def decode(self, reader: SSHReader) -> None:
        self.request_id = reader.read32be()
        self.data = reader.readldata()


@dataclass
class SftpName(WireObject):
    filename: bytes = b""
    longname: bytes = b""
    attributes: SftpAttributes = field(default_factory=SftpAttributes)

    def encode(self, writer: SSHWriter) -> None:
        writer.writeldata(self.filename)
        writer.writeldata(self.longname)
        self.attributes.encode(writer)

    def decode(self, reader: SSHReader) -> None:
        self.filename = reader.readldata()
        self.longname = reader.readldata()
        self.attributes.decode(reader)


@dataclass
class Sftp104_Name(SftpPacket):
    msgtype: ClassVar[int] = 104
    request_id: int = 0
    names: tuple[SftpName, ...] = ()

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.request_id)
        writer.write32be(len(self.names))
        for name in self.names:
            name.encode(writer)

    def decode(self, reader: SSHReader) -> None:
        self.request_id = reader.read32be()
        count = reader.read32be()
        if count > reader.remaining() // 12:
            raise ProtocolError("truncated SFTP name list")
        names: list[SftpName] = []
        for _ in range(count):
            name = SftpName()
            name.decode(reader)
            names.append(name)
        self.names = tuple(names)


@dataclass
class Sftp105_Attrs(SftpPacket):
    msgtype: ClassVar[int] = 105
    request_id: int = 0
    attributes: SftpAttributes = field(default_factory=SftpAttributes)

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.request_id)
        self.attributes.encode(writer)

    def decode(self, reader: SSHReader) -> None:
        self.request_id = reader.read32be()
        self.attributes.decode(reader)


@dataclass
class Sftp200_Extended(SftpPacket):
    msgtype: ClassVar[int] = 200
    request_id: int = 0
    extension: bytes = b""
    undecoded: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.request_id)
        writer.writeldata(self.extension)
        writer.write(self.undecoded)

    def decode(self, reader: SSHReader) -> None:
        self.request_id = reader.read32be()
        self.extension = reader.readldata()
        self.undecoded = reader.read(reader.remaining())


@dataclass
class Sftp201_ExtendedReply(SftpPacket):
    msgtype: ClassVar[int] = 201
    request_id: int = 0
    undecoded: bytes = b""

    def encode(self, writer: SSHWriter) -> None:
        writer.write32be(self.request_id)
        writer.write(self.undecoded)

    def decode(self, reader: SSHReader) -> None:
        self.request_id = reader.read32be()
        self.undecoded = reader.read(reader.remaining())


@dataclass
class SftpUnknown(SftpPacket):
    type_code: int = 0
    undecoded: bytes = b""
    reason: str = "unknown SFTP message type"

    @property
    def msgtype(self) -> int:
        return self.type_code

    @property
    def name(self) -> str:
        return f"SSH_FXP_UNKNOWN_{self.type_code}"

    def encode(self, writer: SSHWriter) -> None:
        writer.write(self.undecoded)

    def decode(self, reader: SSHReader) -> None:
        self.undecoded = reader.read(reader.remaining())


SFTP_CLASSES: tuple[type[SftpPacket], ...] = (
    Sftp1_Init,
    Sftp2_Version,
    Sftp3_Open,
    Sftp4_Close,
    Sftp5_Read,
    Sftp6_Write,
    Sftp7_Lstat,
    Sftp8_Fstat,
    Sftp9_Setstat,
    Sftp10_Fsetstat,
    Sftp11_Opendir,
    Sftp12_Readdir,
    Sftp13_Remove,
    Sftp14_Mkdir,
    Sftp15_Rmdir,
    Sftp16_Realpath,
    Sftp17_Stat,
    Sftp18_Rename,
    Sftp19_Readlink,
    Sftp20_Symlink,
    Sftp101_Status,
    Sftp102_Handle,
    Sftp103_Data,
    Sftp104_Name,
    Sftp105_Attrs,
    Sftp200_Extended,
    Sftp201_ExtendedReply,
)
SFTP_TYPES: dict[int, type[SftpPacket]] = {cls().msgtype: cls for cls in SFTP_CLASSES}


@dataclass
class SftpFrame(WireObject):
    packet: SftpPacket = field(default_factory=Sftp1_Init)

    def encode(self, writer: SSHWriter) -> None:
        body = encode_object(self.packet)
        writer.write32be(1 + len(body))
        writer.writebyte(self.packet.msgtype)
        writer.write(body)

    def decode(self, reader: SSHReader) -> None:
        length = reader.read32be()
        if not 1 <= length <= SftpStream.max_packet:
            raise ProtocolError("invalid SFTP frame length")
        body = SSHReader(reader.read(length))
        msgtype = body.readbyte()
        data = body.read(body.remaining())
        packet = SFTP_TYPES[msgtype]() if msgtype in SFTP_TYPES else SftpUnknown(msgtype)
        try:
            self.packet = decode_object(packet, data)
        except (EOFError, ProtocolError) as exc:
            self.packet = SftpUnknown(msgtype, data, f"malformed or unsupported body: {exc}")


class SftpStream:
    """Length-framed application stream; SSH channel packets are not SFTP boundaries."""

    max_packet = 1024 * 1024

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.version = 3

    @property
    def pending(self) -> bytes:
        return bytes(self.buffer)

    def feed(self, data: bytes) -> tuple[SftpFrame, ...]:
        self.buffer.extend(data)
        frames: list[SftpFrame] = []
        while len(self.buffer) >= 4:
            length = SSHReader(bytes(self.buffer[:4])).read32be()
            if not 1 <= length <= self.max_packet:
                raise ProtocolError("invalid SFTP frame length")
            if len(self.buffer) < 4 + length:
                break
            frame = decode_object(SftpFrame(), bytes(self.buffer[: 4 + length]))
            if isinstance(frame.packet, Sftp2_Version):
                self.version = frame.packet.version
            elif frame.packet.msgtype not in (1, 2) and self.version != 3:
                frame.packet = SftpUnknown(frame.packet.msgtype, encode_object(frame.packet), f"SFTP version {self.version} is undecoded; only v3 is supported")
            frames.append(frame)
            del self.buffer[: 4 + length]
        return tuple(frames)


class ProtocolTrace:
    """Plaintext message tracing, after verification on receive and before encryption on send.

    Level 1 emits complete message hex, including its type byte, on one line.
    Level 2 emits decoded fields, including passwords and channel data.
    """

    def __init__(self, verbose: int = 0, stream: TextIO | None = None):
        self.verbose = verbose
        self.stream = stream if stream is not None else sys.stderr
        self.kex_algorithm = ""
        self.lock = threading.Lock()
        self.sftp_streams: dict[str, SftpStream] = {}
        self.sftp_status = "requested"

    def name(self, packet: SshPacket) -> str:
        if self.kex_algorithm == KEX_HYBRID and packet.msgtype in (30, 31):
            return "SSH_MSG_KEX_HYBRID_INIT" if packet.msgtype == 30 else "SSH_MSG_KEX_HYBRID_REPLY"
        return MESSAGE_NAMES.get(packet.msgtype, f"SSH_MSG_UNKNOWN_{packet.msgtype}")

    def message(self, direction: str, packet: SshPacket, payload: bytes) -> None:
        if not self.verbose:
            return
        prefix = f"{direction} {self.name(packet)}"
        if self.verbose == 1:
            self._write(f"{prefix} {payload.hex()}\n")
        else:
            lines = [f"{prefix} (type={packet.msgtype}, {len(payload)} bytes)"]
            lines.extend(self._message_fields(direction, packet))
            self._write("\n".join(lines) + "\n")

    def _message_fields(self, direction: str, packet: SshPacket) -> Iterator[str]:
        if isinstance(packet, Msg98_ChannelRequest) and isinstance(packet.request, SubsystemRequest) and packet.request.subsystem == "sftp":
            self.sftp_streams = {"send": SftpStream(), "recv": SftpStream()}
            self.sftp_status = "requested"
        if self.sftp_streams and isinstance(packet, (Msg99_ChannelSuccess, Msg100_ChannelFailure)):
            self.sftp_status = "accepted" if isinstance(packet, Msg99_ChannelSuccess) else "rejected"
        if self.sftp_streams and isinstance(packet, Msg94_ChannelData):
            yield f"  recipient: {packet.recipient} (0x{packet.recipient:x})"
            yield f"  data: SFTP stream ({len(packet.data)} bytes, subsystem {self.sftp_status})"
            yield from self._sftp_fields(self.sftp_streams[direction], packet.data)
            return
        yield from self._fields(packet, "  ")
        if self.sftp_streams and isinstance(packet, (Msg96_ChannelEOF, Msg97_ChannelClose)):
            for side, stream in self.sftp_streams.items():
                if stream.pending and (side == direction or isinstance(packet, Msg97_ChannelClose)):
                    yield f"  incomplete_sftp_{side}: {len(stream.pending)} undecoded bytes at channel end"
                    yield from self._bytes(stream.pending, "    ")
                    stream.buffer.clear()

    def _sftp_fields(self, stream: SftpStream, data: bytes) -> Iterator[str]:
        try:
            frames = stream.feed(data)
        except ProtocolError as exc:
            yield f"    undecoded: invalid SFTP stream: {exc}"
            yield from self._bytes(stream.pending, "      ")
            stream.buffer.clear()
            return
        for frame in frames:
            packet = frame.packet
            if isinstance(packet, Sftp2_Version):
                for side in self.sftp_streams.values():
                    side.version = packet.version
            length = 1 + len(encode_object(packet))
            yield f"    {packet.name} (type={packet.msgtype}, length={length})"
            yield from self._fields(packet, "      ")
        if stream.pending:
            yield f"    incomplete_sftp: {len(stream.pending)} bytes buffered (undecoded until complete)"
            yield from self._bytes(stream.pending, "      ")

    def identification(self, direction: str, value: Hello | Banner) -> None:
        if not self.verbose:
            return
        name = "SSH_IDENTIFICATION" if isinstance(value, Hello) else "SSH_PRE_BANNER"
        data = encode_object(value)
        detail = data.hex() if self.verbose == 1 else repr(data.decode("utf-8", errors="backslashreplace"))
        self._write(f"{direction} {name} {detail}\n")

    @staticmethod
    def timestamp() -> str:
        return datetime.now().strftime("%H:%M:%S.%f")

    def _write(self, text: str) -> None:
        with self.lock:
            self.stream.write(f"{self.timestamp()} {text}")
            self.stream.flush()

    def _fields(self, value: WireObject, indent: str) -> Iterator[str]:
        if not is_dataclass(value):
            yield f"{indent}(empty body)"
            return
        if isinstance(value, AdvertisedHostKey):
            yield f"{indent}fingerprint: {value.fingerprint()}"
            if value.bits() is not None:
                yield f"{indent}bits: {value.bits()}"
        if isinstance(value, ECDSAPublicKeyFields):
            numbers = value.public_numbers()
            yield from self._field("x", numbers.x, indent)
            yield from self._field("y", numbers.y, indent)
        for item in fields(value):
            field_value: object = getattr(value, item.name)
            if isinstance(value, SftpAttributes) and field_value is None:
                continue
            if isinstance(value, Msg20_KexInit) and item.name in value.list_fields:
                yield f"{indent}{item.name}:"
                names = str(field_value).split(",") if field_value else ()
                for name in names:
                    yield f"{indent}  {name}"
                if not names:
                    yield f"{indent}  (empty)"
            else:
                yield from self._field(item.name, field_value, indent)

    def _field(self, name: str, value: object, indent: str) -> Iterator[str]:
        if isinstance(value, TerminalMode):
            yield f"{indent}{name}: {value.description()}"
        elif isinstance(value, WireObject):
            kind = type(value).__name__
            if isinstance(value, (AuthMethod, RequestBody)):
                kind += f" ({value.name})"
            yield f"{indent}{name}: {kind}"
            yield from self._fields(value, indent + "  ")
        elif isinstance(value, tuple):
            yield f"{indent}{name}: {len(value)} entries"
            for index, entry in enumerate(value):
                yield from self._field(f"[{index}]", entry, indent + "  ")
        elif isinstance(value, int) and value >= 2**64:
            yield f"{indent}{name}: integer ({value.bit_length()} bits)"
            data = value.to_bytes((value.bit_length() + 7) // 8, "big")
            yield from self._bytes(data, indent + "  ")
        elif isinstance(value, bytes):
            text = self._text(value)
            if text is not None:
                yield f"{indent}{name}: {text!r}"
            else:
                yield f"{indent}{name}: {len(value)} bytes"
                yield from self._bytes(value, indent + "  ")
        else:
            detail = f"{value} (0x{value:x})" if isinstance(value, int) and not isinstance(value, bool) else repr(value)
            yield f"{indent}{name}: {detail}"

    @staticmethod
    def _text(data: bytes) -> str | None:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return text if all(character.isprintable() or character in "\r\n\t" for character in text) else None

    @staticmethod
    def _bytes(data: bytes, indent: str) -> Iterator[str]:
        for offset in range(0, len(data), 32):
            yield f"{indent}{offset:04x}: {data[offset : offset + 32].hex(' ')}"


class ChaChaPoly:
    """OpenSSH's construction, NOT the RFC 8439 ChaCha20Poly1305 API."""

    def __init__(self, key: bytes):
        if len(key) != 64:
            raise ValueError("SSH ChaCha20/Poly1305 requires 64 key bytes")
        self.body_key, self.header_key = key[:32], key[32:]

    @staticmethod
    def _crypt(key: bytes, sequence: int, counter: int, data: bytes) -> bytes:
        writer = SSHWriter()
        writer.write64le(counter)
        writer.write64be(sequence)
        nonce = writer.getvalue()
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        return cipher.encryptor().update(data)

    def _poly_key(self, sequence: int) -> bytes:
        return self._crypt(self.body_key, sequence, 0, bytes(32))

    def length(self, sequence: int, encrypted_header: bytes) -> int:
        header = self._crypt(self.header_key, sequence, 0, encrypted_header)
        return SSHReader(header).read32be()

    def seal(self, sequence: int, payload: bytes) -> bytes:
        count = padding_size(len(payload), header_size=1)
        body_writer = SSHWriter()
        body_writer.writebyte(count)
        body_writer.write(payload)
        body_writer.write(os.urandom(count))
        body = body_writer.getvalue()
        header_writer = SSHWriter()
        header_writer.write32be(len(body))
        header = header_writer.getvalue()
        encrypted = self._crypt(self.header_key, sequence, 0, header)
        encrypted += self._crypt(self.body_key, sequence, 1, body)
        return encrypted + Poly1305.generate_tag(self._poly_key(sequence), encrypted)

    def open(self, sequence: int, data: bytes) -> SSH2Frame:
        if len(data) < 4 + 8 + 16:
            raise ProtocolError("truncated authenticated packet")
        try:
            Poly1305.verify_tag(self._poly_key(sequence), data[:-16], data[-16:])
        except InvalidSignature as exc:
            raise ProtocolError("SSH packet authentication failed") from exc
        header = self._crypt(self.header_key, sequence, 0, data[:4])
        body = self._crypt(self.body_key, sequence, 1, data[4:-16])
        return decode_object(SSH2Frame(header_size=1), header + body)


class Transport:
    """TCP stream framing with independent send/receive protection state."""

    def __init__(self, sock: socket.socket, trace: ProtocolTrace | None = None):
        self.sock = sock
        self.trace = trace if trace is not None else ProtocolTrace()
        self.send_cipher: ChaChaPoly | None = None
        self.recv_cipher: ChaChaPoly | None = None
        self.send_sequence = 0
        self.recv_sequence = 0
        self.sent_bytes = 0
        self.received_bytes = 0
        self.send_lock = threading.RLock()
        self.outgoing = bytearray()

    def read_exact(self, count: int) -> bytes:
        result = bytearray()
        while len(result) < count:
            if self.outgoing:
                ready, writable, _ = select.select([self.sock], [self.sock], [], self.sock.gettimeout())
                if not ready and not writable:
                    raise TimeoutError("SSH read/write timed out")
                if writable:
                    self.flush()
                if not ready:
                    continue
            part = self.sock.recv(count - len(result))
            if not part:
                raise EOFError("SSH peer closed the connection")
            result.extend(part)
        return bytes(result)

    def exchange_hello(self, server: bool) -> tuple[Hello, Hello]:
        local = Hello()
        self.sock.sendall(encode_object(local))
        self.trace.identification("send", local)
        for _ in range(50):
            line = bytearray()
            while not line.endswith(b"\n"):
                line.extend(self.read_exact(1))
                if len(line) > 255:
                    raise ProtocolError("identification/pre-banner line too long")
            if line.startswith(b"SSH-"):
                remote = decode_object(Hello(), bytes(line))
                self.trace.identification("recv", remote)
                return local, remote
            if server:
                raise ProtocolError("client pre-identification text is forbidden")
            self.trace.identification("recv", Banner(bytes(line)))
            # Server pre-banner lines are intentionally excluded from KEX.
        raise ProtocolError("too many server pre-identification lines")

    def send(self, packet: SshPacket) -> None:
        with self.send_lock:
            if self.send_sequence >= 2**32:
                raise ProtocolError("packet sequence exhausted; rekey required")
            payload = encode_message(packet)
            if len(payload) > MAX_PACKET - 256:
                raise ProtocolError("outgoing packet too large")
            if self.send_cipher is None:
                data = encode_object(SSH2Frame(packet))
            else:
                data = self.send_cipher.seal(self.send_sequence, payload)
            self.outgoing.extend(data)
            self.trace.message("send", packet, payload)
            self.flush()
            self.send_sequence += 1
            self.sent_bytes += len(data)

    def flush(self) -> None:
        """Queue writes to keep full-duplex sessions from blocking."""
        with self.send_lock:
            while self.outgoing:
                if not select.select([], [self.sock], [], 0)[1]:
                    return
                try:
                    count = self.sock.send(self.outgoing, socket.MSG_DONTWAIT)
                except BlockingIOError:
                    return
                if count <= 0:
                    raise EOFError("SSH socket made no write progress")
                del self.outgoing[:count]

    def receive(self) -> SshPacket:
        if self.recv_sequence >= 2**32:
            raise ProtocolError("packet sequence exhausted; rekey required")
        header = self.read_exact(4)
        cipher = self.recv_cipher
        length = SSHReader(header).read32be() if cipher is None else cipher.length(self.recv_sequence, header)
        if length < 8 or length > MAX_PACKET:
            raise ProtocolError(f"invalid packet length: {length}")
        tail = self.read_exact(length + (16 if cipher else 0))
        frame = decode_object(SSH2Frame(), header + tail) if cipher is None else cipher.open(self.recv_sequence, header + tail)
        self.recv_sequence += 1
        self.received_bytes += 4 + len(tail)
        self.trace.message("recv", frame.packet, encode_message(frame.packet))
        return frame.packet


@dataclass(frozen=True)
class ExchangeInputs:
    client_version: str
    server_version: str
    client_init: bytes
    server_init: bytes

    def digest(self, hostkey: HostKey, client_key: bytes, server_key: bytes, encoded_secret: bytes) -> bytes:
        writer = SSHWriter()
        writer.writelstr(self.client_version, "ascii")
        writer.writelstr(self.server_version, "ascii")
        writer.writeldata(self.client_init)
        writer.writeldata(self.server_init)
        writer.writeldata(encode_object(hostkey))
        writer.writeldata(client_key)
        writer.writeldata(server_key)
        writer.write(encoded_secret)
        return hashlib.sha256(writer.getvalue()).digest()


def encoded_curve_secret(secret: bytes) -> bytes:
    # RFC 8731: reinterpret X25519's output bytes as big-endian for SSH mpint;
    # do NOT reverse the X25519 byte string.
    value = secret.lstrip(b"\x00")
    if value and value[0] & 0x80:
        value = b"\x00" + value
    writer = SSHWriter()
    writer.writeldata(value)
    return writer.getvalue()


def derive_key(encoded_secret: bytes, exchange_hash: bytes, letter: bytes, session_id: bytes, size: int = 64) -> bytes:
    material = hashlib.sha256(encoded_secret + exchange_hash + letter + session_id).digest()
    while len(material) < size:
        material += hashlib.sha256(encoded_secret + exchange_hash + material).digest()
    return material[:size]


class KeyExchange:
    def __init__(self, algorithm: str):
        self.algorithm = algorithm
        self.curve = x25519.X25519PrivateKey.generate()
        self.kem: mlkem.MLKEM768PrivateKey | None = None

    def client_init(self) -> bytes:
        public = self.curve.public_key().public_bytes_raw()
        if self.algorithm == KEX_HYBRID:
            self.kem = mlkem.MLKEM768PrivateKey.generate()
            return encode_object(HybridInit(self.kem.public_key().public_bytes_raw(), public))
        return public

    def server_reply(self, client_key: bytes) -> tuple[bytes, bytes]:
        public = self.curve.public_key().public_bytes_raw()
        if self.algorithm == KEX_HYBRID:
            parts = decode_object(HybridInit(), client_key)
            peer = mlkem.MLKEM768PublicKey.from_public_bytes(parts.kem_public)
            kem_secret, ciphertext = peer.encapsulate()
            classical = self.curve.exchange(x25519.X25519PublicKey.from_public_bytes(parts.x25519_public))
            shared = hashlib.sha256(kem_secret + classical).digest()
            writer = SSHWriter()
            writer.writeldata(shared)
            return encode_object(HybridReply(ciphertext, public)), writer.getvalue()
        if len(client_key) != 32:
            raise ProtocolError("Curve25519 public key must have 32 bytes")
        secret = self.curve.exchange(x25519.X25519PublicKey.from_public_bytes(client_key))
        return public, encoded_curve_secret(secret)

    def client_finish(self, server_key: bytes) -> bytes:
        if self.algorithm == KEX_HYBRID:
            if self.kem is None:
                raise ProtocolError("missing ML-KEM client private key")
            parts = decode_object(HybridReply(), server_key)
            kem_secret = self.kem.decapsulate(parts.kem_ciphertext)
            classical = self.curve.exchange(x25519.X25519PublicKey.from_public_bytes(parts.x25519_public))
            shared = hashlib.sha256(kem_secret + classical).digest()
            self.kem = None
            writer = SSHWriter()
            writer.writeldata(shared)
            return writer.getvalue()
        if len(server_key) != 32:
            raise ProtocolError("Curve25519 public key must have 32 bytes")
        secret = self.curve.exchange(x25519.X25519PublicKey.from_public_bytes(server_key))
        return encoded_curve_secret(secret)


class Connection:
    """Shared client/server transport and rekey state machine."""

    def __init__(
        self,
        sock: socket.socket,
        server: bool = False,
        host_key: ed25519.Ed25519PrivateKey | None = None,
        pinned_key: HostKey | None = None,
        curve_only: bool = False,
        verbose: int = 0,
        trace_stream: TextIO | None = None,
    ):
        self.transport = Transport(sock, ProtocolTrace(verbose, trace_stream))
        self.server = server
        self.host_key = host_key
        self.pinned_key = pinned_key
        self.unverified_key_warned = False
        self.curve_only = curve_only
        self.local_version, self.remote_version = self.transport.exchange_hello(server)
        self.session_id = b""
        self.auth_service_started = False
        self.pending_packets: deque[SshPacket] = deque()
        self.suite: Algorithms | None = None
        self.rekey_deadline = time.monotonic() + 3600
        self.key_exchange()

    def _expect_kex(self, msgtype: int, strict: bool) -> SshPacket:
        for _ in range(100):
            packet = self.transport.receive()
            if packet.msgtype == msgtype:
                return packet
            if not strict and packet.msgtype in (2, 4):
                # Explicitly ignore IGNORE/DEBUG during non-strict KEX.
                continue
            self._check_disconnect(packet)
            raise ProtocolError(f"expected KEX message {msgtype}, got {packet.msgtype}")
        raise ProtocolError("too many transport messages during KEX")

    @staticmethod
    def _check_disconnect(packet: SshPacket) -> None:
        if isinstance(packet, Msg1_Disconnect):
            raise ProtocolError(f"peer disconnected ({packet.reason}): {packet.description}")

    def _proposals(self, peer: SshPacket | None) -> tuple[Msg20_KexInit, Msg20_KexInit]:
        local = Msg20_KexInit.proposal(self.server, self.curve_only)
        self.transport.send(local)
        previous_strict = bool(self.suite and self.suite.strict)
        if peer is None:
            peer = self._receive_proposal()
        if not isinstance(peer, Msg20_KexInit):
            raise ProtocolError("expected KEXINIT")
        client, server = (peer, local) if self.server else (local, peer)
        self.suite = Algorithms.negotiate(client, server)
        if previous_strict:
            # Strict KEX is negotiated once; OpenSSH omits its marker on rekey.
            self.suite = replace(self.suite, strict=True)
        self.suite.require_supported()
        self.transport.trace.kex_algorithm = self.suite.kex
        if not self.session_id and self.suite.strict:
            if self.transport.recv_sequence != 1:
                raise ProtocolError("strict KEX requires KEXINIT as first packet")
        if peer.kexfollows:
            guessed_kex = peer.kex_algorithms.split(",")[0]
            guessed_host = peer.hostkey_algorithms.split(",")[0]
            if guessed_kex != self.suite.kex or guessed_host != self.suite.hostkey:
                # RFC 4253: discard one wrong guessed packet.
                self.transport.receive()
        return client, server

    def _receive_proposal(self) -> SshPacket:
        if not self.session_id:
            return self._expect_kex(20, False)
        for _ in range(1000):
            packet = self.transport.receive()
            self._check_disconnect(packet)
            if packet.msgtype == 20:
                return packet
            # Application messages already in flight before peer KEXINIT must
            # be delivered later, in their original order.
            if packet.msgtype not in (2, 4):
                self.pending_packets.append(packet)
        raise ProtocolError("too many in-flight messages before rekey proposal")

    def key_exchange(self, peer: SshPacket | None = None) -> None:
        client, server = self._proposals(peer)
        assert self.suite is not None
        client_version, server_version = (
            (self.remote_version.version, self.local_version.version) if self.server else (self.local_version.version, self.remote_version.version)
        )
        inputs = ExchangeInputs(client_version, server_version, encode_message(client), encode_message(server))
        exchange = KeyExchange(self.suite.kex)
        if self.server:
            encoded_secret, digest = self._server_exchange(exchange, inputs)
        else:
            encoded_secret, digest = self._client_exchange(exchange, inputs)
        if not self.session_id:
            self.session_id = digest
        self._newkeys(encoded_secret, digest)

    def _server_exchange(self, exchange: KeyExchange, inputs: ExchangeInputs) -> tuple[bytes, bytes]:
        assert self.suite is not None
        packet = self._expect_kex(30, self.suite.strict)
        assert isinstance(packet, Msg30_ECDHInit)
        server_key, encoded_secret = exchange.server_reply(packet.pubkey)
        if self.host_key is None:
            raise HostKeyError("server needs an Ed25519 private host key")
        host = HostKey("ssh-ed25519", self.host_key.public_key().public_bytes_raw())
        digest = inputs.digest(host, packet.pubkey, server_key, encoded_secret)
        signature = Signature("ssh-ed25519", self.host_key.sign(digest))
        self.transport.send(Msg31_ECDHReply(host, server_key, signature))
        return encoded_secret, digest

    def _client_exchange(self, exchange: KeyExchange, inputs: ExchangeInputs) -> tuple[bytes, bytes]:
        assert self.suite is not None
        client_key = exchange.client_init()
        self.transport.send(Msg30_ECDHInit(client_key))
        packet = self._expect_kex(31, self.suite.strict)
        assert isinstance(packet, Msg31_ECDHReply)
        if self.pinned_key is not None:
            if not hmac.compare_digest(encode_object(packet.hostkey), encode_object(self.pinned_key)):
                raise HostKeyError(f"server host key does not match the pin: {packet.hostkey.fingerprint()}")
        elif not self.unverified_key_warned:
            warnings.warn(f"host key is not verified: {packet.hostkey.fingerprint()}", RuntimeWarning, stacklevel=2)
            self.unverified_key_warned = True
        encoded_secret = exchange.client_finish(packet.pubkey)
        digest = inputs.digest(packet.hostkey, client_key, packet.pubkey, encoded_secret)
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(packet.hostkey.key).verify(packet.signature.data, digest)
        except InvalidSignature as exc:
            raise HostKeyError("invalid server key-exchange signature") from exc
        return encoded_secret, digest

    def _newkeys(self, encoded_secret: bytes, digest: bytes) -> None:
        assert self.suite is not None
        c2s = derive_key(encoded_secret, digest, b"C", self.session_id)
        s2c = derive_key(encoded_secret, digest, b"D", self.session_id)
        self.transport.send(Msg21_NewKeys())  # Uses the old outgoing keys.
        self.transport.send_cipher = ChaChaPoly(s2c if self.server else c2s)
        if self.suite.strict:
            self.transport.send_sequence = 0
        self._expect_kex(21, self.suite.strict)  # Uses the old incoming keys.
        self.transport.recv_cipher = ChaChaPoly(c2s if self.server else s2c)
        if self.suite.strict:
            self.transport.recv_sequence = 0
        self.transport.sent_bytes = self.transport.received_bytes = 0
        self.rekey_deadline = time.monotonic() + 3600

    def send(self, packet: SshPacket) -> None:
        if self.transport.sent_bytes > 512 * 1024 * 1024 or self.transport.received_bytes > 512 * 1024 * 1024 or time.monotonic() >= self.rekey_deadline:
            self.key_exchange()
        self.transport.send(packet)

    def receive(self) -> SshPacket:
        for _ in range(100):
            packet = self.pending_packets.popleft() if self.pending_packets else self.transport.receive()
            self._check_disconnect(packet)
            if packet.msgtype == 20:
                self.key_exchange(packet)
            elif packet.msgtype in (2, 4):
                # IGNORE/DEBUG bodies deliberately ignored after authentication
                # of their transport packets; never used to make decisions.
                continue
            else:
                return packet
        raise ProtocolError("too many ignored transport messages")

    def expect(self, msgtype: int) -> SshPacket:
        packet = self.receive()
        if packet.msgtype != msgtype:
            raise ProtocolError(f"expected message {msgtype}, got {packet.msgtype}")
        return packet

    def close(self) -> None:
        self.transport.sock.close()


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str | None = field(default=None, repr=False)
    authorized_keys: tuple[HostKey, ...] = ()

    def methods(self) -> str:
        names: list[str] = []
        if self.authorized_keys:
            names.append("publickey")
        if self.password is not None:
            names.append("password")
        return ",".join(names)

    def matches(self, username: str, password: bytes) -> bool:
        user_ok = hmac.compare_digest(self.username.encode("utf-8"), username.encode("utf-8"))
        password_ok = hmac.compare_digest((self.password or "").encode("utf-8"), password)
        return user_ok & password_ok & (self.password is not None)


def verify_user_key(connection: Connection, credentials: Credentials, packet: Msg50_UserAuthRequest) -> bool | None:
    method = packet.method
    assert isinstance(method, PublicKeyAuth)
    trusted = method.algorithm == "ssh-ed25519" and any(hmac.compare_digest(method.public_key, encode_object(key)) for key in credentials.authorized_keys)
    if not method.signed:
        if trusted:
            connection.send(Msg60_UserAuthPKOK(method.algorithm, method.public_key))
            return None
        return False
    if not trusted or method.signature is None:
        return False
    key = decode_object(HostKey(), method.public_key)
    method.signature.require_ed25519()
    signed_data = packet.signature_input(connection.session_id)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(key.key).verify(method.signature.data, signed_data)
    except InvalidSignature:
        return False
    return True


def client_publickey_authenticate(connection: Connection, username: str, private_key: ed25519.Ed25519PrivateKey) -> None:
    begin_client_auth(connection)
    host = HostKey("ssh-ed25519", private_key.public_key().public_bytes_raw())
    method = PublicKeyAuth(signed=True, public_key=encode_object(host))
    request = Msg50_UserAuthRequest(username=username, method=method)
    signed_data = request.signature_input(connection.session_id)
    method.signature = Signature("ssh-ed25519", private_key.sign(signed_data))
    connection.send(request)
    finish_client_auth(connection)


def server_authenticate(connection: Connection, credentials: Credentials) -> None:
    request = connection.expect(5)
    assert isinstance(request, Msg5_ServiceRequest)
    if request.service != "ssh-userauth":
        raise ProtocolError("only ssh-userauth service supported")
    connection.send(Msg6_ServiceAccept("ssh-userauth"))
    for _ in range(12):
        packet = connection.expect(50)
        assert isinstance(packet, Msg50_UserAuthRequest)
        account_matches = packet.service == "ssh-connection" and packet.username == credentials.username
        accepted = False
        if isinstance(packet.method, PasswordAuth):
            accepted = account_matches and not packet.method.change and credentials.matches(packet.username, packet.method.password)
        elif isinstance(packet.method, PublicKeyAuth) and account_matches:
            outcome = verify_user_key(connection, credentials, packet)
            if outcome is None:
                continue  # Valid unsigned probe was answered with PK_OK.
            accepted = outcome
        # NoneAuth and UnknownAuth are explicitly rejected. UnknownAuth retains
        # the complete unsupported method-specific payload for inspection.
        if accepted:
            connection.send(Msg52_UserAuthSuccess())
            return
        connection.send(Msg51_UserAuthFailure(credentials.methods(), False))
    raise AuthenticationError("too many authentication attempts")


def begin_client_auth(connection: Connection) -> None:
    if connection.auth_service_started:
        return
    connection.send(Msg5_ServiceRequest("ssh-userauth"))
    reply = connection.expect(6)
    assert isinstance(reply, Msg6_ServiceAccept)
    if reply.service != "ssh-userauth":
        raise ProtocolError("wrong accepted service")
    connection.auth_service_started = True


def client_authenticate(connection: Connection, credentials: Credentials) -> None:
    begin_client_auth(connection)
    if credentials.password is None:
        raise AuthenticationError("password not supplied")
    method = PasswordAuth(password=credentials.password.encode("utf-8"))
    connection.send(Msg50_UserAuthRequest(username=credentials.username, method=method))
    finish_client_auth(connection)


def finish_client_auth(connection: Connection) -> None:
    for _ in range(20):
        packet = connection.receive()
        if isinstance(packet, Msg52_UserAuthSuccess):
            return
        if isinstance(packet, Msg53_UserAuthBanner):
            continue  # Decoded server banner intentionally not printed by this API.
        if isinstance(packet, Msg51_UserAuthFailure):
            raise AuthenticationError(f"authentication rejected; methods={packet.methods}, partial={packet.partial}")
        raise ProtocolError(f"unexpected authentication message {packet.msgtype}")
    raise ProtocolError("too many authentication banners")


def handle_global(connection: Connection, packet: SshPacket) -> bool:
    if not isinstance(packet, Msg80_GlobalRequest):
        return False
    # Advertisements are decoded for inspection; they do not update trust or
    # enable automatic key rotation. Unimplemented requests still fail when
    # the peer asks for a reply; unknown bodies remain explicitly opaque.
    if packet.want_reply:
        connection.send(Msg82_RequestFailure())
    return True


@dataclass(frozen=True)
class ChannelData:
    """Application data delivered by a channel, not a wire message."""

    stream: int
    data: bytes


class Channel:
    """One SSH session channel, including bounded receive/send windows."""

    def __init__(self, connection: Connection, remote: int, send_window: int, max_packet: int):
        if max_packet < 1:
            raise ProtocolError("zero maximum channel packet size")
        self.connection = connection
        self.remote = remote
        self.send_window = send_window
        self.max_packet = min(max_packet, CHANNEL_PACKET)
        self.recv_window = CHANNEL_WINDOW
        self.peer_eof = False
        self.peer_closed = False
        self.sent_eof = False
        self.sent_close = False
        self.exit_status = 255
        self.request_reply: bool | None = None

    @classmethod
    def open_client(cls, connection: Connection) -> Channel:
        connection.send(Msg90_ChannelOpen())
        while True:
            packet = connection.receive()
            if handle_global(connection, packet):
                continue
            if isinstance(packet, Msg92_ChannelOpenFailure):
                raise ProtocolError(f"server rejected session channel: {packet.description}")
            if not isinstance(packet, Msg91_ChannelOpenConfirmation) or packet.recipient != 0 or packet.extra:
                raise ProtocolError("expected session open confirmation")
            return cls(connection, packet.sender, packet.window, packet.max_packet)

    @classmethod
    def open_server(cls, connection: Connection) -> Channel:
        while True:
            packet = connection.receive()
            if handle_global(connection, packet):
                continue
            if not isinstance(packet, Msg90_ChannelOpen):
                raise ProtocolError("expected channel open")
            if packet.channel_type != "session":
                connection.send(Msg92_ChannelOpenFailure(packet.sender, 1, "only session channels supported"))
                continue
            result = cls(connection, packet.sender, packet.window, packet.max_packet)
            connection.send(Msg91_ChannelOpenConfirmation(recipient=packet.sender))
            return result

    def request(self, request: RequestBody, want_reply: bool = True) -> None:
        self.request_reply = None
        self.connection.send(Msg98_ChannelRequest(self.remote, request, want_reply))

    def reply(self, success: bool) -> None:
        response = Msg99_ChannelSuccess(self.remote) if success else Msg100_ChannelFailure(self.remote)
        self.connection.send(response)

    def send_data(self, data: bytes, stream: int = 0) -> int:
        if self.sent_eof or self.sent_close or self.peer_closed:
            raise ProtocolError("data sent on a closed channel")
        count = min(len(data), self.send_window, self.max_packet)
        if count:
            if stream:
                packet: SshPacket = Msg95_ChannelExtendedData(self.remote, stream, data[:count])
            else:
                packet = Msg94_ChannelData(self.remote, data[:count])
            self.connection.send(packet)
            self.send_window -= count
        return count

    def acknowledge(self, count: int) -> None:
        if count < 0 or self.recv_window + count > CHANNEL_WINDOW:
            raise ProtocolError("invalid channel receive-window replenishment")
        if count and not self.sent_close:
            self.connection.send(Msg93_ChannelWindowAdjust(self.remote, count))
            self.recv_window += count

    def eof(self) -> None:
        if not self.sent_eof and not self.sent_close:
            self.connection.send(Msg96_ChannelEOF(self.remote))
            self.sent_eof = True

    def close(self) -> None:
        if not self.sent_close:
            self.connection.send(Msg97_ChannelClose(self.remote))
            self.sent_close = True

    def handle(self, packet: SshPacket) -> ChannelData | Msg98_ChannelRequest | None:
        if handle_global(self.connection, packet):
            return None
        if isinstance(packet, Msg90_ChannelOpen):
            self.connection.send(Msg92_ChannelOpenFailure(packet.sender, 1, "only one session per connection supported"))
            return None
        if not isinstance(packet, ChannelMessage) or packet.msgtype not in range(93, 101) or packet.recipient != 0:
            raise ProtocolError(f"unexpected channel message {packet.msgtype}")
        if isinstance(packet, (Msg94_ChannelData, Msg95_ChannelExtendedData)):
            if self.peer_eof or self.peer_closed or len(packet.data) > self.recv_window or len(packet.data) > CHANNEL_PACKET:
                raise ProtocolError("channel data violates state/window/packet limit")
            self.recv_window -= len(packet.data)
            stream = packet.stream if isinstance(packet, Msg95_ChannelExtendedData) else 0
            return ChannelData(stream, packet.data)
        if isinstance(packet, Msg98_ChannelRequest):
            return packet
        self._control(packet)
        return None

    def _control(self, packet: SshPacket) -> None:
        if isinstance(packet, Msg93_ChannelWindowAdjust):
            if self.send_window + packet.adjustment > 0xFFFFFFFF:
                raise ProtocolError("channel window overflow")
            self.send_window += packet.adjustment
        elif isinstance(packet, Msg96_ChannelEOF):
            self.peer_eof = True
        elif isinstance(packet, Msg97_ChannelClose):
            self.peer_closed = True
            self.close()
        elif isinstance(packet, (Msg99_ChannelSuccess, Msg100_ChannelFailure)):
            self.request_reply = isinstance(packet, Msg99_ChannelSuccess)

    def handle_client_request(self, packet: Msg98_ChannelRequest) -> None:
        request = packet.request
        if isinstance(request, ExitStatusRequest):
            self.exit_status = request.status
        elif isinstance(request, ExitSignalRequest):
            self.exit_status = 255
        if packet.want_reply:
            self.reply(isinstance(request, (ExitStatusRequest, ExitSignalRequest)))


@dataclass(frozen=True)
class CommandResult:
    stdout: bytes
    stderr: bytes
    exit_status: int


@dataclass
class TerminalAttributes:
    """Typed boundary around POSIX's seven-element tcgetattr/tcsetattr list."""

    input_flags: int
    output_flags: int
    control_flags: int
    local_flags: int
    input_speed: int
    output_speed: int
    characters: list[bytes | int]

    @classmethod
    def read(cls, descriptor: int) -> TerminalAttributes:
        values = termios.tcgetattr(descriptor)
        return cls(values[0], values[1], values[2], values[3], values[4], values[5], list(values[6]))

    def apply(self, descriptor: int) -> None:
        values: list[int | list[bytes | int]] = [
            self.input_flags,
            self.output_flags,
            self.control_flags,
            self.local_flags,
            self.input_speed,
            self.output_speed,
            self.characters,
        ]
        termios.tcsetattr(descriptor, termios.TCSANOW, values)

    @staticmethod
    def flag_field(opcode: int) -> str | None:
        if 30 <= opcode <= 42:
            return "input_flags"
        if 50 <= opcode <= 62:
            return "local_flags"
        if 70 <= opcode <= 75:
            return "output_flags"
        return "control_flags" if 90 <= opcode <= 93 else None

    def set_mode(self, mode: TerminalMode, disabled: int) -> None:
        if mode.value is None or mode.opcode not in TerminalMode.names:
            return
        constant: int | None = getattr(termios, mode.name, None)
        if 1 <= mode.opcode <= 18 and constant is not None:
            if mode.value <= 255:
                self.characters[constant] = bytes([disabled if mode.value == 255 else mode.value])
        elif mode.opcode in (128, 129):
            speed: int | None = getattr(termios, f"B{mode.value}", None)
            if speed is not None:
                setattr(self, "input_speed" if mode.opcode == 128 else "output_speed", speed)
        elif constant is not None:
            name = self.flag_field(mode.opcode)
            if name is not None:
                flags: int = getattr(self, name)
                if mode.opcode in (90, 91):
                    if mode.value:
                        flags = (flags & ~termios.CSIZE) | constant
                else:
                    flags = flags | constant if mode.value else flags & ~constant
                setattr(self, name, flags)

    def modes(self, disabled: int) -> TerminalModes:
        entries: list[TerminalMode] = []
        for opcode, name in TerminalMode.names.items():
            constant: int | None = getattr(termios, name, None)
            if 1 <= opcode <= 18 and constant is not None:
                character = self.characters[constant]
                value = character if isinstance(character, int) else character[0]
                entries.append(TerminalMode(opcode, 255 if value == disabled else value))
            elif constant is not None and (flag_field := self.flag_field(opcode)) is not None:
                entries.append(TerminalMode(opcode, int(bool(getattr(self, flag_field) & constant))))
        for opcode, speed in ((128, self.input_speed), (129, self.output_speed)):
            for name in dir(termios):
                if name.startswith("B") and name[1:].isdigit() and getattr(termios, name) == speed:
                    entries.append(TerminalMode(opcode, int(name[1:])))
                    break
        entries.append(TerminalMode(0))
        return TerminalModes(tuple(entries))


class PseudoTerminal:
    def __init__(self, request: PtyRequest):
        master, self.slave = pty.openpty()
        self.stream = os.fdopen(master, "r+b", buffering=0)
        try:
            attributes = TerminalAttributes.read(self.slave)
            disabled = os.fpathconf(self.slave, "PC_VDISABLE")
            for mode in request.modes.entries:
                attributes.set_mode(mode, disabled)
            attributes.apply(self.slave)
            self.resize(WindowChangeRequest(request.columns, request.rows, request.width_pixels, request.height_pixels))
            os.set_blocking(master, False)
        except BaseException:
            self.close()
            raise

    def resize(self, request: WindowChangeRequest) -> None:
        dimensions = struct.unpack("HHHH", fcntl.ioctl(self.stream.fileno(), termios.TIOCGWINSZ, bytes(8)))
        requested = (request.rows, request.columns, request.width_pixels, request.height_pixels)
        updated = tuple(min(value, 65535) if value else old for value, old in zip(requested, dimensions))
        fcntl.ioctl(self.stream.fileno(), termios.TIOCSWINSZ, struct.pack("HHHH", *updated))

    def close_slave(self) -> None:
        if self.slave >= 0:
            os.close(self.slave)
            self.slave = -1

    def eof_data(self) -> bytes:
        attributes = TerminalAttributes.read(self.stream.fileno())
        if not attributes.local_flags & termios.ICANON:
            return b""  # A raw PTY has no byte sequence representing half-close.
        value = attributes.characters[termios.VEOF]
        character = bytes([value]) if isinstance(value, int) else value
        if character == bytes([os.fpathconf(self.stream.fileno(), "PC_VDISABLE")]):
            return b""
        return character * 2  # Finish a partial canonical line, then report EOF.

    def close(self) -> None:
        self.close_slave()
        if not self.stream.closed:
            self.stream.close()


def find_sftp_server() -> Path | None:
    candidates = ("/usr/lib/openssh/sftp-server", "/usr/lib/ssh/sftp-server", "/usr/libexec/openssh/sftp-server", "/usr/libexec/sftp-server")
    for candidate in candidates:
        if Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return Path(candidate)
    executable = shutil.which("sftp-server")
    return Path(executable) if executable else None


@dataclass
class SessionConfig:
    sftp_server: Path | None = field(default_factory=find_sftp_server)
    allowed_environment: tuple[str, ...] = ("TERM", "COLORTERM", "LANG")

    def accepts_environment(self, name: str) -> bool:
        return name in self.allowed_environment or name.startswith("LC_")


class ClientSession:
    def __init__(self, channel: Channel, source: BinaryIO, stdout: BinaryIO, stderr: BinaryIO):
        self.channel = channel
        self.source = source
        self.stdout = stdout
        self.stderr = stderr
        self.resize_pending = False
        try:
            self.input_fd: int | None = source.fileno()
        except (AttributeError, io.UnsupportedOperation):
            self.input_fd = None

    def _request(self, request: RequestBody) -> None:
        self.channel.request(request)
        while self.channel.request_reply is None:
            self._packet()
            if self.channel.peer_closed:
                raise ProtocolError("session closed before request reply")
        if not self.channel.request_reply:
            raise ProtocolError(f"server rejected {request.name} request")

    def run(self, command: str | None, terminal: PtyRequest | None = None, subsystem: str | None = None) -> int:
        if subsystem is not None and (command is not None or terminal is not None):
            raise ValueError("subsystem cannot be combined with a command or PTY")
        if terminal is not None:
            self._request(terminal)
        request = SubsystemRequest(subsystem) if subsystem is not None else ExecRequest(command) if command is not None else ShellRequest()
        self._request(request)
        resize = terminal is not None and self.input_fd is not None and os.isatty(self.input_fd) and threading.current_thread() is threading.main_thread()
        previous = signal.signal(signal.SIGWINCH, self._resize) if resize else None
        try:
            while not self.channel.peer_closed:
                self._step()
            return self.channel.exit_status
        finally:
            if previous is not None:
                signal.signal(signal.SIGWINCH, previous)

    def _resize(self, number: int, frame: object) -> None:
        self.resize_pending = True

    def _step(self) -> None:
        channel = self.channel
        can_input = not channel.sent_eof and channel.send_window > 0
        if can_input and self.input_fd is None:
            self._input()
        readers: list[int | socket.socket] = [channel.connection.transport.sock]
        if can_input and self.input_fd is not None:
            readers.append(self.input_fd)
        immediate = can_input and self.input_fd is None and not channel.sent_eof
        transport = channel.connection.transport
        writers = [transport.sock] if transport.outgoing else []
        ready, writable, _ = select.select(readers, writers, [], 0 if immediate else 0.25)
        if writable:
            transport.flush()
        if channel.connection.transport.sock in ready:
            self._packet()
        if self.input_fd is not None and self.input_fd in ready and not channel.peer_closed:
            self._input()
        if self.resize_pending and self.input_fd is not None and not channel.peer_closed:
            self.resize_pending = False
            size = os.get_terminal_size(self.input_fd)
            channel.request(WindowChangeRequest(size.columns, size.lines), want_reply=False)

    def _input(self) -> None:
        count = min(self.channel.send_window, self.channel.max_packet)
        data = self.source.read(count) if self.input_fd is None else os.read(self.input_fd, count)
        if not data:
            self.channel.eof()
        else:
            self.channel.send_data(data)

    @staticmethod
    def _write(destination: BinaryIO, data: bytes) -> None:
        view = memoryview(data)
        while view:
            count = destination.write(view)
            if count is None or count <= 0:
                raise OSError("output stream made no progress")
            view = view[count:]
        destination.flush()

    def _packet(self) -> None:
        channel = self.channel
        event = channel.handle(channel.connection.receive())
        if isinstance(event, ChannelData):
            if event.stream not in (0, 1):
                raise ProtocolError(f"unsupported extended-data stream: {event.stream}")
            self._write(self.stderr if event.stream else self.stdout, event.data)
            channel.acknowledge(len(event.data))
        elif isinstance(event, Msg98_ChannelRequest):
            channel.handle_client_request(event)


class SSHClient:
    def __init__(self, sock: socket.socket, pinned_key: HostKey | None = None, curve_only: bool = False, verbose: int = 0, trace_stream: TextIO | None = None):
        self.connection = Connection(sock, pinned_key=pinned_key, curve_only=curve_only, verbose=verbose, trace_stream=trace_stream)

    def authenticate(self, username: str, password: str) -> None:
        client_authenticate(self.connection, Credentials(username, password))

    def authenticate_publickey(self, username: str, private_key: ed25519.Ed25519PrivateKey) -> None:
        client_publickey_authenticate(self.connection, username, private_key)

    def run(self, command: str | None, input_data: bytes = b"", *, terminal: PtyRequest | None = None) -> CommandResult:
        stdout, stderr = io.BytesIO(), io.BytesIO()
        status = self.run_stream(command, io.BytesIO(input_data), stdout, stderr, terminal=terminal)
        return CommandResult(stdout.getvalue(), stderr.getvalue(), status)

    def run_stream(
        self, command: str | None, source: BinaryIO, stdout: BinaryIO, stderr: BinaryIO, *, terminal: PtyRequest | None = None, subsystem: str | None = None
    ) -> int:
        channel = Channel.open_client(self.connection)
        return ClientSession(channel, source, stdout, stderr).run(command, terminal, subsystem)

    def run_subsystem(self, subsystem: str, source: BinaryIO, stdout: BinaryIO, stderr: BinaryIO) -> int:
        return self.run_stream(None, source, stdout, stderr, subsystem=subsystem)

    def close(self) -> None:
        self.connection.close()


class ServerSession:
    """Shell/exec, PTY, or SFTP process with bounded, full-duplex channel forwarding."""

    def __init__(self, channel: Channel, config: SessionConfig | None = None):
        self.channel = channel
        self.config = config if config is not None else SessionConfig()
        self.terminal: PseudoTerminal | None = None
        self.terminal_name = ""
        self.environment: dict[str, str] = {}
        self.input_descriptor: int | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.outputs: dict[int, tuple[IO[bytes], int]] = {}
        self.pending_input = bytearray()
        self.stdin_closed = False

    def run(self) -> None:
        try:
            while self.process is None and not self.channel.peer_closed:
                self._packet()
            while self.process is not None and not self.channel.peer_closed:
                if self.process.poll() is not None and not self.outputs:
                    self._finish()
                    return
                self._step()
        finally:
            self._cleanup()

    def _start(self, command: str | None) -> None:
        if command is not None and "\x00" in command:
            raise ProtocolError("NUL in exec command")
        arguments = ["/bin/sh"] if command is None else ["/bin/sh", "-c", command]
        self._start_program(arguments)

    def _start_program(self, arguments: list[str]) -> None:
        environment = os.environ | self.environment
        if self.terminal is not None:
            environment["TERM"] = self.terminal_name
            arguments = [sys.executable, str(Path(__file__).resolve()), "--_pty-exec", *arguments]
            try:
                process = subprocess.Popen(
                    arguments,
                    stdin=self.terminal.slave,
                    stdout=self.terminal.slave,
                    stderr=self.terminal.slave,
                    start_new_session=True,
                    env=environment,
                    bufsize=0,
                )
            finally:
                self.terminal.close_slave()
            self.input_descriptor = self.terminal.stream.fileno()
            self.outputs[self.input_descriptor] = (self.terminal.stream, 0)
        else:
            process = subprocess.Popen(
                arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, env=environment, bufsize=0
            )
            assert process.stdin and process.stdout and process.stderr
            self.input_descriptor = process.stdin.fileno()
            for stream, kind in ((process.stdout, 0), (process.stderr, 1)):
                os.set_blocking(stream.fileno(), False)
                self.outputs[stream.fileno()] = (stream, kind)
        assert self.input_descriptor is not None
        os.set_blocking(self.input_descriptor, False)
        self.process = process

    def _request(self, packet: Msg98_ChannelRequest) -> None:
        request = packet.request
        success = False
        try:
            if isinstance(request, PtyRequest) and self.process is None and self.terminal is None:
                if b"\x00" in request.terminal:
                    raise ProtocolError("NUL in terminal name")
                self.terminal = PseudoTerminal(request)
                self.terminal_name = os.fsdecode(request.terminal) or "dumb"
                success = True
            elif isinstance(request, WindowChangeRequest) and self.terminal is not None:
                self.terminal.resize(request)
                success = True
            elif isinstance(request, EnvRequest) and self.process is None:
                success = self._environment(request)
            elif isinstance(request, SubsystemRequest) and request.subsystem == "sftp" and self.process is None and self.terminal is None:
                if self.config.sftp_server is not None:
                    self._start_program([str(self.config.sftp_server)])
                    success = True
            elif isinstance(request, (ExecRequest, ShellRequest)) and self.process is None:
                command = request.command if isinstance(request, ExecRequest) else None
                self._start(command)
                success = True
            elif isinstance(request, SignalRequest) and self.process is not None:
                allowed = {"INT": signal.SIGINT, "TERM": signal.SIGTERM, "HUP": signal.SIGHUP, "KILL": signal.SIGKILL}
                if request.signal in allowed and self.process.poll() is None:
                    os.killpg(self.process.pid, allowed[request.signal])
                    success = True
        except (OSError, ValueError):
            success = False
        if packet.want_reply:
            self.channel.reply(success)

    def _environment(self, request: EnvRequest) -> bool:
        if not request.variable or b"\x00" in request.variable or b"=" in request.variable or b"\x00" in request.value:
            return False
        name = os.fsdecode(request.variable)
        if not self.config.accepts_environment(name):
            return False
        self.environment[name] = os.fsdecode(request.value)
        return True

    def _packet(self) -> None:
        event = self.channel.handle(self.channel.connection.receive())
        if isinstance(event, Msg98_ChannelRequest):
            self._request(event)
        elif isinstance(event, ChannelData):
            if self.process is None or event.stream != 0:
                raise ProtocolError("unexpected client channel data")
            if self.stdin_closed:
                # The subprocess already closed its input; release credit for
                # bytes that can no longer be delivered (normal broken pipe).
                self.channel.acknowledge(len(event.data))
            else:
                self.pending_input.extend(event.data)

    def _close_stdin(self) -> None:
        if not self.stdin_closed:
            if self.terminal is not None:
                self.pending_input.extend(self.terminal.eof_data())
            else:
                assert self.process is not None and self.process.stdin is not None
                self.process.stdin.close()
            self.stdin_closed = True

    def _write_stdin(self) -> None:
        assert self.input_descriptor is not None
        try:
            count = os.write(self.input_descriptor, self.pending_input)
        except BlockingIOError:
            return
        except OSError as exc:
            if exc.errno not in (errno.EPIPE, errno.EIO):
                raise
            count = len(self.pending_input)
            self.stdin_closed = True
            if self.terminal is None:
                self._close_pipe()
        del self.pending_input[:count]
        # Locally synthesized PTY EOF characters consume no SSH receive credit.
        credit = min(count, CHANNEL_WINDOW - self.channel.recv_window)
        self.channel.acknowledge(credit)

    def _close_pipe(self) -> None:
        if self.process is not None and self.process.stdin is not None and not self.process.stdin.closed:
            self.process.stdin.close()

    def _read_output(self, descriptor: int) -> None:
        channel = self.channel
        stream, kind = self.outputs[descriptor]
        try:
            data = os.read(descriptor, min(channel.send_window, channel.max_packet))
        except BlockingIOError:
            return
        except OSError as exc:
            if self.terminal is None or exc.errno != errno.EIO:
                raise
            data = b""  # Linux PTY masters report EIO when the final slave closes.
        if not data:
            del self.outputs[descriptor]
            stream.close()
            if self.terminal is not None:
                self.stdin_closed = True
                self.channel.acknowledge(min(len(self.pending_input), CHANNEL_WINDOW - self.channel.recv_window))
                self.pending_input.clear()
        else:
            if channel.send_data(data, kind) != len(data):
                raise ProtocolError("internal channel-window accounting error")

    def _step(self) -> None:
        assert self.process is not None
        if self.channel.peer_eof and not self.pending_input and not self.stdin_closed:
            self._close_stdin()
        network = self.channel.connection.transport.sock
        readers: list[int | socket.socket] = [network]
        if self.channel.send_window:
            readers.extend(self.outputs)
        writers: list[int | socket.socket] = []
        if self.channel.connection.transport.outgoing:
            writers.append(network)
        if self.pending_input and (not self.stdin_closed or self.terminal is not None):
            assert self.input_descriptor is not None
            writers.append(self.input_descriptor)
        ready, writable, _ = select.select(readers, writers, [], 0.25)
        if network in writable:
            self.channel.connection.transport.flush()
        if network in ready:
            self._packet()
        if self.channel.peer_closed:
            return
        for descriptor in ready:
            if isinstance(descriptor, int) and self.channel.send_window:
                self._read_output(descriptor)
        if self.pending_input and self.input_descriptor in writable:
            self._write_stdin()

    def _finish(self) -> None:
        assert self.process is not None
        status = self.process.wait()
        status = status if status >= 0 else 128 - status
        self.channel.request(ExitStatusRequest(status & 0xFFFFFFFF), want_reply=False)
        self.channel.eof()
        self.channel.close()
        # Complete channel close before tearing down TCP; avoid dropping the
        # final status/output through an unread-data TCP reset.
        network = self.channel.connection.transport.sock
        deadline = time.monotonic() + 5
        while not self.channel.peer_closed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            transport = self.channel.connection.transport
            writers = [network] if transport.outgoing else []
            ready, writable, _ = select.select([network], writers, [], remaining)
            if writable:
                transport.flush()
            if ready:
                self._packet()
            if not ready and not writable:
                break

    def _cleanup(self) -> None:
        if self.terminal is not None:
            self.terminal.close()
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
            except ProcessLookupError:
                self.process.wait()
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


class SSHServer:
    """Configured login; commands run as the existing OS user."""

    def __init__(
        self,
        host_key: ed25519.Ed25519PrivateKey,
        credentials: Credentials,
        curve_only: bool = False,
        verbose: int = 0,
        trace_stream: TextIO | None = None,
        session_config: SessionConfig | None = None,
    ):
        if not credentials.methods():
            raise ValueError("server requires a password or an authorized user key")
        self.host_key = host_key
        self.credentials = credentials
        self.curve_only = curve_only
        self.verbose = verbose
        self.trace_stream = trace_stream
        self.session_config = session_config if session_config is not None else SessionConfig()

    def serve(self, sock: socket.socket) -> None:
        connection: Connection | None = None
        try:
            connection = Connection(sock, server=True, host_key=self.host_key, curve_only=self.curve_only, verbose=self.verbose, trace_stream=self.trace_stream)
            server_authenticate(connection, self.credentials)
            ServerSession(Channel.open_server(connection), self.session_config).run()
        finally:
            if connection is not None:
                connection.close()
            else:
                sock.close()


def load_private_key(path: Path) -> ed25519.Ed25519PrivateKey:
    data = path.read_bytes()
    try:
        key = serialization.load_ssh_private_key(data, password=None)
    except TypeError:
        password = getpass.getpass("Host-key passphrase: ").encode("utf-8")
        key = serialization.load_ssh_private_key(data, password=password)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise HostKeyError("server host key must be Ed25519")
    return key


def generate_host_key(path: Path) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
    public = HostKey("ssh-ed25519", key.public_key().public_bytes_raw())
    with path.open("xb") as destination:
        os.chmod(path, 0o600)
        destination.write(private)
    public_path = Path(str(path) + ".pub")
    with public_path.open("xb") as destination:
        destination.write(public.openssh() + b"\n")
    print(public.fingerprint())


def print_transcript(path: Path) -> None:
    for event in decode_transcript(path.read_text()):
        value = event.value
        prefix = f"{event.direction} offset={event.offset}"
        if isinstance(value, Hello):
            print(f"{prefix} identification={value.version!r}")
        elif isinstance(value, EncryptedData):
            print(f"{prefix} {len(value.data)} encrypted bytes (undecoded)")
        elif isinstance(value, Banner):
            print(f"{prefix} pre-banner={value.data!r}")
        elif isinstance(value.packet, Msg20_KexInit):
            print(f"{prefix} KEXINIT length={value.packet_length}")
            for name in value.packet.list_fields:
                print(f"    {name}: {getattr(value.packet, name)}")
        elif isinstance(value.packet, Msg30_ECDHInit):
            print(f"{prefix} KEX_INIT public blob={len(value.packet.pubkey)} bytes")
        elif isinstance(value.packet, Msg31_ECDHReply):
            packet = value.packet
            print(f"{prefix} KEX_REPLY public blob={len(packet.pubkey)} bytes host={packet.hostkey.fingerprint()} signature={len(packet.signature.data)} bytes")
        else:
            print(f"{prefix} type={value.packet.msgtype} length={value.packet_length}")


def read_password(password: str | None) -> str:
    if password is not None:
        return password
    if "SSH_PASSWORD" in os.environ:
        return os.environ["SSH_PASSWORD"]
    return getpass.getpass("Password: ")


@contextmanager
def local_terminal(enabled: bool, source: BinaryIO) -> Iterator[PtyRequest | None]:
    if not enabled:
        yield None
        return
    descriptor = source.fileno()
    size = shutil.get_terminal_size((80, 24))
    request = PtyRequest(os.fsencode(os.environ.get("TERM", "xterm")), size.columns, size.lines)
    original: TerminalAttributes | None = None
    if os.isatty(descriptor):
        original = TerminalAttributes.read(descriptor)
        request.modes = original.modes(os.fpathconf(descriptor, "PC_VDISABLE"))
        tty.setraw(descriptor)
    try:
        yield request
    finally:
        if original is not None:
            original.apply(descriptor)


def pty_child(arguments: list[str]) -> None:
    """Popen has created a new session; acquire its controlling terminal before exec."""
    if not arguments:
        raise ValueError("missing PTY child command")
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    os.execvpe(arguments[0], arguments, os.environ)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    keygen = commands.add_parser("keygen", help="generate an Ed25519 host key")
    keygen.add_argument("path", type=Path)
    decode = commands.add_parser("decode", help="decode a direction-marked hex capture")
    decode.add_argument("path", type=Path)
    server = commands.add_parser("server", help="authenticated shell, PTY, and SFTP sessions")
    client = commands.add_parser("client", help="connect and run a shell/command")
    for endpoint in (server, client):
        endpoint.add_argument("-v", "--verbose", action="count", default=0, help="trace message hex; repeat for decoded fields")
        endpoint.add_argument("-p", "--port", type=int, default=22)
        endpoint.add_argument("-u", "--user", required=True)
        endpoint.add_argument("-k", "--host-key", type=Path, required=endpoint is server, help="server: private key; client: optional pinned .pub file")
        endpoint.add_argument("-P", "--password", help="login password; otherwise use SSH_PASSWORD or prompt")
        endpoint.add_argument("-c", "--curve25519", action="store_true", help="disable hybrid ML-KEM")
        endpoint.add_argument("-t", "--timeout", type=float, default=30, help="timeout for incomplete network reads, seconds")
    server.add_argument("-a", "--authorized-key", type=Path, help="allow this Ed25519 user public key")
    server.add_argument("-l", "--listen", default="127.0.0.1")
    server.add_argument("-o", "--once", action="store_true")
    server.add_argument("-s", "--sftp-server", type=Path, help="OpenSSH sftp-server executable; otherwise autodetect")
    client.add_argument("-i", "--identity", type=Path, help="Ed25519 user private key")
    client.add_argument("-T", "--pty", action="store_true", help="request a PTY; use local raw mode when stdin is a terminal")
    client.add_argument("-s", "--subsystem", help="run a subsystem, e.g. sftp; stdin/stdout carry its binary protocol")
    client.add_argument("host")
    client.add_argument("command", nargs=argparse.REMAINDER, help="remote command; omit for a non-PTY shell")
    return parser


def run_server(args: argparse.Namespace) -> None:
    authorized = () if args.authorized_key is None else (HostKey.from_public_file(args.authorized_key),)
    key_only = bool(authorized) and args.password is None and "SSH_PASSWORD" not in os.environ
    password = None if key_only else read_password(args.password)
    credentials = Credentials(args.user, password, authorized)
    config = SessionConfig() if args.sftp_server is None else SessionConfig(args.sftp_server)
    server = SSHServer(load_private_key(args.host_key), credentials, args.curve25519, verbose=args.verbose, session_config=config)
    with socket.create_server((args.listen, args.port)) as listener:
        print(f"Listening on {args.listen}:{listener.getsockname()[1]}", file=sys.stderr)
        while True:
            peer, _ = listener.accept()
            peer.settimeout(args.timeout)
            try:
                server.serve(peer)
            except (OSError, EOFError, ValueError) as exc:
                print(f"SSH connection failed: {exc}", file=sys.stderr)
            if args.once:
                return


def run_client(args: argparse.Namespace) -> int:
    pinned = HostKey.from_public_file(args.host_key) if args.host_key is not None else None
    password = None if args.identity is not None else read_password(args.password)
    with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
        client = SSHClient(sock, pinned, args.curve25519, verbose=args.verbose)
        if args.identity is not None:
            client.authenticate_publickey(args.user, load_private_key(args.identity))
        else:
            assert password is not None
            client.authenticate(args.user, password)
        command = " ".join(args.command) if args.command else None
        with local_terminal(args.pty, sys.stdin.buffer) as terminal:
            return client.run_stream(command, sys.stdin.buffer, sys.stdout.buffer, sys.stderr.buffer, terminal=terminal, subsystem=args.subsystem)


def main() -> int:
    if sys.argv[1:2] == ["--_pty-exec"]:
        pty_child(sys.argv[2:])
        return 255
    args = build_parser().parse_args()
    try:
        if args.mode == "keygen":
            generate_host_key(args.path)
        elif args.mode == "decode":
            print_transcript(args.path)
        elif args.mode == "server":
            run_server(args)
        elif args.mode == "client":
            return run_client(args)
    except (OSError, EOFError, ValueError) as exc:
        print(f"ssh.py: {exc}", file=sys.stderr)
        return 255
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
