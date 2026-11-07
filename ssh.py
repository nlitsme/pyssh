# written by chatgpt GPT-6
"""Small, inspectable SSH-2 client/server and lossless handshake decoder.

Suite: ML-KEM-768/X25519 (or Curve25519), Ed25519, OpenSSH ChaCha20/
Poly1305, no compression. Authentication: password and Ed25519 user key.
One session per connection.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import io
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import IO, BinaryIO, ClassVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mlkem, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305
from datareader import BaseReader, DataReader
from datawriter import BaseWriter, DataWriter

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


def padding_size(
    payload_size: int, block_size: int = 8, header_size: int = 5
) -> int:
    """Include the message type in payload_size; ChaCha uses header_size=1."""
    if payload_size < 1 or block_size < 8 or block_size > 128:
        raise ValueError("invalid payload size or block size")
    padding = -(header_size + payload_size) % block_size
    return padding if padding >= 4 else padding + block_size


def writeldata(writer: BaseWriter, data: bytes) -> None:
    writer.write32be(len(data))
    if data:
        writer.write(data)


def writelstr(writer: BaseWriter, text: str) -> None:
    writeldata(writer, text.encode("utf-8"))


def readldata(reader: BaseReader) -> bytes:
    size = reader.read32be()
    if size > MAX_PACKET:
        raise ProtocolError(f"SSH string too long: {size}")
    return reader.read(size)


def readlstr(reader: BaseReader) -> str:
    # Deliberately do not use readstr(): SSH strings retain NULs and must
    # reject malformed UTF-8, rather than silently skipping undecoded bytes.
    return readldata(reader).decode("utf-8")


def require_end(reader: DataReader) -> None:
    if reader.remaining():
        raise ProtocolError(f"{reader.remaining()} unexpected trailing bytes")


@dataclass
class Hello:
    version: str = VERSION
    ending: bytes = b"\r\n"

    def __post_init__(self) -> None:
        if "\r" in self.version or "\n" in self.version:
            raise ProtocolError("newline in identification")
        parts = self.version.split("-", 2)
        if len(parts) != 3 or parts[0] != "SSH":
            raise ProtocolError("invalid SSH identification")
        if parts[1] not in ("2.0", "1.99"):
            raise ProtocolError("only SSH-2 is supported")
        software = parts[2].split(" ", 1)[0]
        if not software or any(
            ord(c) < 33 or ord(c) > 126 or c == "-" for c in software
        ):
            raise ProtocolError("invalid software identifier")
        if self.ending not in (b"\n", b"\r\n"):
            raise ProtocolError("invalid identification terminator")
        if len(self.to_bytes()) > 255:
            raise ProtocolError("identification exceeds 255 bytes")

    @classmethod
    def from_bytes(cls, line: bytes) -> Hello:
        if not line.endswith(b"\n"):
            raise ProtocolError("unterminated identification")
        ending = b"\r\n" if line.endswith(b"\r\n") else b"\n"
        return cls(line[: -len(ending)].decode("ascii"), ending)

    def to_bytes(self) -> bytes:
        return self.version.encode("ascii") + self.ending

    def encode(self, writer: BaseWriter) -> None:
        writer.write(self.to_bytes())


class SshPacket:
    msgtype: int

    def encode(self, writer: BaseWriter) -> None:
        raise NotImplementedError

    def to_payload(self) -> bytes:
        writer = DataWriter()
        writer.writebyte(self.msgtype)
        self.encode(writer)
        return writer.getvalue()

    @staticmethod
    def decode(msgtype: int, body: bytes) -> SshPacket:
        reader = DataReader(body)
        if msgtype == 20:
            packet: SshPacket = Msg20_KexInit.from_reader(reader)
        elif msgtype == 21:
            packet = Msg21_NewKeys()
        elif msgtype == 30:
            packet = Msg30_ECDHInit(readldata(reader))
        elif msgtype == 31:
            packet = Msg31_ECDHReply.from_reader(reader)
        else:
            # Unknown/connection messages remain explicitly opaque, lossless
            # RawPackets until consumed by their state-specific parser.
            return RawPacket(msgtype, body)
        require_end(reader)
        return packet

    @staticmethod
    def from_payload(payload: bytes) -> SshPacket:
        if not payload:
            raise ProtocolError("empty SSH payload")
        return SshPacket.decode(payload[0], payload[1:])


@dataclass
class RawPacket(SshPacket):
    msgtype: int
    body: bytes = b""

    def encode(self, writer: BaseWriter) -> None:
        if self.body:
            writer.write(self.body)


class Message:
    """Typed builder for state-specific SSH messages."""

    def __init__(self, msgtype: int):
        self.msgtype = msgtype
        self.writer = DataWriter()

    def u32(self, value: int) -> Message:
        self.writer.write32be(value)
        return self

    def boolean(self, value: bool) -> Message:
        self.writer.writebyte(int(value))
        return self

    def string(self, value: bytes | str) -> Message:
        data = value.encode("utf-8") if isinstance(value, str) else value
        writeldata(self.writer, data)
        return self

    def raw(self, value: bytes) -> Message:
        if value:
            self.writer.write(value)
        return self

    def build(self) -> RawPacket:
        return RawPacket(self.msgtype, self.writer.getvalue())


class MessageReader(DataReader):
    def __init__(self, packet: SshPacket):
        super().__init__(packet.to_payload()[1:])

    def string(self) -> bytes:
        return readldata(self)

    def text(self) -> str:
        return readlstr(self)

    def u32(self) -> int:
        return self.read32be()

    def boolean(self) -> bool:
        value = self.readbyte()
        if value not in (0, 1):
            raise ProtocolError("noncanonical boolean")
        return bool(value)

    def end(self) -> None:
        require_end(self)


@dataclass
class Msg20_KexInit(SshPacket):
    msgtype: int = field(default=20, init=False)
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

    def encode(self, writer: BaseWriter) -> None:
        if len(self.cookie) != 16:
            raise ProtocolError("KEXINIT cookie must have 16 bytes")
        writer.write(self.cookie)
        for name in self.list_fields:
            value: str = getattr(self, name)
            writeldata(writer, value.encode("ascii"))
        writer.writebyte(int(self.kexfollows))
        writer.write32be(self.reserved)

    @classmethod
    def from_reader(cls, reader: DataReader) -> Msg20_KexInit:
        result = cls(cookie=reader.read(16))
        for name in cls.list_fields:
            value = readldata(reader).decode("ascii")
            if value and any(
                not item or any(ord(c) < 33 or ord(c) > 126 for c in item)
                for item in value.split(",")
            ):
                raise ProtocolError("malformed algorithm name-list")
            setattr(result, name, value)
        result.kexfollows = bool(reader.readbyte())
        result.reserved = reader.read32be()
        return result

    @classmethod
    def proposal(cls, server: bool, curve_only: bool = False) -> Msg20_KexInit:
        result = cls()
        if curve_only:
            result.kex_algorithms = KEX_CURVE
        side = "s" if server else "c"
        result.kex_algorithms += f",kex-strict-{side}-v00@openssh.com"
        return result


@dataclass
class Msg21_NewKeys(SshPacket):
    msgtype: int = field(default=21, init=False)

    def encode(self, writer: BaseWriter) -> None:
        pass


@dataclass
class Msg30_ECDHInit(SshPacket):
    """Also the outer format of SSH_MSG_KEX_HYBRID_INIT."""

    msgtype: int = field(default=30, init=False)
    pubkey: bytes = b""

    def encode(self, writer: BaseWriter) -> None:
        writeldata(writer, self.pubkey)


@dataclass
class HostKey:
    algorithm: str
    key: bytes

    def to_bytes(self) -> bytes:
        return Message(0).string(self.algorithm).string(self.key).build().body

    def encode(self, writer: BaseWriter) -> None:
        writer.write(self.to_bytes())

    @classmethod
    def from_bytes(cls, data: bytes) -> HostKey:
        reader = DataReader(data)
        result = cls(readlstr(reader), readldata(reader))
        require_end(reader)
        if result.algorithm != "ssh-ed25519" or len(result.key) != 32:
            raise ProtocolError("only 32-byte ssh-ed25519 host keys supported")
        return result

    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.to_bytes()).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")

    def openssh(self) -> bytes:
        return b"ssh-ed25519 " + base64.b64encode(self.to_bytes())

    @classmethod
    def from_public_file(cls, path: Path) -> HostKey:
        key = serialization.load_ssh_public_key(path.read_bytes())
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise HostKeyError("the pinned public key must be Ed25519")
        return cls("ssh-ed25519", key.public_bytes_raw())


@dataclass
class Signature:
    algorithm: str
    data: bytes

    def to_bytes(self) -> bytes:
        return Message(0).string(self.algorithm).string(self.data).build().body

    def encode(self, writer: BaseWriter) -> None:
        writer.write(self.to_bytes())

    @classmethod
    def from_bytes(cls, data: bytes) -> Signature:
        reader = DataReader(data)
        result = cls(readlstr(reader), readldata(reader))
        require_end(reader)
        if result.algorithm != "ssh-ed25519" or len(result.data) != 64:
            raise ProtocolError("invalid Ed25519 signature blob")
        return result


@dataclass
class Msg31_ECDHReply(SshPacket):
    """Also the outer format of SSH_MSG_KEX_HYBRID_REPLY."""

    msgtype: int = field(default=31, init=False)
    hostkey: HostKey
    pubkey: bytes
    signature: Signature

    def encode(self, writer: BaseWriter) -> None:
        writeldata(writer, self.hostkey.to_bytes())
        writeldata(writer, self.pubkey)
        writeldata(writer, self.signature.to_bytes())

    @classmethod
    def from_reader(cls, reader: DataReader) -> Msg31_ECDHReply:
        return cls(
            HostKey.from_bytes(readldata(reader)),
            readldata(reader),
            Signature.from_bytes(readldata(reader)),
        )


@dataclass(frozen=True)
class HybridInit:
    kem_public: bytes
    x25519_public: bytes

    @classmethod
    def decode(cls, data: bytes) -> HybridInit:
        if len(data) != 1216:
            raise ProtocolError("hybrid client key must contain 1216 bytes")
        return cls(data[:1184], data[1184:])


@dataclass(frozen=True)
class HybridReply:
    kem_ciphertext: bytes
    x25519_public: bytes

    @classmethod
    def decode(cls, data: bytes) -> HybridReply:
        if len(data) != 1120:
            raise ProtocolError("hybrid server reply must contain 1120 bytes")
        return cls(data[:1088], data[1088:])


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
    def negotiate(
        cls, client: Msg20_KexInit, server: Msg20_KexInit
    ) -> Algorithms:
        choose = cls.choose
        c2s = choose(client.c2s_encryption, server.c2s_encryption)
        s2c = choose(client.s2c_encryption, server.s2c_encryption)
        return cls(
            choose(client.kex_algorithms, server.kex_algorithms),
            choose(client.hostkey_algorithms, server.hostkey_algorithms),
            c2s,
            s2c,
            "implicit"
            if c2s == CIPHER
            else choose(client.c2s_mac, server.c2s_mac),
            "implicit"
            if s2c == CIPHER
            else choose(client.s2c_mac, server.s2c_mac),
            choose(client.c2s_comp, server.c2s_comp),
            choose(client.s2c_comp, server.s2c_comp),
            "kex-strict-c-v00@openssh.com" in client.kex_algorithms.split(",")
            and "kex-strict-s-v00@openssh.com"
            in server.kex_algorithms.split(","),
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


@dataclass
class SSH2Frame:
    packet: SshPacket
    padding: bytes = b""

    @property
    def packet_length(self) -> int:
        return 1 + len(self.packet.to_payload()) + len(self.padding)

    def to_bytes(self) -> bytes:
        payload = self.packet.to_payload()
        pad = self.padding or os.urandom(padding_size(len(payload)))
        length = 1 + len(payload) + len(pad)
        return struct.pack(">IB", length, len(pad)) + payload + pad

    def encode(self, writer: BaseWriter) -> None:
        writer.write(self.to_bytes())

    @classmethod
    def from_bytes(cls, data: bytes, header_size: int = 5) -> SSH2Frame:
        if len(data) < 6:
            raise ProtocolError("truncated SSH frame")
        length, pad = struct.unpack(">IB", data[:5])
        if length > MAX_PACKET or length + 4 != len(data):
            raise ProtocolError("invalid SSH packet length")
        if (length + header_size - 1) % 8:
            raise ProtocolError("unaligned SSH frame")
        if pad < 4 or pad + 2 > length:
            raise ProtocolError("invalid SSH padding length")
        return cls(SshPacket.from_payload(data[5:-pad]), data[-pad:])


@dataclass(frozen=True)
class EncryptedData:
    """Opaque ciphertext; encrypted message boundaries are unknown."""

    data: bytes

    def to_bytes(self) -> bytes:
        return self.data


@dataclass(frozen=True)
class Banner:
    """Preserved server pre-identification line; not part of the KEX hash."""

    data: bytes

    def to_bytes(self) -> bytes:
        return self.data


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
            return Hello.from_bytes(line)
        if len(self.buffer) < 4:
            return None
        length = struct.unpack(">I", self.buffer[:4])[0]
        if length < 12 or length > MAX_PACKET:
            raise ProtocolError("invalid plaintext frame length")
        if len(self.buffer) < length + 4:
            return None
        frame = SSH2Frame.from_bytes(self._take(length + 4))
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


class ChaChaPoly:
    """OpenSSH's construction, NOT the RFC 8439 ChaCha20Poly1305 API."""

    def __init__(self, key: bytes):
        if len(key) != 64:
            raise ValueError("SSH ChaCha20/Poly1305 requires 64 key bytes")
        self.body_key, self.header_key = key[:32], key[32:]

    @staticmethod
    def _crypt(key: bytes, sequence: int, counter: int, data: bytes) -> bytes:
        nonce = struct.pack("<Q", counter) + struct.pack(">Q", sequence)
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        return cipher.encryptor().update(data)

    def _poly_key(self, sequence: int) -> bytes:
        return self._crypt(self.body_key, sequence, 0, bytes(32))

    def length(self, sequence: int, encrypted_header: bytes) -> int:
        header = self._crypt(self.header_key, sequence, 0, encrypted_header)
        return struct.unpack(">I", header)[0]

    def seal(self, sequence: int, payload: bytes) -> bytes:
        count = padding_size(len(payload), header_size=1)
        body = bytes([count]) + payload + os.urandom(count)
        header = struct.pack(">I", len(body))
        encrypted = self._crypt(self.header_key, sequence, 0, header)
        encrypted += self._crypt(self.body_key, sequence, 1, body)
        return encrypted + Poly1305.generate_tag(
            self._poly_key(sequence), encrypted
        )

    def open(self, sequence: int, data: bytes) -> SSH2Frame:
        if len(data) < 4 + 8 + 16:
            raise ProtocolError("truncated authenticated packet")
        try:
            Poly1305.verify_tag(
                self._poly_key(sequence), data[:-16], data[-16:]
            )
        except InvalidSignature as exc:
            raise ProtocolError("SSH packet authentication failed") from exc
        header = self._crypt(self.header_key, sequence, 0, data[:4])
        body = self._crypt(self.body_key, sequence, 1, data[4:-16])
        return SSH2Frame.from_bytes(header + body, header_size=1)


class Transport:
    """TCP stream framing with independent send/receive protection state."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
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
                ready, writable, _ = select.select(
                    [self.sock],
                    [self.sock],
                    [],
                    self.sock.gettimeout(),
                )
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
        self.sock.sendall(local.to_bytes())
        for _ in range(50):
            line = bytearray()
            while not line.endswith(b"\n"):
                line.extend(self.read_exact(1))
                if len(line) > 255:
                    raise ProtocolError(
                        "identification/pre-banner line too long"
                    )
            if line.startswith(b"SSH-"):
                return local, Hello.from_bytes(bytes(line))
            if server:
                raise ProtocolError(
                    "client pre-identification text is forbidden"
                )
            # Server pre-banner lines are intentionally excluded from KEX.
        raise ProtocolError("too many server pre-identification lines")

    def send(self, packet: SshPacket) -> None:
        with self.send_lock:
            if self.send_sequence >= 2**32:
                raise ProtocolError(
                    "packet sequence exhausted; rekey required"
                )
            payload = packet.to_payload()
            if len(payload) > MAX_PACKET - 256:
                raise ProtocolError("outgoing packet too large")
            if self.send_cipher is None:
                data = SSH2Frame(packet).to_bytes()
            else:
                data = self.send_cipher.seal(self.send_sequence, payload)
            self.outgoing.extend(data)
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
        length = (
            struct.unpack(">I", header)[0]
            if cipher is None
            else cipher.length(self.recv_sequence, header)
        )
        if length < 8 or length > MAX_PACKET:
            raise ProtocolError(f"invalid packet length: {length}")
        tail = self.read_exact(length + (16 if cipher else 0))
        frame = (
            SSH2Frame.from_bytes(header + tail)
            if cipher is None
            else cipher.open(self.recv_sequence, header + tail)
        )
        self.recv_sequence += 1
        self.received_bytes += 4 + len(tail)
        return frame.packet


@dataclass(frozen=True)
class ExchangeInputs:
    client_version: str
    server_version: str
    client_init: bytes
    server_init: bytes

    def digest(
        self,
        hostkey: HostKey,
        client_key: bytes,
        server_key: bytes,
        encoded_secret: bytes,
    ) -> bytes:
        writer = DataWriter()
        for value in (
            self.client_version.encode("ascii"),
            self.server_version.encode("ascii"),
            self.client_init,
            self.server_init,
            hostkey.to_bytes(),
            client_key,
            server_key,
        ):
            writeldata(writer, value)
        writer.write(encoded_secret)
        return hashlib.sha256(writer.getvalue()).digest()


def encoded_curve_secret(secret: bytes) -> bytes:
    # RFC 8731: reinterpret X25519's output bytes as big-endian for SSH mpint;
    # do NOT reverse the X25519 byte string.
    value = secret.lstrip(b"\x00")
    if value and value[0] & 0x80:
        value = b"\x00" + value
    return Message(0).string(value).build().body


def derive_key(
    encoded_secret: bytes,
    exchange_hash: bytes,
    letter: bytes,
    session_id: bytes,
    size: int = 64,
) -> bytes:
    material = hashlib.sha256(
        encoded_secret + exchange_hash + letter + session_id,
    ).digest()
    while len(material) < size:
        material += hashlib.sha256(
            encoded_secret + exchange_hash + material
        ).digest()
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
            return self.kem.public_key().public_bytes_raw() + public
        return public

    def server_reply(self, client_key: bytes) -> tuple[bytes, bytes]:
        public = self.curve.public_key().public_bytes_raw()
        if self.algorithm == KEX_HYBRID:
            parts = HybridInit.decode(client_key)
            peer = mlkem.MLKEM768PublicKey.from_public_bytes(parts.kem_public)
            kem_secret, ciphertext = peer.encapsulate()
            classical = self.curve.exchange(
                x25519.X25519PublicKey.from_public_bytes(parts.x25519_public),
            )
            shared = hashlib.sha256(kem_secret + classical).digest()
            return ciphertext + public, Message(0).string(shared).build().body
        if len(client_key) != 32:
            raise ProtocolError("Curve25519 public key must have 32 bytes")
        secret = self.curve.exchange(
            x25519.X25519PublicKey.from_public_bytes(client_key)
        )
        return public, encoded_curve_secret(secret)

    def client_finish(self, server_key: bytes) -> bytes:
        if self.algorithm == KEX_HYBRID:
            if self.kem is None:
                raise ProtocolError("missing ML-KEM client private key")
            parts = HybridReply.decode(server_key)
            kem_secret = self.kem.decapsulate(parts.kem_ciphertext)
            classical = self.curve.exchange(
                x25519.X25519PublicKey.from_public_bytes(parts.x25519_public),
            )
            shared = hashlib.sha256(kem_secret + classical).digest()
            self.kem = None
            return Message(0).string(shared).build().body
        if len(server_key) != 32:
            raise ProtocolError("Curve25519 public key must have 32 bytes")
        secret = self.curve.exchange(
            x25519.X25519PublicKey.from_public_bytes(server_key)
        )
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
    ):
        self.transport = Transport(sock)
        self.server = server
        self.host_key = host_key
        self.pinned_key = pinned_key
        self.curve_only = curve_only
        self.local_version, self.remote_version = (
            self.transport.exchange_hello(server)
        )
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
            raise ProtocolError(
                f"expected KEX message {msgtype}, got {packet.msgtype}"
            )
        raise ProtocolError("too many transport messages during KEX")

    @staticmethod
    def _check_disconnect(packet: SshPacket) -> None:
        if packet.msgtype == 1:
            reader = MessageReader(packet)
            code, text = reader.u32(), reader.text()
            reader.text()
            reader.end()
            raise ProtocolError(f"peer disconnected ({code}): {text}")

    def _proposals(
        self, peer: SshPacket | None
    ) -> tuple[Msg20_KexInit, Msg20_KexInit]:
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
        if not self.session_id and self.suite.strict:
            if self.transport.recv_sequence != 1:
                raise ProtocolError(
                    "strict KEX requires KEXINIT as first packet"
                )
        if peer.kexfollows:
            guessed_kex = peer.kex_algorithms.split(",")[0]
            guessed_host = peer.hostkey_algorithms.split(",")[0]
            if (
                guessed_kex != self.suite.kex
                or guessed_host != self.suite.hostkey
            ):
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
        raise ProtocolError(
            "too many in-flight messages before rekey proposal"
        )

    def key_exchange(self, peer: SshPacket | None = None) -> None:
        client, server = self._proposals(peer)
        assert self.suite is not None
        client_version, server_version = (
            (self.remote_version.version, self.local_version.version)
            if self.server
            else (self.local_version.version, self.remote_version.version)
        )
        inputs = ExchangeInputs(
            client_version,
            server_version,
            client.to_payload(),
            server.to_payload(),
        )
        exchange = KeyExchange(self.suite.kex)
        if self.server:
            encoded_secret, digest = self._server_exchange(exchange, inputs)
        else:
            encoded_secret, digest = self._client_exchange(exchange, inputs)
        if not self.session_id:
            self.session_id = digest
        self._newkeys(encoded_secret, digest)

    def _server_exchange(
        self, exchange: KeyExchange, inputs: ExchangeInputs
    ) -> tuple[bytes, bytes]:
        assert self.suite is not None
        packet = self._expect_kex(30, self.suite.strict)
        assert isinstance(packet, Msg30_ECDHInit)
        server_key, encoded_secret = exchange.server_reply(packet.pubkey)
        if self.host_key is None:
            raise HostKeyError("server needs an Ed25519 private host key")
        host = HostKey(
            "ssh-ed25519", self.host_key.public_key().public_bytes_raw()
        )
        digest = inputs.digest(host, packet.pubkey, server_key, encoded_secret)
        signature = Signature("ssh-ed25519", self.host_key.sign(digest))
        self.transport.send(Msg31_ECDHReply(host, server_key, signature))
        return encoded_secret, digest

    def _client_exchange(
        self, exchange: KeyExchange, inputs: ExchangeInputs
    ) -> tuple[bytes, bytes]:
        assert self.suite is not None
        client_key = exchange.client_init()
        self.transport.send(Msg30_ECDHInit(client_key))
        packet = self._expect_kex(31, self.suite.strict)
        assert isinstance(packet, Msg31_ECDHReply)
        if self.pinned_key is None or not hmac.compare_digest(
            packet.hostkey.to_bytes(), self.pinned_key.to_bytes()
        ):
            raise HostKeyError(
                f"untrusted server host key: {packet.hostkey.fingerprint()}"
            )
        encoded_secret = exchange.client_finish(packet.pubkey)
        digest = inputs.digest(
            packet.hostkey, client_key, packet.pubkey, encoded_secret
        )
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(
                packet.hostkey.key
            ).verify(
                packet.signature.data,
                digest,
            )
        except InvalidSignature as exc:
            raise HostKeyError(
                "invalid server key-exchange signature"
            ) from exc
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
        if (
            self.transport.sent_bytes > 512 * 1024 * 1024
            or self.transport.received_bytes > 512 * 1024 * 1024
            or time.monotonic() >= self.rekey_deadline
        ):
            self.key_exchange()
        self.transport.send(packet)

    def receive(self) -> SshPacket:
        for _ in range(100):
            packet = (
                self.pending_packets.popleft()
                if self.pending_packets
                else self.transport.receive()
            )
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
            raise ProtocolError(
                f"expected message {msgtype}, got {packet.msgtype}"
            )
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
        user_ok = hmac.compare_digest(
            self.username.encode("utf-8"), username.encode("utf-8")
        )
        password_ok = hmac.compare_digest(
            (self.password or "").encode("utf-8"), password
        )
        return user_ok & password_ok & (self.password is not None)


def verify_user_key(
    connection: Connection, credentials: Credentials, reader: MessageReader
) -> bool | None:
    signed, algorithm, blob = reader.boolean(), reader.text(), reader.string()
    # The signed request includes everything through the key blob, but not
    # the trailing signature string.
    prefix = bytes([50]) + reader.data[: reader.tell()]
    trusted = algorithm == "ssh-ed25519" and any(
        hmac.compare_digest(blob, key.to_bytes())
        for key in credentials.authorized_keys
    )
    if not signed:
        reader.end()
        if trusted:
            connection.send(Message(60).string(algorithm).string(blob).build())
            return None
        return False
    signature_blob = reader.string()
    reader.end()
    if not trusted:
        return False
    key, signature = (
        HostKey.from_bytes(blob),
        Signature.from_bytes(signature_blob),
    )
    payload = Message(0).string(connection.session_id).raw(prefix).build().body
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(key.key).verify(
            signature.data, payload
        )
    except InvalidSignature:
        return False
    return True


def client_publickey_authenticate(
    connection: Connection,
    username: str,
    private_key: ed25519.Ed25519PrivateKey,
) -> None:
    begin_client_auth(connection)
    host = HostKey("ssh-ed25519", private_key.public_key().public_bytes_raw())
    request = (
        Message(50)
        .string(username)
        .string("ssh-connection")
        .string("publickey")
        .boolean(True)
        .string("ssh-ed25519")
        .string(host.to_bytes())
    )
    signed = (
        Message(0)
        .string(connection.session_id)
        .raw(request.build().to_payload())
        .build()
        .body
    )
    signature = Signature("ssh-ed25519", private_key.sign(signed))
    connection.send(request.string(signature.to_bytes()).build())
    finish_client_auth(connection)


def server_authenticate(
    connection: Connection, credentials: Credentials
) -> None:
    request = MessageReader(connection.expect(5))
    if request.text() != "ssh-userauth":
        raise ProtocolError("only ssh-userauth service supported")
    request.end()
    connection.send(Message(6).string("ssh-userauth").build())
    for _ in range(12):
        reader = MessageReader(connection.expect(50))
        username, service, method = reader.text(), reader.text(), reader.text()
        accepted = False
        if method == "password":
            change, password = reader.boolean(), reader.string()
            if change:
                # New password explicitly consumed; changes rejected.
                reader.string()
            reader.end()
            accepted = (
                not change
                and service == "ssh-connection"
                and credentials.matches(username, password)
            )
        elif method == "publickey":
            if (
                service == "ssh-connection"
                and username == credentials.username
            ):
                outcome = verify_user_key(connection, credentials, reader)
                if outcome is None:
                    continue  # Valid unsigned probe was answered with PK_OK.
                accepted = outcome
            else:
                reader.read(
                    reader.remaining()
                )  # Wrong account/service: reject opaque body.
        elif method == "none":
            reader.end()
        else:
            # Unsupported authentication-method fields are opaque and rejected.
            reader.read(reader.remaining())
        if accepted:
            connection.send(RawPacket(52))
            return
        connection.send(
            Message(51).string(credentials.methods()).boolean(False).build()
        )
    raise AuthenticationError("too many authentication attempts")


def begin_client_auth(connection: Connection) -> None:
    if connection.auth_service_started:
        return
    connection.send(Message(5).string("ssh-userauth").build())
    reader = MessageReader(connection.expect(6))
    if reader.text() != "ssh-userauth":
        raise ProtocolError("wrong accepted service")
    reader.end()
    connection.auth_service_started = True


def client_authenticate(
    connection: Connection, credentials: Credentials
) -> None:
    begin_client_auth(connection)
    if credentials.password is None:
        raise AuthenticationError("password not supplied")
    connection.send(
        Message(50)
        .string(credentials.username)
        .string("ssh-connection")
        .string("password")
        .boolean(False)
        .string(credentials.password)
        .build()
    )
    finish_client_auth(connection)


def finish_client_auth(connection: Connection) -> None:
    for _ in range(20):
        packet = connection.receive()
        reader = MessageReader(packet)
        if packet.msgtype == 52:
            reader.end()
            return
        if packet.msgtype == 53:
            reader.text()  # Banner intentionally not printed by this API.
            reader.text()  # Language tag.
            reader.end()
            continue
        if packet.msgtype == 51:
            methods, partial = reader.text(), reader.boolean()
            reader.end()
            raise AuthenticationError(
                f"authentication rejected; methods={methods}, "
                f"partial={partial}"
            )
        raise ProtocolError(
            f"unexpected authentication message {packet.msgtype}"
        )
    raise ProtocolError("too many authentication banners")


def handle_global(connection: Connection, packet: SshPacket) -> bool:
    if packet.msgtype != 80:
        return False
    reader = MessageReader(packet)
    reader.text()  # Global request name; all are rejected.
    want_reply = reader.boolean()
    reader.read(
        reader.remaining()
    )  # Unsupported request-specific data is opaque.
    if want_reply:
        connection.send(RawPacket(82))
    return True


@dataclass(frozen=True)
class ChannelData:
    stream: int
    data: bytes


@dataclass(frozen=True)
class ChannelRequest:
    name: str
    want_reply: bool
    data: bytes

    def reader(self) -> DataReader:
        return DataReader(self.data)


class Channel:
    """One SSH session channel, including bounded receive/send windows."""

    def __init__(
        self,
        connection: Connection,
        remote: int,
        send_window: int,
        max_packet: int,
    ):
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
        connection.send(
            Message(90)
            .string("session")
            .u32(0)
            .u32(CHANNEL_WINDOW)
            .u32(CHANNEL_PACKET)
            .build()
        )
        while True:
            packet = connection.receive()
            if handle_global(connection, packet):
                continue
            reader = MessageReader(packet)
            if packet.msgtype == 92:
                raise ProtocolError("server rejected session channel")
            if packet.msgtype != 91 or reader.u32() != 0:
                raise ProtocolError("expected session open confirmation")
            result = cls(connection, reader.u32(), reader.u32(), reader.u32())
            reader.end()
            return result

    @classmethod
    def open_server(cls, connection: Connection) -> Channel:
        while True:
            packet = connection.receive()
            if handle_global(connection, packet):
                continue
            if packet.msgtype != 90:
                raise ProtocolError("expected channel open")
            reader = MessageReader(packet)
            name, remote = reader.text(), reader.u32()
            window, max_packet = reader.u32(), reader.u32()
            if name != "session":
                connection.send(
                    Message(92)
                    .u32(remote)
                    .u32(1)
                    .string("only session channels supported")
                    .string("")
                    .build()
                )
                continue
            reader.end()
            result = cls(connection, remote, window, max_packet)
            connection.send(
                Message(91)
                .u32(remote)
                .u32(0)
                .u32(CHANNEL_WINDOW)
                .u32(CHANNEL_PACKET)
                .build()
            )
            return result

    def request(
        self, name: str, data: bytes = b"", want_reply: bool = True
    ) -> None:
        self.request_reply = None
        self.connection.send(
            Message(98)
            .u32(self.remote)
            .string(name)
            .boolean(want_reply)
            .raw(data)
            .build()
        )

    def reply(self, success: bool) -> None:
        self.connection.send(
            Message(99 if success else 100).u32(self.remote).build()
        )

    def send_data(self, data: bytes, stream: int = 0) -> int:
        if self.sent_eof or self.sent_close or self.peer_closed:
            raise ProtocolError("data sent on a closed channel")
        count = min(len(data), self.send_window, self.max_packet)
        if count:
            message = Message(95 if stream else 94).u32(self.remote)
            if stream:
                message.u32(stream)
            self.connection.send(message.string(data[:count]).build())
            self.send_window -= count
        return count

    def acknowledge(self, count: int) -> None:
        if count < 0 or self.recv_window + count > CHANNEL_WINDOW:
            raise ProtocolError("invalid channel receive-window replenishment")
        if count and not self.sent_close:
            self.connection.send(
                Message(93).u32(self.remote).u32(count).build()
            )
            self.recv_window += count

    def eof(self) -> None:
        if not self.sent_eof and not self.sent_close:
            self.connection.send(Message(96).u32(self.remote).build())
            self.sent_eof = True

    def close(self) -> None:
        if not self.sent_close:
            self.connection.send(Message(97).u32(self.remote).build())
            self.sent_close = True

    def _extra_open(self, packet: SshPacket) -> None:
        reader = MessageReader(packet)
        reader.text()
        remote = reader.u32()
        # Additional channel type-specific fields are opaque and rejected.
        self.connection.send(
            Message(92)
            .u32(remote)
            .u32(1)
            .string("only one session per connection supported")
            .string("")
            .build()
        )

    def handle(self, packet: SshPacket) -> ChannelData | ChannelRequest | None:
        if handle_global(self.connection, packet):
            return None
        if packet.msgtype == 90:
            self._extra_open(packet)
            return None
        reader = MessageReader(packet)
        if packet.msgtype not in range(93, 101) or reader.u32() != 0:
            raise ProtocolError(f"unexpected channel message {packet.msgtype}")
        if packet.msgtype in (94, 95):
            stream = reader.u32() if packet.msgtype == 95 else 0
            data = reader.string()
            reader.end()
            if (
                self.peer_eof
                or self.peer_closed
                or len(data) > self.recv_window
                or len(data) > CHANNEL_PACKET
            ):
                raise ProtocolError(
                    "channel data violates state/window/packet limit"
                )
            self.recv_window -= len(data)
            return ChannelData(stream, data)
        if packet.msgtype == 98:
            name, want_reply = reader.text(), reader.boolean()
            return ChannelRequest(
                name, want_reply, reader.read(reader.remaining())
            )
        self._control(packet.msgtype, reader)
        reader.end()
        return None

    def _control(self, msgtype: int, reader: MessageReader) -> None:
        if msgtype == 93:
            adjustment = reader.u32()
            if self.send_window + adjustment > 0xFFFFFFFF:
                raise ProtocolError("channel window overflow")
            self.send_window += adjustment
        elif msgtype == 96:
            self.peer_eof = True
        elif msgtype == 97:
            self.peer_closed = True
            self.close()
        elif msgtype in (99, 100):
            self.request_reply = msgtype == 99

    def handle_client_request(self, request: ChannelRequest) -> None:
        reader = request.reader()
        if request.name == "exit-status":
            self.exit_status = reader.read32be()
            require_end(reader)
        elif request.name == "exit-signal":
            self.exit_status = 255
            # Explicitly consume signal, core flag, description, language.
            readlstr(reader)
            reader.readbyte()
            readlstr(reader)
            readlstr(reader)
            require_end(reader)
        if request.want_reply:
            self.reply(request.name in ("exit-status", "exit-signal"))


@dataclass(frozen=True)
class CommandResult:
    stdout: bytes
    stderr: bytes
    exit_status: int


class ClientSession:
    def __init__(
        self,
        channel: Channel,
        source: BinaryIO,
        stdout: BinaryIO,
        stderr: BinaryIO,
    ):
        self.channel = channel
        self.source = source
        self.stdout = stdout
        self.stderr = stderr
        try:
            self.input_fd: int | None = source.fileno()
        except (AttributeError, io.UnsupportedOperation):
            self.input_fd = None

    def run(self, command: str | None) -> int:
        body = (
            Message(0).string(command).build().body
            if command is not None
            else b""
        )
        self.channel.request("exec" if command is not None else "shell", body)
        while self.channel.request_reply is None:
            self._packet()
            if self.channel.peer_closed:
                raise ProtocolError("session closed before request reply")
        if not self.channel.request_reply:
            raise ProtocolError("server rejected exec/shell request")
        while not self.channel.peer_closed:
            self._step()
        return self.channel.exit_status

    def _step(self) -> None:
        channel = self.channel
        can_input = not channel.sent_eof and channel.send_window > 0
        if can_input and self.input_fd is None:
            self._input()
        readers: list[int | socket.socket] = [
            channel.connection.transport.sock
        ]
        if can_input and self.input_fd is not None:
            readers.append(self.input_fd)
        immediate = (
            can_input and self.input_fd is None and not channel.sent_eof
        )
        transport = channel.connection.transport
        writers = [transport.sock] if transport.outgoing else []
        ready, writable, _ = select.select(
            readers, writers, [], 0 if immediate else None
        )
        if writable:
            transport.flush()
        if channel.connection.transport.sock in ready:
            self._packet()
        if (
            self.input_fd is not None
            and self.input_fd in ready
            and not channel.peer_closed
        ):
            self._input()

    def _input(self) -> None:
        count = min(self.channel.send_window, self.channel.max_packet)
        data = (
            self.source.read(count)
            if self.input_fd is None
            else os.read(self.input_fd, count)
        )
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
                raise ProtocolError(
                    f"unsupported extended-data stream: {event.stream}"
                )
            self._write(
                self.stderr if event.stream else self.stdout, event.data
            )
            channel.acknowledge(len(event.data))
        elif isinstance(event, ChannelRequest):
            channel.handle_client_request(event)


class SSHClient:
    def __init__(
        self,
        sock: socket.socket,
        pinned_key: HostKey,
        curve_only: bool = False,
    ):
        self.connection = Connection(
            sock, pinned_key=pinned_key, curve_only=curve_only
        )

    def authenticate(self, username: str, password: str) -> None:
        client_authenticate(self.connection, Credentials(username, password))

    def authenticate_publickey(
        self, username: str, private_key: ed25519.Ed25519PrivateKey
    ) -> None:
        client_publickey_authenticate(self.connection, username, private_key)

    def run(
        self, command: str | None, input_data: bytes = b""
    ) -> CommandResult:
        stdout, stderr = io.BytesIO(), io.BytesIO()
        status = self.run_stream(
            command, io.BytesIO(input_data), stdout, stderr
        )
        return CommandResult(stdout.getvalue(), stderr.getvalue(), status)

    def run_stream(
        self,
        command: str | None,
        source: BinaryIO,
        stdout: BinaryIO,
        stderr: BinaryIO,
    ) -> int:
        channel = Channel.open_client(self.connection)
        return ClientSession(channel, source, stdout, stderr).run(command)

    def close(self) -> None:
        self.connection.close()


class ServerSession:
    """Non-PTY shell/exec session with full-duplex, bounded pipe forwarding."""

    def __init__(self, channel: Channel):
        self.channel = channel
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
        arguments = (
            ["/bin/sh"] if command is None else ["/bin/sh", "-c", command]
        )
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            bufsize=0,
        )
        self.process = process
        assert process.stdin and process.stdout and process.stderr
        for stream in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        self.outputs[process.stdout.fileno()] = (process.stdout, 0)
        self.outputs[process.stderr.fileno()] = (process.stderr, 1)

    def _request(self, request: ChannelRequest) -> None:
        success = False
        if request.name in ("exec", "shell") and self.process is None:
            reader = request.reader()
            command = readlstr(reader) if request.name == "exec" else None
            require_end(reader)
            try:
                self._start(command)
                success = True
            except OSError:
                success = False
        elif request.name == "signal" and self.process is not None:
            reader = request.reader()
            name = readlstr(reader)
            require_end(reader)
            allowed = {
                "INT": signal.SIGINT,
                "TERM": signal.SIGTERM,
                "HUP": signal.SIGHUP,
                "KILL": signal.SIGKILL,
            }
            if name in allowed and self.process.poll() is None:
                os.killpg(self.process.pid, allowed[name])
                success = True
        # Other request bodies (pty-req, env, subsystem, etc.) remain opaque
        # and are explicitly rejected, never reported as successfully applied.
        if request.want_reply:
            self.channel.reply(success)

    def _packet(self) -> None:
        event = self.channel.handle(self.channel.connection.receive())
        if isinstance(event, ChannelRequest):
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
            assert self.process is not None and self.process.stdin is not None
            self.process.stdin.close()
            self.stdin_closed = True

    def _write_stdin(self) -> None:
        assert self.process is not None and self.process.stdin is not None
        try:
            count = os.write(self.process.stdin.fileno(), self.pending_input)
        except BlockingIOError:
            return
        except BrokenPipeError:
            count = len(self.pending_input)
            self._close_stdin()
        del self.pending_input[:count]
        self.channel.acknowledge(count)

    def _read_output(self, descriptor: int) -> None:
        channel = self.channel
        stream, kind = self.outputs[descriptor]
        try:
            data = os.read(
                descriptor, min(channel.send_window, channel.max_packet)
            )
        except BlockingIOError:
            return
        if not data:
            del self.outputs[descriptor]
            stream.close()
        else:
            if channel.send_data(data, kind) != len(data):
                raise ProtocolError("internal channel-window accounting error")

    def _step(self) -> None:
        assert self.process is not None and self.process.stdin is not None
        if self.channel.peer_eof and not self.pending_input:
            self._close_stdin()
        network = self.channel.connection.transport.sock
        readers: list[int | socket.socket] = [network]
        if self.channel.send_window:
            readers.extend(self.outputs)
        writers: list[int | socket.socket] = []
        if self.channel.connection.transport.outgoing:
            writers.append(network)
        if self.pending_input and not self.stdin_closed:
            writers.append(self.process.stdin.fileno())
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
        if not self.stdin_closed and self.process.stdin.fileno() in writable:
            self._write_stdin()

    def _finish(self) -> None:
        assert self.process is not None
        status = self.process.wait()
        status = status if status >= 0 else 128 - status
        body = Message(0).u32(status & 0xFFFFFFFF).build().body
        self.channel.request("exit-status", body, want_reply=False)
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
            ready, writable, _ = select.select(
                [network], writers, [], remaining
            )
            if writable:
                transport.flush()
            if ready:
                self._packet()
            if not ready and not writable:
                break

    def _cleanup(self) -> None:
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
        for stream in (
            self.process.stdin,
            self.process.stdout,
            self.process.stderr,
        ):
            if stream is not None and not stream.closed:
                stream.close()


class SSHServer:
    """Configured login; commands run as the existing OS user."""

    def __init__(
        self,
        host_key: ed25519.Ed25519PrivateKey,
        credentials: Credentials,
        curve_only: bool = False,
    ):
        if not credentials.methods():
            raise ValueError(
                "server requires a password or an authorized user key"
            )
        self.host_key = host_key
        self.credentials = credentials
        self.curve_only = curve_only

    def serve(self, sock: socket.socket) -> None:
        connection: Connection | None = None
        try:
            connection = Connection(
                sock,
                server=True,
                host_key=self.host_key,
                curve_only=self.curve_only,
            )
            server_authenticate(connection, self.credentials)
            ServerSession(Channel.open_server(connection)).run()
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
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    public = HostKey("ssh-ed25519", key.public_key().public_bytes_raw())
    with path.open("xb") as destination:
        os.chmod(path, 0o600)
        destination.write(private)
    public_path = Path(str(path) + ".pub")
    with public_path.open("xb") as destination:
        destination.write(public.openssh() + b"\n")
    print(public.fingerprint())


def password_from_environment(name: str | None) -> str:
    if name is not None:
        if name not in os.environ:
            raise ValueError(
                f"password environment variable {name!r} is not set"
            )
        return os.environ[name]
    return getpass.getpass("Password: ")


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
            print(
                f"{prefix} KEX_INIT public blob="
                f"{len(value.packet.pubkey)} bytes"
            )
        elif isinstance(value.packet, Msg31_ECDHReply):
            packet = value.packet
            print(
                f"{prefix} KEX_REPLY public blob={len(packet.pubkey)} bytes "
                f"host={packet.hostkey.fingerprint()} "
                f"signature={len(packet.signature.data)} bytes"
            )
        else:
            print(
                f"{prefix} type={value.packet.msgtype} "
                f"length={value.packet_length}"
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    keygen = commands.add_parser("keygen", help="generate an Ed25519 host key")
    keygen.add_argument("path", type=Path)
    decode = commands.add_parser(
        "decode", help="decode a direction-marked hex capture"
    )
    decode.add_argument("path", type=Path)
    server = commands.add_parser(
        "server", help="authenticated non-PTY shell/exec"
    )
    client = commands.add_parser(
        "client", help="connect and run a shell/command"
    )
    for endpoint in (server, client):
        endpoint.add_argument("--port", type=int, default=2222)
        endpoint.add_argument("--user", required=True)
        endpoint.add_argument(
            "--host-key",
            type=Path,
            required=True,
            help="server: private key; client: pinned .pub file",
        )
        endpoint.add_argument(
            "--password-env",
            help="read password from this environment variable",
        )
        endpoint.add_argument(
            "--curve25519", action="store_true", help="disable hybrid ML-KEM"
        )
        endpoint.add_argument(
            "--timeout",
            type=float,
            default=30,
            help="timeout for incomplete network reads, seconds",
        )
    server.add_argument(
        "--authorized-key",
        type=Path,
        help="allow this Ed25519 user public key",
    )
    client.add_argument(
        "--identity", type=Path, help="Ed25519 user private key"
    )
    server.add_argument("--listen", default="127.0.0.1")
    server.add_argument("--once", action="store_true")
    client.add_argument("host")
    client.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="remote command; omit for a non-PTY shell",
    )
    return parser


def run_server(args: argparse.Namespace) -> None:
    authorized = (
        ()
        if args.authorized_key is None
        else (HostKey.from_public_file(args.authorized_key),)
    )
    password = (
        None
        if authorized and args.password_env is None
        else password_from_environment(args.password_env)
    )
    credentials = Credentials(args.user, password, authorized)
    server = SSHServer(
        load_private_key(args.host_key), credentials, args.curve25519
    )
    with socket.create_server((args.listen, args.port)) as listener:
        print(
            f"Listening on {args.listen}:{listener.getsockname()[1]}",
            file=sys.stderr,
        )
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
    pinned = HostKey.from_public_file(args.host_key)
    password = (
        None
        if args.identity is not None
        else password_from_environment(args.password_env)
    )
    with socket.create_connection(
        (args.host, args.port), timeout=args.timeout
    ) as sock:
        client = SSHClient(sock, pinned, args.curve25519)
        if args.identity is not None:
            client.authenticate_publickey(
                args.user, load_private_key(args.identity)
            )
        else:
            assert password is not None
            client.authenticate(args.user, password)
        command = " ".join(args.command) if args.command else None
        return client.run_stream(
            command, sys.stdin.buffer, sys.stdout.buffer, sys.stderr.buffer
        )


def main() -> int:
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
