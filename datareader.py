# written by chatgpt GPT-6 (packaging header only)
# Original helper implementation supplied by the user.
from abc import ABC, abstractmethod
from typing import IO
import struct
import os

"""
FileReader and DataReader provide an easy method of deconstructing binary data into more useful types.

TODO:
    add fileno() to FileReader
"""

class BaseReader(ABC):
    """
    Subclasses need to implement only three primitives:
       tell() -> int
       _seek_raw(pos:int, whence=SEEK_SET) -> int   # no flag bookkeeping
       _read_raw(n:int) -> bytes                     # up to n bytes, never raise

    All EOF / exact-vs-available logic lives here, in terms of those primitives,
    so the two readers cannot drift apart.

    Read contract:
      eof()             -> True iff the most recent read reached end-of-data.
                           Set by any read that comes up short (including a
                           readexact that lands exactly on the end); cleared by
                           seek(). Cheap: just a flag, no I/O.
      readexact(n)      -> exactly n bytes, or raise EOFError consuming nothing.
                           n==0 always returns b"". n is None reads the rest.
      readavailable(n)  -> up to n bytes (fewer near the end), never raises
                           for EOF. n is None reads the rest.
      read = readexact  (back-compat alias; truncated reads are errors here)
      readbyte()        -> exactly 1 byte, or raise EOFError.
    """
    SEEK_SET = 0
    SEEK_CUR = 1
    SEEK_END = 2

    # set True by a read that reaches the end; cleared by seek().
    _at_end = False

    # ---- primitives the subclass must provide ----

    @abstractmethod
    def tell(self) -> int: ...

    @abstractmethod
    def size(self) -> int: ...

    @abstractmethod
    def _seek_raw(self, pos:int, whence=SEEK_SET) -> int:
        """Reposition the cursor. Returns the new absolute position."""
        ...

    @abstractmethod
    def _read_raw(self, n:int) -> bytes:
        """
        Read up to n bytes from the current position and advance by however
        many were actually read. Returns fewer than n (possibly b"") only at
        end-of-data. Must never raise for EOF. n is always a concrete int >= 0.

        Implementations set self._at_end = True iff this read reached the end
        of available data (i.e. could not have returned more). This is the one
        place that observes the boundary, so it is the one place that records
        it -- no extra probe needed.
        """
        ...

    # ---- seek wraps the primitive so it can clear the eof flag in one place ----

    def seek(self, pos:int, whence=SEEK_SET) -> int:
        self._at_end = False
        return self._seek_raw(pos, whence)

    # ---- EOF state ----

    def eof(self) -> bool:
        """
        True iff the most recent read reached end-of-data. Just a flag read;
        no syscall. If the underlying file grew, the next read clears it.
        """
        return self._at_end

    # ---- the two real read methods ----

    def readavailable(self, n: int | None = None) -> bytes:
        """
        Return up to n bytes; fewer (possibly b"") at end-of-data. Never raises
        for EOF. With n is None, returns all remaining bytes.
        """
        if n is None:
            chunks = []
            while True:
                c = self._read_raw(1 << 16)
                if not c:
                    break
                chunks.append(c)
            return b"".join(chunks)
        if n <= 0:
            return b""
        return self._read_raw(n)

    def readexact(self, n: int | None = None) -> bytes:
        """
        Return exactly n bytes, or raise EOFError without moving the cursor.
        n==0 returns b"" (even at EOF). n is None returns all remaining.
        A read that lands exactly on the end succeeds and sets eof(), because
        _read_raw records the boundary it just observed.
        """
        if n is None:
            return self.readavailable(None)
        if n == 0:
            return b""
        here = self.tell()
        data = self._read_raw(n)
        if len(data) != n:
            # short read: this is an error. restore position so the caller
            # can recover (e.g. seek elsewhere and retry).
            self._at_end = False          # nothing consumed; not at end here
            self._seek_raw(here, self.SEEK_SET)
            raise EOFError(f"wanted {n} bytes, only {len(data)} available")
        return data

    # back-compat: read() means "exact". Truncated structured reads are errors.
    def read(self, n: int | None = None) -> bytes:
        return self.readexact(n)

    def readbyte(self) -> int:
        return self.readexact(1)[0]

    def readuntil(self, terminator: bytes) -> bytes:
        """Read through the first terminator, including it in the result.

        Return the remaining bytes if EOF occurs first, or b"" at EOF.
        The terminator must be nonempty bytes. Bytes after the terminator
        remain unread, including any fetched while searching in chunks.
        """
        if not isinstance(terminator, bytes):
            raise TypeError("terminator must be bytes")
        if not terminator:
            raise ValueError("terminator must not be empty")

        data = bytearray()
        search_start = 0
        while True:
            chunk = self.readavailable(1 << 16)
            if not chunk:
                return bytes(data)
            data.extend(chunk)
            index = data.find(terminator, search_start)
            if index != -1:
                end = index + len(terminator)
                unread = len(data) - end
                if unread:
                    self.seek(-unread, self.SEEK_CUR)
                return bytes(data[:end])
            # Retain possible matches spanning the next chunk boundary.
            search_start = max(0, len(data) - len(terminator) + 1)

    def readline(self, terminator: str = "\n", encoding: str = "utf-8") -> str:
        """Read and decode through terminator, retaining it in the text.

        Encode the terminator and decode the result using encoding. Invalid
        text raises UnicodeDecodeError after consuming the bytes; no bytes
        are silently discarded. An unterminated final line is returned at EOF.
        """
        return self.readuntil(terminator.encode(encoding)).decode(encoding)

    """
    Skip forward by the specified nr of bytes.
    """
    def skip(self, count:int) -> None:
        self.seek(count, self.SEEK_CUR)

    """
    Reads a text string of <n> bytes.
    """
    def readstr(self, n, encoding='utf-8', strip=False):
        data = self.read(n)
        txt = data.decode(encoding, errors='ignore')
        txt = txt.rstrip("\x00")
        if strip:
            txt = txt.rstrip()
        return txt

    """
    Read various types of integers, in either little- or big-endian style.
    """
    def reads16le(self):
        return struct.unpack("<h", self.read(2))[0]
    def read16le(self):
        return struct.unpack("<H", self.read(2))[0]
    def read24le(self):
        l, h = struct.unpack("<HB", self.read(3))
        return (h<<16) + l
    def read32le(self):
        return struct.unpack("<L", self.read(4))[0]
    def read48le(self):
        l, h = struct.unpack("<LH", self.read(6))
        return (h<<32) + l
    def read64le(self):
        return struct.unpack("<Q", self.read(8))[0]
    def read96le(self):
        l, h = struct.unpack("<QL", self.read(12))
        return (h<<64) + l
    def read128le(self):
        l, h = struct.unpack("<QQ", self.read(16))
        return (h<<64) + l

    def read16be(self):
        return struct.unpack(">H", self.read(2))[0]
    def read24be(self):
        h, l = struct.unpack(">BH", self.read(3))
        return (h<<16) + l
    def read32be(self):
        return struct.unpack(">L", self.read(4))[0]
    def read48be(self):
        h, l = struct.unpack(">HL", self.read(6))
        return (h<<32) + l
    def read64be(self):
        return struct.unpack(">Q", self.read(8))[0]
    def read96be(self):
        h, l = struct.unpack(">LQ", self.read(12))
        return (h<<64) + l
    def read128be(self):
        h, l = struct.unpack(">QQ", self.read(16))
        return (h<<64) + l
    def readfloat64be(self):
        return struct.unpack(">d", self.read(8))[0]
    def readfloat64le(self):
        return struct.unpack("<d", self.read(8))[0]

class StreamRange:
    def __init__(self, fh, start, size):
        self.fh = fh
        self.start = start
        if size is None:
            self.end = None
        else:
            self.end = self.start + size

    def tell(self):
        return self.fh.tell()-self.start

    def seek(self, ofs, whence=BaseReader.SEEK_SET):
        if whence==BaseReader.SEEK_SET:
            res = self.fh.seek(self.start + ofs) - self.start
        elif whence==BaseReader.SEEK_CUR:
            res = self.fh.seek(ofs, whence) - self.start
        elif whence==BaseReader.SEEK_END:
            if self.end is None:
                res = self.fh.seek(ofs, whence) - self.start
            else:
                res = self.fh.seek(self.end + ofs, BaseReader.SEEK_SET) - self.start
        return res

    def read(self, n=None):
        if self.end is None:
            return self.fh.read(n)
        remaining = self.end - self.start - self.tell()
        if n is None or n>remaining:
            n = remaining

        return self.fh.read(n)


class FileReader(BaseReader):
    def __init__(self, fh:IO):
        self.fh = fh

    def fileno(self):
        return self.fh.fileno()

    def size(self):
        # todo: should i implement a seek(end) alternative?
        return os.fstat(self.fileno()).st_size

    def tell(self):
        return self.fh.tell()

    def _seek_raw(self, pos, whence=BaseReader.SEEK_SET):
        return self.fh.seek(pos, whence)

    def subreader(self, n=None):
        return FileReader(StreamRange(self.fh, self.fh.tell(), n))

    def _read_raw(self, n:int) -> bytes:
        # file objects already return up-to-n bytes and never raise at EOF,
        # which is exactly the _read_raw contract.
        data = self.fh.read(n)
        # a short read definitively hit the end. (a full read *might* be
        # exactly at the end too, but we can't know that without another
        # syscall, so we leave the flag for the next read to discover.)
        if len(data) < n:
            self._at_end = True
        return data

    def readzstr(self, encoding='utf-8') -> str:
        data = []
        while True:
            byte = self.readavailable(1)
            if not byte or byte == b"\x00":
                break
            data.append(byte[0])
        return bytes(data).decode(encoding)


class DataReader(BaseReader):
    def __init__(self, data:bytes):
        self.data = data
        self.pos = 0

    def size(self):
        return len(self.data)

    def tell(self):
        return self.pos

    def _seek_raw(self, pos, whence=BaseReader.SEEK_SET):
        match whence:
            case self.SEEK_SET: pass
            case self.SEEK_CUR: pos += self.pos
            case self.SEEK_END: pos += len(self.data)
        if pos < 0:
            raise ValueError()
        self.pos = pos
        return pos

    def have(self, n):
        return self.pos + n <= len(self.data)

    def remaining(self):
        return len(self.data) - self.pos

    def _read_raw(self, n:int) -> bytes:
        # return up to n bytes, never raise at EOF.
        end = min(self.pos + n, len(self.data))
        out = self.data[self.pos:end]
        self.pos = end
        # we know the length for free, so we can give the strong guarantee:
        # eof() is True the instant the cursor reaches the end, even on a
        # perfectly-aligned exact read.
        if end == len(self.data):
            self._at_end = True
        return out

    def subreader(self, n=None):
        if n is None:
            return DataReader(self.data[self.pos:])
        else:
            return DataReader(self.data[self.pos:self.pos+n])

    def readzstr(self, encoding='utf-8') -> str:
        i = self.data.find(b"\x00", self.pos)
        if i==-1:
            return self.readavailable().decode(encoding)
        p0 = self.pos
        self.pos = i+1
        return self.data[p0:self.pos-1].decode(encoding)

import unittest
class TestReader(unittest.TestCase):
    def test_readuntil(self) -> None:
        from io import BytesIO

        data = b"prefix\x00\xffmiddle\x00\xfftail"
        for reader in (DataReader(data), FileReader(BytesIO(data))):
            with self.subTest(reader=type(reader).__name__):
                self.assertEqual(reader.readuntil(b"\x00\xff"), b"prefix\x00\xff")
                self.assertEqual(reader.tell(), 8)
                self.assertFalse(reader.eof())
                self.assertEqual(reader.readuntil(b"\x00\xff"), b"middle\x00\xff")
                self.assertEqual(reader.readuntil(b"\x00\xff"), b"tail")
                self.assertTrue(reader.eof())
                self.assertEqual(reader.readuntil(b"\x00\xff"), b"")

    def test_readuntil_chunk_boundary(self) -> None:
        from io import BytesIO

        # The first terminator spans a chunk boundary and overlaps a prefix.
        prefix = b"x" * ((1 << 16) - 3) + b"a"
        data = prefix + b"aaab" + b"tail"
        for reader in (DataReader(data), FileReader(BytesIO(data))):
            with self.subTest(reader=type(reader).__name__):
                self.assertEqual(reader.readuntil(b"aaab"), prefix + b"aaab")
                self.assertEqual(reader.tell(), len(prefix) + 4)
                self.assertFalse(reader.eof())
                self.assertEqual(reader.read(), b"tail")

    def test_readuntil_long_terminator(self) -> None:
        from io import BytesIO

        terminator = b"a" * ((1 << 16) + 1) + b"b"
        data = b"prefix" + terminator + b"tail"
        for reader in (DataReader(data), FileReader(BytesIO(data))):
            with self.subTest(reader=type(reader).__name__):
                self.assertEqual(reader.readuntil(terminator), data[:-4])
                self.assertEqual(reader.read(), b"tail")

    def test_readuntil_invalid_terminator(self) -> None:
        from io import BytesIO

        for reader in (DataReader(b"abc"), FileReader(BytesIO(b"abc"))):
            with self.subTest(reader=type(reader).__name__):
                with self.assertRaises(ValueError):
                    reader.readuntil(b"")
                with self.assertRaises(TypeError):
                    reader.readuntil("\n")
                self.assertEqual(reader.tell(), 0)

    def test_readline(self) -> None:
        from io import BytesIO

        data = "\nhello\ncafé\r\nlast".encode("utf-8")
        for reader in (DataReader(data), FileReader(BytesIO(data))):
            with self.subTest(reader=type(reader).__name__):
                self.assertEqual(reader.readline(), "\n")
                self.assertEqual(reader.readline(), "hello\n")
                self.assertEqual(reader.readline("\r\n"), "café\r\n")
                self.assertEqual(reader.readline(), "last")
                self.assertEqual(reader.readline(), "")

    def test_readline_encoding(self) -> None:
        from io import BytesIO

        data = b"caf\xe9|\xff\nrest"
        for reader in (DataReader(data), FileReader(BytesIO(data))):
            with self.subTest(reader=type(reader).__name__):
                self.assertEqual(reader.readline("|", "latin-1"), "café|")
                with self.assertRaises(UnicodeDecodeError):
                    reader.readline()
                self.assertEqual(reader.read(), b"rest")

    def test_readuntil_subreader(self) -> None:
        from io import BytesIO

        data = b"skipline\nend\noutside"
        for reader in (DataReader(data), FileReader(BytesIO(data))):
            with self.subTest(reader=type(reader).__name__):
                reader.seek(4)
                subreader = reader.subreader(8)
                self.assertEqual(subreader.readline(), "line\n")
                self.assertEqual(subreader.readline(), "end")
                self.assertEqual(subreader.readline(), "")

    def testRd(self):
        r = DataReader(b"abcdefghijklmnopqrstu\x00\x00xy")
        self.assertEqual(r.read(4), b"abcd")
        self.assertEqual(r.readstr(4), "efgh")
        self.assertEqual(r.readbyte(), 0x69)
        self.assertEqual(r.read32le(), 0x6d6c6b6a)
        self.assertEqual(r.read32be(), 0x6e6f7071)
        self.assertEqual(r.readstr(6), "rstu")

    def testReadRest(self):
        from io import BytesIO
        self.checkReadRest(DataReader(bytes(range(16))))
        self.checkReadRest(FileReader(BytesIO(bytes(range(16)))))

    def checkReadRest(self, r):
        self.assertEqual(r.read(4), b"\x00\x01\x02\x03")
        self.assertEqual(r.read(), bytes(range(4, 16)))

    def testSeekTell(self):
        from io import BytesIO
        self.checkSeekTell(DataReader(bytes(range(256))))
        self.checkSeekTell(FileReader(BytesIO(bytes(range(256)))))

    def checkSeekTell(self, r):
        self.assertEqual(r.tell(), 0)
        self.assertEqual(r.read(4), b"\x00\x01\x02\x03")
        self.assertEqual(r.tell(), 4)

        self.assertEqual(r.seek(8), 8)

        self.assertEqual(r.tell(), 8)
        self.assertEqual(r.read(4), b"\x08\x09\x0a\x0b")

        self.assertEqual(r.seek(-4, r.SEEK_CUR), 8)
        self.assertEqual(r.read(4), b"\x08\x09\x0a\x0b")

        r.seek(-4, r.SEEK_END)
        self.assertEqual(r.read(4), b"\xfc\xfd\xfe\xff")

        with self.assertRaises(EOFError):
            r.readbyte()

        r.seek(0)
        self.assertEqual(r.tell(), 0)
        self.assertEqual(r.read(4), b"\x00\x01\x02\x03")
        self.assertEqual(r.tell(), 4)

    def testIntReads(self):
        from io import BytesIO
        self.checkIntReads(DataReader(bytes(range(256))))
        self.checkIntReads(FileReader(BytesIO(bytes(range(256)))))

    def checkIntReads(self, r):
        self.assertEqual(r.readbyte(), 0)
        self.assertEqual(r.read16le(), 0x0201)
        self.assertEqual(r.read24le(), 0x050403)
        self.assertEqual(r.read32le(), 0x09080706)
        self.assertEqual(r.read48le(), 0x0f0e0d0c0b0a)
        self.assertEqual(r.read64le(), 0x1716151413121110)
        self.assertEqual(r.read96le(), 0x232221201f1e1d1c1b1a1918)
        self.assertEqual(r.read128le(), 0x333231302f2e2d2c2b2a292827262524)
        self.assertEqual(r.read16be(), 0x3435)
        self.assertEqual(r.read24be(), 0x363738)
        self.assertEqual(r.read32be(), 0x393a3b3c)
        self.assertEqual(r.read48be(), 0x3d3e3f404142)
        self.assertEqual(r.read64be(), 0x434445464748494a)
        self.assertEqual(r.read96be(), 0x4b4c4d4e4f50515253545556)
        self.assertEqual(r.read128be(), 0x5758595a5b5c5d5e5f60616263646566)

    def testEof(self):
        tests = [
                self.checkEof1a,
                self.checkEof1b,
                self.checkEof1c,
                self.checkEof2,
                self.checkEof3,
                self.checkEof4,
                ]
        from io import BytesIO
        for tst in tests:
            tst(DataReader(bytes(range(16))))
            tst(FileReader(BytesIO(bytes(range(16)))))

    def checkEof1a(self, r):
        self.assertEqual(r.readbyte(), 0)
        self.assertEqual(r.read(15), bytes(range(1, 16)))
        self.assertEqual(r.read(0), b"")
        with self.assertRaises(EOFError):
            r.read(1)

    def checkEof1b(self, r):
        self.assertEqual(r.readbyte(), 0)
        # failed exact read consumes nothing: position stays put...
        with self.assertRaises(EOFError):
            r.read(16)
        # ...so the 15 remaining bytes are still readable.
        self.assertEqual(r.read(15), bytes(range(1, 16)))
        with self.assertRaises(EOFError):
            r.read(1)

    def checkEof1c(self, r):
        self.assertEqual(r.readbyte(), 0)
        self.assertEqual(r.read(0), b"")
        self.assertEqual(r.read(15), bytes(range(1, 16)))
        with self.assertRaises(EOFError):
            r.read(1)

    def checkEof2(self, r):
        self.assertEqual(r.read(16), bytes(range(16)))
        with self.assertRaises(EOFError):
            r.read(1)

    def checkEof3(self, r):
        self.assertEqual(r.read(16), bytes(range(16)))
        r.seek(15)
        with self.assertRaises(EOFError):
            r.read(2)

    def checkEof4(self, r):
        self.assertEqual(r.read(16), bytes(range(16)))
        r.seek(15)
        self.assertEqual(r.readbyte(), 15)
        with self.assertRaises(EOFError):
            r.read(2)

    def testExactVsAvailable(self):
        from io import BytesIO
        self.checkExactVsAvailable(DataReader(bytes(range(16))))
        self.checkExactVsAvailable(FileReader(BytesIO(bytes(range(16)))))

    def checkExactVsAvailable(self, r):
        # eof() is false at the start
        self.assertFalse(r.eof())
        self.assertEqual(r.tell(), 0)

        # readexact lands exactly on the end -> succeeds
        self.assertEqual(r.readexact(16), bytes(range(16)))

        # readexact(0) at EOF -> b"", no throw
        self.assertEqual(r.readexact(0), b"")
        # read() is the exact alias
        self.assertEqual(r.read(0), b"")

        # seek clears the at-end condition
        r.seek(10)
        self.assertFalse(r.eof())

        # readavailable past the end returns the short tail and reaches EOF.
        # a short read sets eof() on BOTH readers (the end was observed).
        self.assertEqual(r.readavailable(100), bytes(range(10, 16)))
        self.assertTrue(r.eof())
        # and never throws once empty
        self.assertEqual(r.readavailable(5), b"")

    def testAlignedEofStrongVsWeak(self):
        # The one place the two readers intentionally differ:
        # a perfectly-aligned exact read that consumes through the end.
        # DataReader knows the length for free -> eof() is True immediately.
        # FileReader would need a syscall to know -> it reports eof() only
        # after the next read comes up empty. This is a deliberate tradeoff
        # to keep eof() free of I/O.
        from io import BytesIO

        d = DataReader(bytes(range(16)))
        d.readexact(16)
        self.assertTrue(d.eof())          # strong guarantee

        f = FileReader(BytesIO(bytes(range(16))))
        f.readexact(16)
        self.assertFalse(f.eof())         # not yet known...
        self.assertEqual(f.readavailable(1), b"")
        self.assertTrue(f.eof())          # ...discovered on next read

    def testConsumeNothingOnShort(self):
        from io import BytesIO
        self.checkConsumeNothing(DataReader(bytes(range(16))))
        self.checkConsumeNothing(FileReader(BytesIO(bytes(range(16)))))

    def checkConsumeNothing(self, r):
        r.seek(14)
        # asking for 4 with only 2 left: raises and leaves position untouched
        with self.assertRaises(EOFError):
            r.readexact(4)
        self.assertEqual(r.tell(), 14)
        # the 2 bytes that were there can still be read
        self.assertEqual(r.readavailable(4), bytes([14, 15]))

    def testReadAllNone(self):
        from io import BytesIO
        for r in (DataReader(bytes(range(16))), FileReader(BytesIO(bytes(range(16))))):
            r.seek(4)
            self.assertEqual(r.readexact(None), bytes(range(4, 16)))
            self.assertTrue(r.eof())

def new(arg):
    if type(arg)==bytes:
        return DataReader(arg)
    return FileReader(arg)
