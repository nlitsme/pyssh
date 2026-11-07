# written by chatgpt GPT-6 (packaging header only)
# Original helper implementation supplied by the user.
from abc import ABC, abstractmethod
from typing import IO
import struct

class BaseWriter(ABC):
    """
    Subclasses need to implement:
       tell() -> int
       seek(pos:int, whence=SEEK_SET) -> int
       write(data)
       writebyte(b)
    """
    SEEK_SET = 0
    SEEK_CUR = 1
    SEEK_END = 2

    """
    Returns the current position of the stream.
    """
    @abstractmethod
    def tell(self) -> int: ...

    """
    Repositions the current position of the stream.
    Also clears the EOF state.

    Returns the new absolute position.
    """
    @abstractmethod
    def seek(self, pos:int, whence=SEEK_SET) -> int: ...

    """
    Writes the specified bytes.
    """
    @abstractmethod
    def write(self, data:bytes) -> None: ...

    """
    Writes 1 byte, or throws on EOF.
    """
    @abstractmethod
    def writebyte(self, b:int) -> None: ...

    def writefixed(self, data, size):
        self.write(data.zfill(size)[:size])

    def writestr(self, txt, encoding='utf-8'):
        self.write(txt.encode(encoding))

    def write16le(self, value):
        self.write(struct.pack("<H", value))
    def write24le(self, value):
        self.write(struct.pack("<HB", value&0xffff, value>>16))
    def write32le(self, value):
        self.write(struct.pack("<L", value))
    def write48le(self, value):
        self.write(struct.pack("<LH", value&0xFFFFFFFF, value>>32))
    def write64le(self, value):
        self.write(struct.pack("<Q", value))
    def write96le(self, value):
        self.write(struct.pack("<QL", value&0xFFFFFFFFFFFFFFFF, value>>64))
    def write128le(self, value):
        self.write(struct.pack("<QQ", value&0xFFFFFFFFFFFFFFFF, value>>64))

    def write16be(self, value):
        self.write(struct.pack(">H", value))
    def write24be(self, value):
        self.write(struct.pack(">BH", value>>16, value&0xFFFF))
    def write32be(self, value):
        self.write(struct.pack(">L", value))
    def write48be(self, value):
        self.write(struct.pack(">HL", value>>32, value&0xFFFFFFFF))
    def write64be(self, value):
        self.write(struct.pack(">Q", value))
    def write96be(self, value):
        self.write(struct.pack(">LQ", value>>64, value&0xFFFFFFFFFFFFFFFF))
    def write128be(self, value):
        self.write(struct.pack(">QQ", value>>64, value&0xFFFFFFFFFFFFFFFF))


class FileWriter(BaseWriter):
    def __init__(self, fh:IO):
        self.fh = fh

    def tell(self):
        return self.fh.tell()

    def seek(self, pos, whence=BaseWriter.SEEK_SET):
        self.fh.seek(pos, whence)

    def write(self, data):
        self.fh.write(data)

    def writebyte(self, value):
        self.write(struct.pack(">B", value))


class DataWriter(BaseWriter):
    """
    DataWriter's result can be obtained with `getvalue`, like BytesIO and StringIO.
    """
    def __init__(self):
        self.data = []
        self.pos = 0

    def getvalue(self):
        return bytes(self.data)

    def tell(self):
        return self.pos

    def seek(self, pos, whence=BaseWriter.SEEK_SET):
        match whence:           
            case self.SEEK_SET: pass
            case self.SEEK_CUR: pos += self.pos
            case self.SEEK_END: pos += len(self.data)
        if pos < 0:
            raise ValueError()
        self.pos = pos

    def writebyte(self, value):
        if self.pos >= len(self.data):
            self.data.extend([0] * (self.pos-len(self.data)+1))
        self.data[self.pos] = value
        self.pos += 1

    def write(self, data):
        if self.pos+len(data) >= len(self.data):
            self.data.extend([0] * (self.pos-len(self.data)+1))
        self.data[self.pos:self.pos+len(data)] = data
        self.pos += len(data)


def new(arg=None):
    if arg:
        return FileWriter(arg)
    return DataWriter()

import unittest
class TestWriter(unittest.TestCase):
    def testWr(self):
        w = DataWriter()
        w.writebyte(1)
        w.writestr("txt")
        w.write32le(0x12345678)

        self.assertEqual(w.getvalue(), b'\x01txtxV4\x12')

    def testIntWrites(self):
        from io import BytesIO
        w = DataWriter()
        self.checkIntWrites(w)
        self.assertEqual(w.getvalue(), bytes(range(0x67)))
        d = BytesIO()
        self.checkIntWrites(FileWriter(d))
        self.assertEqual(d.getvalue(), bytes(range(0x67)))

    def checkIntWrites(self, w):
        w.writebyte(0)
        w.write16le(0x0201)
        w.write24le(0x050403)
        w.write32le(0x09080706)
        w.write48le(0x0f0e0d0c0b0a)
        w.write64le(0x1716151413121110)
        w.write96le(0x232221201f1e1d1c1b1a1918)
        w.write128le(0x333231302f2e2d2c2b2a292827262524)
        w.write16be(0x3435)
        w.write24be(0x363738)
        w.write32be(0x393a3b3c)
        w.write48be(0x3d3e3f404142)
        w.write64be(0x434445464748494a)
        w.write96be(0x4b4c4d4e4f50515253545556)
        w.write128be(0x5758595a5b5c5d5e5f60616263646566)




