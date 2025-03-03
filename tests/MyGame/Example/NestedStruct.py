# automatically generated by the FlatBuffers compiler, do not modify

# namespace: Example

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class NestedStruct(object):
    __slots__ = ['_tab']

    @classmethod
    def SizeOf(cls) -> int:
        return 32

    # NestedStruct
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # NestedStruct
    def A(self, j = None):
        if j is None:
            return [self._tab.Get(flatbuffers.number_types.Int32Flags, self._tab.Pos + flatbuffers.number_types.UOffsetTFlags.py_type(0 + i * 4)) for i in range(self.ALength())]
        elif j >= 0 and j < self.ALength():
            return self._tab.Get(flatbuffers.number_types.Int32Flags, self._tab.Pos + flatbuffers.number_types.UOffsetTFlags.py_type(0 + j * 4))
        else:
            return None

    # NestedStruct
    def AAsNumpy(self):
        return self._tab.GetArrayAsNumpy(flatbuffers.number_types.Int32Flags, self._tab.Pos + 0, self.ALength())

    # NestedStruct
    def ALength(self) -> int:
        return 2

    # NestedStruct
    def AIsNone(self) -> bool:
        return False

    # NestedStruct
    def B(self): return self._tab.Get(flatbuffers.number_types.Int8Flags, self._tab.Pos + flatbuffers.number_types.UOffsetTFlags.py_type(8))
    # NestedStruct
    def C(self, j = None):
        if j is None:
            return [self._tab.Get(flatbuffers.number_types.Int8Flags, self._tab.Pos + flatbuffers.number_types.UOffsetTFlags.py_type(9 + i * 1)) for i in range(self.CLength())]
        elif j >= 0 and j < self.CLength():
            return self._tab.Get(flatbuffers.number_types.Int8Flags, self._tab.Pos + flatbuffers.number_types.UOffsetTFlags.py_type(9 + j * 1))
        else:
            return None

    # NestedStruct
    def CAsNumpy(self):
        return self._tab.GetArrayAsNumpy(flatbuffers.number_types.Int8Flags, self._tab.Pos + 9, self.CLength())

    # NestedStruct
    def CLength(self) -> int:
        return 2

    # NestedStruct
    def CIsNone(self) -> bool:
        return False

    # NestedStruct
    def D(self, j = None):
        if j is None:
            return [self._tab.Get(flatbuffers.number_types.Int64Flags, self._tab.Pos + flatbuffers.number_types.UOffsetTFlags.py_type(16 + i * 8)) for i in range(self.DLength())]
        elif j >= 0 and j < self.DLength():
            return self._tab.Get(flatbuffers.number_types.Int64Flags, self._tab.Pos + flatbuffers.number_types.UOffsetTFlags.py_type(16 + j * 8))
        else:
            return None

    # NestedStruct
    def DAsNumpy(self):
        return self._tab.GetArrayAsNumpy(flatbuffers.number_types.Int64Flags, self._tab.Pos + 16, self.DLength())

    # NestedStruct
    def DLength(self) -> int:
        return 2

    # NestedStruct
    def DIsNone(self) -> bool:
        return False


def CreateNestedStruct(builder, a, b, c, d):
    builder.Prep(8, 32)
    for _idx0 in range(2 , 0, -1):
        builder.PrependInt64(d[_idx0-1])
    builder.Pad(5)
    for _idx0 in range(2 , 0, -1):
        builder.PrependInt8(c[_idx0-1])
    builder.PrependInt8(b)
    for _idx0 in range(2 , 0, -1):
        builder.PrependInt32(a[_idx0-1])
    return builder.Offset()

try:
    from typing import List
except:
    pass

class NestedStruct(object):

    # NestedStruct
    def __init__(self):
        self.a = None  # type: List[int]
        self.b = 0  # type: int
        self.c = None  # type: List[int]
        self.d = None  # type: List[int]

    @classmethod
    def InitFromBuf(cls, buf, pos):
        nestedStruct = NestedStruct()
        nestedStruct.Init(buf, pos)
        return cls.InitFromObj(nestedStruct)

    @classmethod
    def InitFromPackedBuf(cls, buf, pos=0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, pos)
        return cls.InitFromBuf(buf, pos+n)

    @classmethod
    def InitFromObj(cls, nestedStruct):
        x = NestedStruct()
        x._UnPack(nestedStruct)
        return x

    # NestedStruct
    def _UnPack(self, nestedStruct):
        if nestedStruct is None:
            return
        if not nestedStruct.AIsNone():
            if np is None:
                self.a = []
                for i in range(nestedStruct.ALength()):
                    self.a.append(nestedStruct.A(i))
            else:
                self.a = nestedStruct.AAsNumpy()
        self.b = nestedStruct.B()
        if not nestedStruct.CIsNone():
            if np is None:
                self.c = []
                for i in range(nestedStruct.CLength()):
                    self.c.append(nestedStruct.C(i))
            else:
                self.c = nestedStruct.CAsNumpy()
        if not nestedStruct.DIsNone():
            if np is None:
                self.d = []
                for i in range(nestedStruct.DLength()):
                    self.d.append(nestedStruct.D(i))
            else:
                self.d = nestedStruct.DAsNumpy()

    # NestedStruct
    def Pack(self, builder):
        return CreateNestedStruct(builder, self.a, self.b, self.c, self.d)
