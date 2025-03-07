# automatically generated by the FlatBuffers compiler, do not modify

# namespace: NestedUnion

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from MyGame.Example.NestedUnion.Test import Test
from typing import Optional
np = import_numpy()

class Vec3(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Vec3()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsVec3(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Vec3
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Vec3
    def x(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Float64Flags, o + self._tab.Pos)
        return 0.0

    # Vec3
    def y(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Float64Flags, o + self._tab.Pos)
        return 0.0

    # Vec3
    def z(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Float64Flags, o + self._tab.Pos)
        return 0.0

    # Vec3
    def test1(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Float64Flags, o + self._tab.Pos)
        return 0.0

    # Vec3
    def test2(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, o + self._tab.Pos)
        return 0

    # Vec3
    def test3(self) -> Optional[Test]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        if o != 0:
            x = o + self._tab.Pos
            obj = Test()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

def Vec3Start(builder: flatbuffers.Builder):
    builder.StartObject(6)

def Start(builder: flatbuffers.Builder):
    Vec3Start(builder)

def Vec3Addx(builder: flatbuffers.Builder, x: float):
    builder.PrependFloat64Slot(0, x, 0.0)

def Addx(builder: flatbuffers.Builder, x: float):
    Vec3Addx(builder, x)

def Vec3Addy(builder: flatbuffers.Builder, y: float):
    builder.PrependFloat64Slot(1, y, 0.0)

def Addy(builder: flatbuffers.Builder, y: float):
    Vec3Addy(builder, y)

def Vec3Addz(builder: flatbuffers.Builder, z: float):
    builder.PrependFloat64Slot(2, z, 0.0)

def Addz(builder: flatbuffers.Builder, z: float):
    Vec3Addz(builder, z)

def Vec3Addtest1(builder: flatbuffers.Builder, test1: float):
    builder.PrependFloat64Slot(3, test1, 0.0)

def Addtest1(builder: flatbuffers.Builder, test1: float):
    Vec3Addtest1(builder, test1)

def Vec3Addtest2(builder: flatbuffers.Builder, test2: int):
    builder.PrependUint8Slot(4, test2, 0)

def Addtest2(builder: flatbuffers.Builder, test2: int):
    Vec3Addtest2(builder, test2)

def Vec3Addtest3(builder: flatbuffers.Builder, test3: Any):
    builder.PrependStructSlot(5, flatbuffers.number_types.UOffsetTFlags.py_type(test3), 0)

def Addtest3(builder: flatbuffers.Builder, test3: Any):
    Vec3Addtest3(builder, test3)

def Vec3End(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return Vec3End(builder)

import MyGame.Example.NestedUnion.Test
try:
    from typing import Optional
except:
    pass

class Vec3T(object):

    # Vec3T
    def __init__(self):
        self.x = 0.0  # type: float
        self.y = 0.0  # type: float
        self.z = 0.0  # type: float
        self.test1 = 0.0  # type: float
        self.test2 = 0  # type: int
        self.test3 = None  # type: Optional[MyGame.Example.NestedUnion.Test.TestT]

    @classmethod
    def InitFromBuf(cls, buf, pos):
        vec3 = Vec3()
        vec3.Init(buf, pos)
        return cls.InitFromObj(vec3)

    @classmethod
    def InitFromPackedBuf(cls, buf, pos=0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, pos)
        return cls.InitFromBuf(buf, pos+n)

    @classmethod
    def InitFromObj(cls, vec3):
        x = Vec3T()
        x._UnPack(vec3)
        return x

    # Vec3T
    def _UnPack(self, vec3):
        if vec3 is None:
            return
        self.x = vec3.x()
        self.y = vec3.y()
        self.z = vec3.z()
        self.test1 = vec3.test1()
        self.test2 = vec3.test2()
        if vec3.test3() is not None:
            self.test3 = MyGame.Example.NestedUnion.Test.TestT.InitFromObj(vec3.test3())

    # Vec3T
    def Pack(self, builder):
        Vec3Start(builder)
        Vec3Addx(builder, self.x)
        Vec3Addy(builder, self.y)
        Vec3Addz(builder, self.z)
        Vec3Addtest1(builder, self.test1)
        Vec3Addtest2(builder, self.test2)
        if self.test3 is not None:
            test3 = self.test3.Pack(builder)
            Vec3Addtest3(builder, test3)
        vec3 = Vec3End(builder)
        return vec3
