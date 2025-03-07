# automatically generated by the FlatBuffers compiler, do not modify

# namespace: Example

import flatbuffers
from flatbuffers.compat import import_numpy
np = import_numpy()

class Ability(object):
    __slots__ = ['_tab']

    @classmethod
    def SizeOf(cls):
        return 8

    # Ability
    def Init(self, buf, pos):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Ability
    def id(self): return self._tab.Get(flatbuffers.number_types.Uint32Flags, self._tab.Pos + flatbuffers.number_types.UOffsetTFlags.py_type(0))
    # Ability
    def distance(self): return self._tab.Get(flatbuffers.number_types.Uint32Flags, self._tab.Pos + flatbuffers.number_types.UOffsetTFlags.py_type(4))

def CreateAbility(builder, id, distance):
    builder.Prep(4, 8)
    builder.PrependUint32(distance)
    builder.PrependUint32(id)
    return builder.Offset()


class AbilityT(object):

    # AbilityT
    def __init__(self):
        self.id = 0  # type: int
        self.distance = 0  # type: int

    @classmethod
    def InitFromBuf(cls, buf, pos):
        ability = Ability()
        ability.Init(buf, pos)
        return cls.InitFromObj(ability)

    @classmethod
    def InitFromPackedBuf(cls, buf, pos=0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, pos)
        return cls.InitFromBuf(buf, pos+n)

    @classmethod
    def InitFromObj(cls, ability):
        x = AbilityT()
        x._UnPack(ability)
        return x

    # AbilityT
    def _UnPack(self, ability):
        if ability is None:
            return
        self.id = ability.id()
        self.distance = ability.distance()

    # AbilityT
    def Pack(self, builder):
        return CreateAbility(builder, self.id, self.distance)
