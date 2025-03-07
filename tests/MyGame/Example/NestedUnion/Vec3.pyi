from __future__ import annotations

import flatbuffers
import numpy as np

import flatbuffers
import typing
from MyGame.Example.NestedUnion.Color import Color
from MyGame.Example.NestedUnion.Test import Test, TestT
from MyGame.Example.NestedUnion.Vec3 import Vec3

uoffset: typing.TypeAlias = flatbuffers.number_types.UOffsetTFlags.py_type

class Vec3(object):
  @classmethod
  def GetRootAs(cls, buf: bytes, offset: int) -> Vec3: ...
  @classmethod
  def GetRootAsVec3(cls, buf: bytes, offset: int) -> Vec3: ...
  def Init(self, buf: bytes, pos: int) -> None: ...
  def x(self) -> float: ...
  def y(self) -> float: ...
  def z(self) -> float: ...
  def test1(self) -> float: ...
  def test2(self) -> typing.Literal[Color.Red, Color.Green, Color.Blue]: ...
  def test3(self) -> Test | None: ...
class Vec3T(object):
  x: float
  y: float
  z: float
  test1: float
  test2: typing.Literal[Color.Red, Color.Green, Color.Blue]
  test3: TestT | None
  @classmethod
  def InitFromBuf(cls, buf: bytes, pos: int) -> Vec3T: ...
  @classmethod
  def InitFromPackedBuf(cls, buf: bytes, pos: int = 0) -> Vec3T: ...
  @classmethod
  def InitFromObj(cls, vec3: Vec3) -> Vec3T: ...
  def _UnPack(self, vec3: Vec3) -> None: ...
  def Pack(self, builder: flatbuffers.Builder) -> None: ...
def Vec3Start(builder: flatbuffers.Builder) -> None: ...
def Start(builder: flatbuffers.Builder) -> None: ...
def Vec3Addx(builder: flatbuffers.Builder, x: float) -> None: ...
def Vec3Addy(builder: flatbuffers.Builder, y: float) -> None: ...
def Vec3Addz(builder: flatbuffers.Builder, z: float) -> None: ...
def Vec3Addtest1(builder: flatbuffers.Builder, test1: float) -> None: ...
def Vec3Addtest2(builder: flatbuffers.Builder, test2: typing.Literal[Color.Red, Color.Green, Color.Blue]) -> None: ...
def Vec3Addtest3(builder: flatbuffers.Builder, test3: uoffset) -> None: ...
def Vec3End(builder: flatbuffers.Builder) -> uoffset: ...
def End(builder: flatbuffers.Builder) -> uoffset: ...

