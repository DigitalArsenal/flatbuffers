from __future__ import annotations

import flatbuffers
import numpy as np

import typing
from typing import cast

uoffset: typing.TypeAlias = flatbuffers.number_types.UOffsetTFlags.py_type

class Curve(object):
  X25519 = cast(int, ...)
  Secp256k1 = cast(int, ...)
  P256 = cast(int, ...)

