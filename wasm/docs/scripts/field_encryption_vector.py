"""Open wallet-sealed fields outside the browser (Python `cryptography`).

Independent of the page's code: SLIP-10 from the wallet seed to the
contact-encryption X25519 key (m/44'/0'/0'/1'/0'), the SDS $ENC header parsed
by hand, then X25519, HKDF-SHA256 and AES-256-CTR from `cryptography`.

stdin: JSON {"seedHex": ..., "account": 0, "fields": [{"ciphertextHex",
"encHex", "fieldId"}...]}. stdout: JSON {"publicKeyHex", "fields":
[{"plaintextHex"} | {"refused": reason}]}.
"""

import hashlib
import hmac
import json
import struct
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HARDENED = 0x80000000


def contact_key(seed: bytes, account: int) -> X25519PrivateKey:
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    key, chain = digest[:32], digest[32:]
    for index in (44, 0, account, 1, 0):
        data = b"\x00" + key + struct.pack(">I", index | HARDENED)
        digest = hmac.new(chain, data, hashlib.sha512).digest()
        key, chain = digest[:32], digest[32:]
    return X25519PrivateKey.from_private_bytes(key)


def parse_enc(buf: bytes) -> dict:
    if buf[4:8] != b"$ENC":
        raise ValueError("not an $ENC record")
    table = struct.unpack_from("<I", buf, 0)[0]
    vtable = table - struct.unpack_from("<i", buf, table)[0]
    vt_len = struct.unpack_from("<H", buf, vtable)[0]

    def slot(i):
        at = vtable + 4 + 2 * i
        if at >= vtable + vt_len:
            return 0
        return struct.unpack_from("<H", buf, at)[0]

    def vector(i):
        off = slot(i)
        if not off:
            return b""
        pos = table + off
        pos += struct.unpack_from("<I", buf, pos)[0]
        n = struct.unpack_from("<I", buf, pos)[0]
        return bytes(buf[pos + 4:pos + 4 + n])

    def scalar(i, default):
        off = slot(i)
        return buf[table + off] if off else default

    return {
        "version": scalar(0, 1),
        "keyExchange": scalar(1, 0),
        "symmetric": scalar(2, 0),
        "kdf": scalar(3, 0),
        "ephemeral": vector(4),
        "recipientKeyId": vector(6),
        "context": vector(7).decode("utf-8"),
        "rootType": vector(9).decode("utf-8"),
    }


def hkdf(ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def open_field(private: X25519PrivateKey, public: bytes, enc: dict, ciphertext: bytes, field_id: int) -> bytes:
    if (enc["keyExchange"], enc["symmetric"], enc["kdf"]) != (0, 0, 0):
        raise ValueError("unsupported $ENC suite")
    if not enc["context"].startswith("sdn-field-encryption/v1|"):
        raise ValueError("not a field-encryption context")
    if enc["recipientKeyId"] != hashlib.sha256(public).digest()[:8]:
        raise ValueError("sealed for another wallet")
    shared = private.exchange(X25519PublicKey.from_public_bytes(enc["ephemeral"]))
    master = hkdf(shared, enc["context"].encode("utf-8"), 32)
    suffix = struct.pack(">HI", field_id, 0)
    key = hkdf(master, b"flatbuffers-field" + suffix, 32)
    iv = hkdf(master, b"flatbuffers-iv" + suffix, 16)
    decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def main() -> int:
    request = json.load(sys.stdin)
    private = contact_key(bytes.fromhex(request["seedHex"]), request.get("account", 0))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    out = []
    for field in request["fields"]:
        try:
            enc = parse_enc(bytes.fromhex(field["encHex"]))
            plain = open_field(private, public, enc, bytes.fromhex(field["ciphertextHex"]), field["fieldId"])
            out.append({"plaintextHex": plain.hex(), "context": enc["context"]})
        except ValueError as error:
            out.append({"refused": str(error)})
    json.dump({"publicKeyHex": public.hex(), "fields": out}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
