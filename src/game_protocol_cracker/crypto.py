"""XOR rolling-key cipher.

Generic implementation of a per-byte cipher that derives its round key
from a rolling 16-bit counter. This pattern appears in a wide range of
mobile game SDKs where the initial key is negotiated during the
handshake and then incremented once per protocol message.

Algorithm (per message):

    key = key + 1
    if key == wrap_at: key = 0
    not_key = (~key) & 0xFFFFFFFF
    w8 = not_key & 0xFF
    w9 = ((not_key >> 4) & 0x0F) | ((w8 & 0xFF) << 4)

Per byte:

    decrypt:  plain = ((~(cipher ^ w9)) & 0xFF - w8) & 0xFF
    encrypt:  cipher = (~((w8 + plain) ^ w9)) & 0xFF

Optional frame integrity byte (used by some variants):

    check = (~((sum(plaintext) + w8) ^ w9)) & 0xFF
"""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_WRAP_KEY = 0x70A3


def derive_key_params(key: int) -> tuple[int, int]:
    """Derive per-byte w8/w9 round parameters from the rolling key counter."""
    not_key = (~key) & 0xFFFFFFFF
    w8 = not_key & 0xFF
    w9 = ((not_key >> 4) & 0x0F) | ((w8 & 0xFF) << 4)
    return w8, w9


def decrypt_byte(enc_byte: int, w8: int, w9: int) -> int:
    """Decrypt a single byte using precomputed round parameters."""
    xored = (~(enc_byte ^ w9)) & 0xFF
    return (xored - w8) & 0xFF


def encrypt_byte(plain_byte: int, w8: int, w9: int) -> int:
    """Encrypt a single byte using precomputed round parameters."""
    return (~(((w8 + plain_byte) & 0xFF) ^ w9)) & 0xFF


def update_key(key: int, wrap_at: int = DEFAULT_WRAP_KEY) -> int:
    """Increment the rolling key counter, wrapping to zero at ``wrap_at``."""
    key += 1
    if key == wrap_at:
        return 0
    return key


def decrypt_payload(
    payload: bytes,
    key: int,
    wrap_at: int = DEFAULT_WRAP_KEY,
) -> tuple[bytes, int]:
    """Decrypt a full payload. Returns ``(decrypted, new_key)``.

    The input ``key`` is the counter *before* this message; the returned
    counter is the one after advancing and decrypting.
    """
    new_key = update_key(key, wrap_at)
    w8, w9 = derive_key_params(new_key)
    out = bytearray(len(payload))
    for i, b in enumerate(payload):
        out[i] = decrypt_byte(b, w8, w9)
    return bytes(out), new_key


def encrypt_payload(
    payload: bytes,
    key: int,
    wrap_at: int = DEFAULT_WRAP_KEY,
) -> tuple[bytes, int]:
    """Encrypt a full payload. Returns ``(encrypted, new_key)``."""
    new_key = update_key(key, wrap_at)
    w8, w9 = derive_key_params(new_key)
    out = bytearray(len(payload))
    for i, b in enumerate(payload):
        out[i] = encrypt_byte(b, w8, w9)
    return bytes(out), new_key


def compute_check(plaintext: bytes, key: int) -> int:
    """Compute the per-frame integrity byte used by some variants.

    ``key`` must already be advanced to the value this frame uses (same
    value that derives w8/w9).
    """
    w8, w9 = derive_key_params(key)
    s = sum(plaintext) & 0xFF
    return (~((s + w8) ^ w9)) & 0xFF


@dataclass
class RollingKeyCipher:
    """Stateful wrapper around the rolling-key primitives.

    Instantiate with the negotiated starting key and call
    :meth:`encrypt` / :meth:`decrypt` in protocol order. The internal
    counter is advanced for you.
    """

    key: int = 0
    wrap_at: int = DEFAULT_WRAP_KEY

    def decrypt(self, payload: bytes) -> bytes:
        out, self.key = decrypt_payload(payload, self.key, self.wrap_at)
        return out

    def encrypt(self, payload: bytes) -> bytes:
        out, self.key = encrypt_payload(payload, self.key, self.wrap_at)
        return out

    def check_byte(self, plaintext: bytes) -> int:
        """Integrity byte for the *next* message given the current key."""
        probe = update_key(self.key, self.wrap_at)
        return compute_check(plaintext, probe)

    def fork(self) -> RollingKeyCipher:
        """Return an independent copy sharing the current counter."""
        return RollingKeyCipher(key=self.key, wrap_at=self.wrap_at)
