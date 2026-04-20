"""Plugin hooks for custom cipher and frame-format variants.

Register a callable or class under a short name, then reference it from
the CLI via ``--cipher <name>`` or ``--frame-format <name>``.
"""

from __future__ import annotations

from collections.abc import Callable

from game_protocol_cracker.crypto import RollingKeyCipher
from game_protocol_cracker.frames import (
    DelimiterFormat,
    FrameFormat,
    LengthPrefixedFormat,
    MagicPrefixedFormat,
    VarintPrefixedFormat,
)

CipherFactory = Callable[..., RollingKeyCipher]
FrameFormatFactory = Callable[..., FrameFormat]

_CIPHERS: dict[str, CipherFactory] = {
    "rolling-xor": lambda **kw: RollingKeyCipher(**kw),
}

_FRAME_FORMATS: dict[str, FrameFormatFactory] = {
    "magic-prefixed": lambda **kw: MagicPrefixedFormat(**kw),
    "length-prefixed": lambda **kw: LengthPrefixedFormat(**kw),
    "varint-prefixed": lambda **kw: VarintPrefixedFormat(**kw),
    "delimiter": lambda **kw: DelimiterFormat(**kw),
}


def register_cipher(name: str, factory: CipherFactory) -> None:
    _CIPHERS[name] = factory


def get_cipher(name: str, **kwargs) -> RollingKeyCipher:
    if name not in _CIPHERS:
        raise KeyError(f"Unknown cipher: {name!r}. Known: {sorted(_CIPHERS)}")
    return _CIPHERS[name](**kwargs)


def register_frame_format(name: str, factory: FrameFormatFactory) -> None:
    _FRAME_FORMATS[name] = factory


def get_frame_format(name: str, **kwargs) -> FrameFormat:
    if name not in _FRAME_FORMATS:
        raise KeyError(
            f"Unknown frame format: {name!r}. Known: {sorted(_FRAME_FORMATS)}"
        )
    return _FRAME_FORMATS[name](**kwargs)


def list_ciphers() -> list[str]:
    return sorted(_CIPHERS)


def list_frame_formats() -> list[str]:
    return sorted(_FRAME_FORMATS)
