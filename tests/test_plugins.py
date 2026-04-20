"""Tests for the plugin registry."""

from __future__ import annotations

import pytest

from game_protocol_cracker.crypto import RollingKeyCipher
from game_protocol_cracker.plugins import (
    get_cipher,
    get_frame_format,
    list_ciphers,
    list_frame_formats,
    register_cipher,
    register_frame_format,
)


def test_builtin_cipher_listed():
    assert "rolling-xor" in list_ciphers()


def test_builtin_formats_listed():
    for name in ("magic-prefixed", "length-prefixed", "varint-prefixed", "delimiter"):
        assert name in list_frame_formats()


def test_get_cipher_returns_instance():
    c = get_cipher("rolling-xor", key=5)
    assert isinstance(c, RollingKeyCipher)
    assert c.key == 5


def test_register_custom_cipher():
    register_cipher("test-alias", lambda **kw: RollingKeyCipher(key=42, **kw))
    c = get_cipher("test-alias")
    assert c.key == 42


def test_register_custom_frame_format():
    class Dummy:
        name = "dummy"

        def iter_frames(self, buffer: bytes):
            yield from ()

    register_frame_format("dummy", lambda **kw: Dummy())
    fmt = get_frame_format("dummy")
    assert fmt.name == "dummy"


def test_get_unknown_raises():
    with pytest.raises(KeyError):
        get_cipher("nope")
    with pytest.raises(KeyError):
        get_frame_format("nope")
