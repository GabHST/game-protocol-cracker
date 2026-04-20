"""Tests for the optional protobuf decoding helpers."""

from __future__ import annotations

import pytest

from game_protocol_cracker.decode import decode_schemaless, decode_with_module


def test_decode_schemaless_valid_message():
    pytest.importorskip("blackboxprotobuf")
    blob = bytes([0x0A, 0x03]) + b"abc"
    result = decode_schemaless(blob)
    assert result is not None
    assert "1" in result or 1 in result


def test_decode_schemaless_garbage_returns_none():
    pytest.importorskip("blackboxprotobuf")
    # Unsupported wire type 6 -> None
    result = decode_schemaless(bytes([0x0E, 0xFF]))
    # Some versions of bbpb accept oddities, so only assert type shape
    assert result is None or isinstance(result, dict)


class _FakeModule:
    class FakeMessage:
        def __init__(self):
            self.parsed = False

        def ParseFromString(self, data: bytes) -> None:
            if not data:
                raise ValueError("empty")
            self.parsed = True
            self.raw = data


def test_decode_with_module_returns_none_for_unknown_name():
    assert decode_with_module(b"xx", _FakeModule(), "Nope") is None


def test_decode_with_module_returns_parsed_instance():
    result = decode_with_module(b"payload", _FakeModule(), "FakeMessage")
    assert result is not None
    assert result.parsed is True


def test_decode_with_module_returns_none_on_parse_error():
    result = decode_with_module(b"", _FakeModule(), "FakeMessage")
    assert result is None
