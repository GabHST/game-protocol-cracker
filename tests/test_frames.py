"""Tests for the pluggable frame parsers."""

from __future__ import annotations

import struct

import pytest

from game_protocol_cracker.frames import (
    DelimiterFormat,
    FrameParser,
    LengthPrefixedFormat,
    MagicPrefixedFormat,
    VarintPrefixedFormat,
)


def _build_magic_frame(cmd: str, data: bytes, magic: int = 0x70A3) -> bytes:
    cmd_b = cmd.encode("ascii")
    return (
        struct.pack(">H", magic)
        + bytes([0, 0])
        + struct.pack(">H", len(cmd_b))
        + cmd_b
        + struct.pack(">I", len(data))
        + data
    )


class TestMagicPrefixedFormat:
    def test_decodes_single_frame(self):
        buf = _build_magic_frame("LoginReqC2S", b"abc")
        frames = list(MagicPrefixedFormat().iter_frames(buf))
        assert len(frames) == 1
        assert frames[0].cmd == "LoginReqC2S"
        assert frames[0].data == b"abc"

    def test_decodes_multiple_frames(self):
        buf = _build_magic_frame("A", b"xx") + _build_magic_frame("B", b"yyyy")
        frames = list(MagicPrefixedFormat().iter_frames(buf))
        assert [f.cmd for f in frames] == ["A", "B"]
        assert [f.data for f in frames] == [b"xx", b"yyyy"]

    def test_skips_leading_garbage(self):
        buf = b"\x00\x01\x02\xff" + _build_magic_frame("CMD", b"x")
        frames = list(MagicPrefixedFormat().iter_frames(buf))
        assert len(frames) == 1
        assert frames[0].cmd == "CMD"

    def test_stops_on_partial_frame(self):
        full = _build_magic_frame("CMD", b"hello")
        frames = list(MagicPrefixedFormat().iter_frames(full[:-2]))
        assert frames == []

    def test_custom_magic(self):
        buf = _build_magic_frame("CMD", b"x", magic=0x1234)
        frames = list(MagicPrefixedFormat(magic=0x1234).iter_frames(buf))
        assert len(frames) == 1
        assert frames[0].cmd == "CMD"


class TestLengthPrefixedFormat:
    def test_single_frame(self):
        body = b"payload"
        buf = struct.pack(">I", len(body)) + body
        frames = list(LengthPrefixedFormat().iter_frames(buf))
        assert len(frames) == 1
        assert frames[0].data == body

    def test_short_prefix(self):
        body = b"hello"
        buf = struct.pack(">H", len(body)) + body
        fmt = LengthPrefixedFormat(length_bytes=2)
        frames = list(fmt.iter_frames(buf))
        assert frames[0].data == body

    def test_body_split_ascii_delim(self):
        body = b"CMD\x00data"
        buf = struct.pack(">I", len(body)) + body
        fmt = LengthPrefixedFormat(body_split="ascii-delim")
        frames = list(fmt.iter_frames(buf))
        assert frames[0].cmd == "CMD"
        assert frames[0].data == b"data"

    def test_little_endian(self):
        body = b"x"
        buf = struct.pack("<H", len(body)) + body
        fmt = LengthPrefixedFormat(length_bytes=2, big_endian=False)
        frames = list(fmt.iter_frames(buf))
        assert frames[0].data == b"x"

    def test_invalid_length_raises(self):
        with pytest.raises(ValueError):
            list(LengthPrefixedFormat(length_bytes=3).iter_frames(b""))


class TestVarintPrefixedFormat:
    def test_single_frame(self):
        buf = bytes([5]) + b"hello"
        frames = list(VarintPrefixedFormat().iter_frames(buf))
        assert frames[0].data == b"hello"

    def test_multi_byte_varint(self):
        length = 200
        body = bytes(length)
        buf = bytes([0xC8, 0x01]) + body
        frames = list(VarintPrefixedFormat().iter_frames(buf))
        assert frames[0].data == body


class TestDelimiterFormat:
    def test_newline_delimited(self):
        buf = b'{"a":1}\n{"b":2}\n'
        frames = list(DelimiterFormat().iter_frames(buf))
        assert [f.data for f in frames] == [b'{"a":1}', b'{"b":2}']

    def test_custom_delimiter(self):
        buf = b"a|b|c|"
        frames = list(DelimiterFormat(delimiter=b"|").iter_frames(buf))
        assert [f.data for f in frames] == [b"a", b"b", b"c"]

    def test_empty_delimiter_rejected(self):
        with pytest.raises(ValueError):
            list(DelimiterFormat(delimiter=b"").iter_frames(b""))


class TestFrameParser:
    def test_default_format(self):
        buf = _build_magic_frame("X", b"y")
        parser = FrameParser()
        assert len(parser.parse(buf)) == 1
