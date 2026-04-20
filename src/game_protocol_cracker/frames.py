"""Pluggable frame parsers for custom binary protocols.

A ``Frame`` is the smallest independently addressable unit the cipher
operates on: it typically has a plaintext command tag and an encrypted
payload. The exact byte layout varies between games, so this module
ships several concrete formats and a ``Protocol`` for plugging in
custom variants.

Supported formats out of the box:

* :class:`MagicPrefixedFormat` - magic word, flags, check byte, length
  prefixed command name, length prefixed payload. This is the layout
  most commonly seen in Chinese mobile game SDKs.
* :class:`LengthPrefixedFormat` - 4-byte big-endian length, then the
  body (command + payload).
* :class:`VarintPrefixedFormat` - protobuf-style varint length prefix.
* :class:`DelimiterFormat` - bytes-delimited messages (e.g. newline).
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class Frame:
    """A decoded frame: command tag, encrypted/plain payload and metadata."""

    cmd: str
    data: bytes
    direction: str = ""
    flags: int = 0
    check: int = 0
    timestamp: float = 0.0
    raw_offset: int = 0
    raw_size: int = 0
    extra: dict[str, object] = field(default_factory=dict)


class FrameFormat(Protocol):
    """Strategy protocol for byte-stream tokenization."""

    name: str

    def iter_frames(self, buffer: bytes) -> Iterator[Frame]:
        """Yield frames out of ``buffer``. Trailing partial frames are ignored."""
        ...


@dataclass(frozen=True)
class MagicPrefixedFormat:
    """Magic-word prefixed frame with explicit command and payload lengths.

    Layout (big-endian):

        [2] magic
        [1] flags
        [1] check
        [2] cmd_len
        [N] cmd (ASCII)
        [4] data_len
        [M] data (still encrypted)
    """

    magic: int = 0x70A3
    name: str = "magic-prefixed"

    def iter_frames(self, buffer: bytes) -> Iterator[Frame]:
        offset = 0
        end = len(buffer)
        while offset + 10 <= end:
            magic = struct.unpack(">H", buffer[offset : offset + 2])[0]
            if magic != self.magic:
                offset += 1
                continue
            flags = buffer[offset + 2]
            check = buffer[offset + 3]
            cmd_len = struct.unpack(">H", buffer[offset + 4 : offset + 6])[0]
            header_end = offset + 6 + cmd_len + 4
            if header_end > end:
                break
            cmd = buffer[offset + 6 : offset + 6 + cmd_len].decode(
                "ascii", errors="replace"
            )
            data_len = struct.unpack(
                ">I", buffer[offset + 6 + cmd_len : header_end]
            )[0]
            total = 6 + cmd_len + 4 + data_len
            if offset + total > end:
                break
            data = buffer[header_end : header_end + data_len]
            yield Frame(
                cmd=cmd,
                data=data,
                flags=flags,
                check=check,
                raw_offset=offset,
                raw_size=total,
            )
            offset += total


@dataclass(frozen=True)
class LengthPrefixedFormat:
    """Length-prefixed frames. Body layout is delegated to ``body_split``.

    By default the body is treated as a single opaque payload with no
    command tag. Pass ``body_split="ascii-delim"`` to split the body on
    the first NUL byte (common layout: ``cmd\\0payload``).
    """

    length_bytes: int = 4
    big_endian: bool = True
    body_split: str = "none"  # "none" or "ascii-delim"
    name: str = "length-prefixed"

    def iter_frames(self, buffer: bytes) -> Iterator[Frame]:
        end = len(buffer)
        offset = 0
        fmt = ">" if self.big_endian else "<"
        if self.length_bytes == 2:
            fmt += "H"
        elif self.length_bytes == 4:
            fmt += "I"
        elif self.length_bytes == 8:
            fmt += "Q"
        else:
            raise ValueError(
                f"Unsupported length_bytes={self.length_bytes} (must be 2, 4 or 8)"
            )
        while offset + self.length_bytes <= end:
            length = struct.unpack(
                fmt, buffer[offset : offset + self.length_bytes]
            )[0]
            frame_end = offset + self.length_bytes + length
            if frame_end > end:
                break
            body = buffer[offset + self.length_bytes : frame_end]
            cmd = ""
            data = body
            if self.body_split == "ascii-delim":
                nul = body.find(b"\x00")
                if nul >= 0:
                    cmd = body[:nul].decode("ascii", errors="replace")
                    data = body[nul + 1 :]
            yield Frame(
                cmd=cmd,
                data=data,
                raw_offset=offset,
                raw_size=self.length_bytes + length,
            )
            offset = frame_end


@dataclass(frozen=True)
class VarintPrefixedFormat:
    """Protobuf-style varint length prefix, then opaque body.

    The body is emitted as ``data`` with an empty ``cmd``; upstream code
    can decode further with a schema.
    """

    name: str = "varint-prefixed"

    def iter_frames(self, buffer: bytes) -> Iterator[Frame]:
        offset = 0
        end = len(buffer)
        while offset < end:
            length, consumed = _read_varint(buffer, offset)
            if length is None:
                break
            body_start = offset + consumed
            body_end = body_start + length
            if body_end > end:
                break
            yield Frame(
                cmd="",
                data=buffer[body_start:body_end],
                raw_offset=offset,
                raw_size=consumed + length,
            )
            offset = body_end


@dataclass(frozen=True)
class DelimiterFormat:
    """Bytes-delimited frames (default: newline-delimited JSON)."""

    delimiter: bytes = b"\n"
    name: str = "delimiter"

    def iter_frames(self, buffer: bytes) -> Iterator[Frame]:
        offset = 0
        end = len(buffer)
        dlen = len(self.delimiter)
        if dlen == 0:
            raise ValueError("delimiter must be at least one byte")
        while offset < end:
            idx = buffer.find(self.delimiter, offset)
            if idx < 0:
                break
            body = buffer[offset:idx]
            yield Frame(
                cmd="",
                data=body,
                raw_offset=offset,
                raw_size=(idx - offset) + dlen,
            )
            offset = idx + dlen


def _read_varint(buffer: bytes, pos: int) -> tuple[int | None, int]:
    result = 0
    shift = 0
    start = pos
    while pos < len(buffer):
        byte = buffer[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if not (byte & 0x80):
            return result, pos - start
        shift += 7
        if shift >= 64:
            return None, 0
    return None, 0


@dataclass
class FrameParser:
    """Façade that binds a :class:`FrameFormat` to a stream buffer."""

    format: FrameFormat = field(
        default_factory=lambda: MagicPrefixedFormat()
    )

    def parse(self, buffer: bytes) -> list[Frame]:
        return list(self.format.iter_frames(buffer))
