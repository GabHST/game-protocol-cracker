"""Auto-detect the starting rolling key from a batch of captured frames.

Two scoring signals are combined:

* Protobuf wire-format validity of the plaintext (matches games whose
  payloads are schema-less protobuf).
* Printable-ASCII density in the first 200 bytes (matches JSON or raw
  text payloads).

The highest combined score across keys ``0..max_key-1`` wins.
C2S and S2C directions are swept independently; game servers frequently
start with different counters per direction.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from game_protocol_cracker.crypto import (
    DEFAULT_WRAP_KEY,
    decrypt_payload,
)
from game_protocol_cracker.frames import Frame


@dataclass(frozen=True)
class KeyGuess:
    """Result of :func:`auto_detect_key` for one direction."""

    direction: str
    key: int
    confidence: float


def score_plaintext(data: bytes) -> float:
    """Combined readability / protobuf score for candidate plaintext.

    Returns a value in ``[0.0, 1.0]``.
    """
    if not data:
        return 0.0
    protobuf = _protobuf_score(data)
    printable = _printable_score(data)
    # Either signal is a strong positive; take the max so we don't
    # penalise pure-binary protobuf or pure-text JSON.
    return max(protobuf, printable)


def auto_detect_key(
    frames: Iterable[Frame],
    direction: str | None = None,
    max_key: int = 32,
    wrap_at: int = DEFAULT_WRAP_KEY,
    sample_size: int = 8,
) -> KeyGuess:
    """Brute-force the initial key for one direction.

    Parameters
    ----------
    frames:
        Frames from the desired direction. Use all frames and pass
        ``direction`` to filter, or pre-filter the iterable.
    direction:
        If set, only frames matching ``direction`` contribute.
    max_key:
        Upper bound for the brute-force sweep (exclusive).
    wrap_at:
        Wrap value for the rolling key (default: ``0x70A3``).
    sample_size:
        Number of frames used to score each candidate key.
    """
    pool = [
        f
        for f in frames
        if (direction is None or f.direction == direction) and len(f.data) >= 8
    ][:sample_size]
    if not pool:
        return KeyGuess(direction=direction or "?", key=0, confidence=0.0)

    best_key = 0
    best_score = -1.0
    for candidate in range(max_key):
        key = candidate
        total = 0.0
        for frame in pool:
            plain, key = decrypt_payload(frame.data, key, wrap_at)
            total += score_plaintext(plain)
        avg = total / len(pool)
        if avg > best_score:
            best_score = avg
            best_key = candidate

    return KeyGuess(
        direction=direction or "?",
        key=best_key,
        confidence=max(0.0, min(1.0, best_score)),
    )


# --- scoring helpers -------------------------------------------------


def _printable_score(data: bytes) -> float:
    sample = data[:200]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(sample)


def _protobuf_score(data: bytes) -> float:
    """Proportion of bytes consumed by valid protobuf wire-format fields."""
    total = len(data)
    if total == 0:
        return 0.0
    consumed = 0
    pos = 0
    valid_tags = 0
    total_tags = 0
    while pos < total:
        tag, new_pos = _read_varint(data, pos)
        if tag is None or new_pos == pos:
            break
        wire_type = tag & 0x07
        field_no = tag >> 3
        total_tags += 1
        if field_no == 0 or field_no > 536_870_911 or wire_type in (3, 4, 6):
            break
        pos = new_pos
        if wire_type == 0:  # varint
            _, after = _read_varint(data, pos)
            if after is None:
                break
            pos = after
        elif wire_type == 1:  # fixed64
            if pos + 8 > total:
                break
            pos += 8
        elif wire_type == 2:  # length-delimited
            length, after = _read_varint(data, pos)
            if length is None or after + length > total:
                break
            pos = after + length
        elif wire_type == 5:  # fixed32
            if pos + 4 > total:
                break
            pos += 4
        else:
            break
        valid_tags += 1
        consumed = pos
    coverage = consumed / total
    if total_tags == 0:
        return 0.0
    validity = valid_tags / total_tags
    return coverage * validity


def _read_varint(buffer: bytes, pos: int) -> tuple[int | None, int]:
    result = 0
    shift = 0
    start = pos
    while pos < len(buffer):
        byte = buffer[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if not (byte & 0x80):
            return result, pos
        shift += 7
        if shift >= 64:
            return None, start
    return None, start
