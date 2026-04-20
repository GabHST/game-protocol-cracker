"""Serialisation helpers for decoded frames."""

from __future__ import annotations

import base64
import csv
import json
from collections.abc import Iterable
from pathlib import Path

from game_protocol_cracker.frames import Frame


def _frame_to_dict(frame: Frame, plaintext: bytes | None = None) -> dict:
    payload_hex = (plaintext if plaintext is not None else frame.data).hex()
    row: dict = {
        "direction": frame.direction,
        "cmd": frame.cmd,
        "flags": frame.flags,
        "check": frame.check,
        "timestamp": frame.timestamp,
        "data_len": len(frame.data),
        "data_hex": payload_hex,
    }
    preview_bytes = (plaintext if plaintext is not None else frame.data)[:80]
    row["preview"] = "".join(
        chr(b) if 32 <= b < 127 else "." for b in preview_bytes
    )
    if frame.extra:
        row["extra_b64"] = base64.b64encode(
            json.dumps(frame.extra, default=str).encode("utf-8")
        ).decode("ascii")
    return row


def export_json(
    frames: Iterable[tuple[Frame, bytes | None]],
    path: Path,
) -> int:
    """Write frames as a JSON array. Returns the number of rows written."""
    rows = [_frame_to_dict(f, plain) for f, plain in frames]
    path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return len(rows)


def export_csv(
    frames: Iterable[tuple[Frame, bytes | None]],
    path: Path,
) -> int:
    """Write frames as CSV. Returns the number of rows written."""
    rows = [_frame_to_dict(f, plain) for f, plain in frames]
    fieldnames = [
        "direction",
        "cmd",
        "flags",
        "check",
        "timestamp",
        "data_len",
        "data_hex",
        "preview",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return len(rows)
