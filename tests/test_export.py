"""Tests for JSON/CSV export."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from game_protocol_cracker.export import export_csv, export_json
from game_protocol_cracker.frames import Frame


def _payload():
    frame = Frame(cmd="LoginReqC2S", data=b"\x00\x01\x02", direction="C2S", flags=0, check=0x42)
    return [(frame, b"hello world")]


def test_export_json(tmp_path: Path):
    path = tmp_path / "out.json"
    n = export_json(_payload(), path)
    assert n == 1
    rows = json.loads(path.read_text(encoding="utf-8"))
    assert rows[0]["cmd"] == "LoginReqC2S"
    assert rows[0]["data_hex"] == "68656c6c6f20776f726c64"
    assert "hello world" in rows[0]["preview"]


def test_export_csv(tmp_path: Path):
    path = tmp_path / "out.csv"
    n = export_csv(_payload(), path)
    assert n == 1
    with path.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["cmd"] == "LoginReqC2S"
    assert rows[0]["check"] == "66"  # 0x42 decimal
