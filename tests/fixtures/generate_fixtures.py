"""Generate synthetic pcap fixtures used by the test suite.

Run from the repo root with::

    python tests/fixtures/generate_fixtures.py

The generator builds a short conversation of encrypted magic-prefixed
frames between a fake client and server, wraps them in TCP + IP +
Ethernet, and writes ``sample.pcap``. No real game traffic is used.
"""

from __future__ import annotations

import struct
import sys
from collections.abc import Sequence
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from game_protocol_cracker.crypto import (  # noqa: E402
    compute_check,
    encrypt_payload,
    update_key,
)

MAGIC = 0x70A3
SERVER_IP = "10.0.0.1"
CLIENT_IP = "10.0.0.2"
SERVER_PORT = 9900
CLIENT_PORT = 50555


def _build_plaintext_protobuf(field_values: Sequence[tuple[int, bytes]]) -> bytes:
    """Build a simple protobuf message with length-delimited fields."""
    buf = bytearray()
    for field_no, value in field_values:
        tag = (field_no << 3) | 2
        buf.append(tag)
        buf.append(len(value))
        buf.extend(value)
    return bytes(buf)


def _build_frame(cmd: str, plaintext: bytes, key_before: int) -> tuple[bytes, int]:
    """Build one magic-prefixed frame. Returns (frame_bytes, key_after)."""
    encrypted, key_after = encrypt_payload(plaintext, key_before)
    key_used = update_key(key_before)
    check = compute_check(plaintext, key_used)
    cmd_bytes = cmd.encode("ascii")
    header = (
        struct.pack(">H", MAGIC)
        + bytes([0, check])
        + struct.pack(">H", len(cmd_bytes))
        + cmd_bytes
        + struct.pack(">I", len(encrypted))
    )
    return header + encrypted, key_after


def build_sample(path: Path) -> list[tuple[str, str, bytes]]:
    """Write ``path`` and return the list of (direction, cmd, plaintext)."""
    c2s_key = 0
    s2c_key = 0
    scripted: list[tuple[str, str, bytes]] = [
        ("C2S", "LoginReqC2S", _build_plaintext_protobuf(
            [(1, b"player-demo"), (2, b"token-123")]
        )),
        ("S2C", "LoginRspS2C", _build_plaintext_protobuf(
            [(1, b"ok"), (2, b"session-abc")]
        )),
        ("C2S", "KeepAliveC2S", _build_plaintext_protobuf([(1, b"ping")])),
        ("S2C", "KeepAliveS2C", _build_plaintext_protobuf([(1, b"pong")])),
        ("C2S", "BuildingUpgradeC2S", _build_plaintext_protobuf(
            [(1, b"\x0a"), (2, b"\x03")]
        )),
        ("S2C", "BuildingUpgradeS2C", _build_plaintext_protobuf(
            [(1, b"\x01"), (2, b"done")]
        )),
    ]

    packets = []
    c2s_seq = 1000
    s2c_seq = 2000
    for direction, cmd, plain in scripted:
        if direction == "C2S":
            frame_bytes, c2s_key = _build_frame(cmd, plain, c2s_key)
            pkt = (
                Ether()
                / IP(src=CLIENT_IP, dst=SERVER_IP)
                / TCP(
                    sport=CLIENT_PORT,
                    dport=SERVER_PORT,
                    seq=c2s_seq,
                    flags="PA",
                )
                / Raw(load=frame_bytes)
            )
            c2s_seq += len(frame_bytes)
        else:
            frame_bytes, s2c_key = _build_frame(cmd, plain, s2c_key)
            pkt = (
                Ether()
                / IP(src=SERVER_IP, dst=CLIENT_IP)
                / TCP(
                    sport=SERVER_PORT,
                    dport=CLIENT_PORT,
                    seq=s2c_seq,
                    flags="PA",
                )
                / Raw(load=frame_bytes)
            )
            s2c_seq += len(frame_bytes)
        packets.append(pkt)

    wrpcap(str(path), packets)
    return scripted


if __name__ == "__main__":
    out = HERE / "sample.pcap"
    scripted = build_sample(out)
    print(f"Wrote {out} with {len(scripted)} frames")
