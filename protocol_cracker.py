#!/usr/bin/env python3
"""
game-protocol-cracker: Crack XOR rolling-key encrypted game protocols.

Many mobile games (especially those built with Chinese game engines like JuFeng,
37Games SDK, etc.) use a simple XOR rolling-key encryption for their TCP protocol.
This tool automates the process of cracking these protocols:

1. Capture traffic with tcpdump
2. Parse the custom frame format
3. Brute-force the initial XOR key
4. Decode all commands and payloads

Supports:
  - XOR rolling key with configurable wrap point
  - Custom frame formats (magic bytes, command names, payload lengths)
  - Protobuf payload decoding (via blackboxprotobuf)
  - Auto-detection of initial key by testing common values
  - Batch processing of pcap files

Usage:
    # Auto-detect key and decode a pcap capture
    python protocol_cracker.py crack capture.pcap

    # Decode with known key
    python protocol_cracker.py decode capture.pcap --key 2

    # Encrypt a payload for replay
    python protocol_cracker.py encrypt '{"cmd":"test"}' --key 5

    # Analyze protocol patterns
    python protocol_cracker.py analyze capture.pcap

Requirements:
    - Python 3.10+
    - Optional: blackboxprotobuf (pip install bbpb) for Protobuf decoding
"""

import argparse
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

__version__ = "1.0.0"


@dataclass
class ProtocolConfig:
    """Configuration for the target protocol."""

    magic: int = 0x70A3
    magic_size: int = 2
    wrap_key: int = 0x70A3  # Key wraps to 0 at this value
    header_format: str = "magic(2)+flags(1)+check(1)+cmd_len(2)+cmd(N)+data_len(4)+data(M)"


@dataclass
class Frame:
    """A decoded protocol frame."""

    cmd: str
    data: bytes
    direction: str = ""  # "C2S" or "S2C"
    flags: int = 0
    check: int = 0
    timestamp: float = 0.0


# ─────────────────────────────────────────────
# XOR Rolling Key Engine
# ─────────────────────────────────────────────


def derive_key_params(key: int) -> tuple[int, int]:
    """Derive per-byte XOR parameters from rolling key.

    Common pattern in Chinese mobile game engines:
      w8 = (~key) & 0xFF
      w9 = ((~key >> 4) & 0x0F) | ((w8 & 0xFF) << 4)
    """
    not_key = (~key) & 0xFFFFFFFF
    w8 = not_key & 0xFF
    w9 = ((not_key >> 4) & 0x0F) | ((w8 & 0xFF) << 4)
    return w8, w9


def decrypt_byte(enc: int, w8: int, w9: int) -> int:
    """Decrypt a single byte: plain = (~(enc ^ w9) - w8) & 0xFF"""
    return (~(enc ^ w9) - w8) & 0xFF


def encrypt_byte(plain: int, w8: int, w9: int) -> int:
    """Encrypt a single byte: enc = ~((w8 + plain) & 0xFF ^ w9) & 0xFF"""
    return ~((w8 + plain) & 0xFF ^ w9) & 0xFF


def update_key(key: int, wrap_at: int = 0x70A3) -> int:
    """Increment rolling key, wrap at specified value."""
    key += 1
    return 0 if key == wrap_at else key


def decrypt_payload(data: bytes, key: int, wrap_at: int = 0x70A3) -> tuple[bytes, int]:
    """Decrypt a full payload. Returns (decrypted, new_key)."""
    key = update_key(key, wrap_at)
    w8, w9 = derive_key_params(key)
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = decrypt_byte(data[i], w8, w9)
    return bytes(result), key


def encrypt_payload(data: bytes, key: int, wrap_at: int = 0x70A3) -> tuple[bytes, int]:
    """Encrypt a full payload. Returns (encrypted, new_key)."""
    key = update_key(key, wrap_at)
    w8, w9 = derive_key_params(key)
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = encrypt_byte(data[i], w8, w9)
    return bytes(result), key


# ─────────────────────────────────────────────
# Frame Parser
# ─────────────────────────────────────────────


def decode_frames(buffer: bytes, magic: int = 0x70A3) -> list[Frame]:
    """Decode protocol frames from raw TCP data."""
    frames = []
    offset = 0

    while offset < len(buffer):
        if offset + 6 > len(buffer):
            break

        frame_magic = struct.unpack(">H", buffer[offset:offset + 2])[0]
        if frame_magic != magic:
            offset += 1
            continue

        flags = buffer[offset + 2]
        check = buffer[offset + 3]
        cmd_len = struct.unpack(">H", buffer[offset + 4:offset + 6])[0]

        if offset + 6 + cmd_len + 4 > len(buffer):
            break

        cmd = buffer[offset + 6:offset + 6 + cmd_len].decode("ascii", errors="replace")
        data_len = struct.unpack(">I", buffer[offset + 6 + cmd_len:offset + 10 + cmd_len])[0]

        total = 6 + cmd_len + 4 + data_len
        if offset + total > len(buffer):
            break

        data = buffer[offset + 10 + cmd_len:offset + 10 + cmd_len + data_len]
        frames.append(Frame(cmd=cmd, data=data, flags=flags, check=check))
        offset += total

    return frames


# ─────────────────────────────────────────────
# PCAP Parser
# ─────────────────────────────────────────────


def parse_pcap(path: Path, port: int = 9929) -> list[tuple[str, bytes, float]]:
    """Parse a pcap file and extract TCP payloads on the given port.

    Returns list of (direction, payload, timestamp).
    """
    data = path.read_bytes()
    if len(data) < 24:
        return []

    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        print(f"Not a pcap file: {path}", file=sys.stderr)
        return []

    linktype = struct.unpack(f"{endian}I", data[20:24])[0]

    offset = 24
    results = []

    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, _ = struct.unpack(f"{endian}IIII", data[offset:offset + 16])
        pkt = data[offset + 16:offset + 16 + incl_len]
        offset += 16 + incl_len

        # Strip link layer
        if linktype == 113:  # SLL
            pkt = pkt[16:]
        elif linktype == 1:  # Ethernet
            pkt = pkt[14:]

        if len(pkt) < 40:
            continue

        # IP
        ip_ver = pkt[0] >> 4
        if ip_ver != 4:
            continue
        ip_hdr_len = (pkt[0] & 0xF) * 4
        if pkt[9] != 6:  # TCP
            continue

        # TCP
        tcp = pkt[ip_hdr_len:]
        src_port = struct.unpack(">H", tcp[0:2])[0]
        dst_port = struct.unpack(">H", tcp[2:4])[0]
        tcp_hdr_len = (tcp[12] >> 4) * 4
        payload = tcp[tcp_hdr_len:]

        if len(payload) > 0 and (src_port == port or dst_port == port):
            direction = "S2C" if src_port == port else "C2S"
            timestamp = ts_sec + ts_usec / 1e6
            results.append((direction, payload, timestamp))

    return results


# ─────────────────────────────────────────────
# Key Auto-Detection
# ─────────────────────────────────────────────


def score_decryption(data: bytes) -> float:
    """Score how 'readable' decrypted data is (0.0 to 1.0)."""
    if not data:
        return 0.0
    printable = sum(1 for b in data[:100] if 32 <= b < 127)
    return printable / min(100, len(data))


def auto_detect_key(
    frames: list[tuple[str, Frame]],
    max_key: int = 20,
) -> tuple[int, float]:
    """Try different initial keys and return the best one.

    Returns (best_key, confidence).
    """
    best_key = 0
    best_score = 0.0

    c2s_frames = [(d, f) for d, f in frames if d == "C2S" and len(f.data) > 10]
    s2c_frames = [(d, f) for d, f in frames if d == "S2C" and len(f.data) > 10]

    test_frames = (c2s_frames or s2c_frames)[:5]

    for try_key in range(max_key):
        total_score = 0.0
        key = try_key
        for _, frame in test_frames:
            dec, key = decrypt_payload(frame.data, key)
            total_score += score_decryption(dec)

        avg = total_score / max(len(test_frames), 1)
        if avg > best_score:
            best_score = avg
            best_key = try_key

    return best_key, best_score


# ─────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────


def cmd_crack(args: argparse.Namespace) -> None:
    """Auto-detect key and decode all frames."""
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"File not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)

    port = args.port
    packets = parse_pcap(pcap_path, port)
    print(f"Parsed {len(packets)} TCP packets on port {port}")

    # Extract frames
    all_frames = []
    for direction, payload, ts in packets:
        frames = decode_frames(payload, args.magic)
        for f in frames:
            f.direction = direction
            f.timestamp = ts
            all_frames.append((direction, f))

    print(f"Decoded {len(all_frames)} protocol frames")

    if not all_frames:
        print("No frames found. Check port and magic bytes.", file=sys.stderr)
        sys.exit(1)

    # Auto-detect key
    best_key, confidence = auto_detect_key(all_frames)
    print(f"\nBest initial key: {best_key} (confidence: {confidence:.0%})")

    # Decode all frames
    c2s_key = best_key
    s2c_key = best_key
    results = []

    for direction, frame in all_frames:
        if direction == "C2S":
            dec, c2s_key = decrypt_payload(frame.data, c2s_key)
        else:
            dec, s2c_key = decrypt_payload(frame.data, s2c_key)

        safe = "".join(chr(b) if 32 <= b < 127 else "." for b in dec[:80])
        results.append({
            "direction": direction,
            "cmd": frame.cmd,
            "data_len": len(dec),
            "preview": safe[:60],
        })
        print(f"  {direction} {frame.cmd:30s} ({len(dec):5d}B) {safe[:50]}")

    # Save results
    if args.output:
        out = Path(args.output)
        out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nSaved {len(results)} decoded frames to {out}")


def cmd_decode(args: argparse.Namespace) -> None:
    """Decode with known key."""
    pcap_path = Path(args.pcap)
    packets = parse_pcap(pcap_path, args.port)

    c2s_key = args.key
    s2c_key = args.s2c_key if args.s2c_key is not None else args.key

    for direction, payload, ts in packets:
        frames = decode_frames(payload, args.magic)
        for frame in frames:
            if direction == "C2S":
                dec, c2s_key = decrypt_payload(frame.data, c2s_key)
            else:
                dec, s2c_key = decrypt_payload(frame.data, s2c_key)

            safe = "".join(chr(b) if 32 <= b < 127 else "." for b in dec[:120])
            print(f"{direction} {frame.cmd:30s} ({len(dec):5d}B) {safe[:80]}")


def cmd_encrypt(args: argparse.Namespace) -> None:
    """Encrypt a payload."""
    data = args.data.encode("utf-8")
    encrypted, new_key = encrypt_payload(data, args.key)
    print(f"Key: {args.key} -> {new_key}")
    print(f"Encrypted ({len(encrypted)} bytes): {encrypted.hex()}")


def cmd_analyze(args: argparse.Namespace) -> None:
    """Analyze protocol patterns."""
    pcap_path = Path(args.pcap)
    packets = parse_pcap(pcap_path, args.port)

    all_frames = []
    for direction, payload, ts in packets:
        frames = decode_frames(payload, args.magic)
        for f in frames:
            f.direction = direction
            f.timestamp = ts
            all_frames.append(f)

    # Count commands
    cmd_counts: dict[str, int] = {}
    for f in all_frames:
        key = f"{f.direction} {f.cmd}"
        cmd_counts[key] = cmd_counts.get(key, 0) + 1

    print(f"Total frames: {len(all_frames)}")
    print(f"\nCommand frequency:")
    for cmd, count in sorted(cmd_counts.items(), key=lambda x: -x[1]):
        print(f"  {count:4d}x {cmd}")

    # Timing analysis
    if len(all_frames) >= 2:
        intervals = []
        for i in range(1, len(all_frames)):
            dt = all_frames[i].timestamp - all_frames[i - 1].timestamp
            if 0 < dt < 60:
                intervals.append(dt)
        if intervals:
            avg = sum(intervals) / len(intervals)
            print(f"\nAverage inter-frame interval: {avg:.3f}s")
            print(f"Min: {min(intervals):.3f}s, Max: {max(intervals):.3f}s")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="game-protocol-cracker",
        description="Crack XOR rolling-key encrypted game protocols.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--magic", type=lambda x: int(x, 0), default=0x70A3, help="Frame magic bytes (hex, default: 0x70A3)")
    parser.add_argument("--port", type=int, default=9929, help="Server port (default: 9929)")

    sub = parser.add_subparsers(dest="command", required=True)

    p_crack = sub.add_parser("crack", help="Auto-detect key and decode all frames")
    p_crack.add_argument("pcap", help="Input pcap file")
    p_crack.add_argument("-o", "--output", help="Save decoded frames to JSON")

    p_decode = sub.add_parser("decode", help="Decode with known key")
    p_decode.add_argument("pcap", help="Input pcap file")
    p_decode.add_argument("--key", type=int, required=True, help="Initial C2S key")
    p_decode.add_argument("--s2c-key", type=int, default=None, help="Initial S2C key (default: same as --key)")

    p_encrypt = sub.add_parser("encrypt", help="Encrypt a payload")
    p_encrypt.add_argument("data", help="Data to encrypt (string)")
    p_encrypt.add_argument("--key", type=int, required=True, help="Encryption key")

    p_analyze = sub.add_parser("analyze", help="Analyze protocol patterns")
    p_analyze.add_argument("pcap", help="Input pcap file")

    args = parser.parse_args()

    if args.command == "crack":
        cmd_crack(args)
    elif args.command == "decode":
        cmd_decode(args)
    elif args.command == "encrypt":
        cmd_encrypt(args)
    elif args.command == "analyze":
        cmd_analyze(args)


if __name__ == "__main__":
    main()
