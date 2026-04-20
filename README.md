# game-protocol-cracker

[![CI](https://github.com/GabHST/game-protocol-cracker/actions/workflows/ci.yml/badge.svg)](https://github.com/GabHST/game-protocol-cracker/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Analyze XOR rolling-key encrypted game protocols: auto-detect keys, decode frames, export the results.

A generic, MIT-licensed reverse-engineering tool built on `scapy`, `click`, `rich` and
(optionally) `blackboxprotobuf`. Bring your own pcap, pick a frame format, and read
plaintext payloads in seconds.

> **Scope:** security research and interoperability work on applications you are
> authorized to analyze. Respect the terms of service of any third-party software
> before running this against captured traffic.

## Why this exists

A lot of mobile game SDKs protect their TCP messages with a per-message XOR
whose round key is a monotonically incrementing 16-bit counter. Captures look
like gibberish next to plaintext command names. The pattern is simple, but every
game wraps it in a slightly different frame layout (magic bytes, length prefix,
check byte...) and picks its own starting counter. This tool automates the
boring parts:

* brute-force the starting counter per direction
* decrypt every frame in the capture with the recovered keys
* emit JSON / CSV for downstream analysis
* give you a small Python API when the CLI isn't enough

## Install

```bash
pip install game-protocol-cracker

# optional: schema-less protobuf decoding
pip install "game-protocol-cracker[protobuf]"
```

Python 3.10+ is required. Development install:

```bash
git clone https://github.com/GabHST/game-protocol-cracker
cd game-protocol-cracker
pip install -e ".[dev]"
pytest
```

## Quick start

### 1. Capture traffic

Any pcap works. Common rooted-Android recipe:

```bash
adb shell su -c "tcpdump -i any -w /sdcard/capture.pcap port 9000"
adb pull /sdcard/capture.pcap
```

### 2. Crack the encryption

```bash
python -m game_protocol_cracker crack capture.pcap --port 9000 -o decoded.json
```

Example output:

```
---------------------------------- capture.pcap -----------------------------------
+--------------------------------------------+
| Direction | Best key | Confidence | Frames |
|-----------+----------+------------+--------|
| C2S       | 0        | 100%       | 147    |
| S2C       | 2        |  96%       | 201    |
+--------------------------------------------+
+-------------------------------------------------------------+
| Dir | Command            | Bytes | Preview                  |
|-----+--------------------+-------+--------------------------|
| C2S | LoginReqC2S        |    24 | ..player-demo..token-123 |
| S2C | LoginRspS2C        |    17 | ..ok..session-abc        |
| C2S | KeepAliveC2S       |     6 | ..ping                   |
| ...                                                         |
+-------------------------------------------------------------+
```

### 3. Inspect with a known key

If you already know the starting counter (e.g. from RE of the client):

```bash
python -m game_protocol_cracker decode capture.pcap --port 9000 \
    --c2s-key 0 --s2c-key 2
```

### 4. Analyze patterns

```bash
python -m game_protocol_cracker analyze capture.pcap --port 9000
```

Produces a per-command histogram and inter-frame timing statistics.

### 5. Encrypt a payload for replay

```bash
python -m game_protocol_cracker encrypt '{"action":"collect"}' --key 5
```

Outputs the ciphertext in hex and the matching frame integrity byte.

## CLI

All commands accept these shared options:

| Flag | Default | Purpose |
|------|---------|---------|
| `--port` | unset | TCP port filter; also labels direction (S2C if `src_port == port`). |
| `--frame-format` | `magic-prefixed` | Tokenizer: `magic-prefixed`, `length-prefixed`, `varint-prefixed`, `delimiter`. |
| `--magic` | `0x70A3` | Magic word for `magic-prefixed` format (accepts hex/octal/decimal). |
| `--wrap-at` | `0x70A3` | Rolling-key wrap value. |

Commands:

| Command | Summary |
|---------|---------|
| `crack PCAP [-o FILE] [--protobuf]` | Brute-force keys and decrypt everything. |
| `decode PCAP --c2s-key N [--s2c-key N]` | Decrypt with known keys. |
| `encrypt DATA --key N [--hex-input]` | Encrypt one message and compute its check byte. |
| `analyze PCAP` | Print command frequency and timing stats. |
| `list-plugins` | Show registered ciphers and frame formats. |

Console scripts `game-protocol-cracker` and `gpc` are registered on install.

## Frame formats

Out of the box the tool ships four tokenizers; register your own through the
plugin hooks if your target uses something exotic.

### `magic-prefixed` (default)

```
[2] magic (big-endian; --magic, default 0x70A3)
[1] flags
[1] check (integrity byte, see "Check byte" below)
[2] cmd_len (big-endian)
[N] cmd (ASCII, e.g. "LoginReqC2S")
[4] data_len (big-endian)
[M] data (XOR-encrypted payload)
```

### `length-prefixed`

2/4/8-byte length, then opaque body. Pass `body_split="ascii-delim"` via the
Python API to split `cmd\0payload` bodies.

### `varint-prefixed`

protobuf-style varint length, then opaque body. Pair with `--protobuf` for a
schema-less dump.

### `delimiter`

Bytes-delimited messages (newline-delimited JSON and friends).

## Python API

```python
from pathlib import Path

from game_protocol_cracker import (
    FrameParser,
    MagicPrefixedFormat,
    PcapReader,
    RollingKeyCipher,
    auto_detect_key,
)

parser = FrameParser(format=MagicPrefixedFormat(magic=0x70A3))
frames = []
for segment in PcapReader(path=Path("capture.pcap"), server_port=9000).iter_segments():
    for frame in parser.parse(segment.payload):
        frame.direction = segment.direction
        frames.append(frame)

guess = auto_detect_key(frames, direction="C2S")
print(f"initial C2S key = {guess.key} (confidence {guess.confidence:.0%})")

cipher = RollingKeyCipher(key=guess.key)
for frame in frames:
    if frame.direction == "C2S":
        print(frame.cmd, cipher.decrypt(frame.data)[:64])
```

### Plugin hooks

Register custom variants and select them from the CLI (`--frame-format name`):

```python
from game_protocol_cracker import (
    FrameParser,
    register_cipher,
    register_frame_format,
    RollingKeyCipher,
)

# Custom cipher variant
def my_cipher(**kwargs):
    return RollingKeyCipher(wrap_at=0x4000, **kwargs)

register_cipher("my-variant", my_cipher)

# Custom frame format
class MyFormat:
    name = "my-format"
    def iter_frames(self, buffer: bytes):
        ...

register_frame_format("my-format", lambda **kw: MyFormat())
```

## Algorithm

For every message:

```
key = key + 1
if key == wrap_at: key = 0
not_key = (~key) & 0xFFFFFFFF
w8 = not_key & 0xFF
w9 = ((not_key >> 4) & 0x0F) | ((w8 & 0xFF) << 4)
```

Per byte:

```
decrypt: plain  = ((~(cipher ^ w9)) & 0xFF - w8) & 0xFF
encrypt: cipher = (~((w8 + plain) ^ w9)) & 0xFF
```

Optional integrity byte used by the magic-prefixed variant:

```
check = (~((sum(plaintext) + w8) ^ w9)) & 0xFF
```

## Auto-detection

`auto_detect_key` sweeps candidate starting counters `0..max_key-1` per
direction. Each decrypted candidate is scored on:

1. **Protobuf wire-format validity** - how much of the plaintext parses as
   a valid protobuf stream (most binary game payloads).
2. **Printable-ASCII density** - for JSON or text payloads.

The highest combined score wins; C2S and S2C are treated independently
because real servers frequently start with different counters per direction.

## Replay-after-login pattern

Some games use a complex login handshake (nested protobuf, device
fingerprints, nonces...) that is painful to rebuild. A pragmatic shortcut:

1. Capture a full login session.
2. Replay the captured login bytes verbatim on a fresh TCP connection.
3. After the handshake completes, remember where the rolling counter landed
   and start emitting your own encrypted frames from there.

This works because the server only requires a valid authenticated session;
it does not care how you reconstructed the login frames. Once authenticated,
game commands are typically small protobuf or JSON blobs inside the same
XOR envelope the rest of the tool already handles.

## Comparison

| Tool | XOR rolling key | Auto-detect key | Frame parser | pcap input | Protobuf decode | CLI |
|------|:---:|:---:|:---:|:---:|:---:|:---:|
| **game-protocol-cracker** | Yes | Yes | Yes | Yes | Optional | Yes |
| [mitmproxy](https://mitmproxy.org/) | Plugin | No | No | No | Plugin | Yes |
| [Wireshark](https://wireshark.org/) | Dissector | No | Dissector | Yes | Plugin | No |
| [protobuf-inspector](https://github.com/mildsunrise/protobuf-inspector) | No | No | No | No | Yes | Yes |
| [scapy](https://scapy.net/) | Manual | No | Manual | Yes | No | Partial |

## Development

```bash
pip install -e ".[dev]"
pytest --cov=game_protocol_cracker
ruff check src/ tests/
python tests/fixtures/generate_fixtures.py   # regenerate synthetic pcap
```

103 tests cover the crypto primitives, all frame formats, the pcap reader and
the CLI end-to-end. The fixtures are synthetic; no real game traffic ships
with the repository.

## Contributing

Bug reports and patches are welcome through GitHub issues and pull requests.
Useful contributions include:

* additional frame-format tokenizers
* cipher variants seen in other games
* regression fixtures built with `tests/fixtures/generate_fixtures.py`

Please run `ruff check src/ tests/` and `pytest` before opening a PR.

## Dependencies

| Package | Purpose |
|---------|---------|
| [scapy](https://scapy.net/) | pcap/pcapng reading, TCP/IP parsing, test fixture generation |
| [click](https://click.palletsprojects.com/) | CLI framework |
| [rich](https://rich.readthedocs.io/) | Tabular terminal output |
| [bbpb](https://github.com/nccgroup/blackboxprotobuf) *(optional)* | Schema-less protobuf decoding |

## License

MIT - see [LICENSE](LICENSE).
