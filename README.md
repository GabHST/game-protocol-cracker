# game-protocol-cracker

Crack XOR rolling-key encrypted game protocols commonly used in mobile games.

> **Disclaimer:** This tool is for educational and security research purposes only. Use responsibly and only on applications you have authorization to test.

## The Problem

Many mobile games use a simple XOR rolling-key encryption for their TCP protocol. This is especially common in games built with Chinese game engines (JuFeng, 37Games SDK, etc.). While the encryption looks intimidating in a packet capture, it follows a predictable pattern that can be reversed.

If you've captured game traffic with tcpdump and see gibberish payloads with readable command names, this tool is probably what you need.

## How It Works

The XOR rolling-key pattern:

```
For each message:
  1. key = key + 1 (wrap at configurable threshold)
  2. w8 = (~key) & 0xFF
  3. w9 = ((~key >> 4) & 0x0F) | ((w8 << 4) & 0xFF0)
  4. For each byte: plain = (~(enc ^ w9) - w8) & 0xFF
```

The tool auto-detects the initial key by trying values 0-19 and scoring decryption results by readability.

## Features

- **Auto-detect** initial encryption key from captured traffic
- **Decode** all frames from a pcap capture
- **Encrypt** payloads for replay testing
- **Analyze** protocol patterns (command frequency, timing)
- **Frame parser** for custom binary protocols (configurable magic bytes)
- **PCAP parser** supporting both Ethernet and SLL link types

## Usage

### Capture traffic

```bash
# On rooted Android emulator
adb shell su -c "tcpdump -i any -w /sdcard/capture.pcap port 9929"
adb pull /sdcard/capture.pcap
```

### Crack the protocol

```bash
# Auto-detect key and decode everything
python protocol_cracker.py crack capture.pcap

# Save decoded frames to JSON
python protocol_cracker.py crack capture.pcap -o decoded.json
```

### Decode with known key

```bash
python protocol_cracker.py decode capture.pcap --key 2
```

### Analyze patterns

```bash
python protocol_cracker.py analyze capture.pcap
```

### Encrypt for replay

```bash
python protocol_cracker.py encrypt '{"action":"collect"}' --key 5
```

## Frame Format

Default format (configurable via `--magic`):

```
[2 bytes] Magic: 0x70A3
[1 byte]  Flags
[1 byte]  Check (payload checksum)
[2 bytes] Command name length (big-endian)
[N bytes] Command name (ASCII, e.g. "LoginReqC2S")
[4 bytes] Payload length (big-endian)
[M bytes] Payload (XOR encrypted)
```

Command names are plaintext — only the payload is encrypted.

## Comparison with Other Tools

| Tool | XOR Key Crack | Frame Parse | PCAP Support | Encrypt | Auto-Detect Key | Protobuf Decode |
|------|:---:|:---:|:---:|:---:|:---:|:---:|
| **game-protocol-cracker** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | Planned |
| [mitmproxy](https://mitmproxy.org/) | No | No | No | No | N/A | Plugin |
| [Wireshark](https://wireshark.org/) | Manual | Custom dissector | Yes | No | No | Plugin |
| [protobuf-inspector](https://github.com/mildsunrise/protobuf-inspector) | No | No | No | No | N/A | Yes (decode only) |
| [scapy](https://scapy.net/) | Manual | Custom | Yes | Manual | No | No |
| [InterceptSuite](https://github.com/InterceptSuite/InterceptSuite) | No | No | No | No | N/A | No |
| Custom scripts | Manual | Manual | Manual | Manual | Manual | Manual |

## Requirements

- Python 3.10+
- No external dependencies for core functionality
- Optional: `pip install bbpb` for Protobuf payload decoding

## Supported Protocols

This tool targets the specific XOR rolling-key pattern described above. Games known to use this or similar patterns include titles built with:

- JuFeng game engine
- 37Games SDK
- Various Chinese mobile game frameworks

The key derivation and frame format can be customized for other implementations.

## License

MIT
