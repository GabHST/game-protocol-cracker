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

## Advanced: Replay Login + Own Crypto

So I figured out a pattern that works really well for games where the login handshake is way more complex than the actual gameplay commands. Sharing it here because it took me a while to get right and I haven't seen it documented anywhere.

### The problem

A lot of these games have a login flow that involves some nasty protobuf with nested fields, timestamps, device fingerprints, crypto nonces, etc. Trying to reconstruct that from scratch is painful. You decode it with blackboxprotobuf, modify one field, re-encode it, and the bytes come out different because field ordering isn't preserved. Server rejects it. Hours wasted.

But here's the thing -- once you're logged in, the actual game commands are usually dead simple. Stuff like `{"action": "collect", "buildingId": 12}` wrapped in the XOR encryption we already cracked.

### The trick

Don't try to rebuild the login. Just replay the exact captured bytes.

```bash
# Step 1: capture a real login session
adb shell su -c "tcpdump -i any -w /sdcard/login.pcap port 9929"
# log into the game normally, then stop capture
adb pull /sdcard/login.pcap

# Step 2: extract the raw login frames
python protocol_cracker.py crack login.pcap -o login_frames.json

# Step 3: look at the login sequence
# usually something like: LoginReqC2S -> LoginRspS2C -> AuthReqC2S -> AuthRspS2C
```

The login request bytes don't change between sessions for most of these games (or they change predictably -- sometimes there's a timestamp you can patch at a known offset). So you save those raw encrypted frames and replay them byte-for-byte to the server.

```python
import socket

# connect and replay the captured login bytes exactly
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("game-server.example.com", 9929))

# send the exact login frames from your capture (raw bytes, no re-encoding)
with open("login_raw_frames.bin", "rb") as f:
    for frame in parse_frames(f.read()):
        sock.send(frame)
        response = sock.recv(4096)

# after login succeeds, you know the XOR key state
# now use YOUR encryption for all subsequent commands
key_state = 4  # wherever the key counter landed after login exchange

payload = '{"action":"collect","buildingId":12}'
encrypted = encrypt_payload(payload, key_state)
frame = build_frame("CollectReqC2S", encrypted)
sock.send(frame)
```

### Why this works

The login handshake has complex protobuf that's hard to reproduce exactly -- field ordering, varint encoding choices, optional fields the server checks for. But the server doesn't care HOW you got authenticated, just that the session is valid. Once you're past login, the commands are just simple JSON or flat protobuf payloads inside the XOR encryption that this tool already handles.

### Important notes

- The XOR key counter is sequential, so you need to track where it is after the login exchange. Count how many frames were sent/received during login to know the starting key for your own commands.
- Some games rotate the server port or IP between sessions. Capture fresh if your replay stops working.
- If the login has a timestamp field, find its byte offset in the raw frame and patch it. Usually it's a 4-byte unix timestamp at a consistent position. You can find it by capturing two logins and diffing the bytes.
- This is obviously for security research on your own apps/games. Don't be stupid with it.

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
