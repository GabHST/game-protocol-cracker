"""game-protocol-cracker: Analyze XOR rolling-key encrypted game protocols.

Public API surface:
    - RollingKeyCipher: encrypt/decrypt payloads with a rolling XOR key
    - FrameParser: tokenize raw TCP streams into protocol frames
    - PcapReader: extract TCP streams from pcap/pcapng captures
    - auto_detect_key: brute-force the starting key from captured frames
    - register_cipher / register_frame_format: plugin hooks for custom variants
"""

from game_protocol_cracker.crypto import (
    RollingKeyCipher,
    compute_check,
    decrypt_payload,
    encrypt_payload,
)
from game_protocol_cracker.detect import auto_detect_key, score_plaintext
from game_protocol_cracker.frames import (
    DelimiterFormat,
    Frame,
    FrameParser,
    LengthPrefixedFormat,
    MagicPrefixedFormat,
    VarintPrefixedFormat,
)
from game_protocol_cracker.pcap import PcapReader, TcpSegment
from game_protocol_cracker.plugins import (
    get_cipher,
    get_frame_format,
    register_cipher,
    register_frame_format,
)

__version__ = "0.2.0"

__all__ = [
    "RollingKeyCipher",
    "decrypt_payload",
    "encrypt_payload",
    "compute_check",
    "Frame",
    "FrameParser",
    "LengthPrefixedFormat",
    "VarintPrefixedFormat",
    "DelimiterFormat",
    "MagicPrefixedFormat",
    "PcapReader",
    "TcpSegment",
    "auto_detect_key",
    "score_plaintext",
    "register_cipher",
    "register_frame_format",
    "get_cipher",
    "get_frame_format",
    "__version__",
]
