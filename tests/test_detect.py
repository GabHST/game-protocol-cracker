"""Tests for the key auto-detection heuristics."""

from __future__ import annotations

from pathlib import Path

from game_protocol_cracker.crypto import encrypt_payload
from game_protocol_cracker.detect import auto_detect_key, score_plaintext
from game_protocol_cracker.frames import Frame, FrameParser, MagicPrefixedFormat
from game_protocol_cracker.pcap import PcapReader


class TestScorePlaintext:
    def test_empty_returns_zero(self):
        assert score_plaintext(b"") == 0.0

    def test_printable_scores_high(self):
        s = score_plaintext(b"hello world, this is readable text")
        assert s > 0.9

    def test_random_binary_scores_low(self):
        s = score_plaintext(bytes(range(256)))
        assert s < 0.75

    def test_valid_protobuf_scores_positive(self):
        # field 1, length-delimited, 3 bytes "abc"
        blob = bytes([0x0A, 0x03]) + b"abc"
        assert score_plaintext(blob) > 0.0


class TestAutoDetectKey:
    def _make_frames(self, payloads: list[bytes], direction: str, key: int) -> list[Frame]:
        frames: list[Frame] = []
        current = key
        for plain in payloads:
            enc, current = encrypt_payload(plain, current)
            frames.append(Frame(cmd="X", data=enc, direction=direction))
        return frames

    def test_recovers_zero_key(self):
        payloads = [b"readable text payload number one",
                    b"another readable string of bytes",
                    b"more text that a human can read"]
        frames = self._make_frames(payloads, "C2S", 0)
        guess = auto_detect_key(frames, "C2S", max_key=16)
        assert guess.key == 0
        assert guess.confidence > 0.5

    def test_recovers_nonzero_key(self):
        payloads = [b"another readable body for test",
                    b"more lines of ascii content 123"]
        frames = self._make_frames(payloads, "C2S", 7)
        guess = auto_detect_key(frames, "C2S", max_key=16)
        assert guess.key == 7

    def test_empty_frames_returns_zero_confidence(self):
        guess = auto_detect_key([], "C2S")
        assert guess.key == 0
        assert guess.confidence == 0.0

    def test_end_to_end_with_sample_pcap(self, sample_pcap: Path):
        reader = PcapReader(path=sample_pcap, server_port=9900)
        parser = FrameParser(format=MagicPrefixedFormat())
        frames: list[Frame] = []
        for segment in reader.iter_segments():
            for f in parser.parse(segment.payload):
                f.direction = segment.direction
                frames.append(f)
        c2s = auto_detect_key(frames, "C2S")
        s2c = auto_detect_key(frames, "S2C")
        assert c2s.key == 0
        assert s2c.key == 0
