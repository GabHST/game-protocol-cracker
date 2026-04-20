"""Tests for the PCAP reader (wraps scapy)."""

from __future__ import annotations

from pathlib import Path

import pytest

from game_protocol_cracker.pcap import PcapReader


class TestPcapReader:
    def test_reads_segments(self, sample_pcap: Path):
        reader = PcapReader(path=sample_pcap, server_port=9900)
        segments = list(reader.iter_segments())
        assert len(segments) == 2  # one reassembled flow per direction
        assert {s.direction for s in segments} == {"C2S", "S2C"}

    def test_port_filter_excludes(self, sample_pcap: Path):
        reader = PcapReader(path=sample_pcap, server_port=1234)
        segments = list(reader.iter_segments())
        assert segments == []

    def test_raw_mode_emits_per_packet(self, sample_pcap: Path):
        reader = PcapReader(
            path=sample_pcap, server_port=9900, reassemble=False
        )
        segments = list(reader.iter_segments())
        assert len(segments) == 6

    def test_missing_file_raises(self, tmp_path):
        reader = PcapReader(path=tmp_path / "missing.pcap", server_port=1)
        with pytest.raises(FileNotFoundError):
            list(reader.iter_segments())
