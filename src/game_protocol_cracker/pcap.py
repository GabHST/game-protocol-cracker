"""PCAP reader with TCP stream reassembly.

Wraps :mod:`scapy` so we inherit support for pcap, pcapng, Linux SLL,
Ethernet, IPv4 and IPv6 without reimplementing link-layer parsing.
Streams are reassembled per ``(src_ip, src_port, dst_ip, dst_port)``
tuple so that frames spanning multiple TCP segments survive.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from scapy.all import PcapReader as _ScapyPcapReader
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6


@dataclass
class TcpSegment:
    """A single reassembled TCP stream slice."""

    direction: str
    payload: bytes
    timestamp: float
    src: str
    dst: str
    src_port: int
    dst_port: int


@dataclass
class _StreamState:
    buffer: bytearray = field(default_factory=bytearray)
    first_ts: float = 0.0


@dataclass
class PcapReader:
    """Yield TCP segments from a pcap/pcapng capture.

    Parameters
    ----------
    path:
        The capture file path.
    server_port:
        If set, only include traffic where ``src_port`` or ``dst_port``
        matches. ``S2C`` is assigned when ``src_port == server_port``,
        otherwise ``C2S``. If ``None``, direction is labelled from the
        capture order of the first segment in each flow.
    reassemble:
        When true (default), concatenate segments from the same flow
        into a single payload blob per flow. When false, emit each
        segment as-is.
    """

    path: Path
    server_port: int | None = None
    reassemble: bool = True

    def iter_segments(self) -> Iterator[TcpSegment]:
        path = Path(self.path)
        if not path.exists():
            raise FileNotFoundError(path)

        if self.reassemble:
            yield from self._iter_reassembled(path)
        else:
            yield from self._iter_raw(path)

    def _iter_raw(self, path: Path) -> Iterator[TcpSegment]:
        with _ScapyPcapReader(str(path)) as reader:
            for pkt in reader:
                seg = self._segment_for(pkt)
                if seg is None:
                    continue
                yield seg

    def _iter_reassembled(self, path: Path) -> Iterator[TcpSegment]:
        flows: dict[tuple, _StreamState] = {}
        metadata: dict[tuple, TcpSegment] = {}

        with _ScapyPcapReader(str(path)) as reader:
            for pkt in reader:
                seg = self._segment_for(pkt)
                if seg is None:
                    continue
                key = (seg.src, seg.src_port, seg.dst, seg.dst_port)
                state = flows.setdefault(key, _StreamState(first_ts=seg.timestamp))
                state.buffer.extend(seg.payload)
                metadata.setdefault(key, seg)

        for key, state in flows.items():
            if not state.buffer:
                continue
            meta = metadata[key]
            yield TcpSegment(
                direction=meta.direction,
                payload=bytes(state.buffer),
                timestamp=state.first_ts,
                src=meta.src,
                dst=meta.dst,
                src_port=meta.src_port,
                dst_port=meta.dst_port,
            )

    def _segment_for(self, pkt) -> TcpSegment | None:
        if TCP not in pkt:
            return None
        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        if not payload:
            return None

        if IP in pkt:
            ip = pkt[IP]
            src, dst = ip.src, ip.dst
        elif IPv6 in pkt:
            ip = pkt[IPv6]
            src, dst = ip.src, ip.dst
        else:
            return None

        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        if self.server_port is not None and self.server_port not in (
            src_port,
            dst_port,
        ):
            return None

        if self.server_port is not None:
            direction = "S2C" if src_port == self.server_port else "C2S"
        else:
            direction = "?"

        ts = float(getattr(pkt, "time", 0.0))
        return TcpSegment(
            direction=direction,
            payload=payload,
            timestamp=ts,
            src=str(src),
            dst=str(dst),
            src_port=src_port,
            dst_port=dst_port,
        )
