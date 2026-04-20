"""Command line entry point.

Uses :mod:`click` for argument parsing and :mod:`rich` for tabular
output. All subcommands share a common set of knobs for wrap key,
frame format and port filter so the tool adapts to different games
without code changes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from game_protocol_cracker import __version__
from game_protocol_cracker.crypto import (
    DEFAULT_WRAP_KEY,
    RollingKeyCipher,
    compute_check,
    decrypt_payload,
    update_key,
)
from game_protocol_cracker.decode import decode_schemaless
from game_protocol_cracker.detect import auto_detect_key
from game_protocol_cracker.export import export_csv, export_json
from game_protocol_cracker.frames import Frame, FrameParser
from game_protocol_cracker.pcap import PcapReader
from game_protocol_cracker.plugins import (
    get_frame_format,
    list_ciphers,
    list_frame_formats,
)

console = Console()
err_console = Console(stderr=True, style="bold red")


def _parse_int_literal(value):
    if isinstance(value, int):
        return value
    return int(value, 0)


def _build_frame_format(name: str, magic: int):
    if name == "magic-prefixed":
        return get_frame_format(name, magic=magic)
    return get_frame_format(name)


def _collect_frames(
    pcap: Path,
    port: int | None,
    frame_format_name: str,
    magic: int,
) -> list[Frame]:
    reader = PcapReader(path=pcap, server_port=port)
    fmt = _build_frame_format(frame_format_name, magic)
    parser = FrameParser(format=fmt)
    all_frames: list[Frame] = []
    for segment in reader.iter_segments():
        frames = parser.parse(segment.payload)
        for frame in frames:
            frame.direction = segment.direction
            frame.timestamp = segment.timestamp
            all_frames.append(frame)
    return all_frames


def _style_preview(data: bytes, limit: int = 60) -> str:
    trimmed = data[:limit]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in trimmed)


@click.group(
    help="Analyze XOR rolling-key encrypted game protocols.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(__version__, prog_name="game-protocol-cracker")
def cli() -> None:
    pass


_common_options = [
    click.option(
        "--port",
        type=int,
        default=None,
        help="Server port filter. Direction is labelled S2C when src_port matches.",
    ),
    click.option(
        "--magic",
        type=_parse_int_literal,
        default=0x70A3,
        show_default=True,
        help="Frame magic word for magic-prefixed format.",
    ),
    click.option(
        "--frame-format",
        "frame_format_name",
        type=click.Choice(list_frame_formats()),
        default="magic-prefixed",
        show_default=True,
        help="Frame tokenizer to use.",
    ),
    click.option(
        "--wrap-at",
        type=_parse_int_literal,
        default=DEFAULT_WRAP_KEY,
        show_default=True,
        help="Rolling-key wrap value.",
    ),
]


def _apply_common_options(cmd):
    for option in reversed(_common_options):
        cmd = option(cmd)
    return cmd


@cli.command("crack", help="Auto-detect keys and decode every frame in a capture.")
@click.argument("pcap", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--max-key",
    type=int,
    default=32,
    show_default=True,
    help="Upper bound (exclusive) for key brute-force sweep.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write decoded frames to this file (.json or .csv).",
)
@click.option(
    "--protobuf/--no-protobuf",
    default=False,
    help="Attempt schema-less protobuf decode of each payload.",
)
@_apply_common_options
def crack(
    pcap: Path,
    port: int | None,
    magic: int,
    frame_format_name: str,
    wrap_at: int,
    max_key: int,
    output: Path | None,
    protobuf: bool,
) -> None:
    frames = _collect_frames(pcap, port, frame_format_name, magic)
    if not frames:
        err_console.print(
            "No frames matched. Try a different --frame-format, --magic or --port."
        )
        sys.exit(1)

    c2s_guess = auto_detect_key(frames, "C2S", max_key=max_key, wrap_at=wrap_at)
    s2c_guess = auto_detect_key(frames, "S2C", max_key=max_key, wrap_at=wrap_at)

    console.rule(f"[bold]{pcap.name}[/bold]")
    summary = Table(show_header=True, header_style="bold cyan")
    summary.add_column("Direction")
    summary.add_column("Best key")
    summary.add_column("Confidence")
    summary.add_column("Frames")
    summary.add_row(
        "C2S",
        str(c2s_guess.key),
        f"{c2s_guess.confidence:.0%}",
        str(sum(1 for f in frames if f.direction == "C2S")),
    )
    summary.add_row(
        "S2C",
        str(s2c_guess.key),
        f"{s2c_guess.confidence:.0%}",
        str(sum(1 for f in frames if f.direction == "S2C")),
    )
    console.print(summary)

    c2s_key = c2s_guess.key
    s2c_key = s2c_guess.key
    decoded: list[tuple[Frame, bytes]] = []
    for frame in frames:
        if frame.direction == "S2C":
            plain, s2c_key = decrypt_payload(frame.data, s2c_key, wrap_at)
        else:
            plain, c2s_key = decrypt_payload(frame.data, c2s_key, wrap_at)
        decoded.append((frame, plain))

    _render_decoded_table(decoded, protobuf=protobuf)

    if output is not None:
        _write_output(output, decoded)


@cli.command("decode", help="Decrypt a capture with known starting keys.")
@click.argument("pcap", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--c2s-key", type=int, required=True, help="Starting C2S key.")
@click.option(
    "--s2c-key",
    type=int,
    default=None,
    help="Starting S2C key (defaults to --c2s-key).",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write decoded frames to this file (.json or .csv).",
)
@_apply_common_options
def decode(
    pcap: Path,
    port: int | None,
    magic: int,
    frame_format_name: str,
    wrap_at: int,
    c2s_key: int,
    s2c_key: int | None,
    output: Path | None,
) -> None:
    frames = _collect_frames(pcap, port, frame_format_name, magic)
    if not frames:
        err_console.print(
            "No frames matched. Try a different --frame-format, --magic or --port."
        )
        sys.exit(1)

    if s2c_key is None:
        s2c_key = c2s_key

    decoded: list[tuple[Frame, bytes]] = []
    for frame in frames:
        if frame.direction == "S2C":
            plain, s2c_key = decrypt_payload(frame.data, s2c_key, wrap_at)
        else:
            plain, c2s_key = decrypt_payload(frame.data, c2s_key, wrap_at)
        decoded.append((frame, plain))

    _render_decoded_table(decoded, protobuf=False)

    if output is not None:
        _write_output(output, decoded)


@cli.command("encrypt", help="Encrypt a payload, emitting hex plus integrity byte.")
@click.argument("data")
@click.option("--key", type=int, required=True, help="Rolling key BEFORE this message.")
@click.option(
    "--wrap-at",
    type=_parse_int_literal,
    default=DEFAULT_WRAP_KEY,
    show_default=True,
)
@click.option(
    "--hex-input",
    is_flag=True,
    default=False,
    help="Interpret ``data`` as a hex string rather than UTF-8 text.",
)
def encrypt(data: str, key: int, wrap_at: int, hex_input: bool) -> None:
    plaintext = (
        bytes.fromhex(data.replace(" ", ""))
        if hex_input
        else data.encode("utf-8")
    )

    cipher = RollingKeyCipher(key=key, wrap_at=wrap_at)
    probe_key = update_key(key, wrap_at)
    check = compute_check(plaintext, probe_key)
    encrypted = cipher.encrypt(plaintext)

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Key (before)", str(key))
    table.add_row("Key (after)", str(cipher.key))
    table.add_row("Check byte", f"0x{check:02x}")
    table.add_row("Plaintext bytes", str(len(plaintext)))
    table.add_row("Ciphertext hex", encrypted.hex())
    console.print(table)


@cli.command("analyze", help="Summarise command frequency and timing in a capture.")
@click.argument("pcap", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@_apply_common_options
def analyze(
    pcap: Path,
    port: int | None,
    magic: int,
    frame_format_name: str,
    wrap_at: int,  # noqa: ARG001 -- accepted for flag symmetry
) -> None:
    frames = _collect_frames(pcap, port, frame_format_name, magic)
    if not frames:
        err_console.print(
            "No frames matched. Try a different --frame-format, --magic or --port."
        )
        sys.exit(1)

    counts: dict[str, int] = {}
    for f in frames:
        key = f"{f.direction} {f.cmd or '<no-cmd>'}"
        counts[key] = counts.get(key, 0) + 1

    table = Table(title=f"Commands in {pcap.name}", show_header=True, header_style="bold cyan")
    table.add_column("#", justify="right")
    table.add_column("Direction / command")
    for cmd, count in sorted(counts.items(), key=lambda x: -x[1]):
        table.add_row(str(count), cmd)
    console.print(table)

    if len(frames) >= 2:
        intervals = []
        for a, b in zip(frames, frames[1:], strict=False):
            dt = b.timestamp - a.timestamp
            if 0 < dt < 60:
                intervals.append(dt)
        if intervals:
            avg = sum(intervals) / len(intervals)
            console.print(
                f"Avg inter-frame interval: [bold]{avg:.3f}s[/bold]  "
                f"min {min(intervals):.3f}s  max {max(intervals):.3f}s"
            )


@cli.command("list-plugins", help="List registered ciphers and frame formats.")
def list_plugins() -> None:
    ciphers = Table(title="Ciphers", show_header=False)
    for name in list_ciphers():
        ciphers.add_row(name)
    formats = Table(title="Frame formats", show_header=False)
    for name in list_frame_formats():
        formats.add_row(name)
    console.print(ciphers)
    console.print(formats)


# --- helpers ---------------------------------------------------------


def _render_decoded_table(
    decoded: list[tuple[Frame, bytes]],
    protobuf: bool,
    limit: int = 40,
) -> None:
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Dir")
    table.add_column("Command")
    table.add_column("Bytes", justify="right")
    table.add_column("Preview")
    for frame, plain in decoded[:limit]:
        preview = _style_preview(plain)
        if protobuf:
            decoded_pb = decode_schemaless(plain)
            if decoded_pb is not None:
                preview = json.dumps(decoded_pb, default=str)[:60]
        table.add_row(
            frame.direction or "?",
            frame.cmd or "<no-cmd>",
            str(len(plain)),
            preview,
        )
    console.print(table)
    if len(decoded) > limit:
        console.print(f"... ({len(decoded) - limit} more frames not shown)")


def _write_output(path: Path, decoded: list[tuple[Frame, bytes]]) -> None:
    suffix = path.suffix.lower()
    payload = list(decoded)
    n = export_csv(payload, path) if suffix == ".csv" else export_json(payload, path)
    console.print(f"[green]Wrote {n} frames to {path}[/green]")


def main() -> None:  # pragma: no cover - invoked by console_scripts
    cli()


if __name__ == "__main__":  # pragma: no cover
    main()
