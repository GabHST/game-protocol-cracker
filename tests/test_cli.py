"""Tests for the click CLI."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from game_protocol_cracker.cli import cli


def test_version_flag():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "game-protocol-cracker" in result.output


def test_help_flag():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Analyze XOR" in result.output


def test_list_plugins_runs():
    runner = CliRunner()
    result = runner.invoke(cli, ["list-plugins"])
    assert result.exit_code == 0
    assert "rolling-xor" in result.output


def test_encrypt_string():
    runner = CliRunner()
    result = runner.invoke(cli, ["encrypt", "hello", "--key", "0"])
    assert result.exit_code == 0
    assert "Check byte" in result.output
    assert "Ciphertext hex" in result.output


def test_encrypt_hex_input():
    runner = CliRunner()
    result = runner.invoke(
        cli, ["encrypt", "deadbeef", "--key", "3", "--hex-input"]
    )
    assert result.exit_code == 0


def test_crack_sample_pcap(sample_pcap: Path, tmp_path: Path):
    out = tmp_path / "decoded.json"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["crack", str(sample_pcap), "--port", "9900", "-o", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    rows = json.loads(out.read_text(encoding="utf-8"))
    cmds = {r["cmd"] for r in rows}
    assert "LoginReqC2S" in cmds
    assert "BuildingUpgradeS2C" in cmds


def test_decode_with_explicit_key(sample_pcap: Path):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["decode", str(sample_pcap), "--port", "9900", "--c2s-key", "0"],
    )
    assert result.exit_code == 0
    assert "LoginReqC2S" in result.output


def test_analyze_sample_pcap(sample_pcap: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", str(sample_pcap), "--port", "9900"])
    assert result.exit_code == 0
    assert "LoginReqC2S" in result.output


def test_crack_csv_export(sample_pcap: Path, tmp_path: Path):
    out = tmp_path / "decoded.csv"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["crack", str(sample_pcap), "--port", "9900", "-o", str(out)],
    )
    assert result.exit_code == 0
    content = out.read_text(encoding="utf-8")
    assert "LoginReqC2S" in content


def test_no_frames_matched_errors(tmp_path: Path, sample_pcap: Path):
    runner = CliRunner()
    # Port that has no traffic
    result = runner.invoke(
        cli, ["crack", str(sample_pcap), "--port", "65000"]
    )
    assert result.exit_code != 0
