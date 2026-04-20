"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from tests.fixtures.generate_fixtures import build_sample  # noqa: E402


@pytest.fixture(scope="session")
def sample_pcap(tmp_path_factory) -> Path:
    path = tmp_path_factory.mktemp("fixture") / "sample.pcap"
    build_sample(path)
    return path


@pytest.fixture(scope="session")
def sample_pcap_expected() -> list[tuple[str, str]]:
    return [
        ("C2S", "LoginReqC2S"),
        ("S2C", "LoginRspS2C"),
        ("C2S", "KeepAliveC2S"),
        ("S2C", "KeepAliveS2C"),
        ("C2S", "BuildingUpgradeC2S"),
        ("S2C", "BuildingUpgradeS2C"),
    ]
