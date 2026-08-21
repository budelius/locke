"""Shared test fixtures for Locke Python tests."""

import json
from pathlib import Path

import pytest

TEST_VECTORS_DIR = Path(__file__).parent.parent.parent / "test-vectors"


@pytest.fixture(autouse=True)
def isolated_user_settings(monkeypatch, tmp_path_factory):
    """Keep the developer's real ~/.config/locke/config.toml out of the tests.

    Points settings discovery at a path that does not exist, so every test
    starts from "no global settings file" unless it opts in.
    """
    from locke import settings

    absent = tmp_path_factory.mktemp("locke-settings") / "absent.toml"
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(absent))
    settings.clear_cache()
    yield
    settings.clear_cache()


@pytest.fixture
def test_vectors_dir() -> Path:
    return TEST_VECTORS_DIR


def load_test_vectors(filename: str) -> dict:
    path = TEST_VECTORS_DIR / filename
    with open(path) as f:
        return json.load(f)
