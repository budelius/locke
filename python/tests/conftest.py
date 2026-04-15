"""Shared test fixtures for Locke Python tests."""

import json
from pathlib import Path

import pytest

TEST_VECTORS_DIR = Path(__file__).parent.parent.parent / "test-vectors"


@pytest.fixture
def test_vectors_dir() -> Path:
    return TEST_VECTORS_DIR


def load_test_vectors(filename: str) -> dict:
    path = TEST_VECTORS_DIR / filename
    with open(path) as f:
        return json.load(f)
