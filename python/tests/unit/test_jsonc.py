"""Tests for locke.jsonc — JSON with comments and trailing commas."""

import io
import json

import pytest

from locke.jsonc import load_jsonc, parse_jsonc, strip_jsonc
from tests.conftest import load_test_vectors

VECTORS = load_test_vectors("jsonc.json")["vectors"]


@pytest.mark.parametrize("vec", VECTORS, ids=[v["name"] for v in VECTORS])
def test_parse_jsonc_vectors(vec):
    assert parse_jsonc(vec["input"]) == vec["expected"]


@pytest.mark.parametrize("vec", VECTORS, ids=[v["name"] for v in VECTORS])
def test_strip_jsonc_yields_valid_json(vec):
    # strip_jsonc output must be plain, parseable JSON equal to expected.
    assert json.loads(strip_jsonc(vec["input"])) == vec["expected"]


def test_plain_json_passthrough():
    assert parse_jsonc('{"a": 1}') == {"a": 1}


def test_load_jsonc_reads_file_object():
    fp = io.StringIO('{\n  // comment\n  "a": 1,\n}')
    assert load_jsonc(fp) == {"a": 1}


def test_load_jsonc_raises_on_malformed():
    with pytest.raises(json.JSONDecodeError):
        load_jsonc(io.StringIO('{"a": }'))
