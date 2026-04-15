"""Tests for locke.flatten — nested JSON to SCREAMING_SNAKE_CASE."""

import pytest

from locke.flatten import flatten_config
from locke.errors import CollisionError
from tests.conftest import load_test_vectors

VECTORS = load_test_vectors("flatten.json")["vectors"]


def _get_vector(name: str) -> dict:
    return next(v for v in VECTORS if v["name"] == name)


class TestFlattenConfig:
    def test_basic_nested(self):
        vec = _get_vector("basic-nested")
        assert flatten_config(vec["input"]) == vec["expected"]

    def test_deep_nesting(self):
        vec = _get_vector("deep-nesting")
        assert flatten_config(vec["input"]) == vec["expected"]

    def test_flat_input(self):
        vec = _get_vector("flat-input")
        assert flatten_config(vec["input"]) == vec["expected"]

    def test_alphabetical_ordering(self):
        vec = _get_vector("alphabetical-ordering")
        result = flatten_config(vec["input"])
        assert list(result.keys()) == vec["expected_keys_order"]

    def test_numeric_values(self):
        vec = _get_vector("numeric-values")
        assert flatten_config(vec["input"]) == vec["expected"]

    def test_collision_error(self):
        vec = _get_vector("collision-error")
        with pytest.raises(CollisionError) as exc_info:
            flatten_config(vec["input"])
        assert vec["expected_collision_key"] in str(exc_info.value)

    def test_empty_config(self):
        vec = _get_vector("empty-config")
        assert flatten_config(vec["input"]) == vec["expected"]

    def test_boolean_values(self):
        vec = _get_vector("boolean-values")
        assert flatten_config(vec["input"]) == vec["expected"]
