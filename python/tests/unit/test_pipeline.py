"""Tests for locke.pipeline — credential resolution priority."""

from contextlib import ExitStack
from unittest.mock import patch

import pytest

from locke.errors import (
    BiometricDeniedError,
    BiometricUnavailableError,
    CredentialNotFoundError,
)
from locke.pipeline import _resolve_from_keystore, resolve_credential
from tests.conftest import load_test_vectors

VECTORS = load_test_vectors("pipeline.json")["vectors"]


def _get_vector(name: str) -> dict:
    return next(v for v in VECTORS if v["name"] == name)


def _make_backends(vec):
    """Build a _BACKENDS-shaped list from the test vector's backends dict."""
    backends = vec["backends"]

    def _mk(value):
        return lambda name: value

    return [
        ("keystore", _mk(backends.get("keystore"))),
        ("env_var", _mk(backends.get("env_var"))),
        ("gitlab_cli", _mk(backends.get("gitlab_cli"))),
        ("dotenv", _mk(backends.get("dotenv"))),
    ]


def _run_with_mocked_backends(vec, fn):
    """Run fn() with all pipeline backends mocked according to the test vector."""
    with ExitStack() as stack:
        stack.enter_context(
            patch("locke.pipeline._BACKENDS", _make_backends(vec))
        )
        stack.enter_context(
            patch("locke.pipeline.detect_environment", return_value=vec["environment"])
        )
        stack.enter_context(
            patch("locke.pipeline.is_production", return_value=vec["environment"] == "production")
        )
        return fn()


class TestResolveCredential:
    def test_keystore_wins(self):
        vec = _get_vector("keystore-wins")
        cred = _run_with_mocked_backends(vec, lambda: resolve_credential(vec["credential_name"]))
        assert cred.value == vec["expected_value"]
        assert cred.source == vec["expected_source"]

    def test_env_fallback(self):
        vec = _get_vector("env-fallback")
        cred = _run_with_mocked_backends(vec, lambda: resolve_credential(vec["credential_name"]))
        assert cred.value == vec["expected_value"]
        assert cred.source == vec["expected_source"]

    def test_glab_fallback(self):
        vec = _get_vector("glab-fallback")
        cred = _run_with_mocked_backends(vec, lambda: resolve_credential(vec["credential_name"]))
        assert cred.value == vec["expected_value"]
        assert cred.source == vec["expected_source"]

    def test_dotenv_fallback_dev(self):
        vec = _get_vector("dotenv-fallback-dev")
        cred = _run_with_mocked_backends(vec, lambda: resolve_credential(vec["credential_name"]))
        assert cred.value == vec["expected_value"]
        assert cred.source == vec["expected_source"]

    def test_production_no_dotenv(self):
        vec = _get_vector("production-fail")

        def run():
            with pytest.raises(CredentialNotFoundError) as exc_info:
                resolve_credential(vec["credential_name"])
            return exc_info.value

        err = _run_with_mocked_backends(vec, run)
        assert err.backends_searched == vec["expected_backends_searched"]

    def test_dev_all_empty(self):
        vec = _get_vector("dev-all-empty")

        def run():
            with pytest.raises(CredentialNotFoundError) as exc_info:
                resolve_credential(vec["credential_name"])
            return exc_info.value

        err = _run_with_mocked_backends(vec, run)
        assert err.backends_searched == vec["expected_backends_searched"]


class TestBiometricFallback:
    """Biometric errors in _resolve_from_keystore should return None, not propagate."""

    @patch("locke.pipeline.keystore_get", side_effect=BiometricDeniedError("denied"))
    def test_denied_returns_none(self, _):
        assert _resolve_from_keystore("SOME_KEY") is None

    @patch("locke.pipeline.keystore_get", side_effect=BiometricUnavailableError("no hw"))
    def test_unavailable_returns_none(self, _):
        assert _resolve_from_keystore("SOME_KEY") is None

    @patch("locke.pipeline.keystore_get", side_effect=BiometricDeniedError("denied"))
    def test_falls_through_to_env_var(self, _):
        """When biometric blocks keystore, pipeline should find the env var."""
        with patch.dict("os.environ", {"MY_SECRET": "from_env"}):
            cred = resolve_credential("MY_SECRET")
            assert cred.value == "from_env"
            assert cred.source == "env_var"
