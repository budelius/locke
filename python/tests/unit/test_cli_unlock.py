"""Tests for the `locke unlock` / `locke bio unlock` CLI command."""

from unittest.mock import patch

from click.testing import CliRunner

from locke.cli.bio import unlock
from locke.errors import BiometricDeniedError, BiometricUnavailableError


def _run(*args):
    return CliRunner().invoke(unlock, list(args))


@patch("locke.keystore._biometric_enabled", return_value=False)
def test_disabled_is_noop(_enabled):
    result = _run()
    assert result.exit_code == 0
    assert "disabled" in result.output


@patch("locke.keystore._bio_session_ttl", return_value=604800.0)
@patch("locke.keystore._read_bio_session", return_value=True)
@patch("locke.keystore._biometric_enabled", return_value=True)
def test_valid_session_is_noop_without_force(_enabled, _sess, _ttl):
    result = _run()
    assert result.exit_code == 0
    assert "already valid" in result.output


@patch("locke.keystore._bio_session_ttl", return_value=604800.0)
@patch("locke.keystore.verify_windows_hello", return_value=True)
@patch("locke.keystore._read_bio_session", return_value=False)
@patch("locke.keystore._biometric_enabled", return_value=True)
def test_expired_session_verifies_and_persists(_enabled, sess, verify, _ttl):
    # First _read_bio_session() (guard) sees no session; after verify, the
    # persisted-session check reads True so the command reports success.
    sess.side_effect = [False, True, True]
    result = _run()
    assert result.exit_code == 0
    assert "Unlocked" in result.output
    verify.assert_called_once()


@patch("locke.keystore._bio_session_ttl", return_value=604800.0)
@patch("locke.keystore._write_bio_session")
@patch("locke.keystore.verify_windows_hello", return_value=True)
@patch("locke.keystore.invalidate_bio_session")
@patch("locke.keystore.reset_bio_cache")
@patch("locke.keystore._read_bio_session")
@patch("locke.keystore._biometric_enabled", return_value=True)
def test_force_reverifies_even_when_valid(
    _enabled, sess, reset, invalidate, verify, write, _ttl
):
    # Guard sees a valid session, but --force bypasses the early return.
    sess.side_effect = [True, False, True]
    result = _run("--force")
    assert result.exit_code == 0
    reset.assert_called_once()
    invalidate.assert_called_once()
    verify.assert_called_once()
    # verify returned True but the post-verify read was False, so unlock
    # persists a session itself.
    write.assert_called_once()


@patch("locke.keystore.verify_windows_hello", side_effect=BiometricDeniedError("cancelled"))
@patch("locke.keystore._read_bio_session", return_value=False)
@patch("locke.keystore._biometric_enabled", return_value=True)
def test_denied_exits_nonzero(_enabled, _sess, _verify):
    result = _run()
    assert result.exit_code == 1
    assert "Unlock failed" in result.output


@patch(
    "locke.keystore.verify_windows_hello",
    side_effect=BiometricUnavailableError("no hello"),
)
@patch("locke.keystore._read_bio_session", return_value=False)
@patch("locke.keystore._biometric_enabled", return_value=True)
def test_unavailable_exits_nonzero(_enabled, _sess, _verify):
    result = _run()
    assert result.exit_code == 1
    assert "unavailable" in result.output.lower()
