"""Tests for locke.keystore — biometric gating and credential CRUD."""

import json
import platform
import time
from unittest.mock import MagicMock, patch

import pytest

from locke.errors import (
    BiometricDeniedError,
    BiometricUnavailableError,
    KeystoreUnavailableError,
)
from locke.keystore import (
    SERVICE_NAME,
    _bio_cache_valid,
    _bio_session_ttl,
    _biometric_enabled,
    _compute_session_hmac,
    _get_machine_id,
    _get_username,
    _is_interactive,
    _read_bio_session,
    _require_biometric,
    _write_bio_session,
    check_windows_hello_available,
    get_credential,
    invalidate_bio_session,
    reset_bio_cache,
    set_credential,
    verify_windows_hello,
)


# ---------------------------------------------------------------------------
# Biometric config helpers
# ---------------------------------------------------------------------------


class TestBiometricEnabled:
    def test_default_true(self):
        with patch.dict("os.environ", {}, clear=True):
            assert _biometric_enabled() is True

    @pytest.mark.parametrize("val", ["false", "False", "0", "no", " FALSE "])
    def test_disabled_variants(self, val):
        with patch.dict("os.environ", {"LOCKE_USE_BIOMETRIC": val}):
            assert _biometric_enabled() is False

    @pytest.mark.parametrize("val", ["true", "1", "yes"])
    def test_enabled_variants(self, val):
        with patch.dict("os.environ", {"LOCKE_USE_BIOMETRIC": val}):
            assert _biometric_enabled() is True


class TestBioCache:
    def setup_method(self):
        reset_bio_cache()

    def test_empty_cache_invalid(self):
        assert _bio_cache_valid() is False

    def test_cache_valid_after_set(self):
        import locke.keystore as ks
        ks._bio_verified_at = time.monotonic()
        assert _bio_cache_valid() is True

    def test_cache_expired(self):
        import locke.keystore as ks
        with patch.dict("os.environ", {"LOCKE_BIO_CACHE_TTL": "0"}):
            ks._bio_verified_at = time.monotonic() - 1
            assert _bio_cache_valid() is False

    def test_reset_invalidates(self):
        import locke.keystore as ks
        ks._bio_verified_at = time.monotonic()
        reset_bio_cache()
        assert _bio_cache_valid() is False


# ---------------------------------------------------------------------------
# Windows Hello availability check
# ---------------------------------------------------------------------------


class TestIsInteractive:
    def test_non_tty_stdin(self):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            assert _is_interactive() is False

    @patch("locke.keystore.platform")
    def test_tty_stdin_non_windows(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            assert _is_interactive() is True

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="ctypes.windll only available on Windows",
    )
    @patch("locke.keystore.platform")
    def test_windows_no_console_window(self, mock_platform):
        mock_platform.system.return_value = "Windows"
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            import ctypes
            with patch.object(
                ctypes.windll.kernel32, "GetConsoleWindow", return_value=0
            ):
                assert _is_interactive() is False

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="ctypes.windll only available on Windows",
    )
    @patch("locke.keystore.platform")
    def test_windows_with_console_window(self, mock_platform):
        mock_platform.system.return_value = "Windows"
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            import ctypes
            with patch.object(
                ctypes.windll.kernel32, "GetConsoleWindow", return_value=12345
            ):
                assert _is_interactive() is True


class TestCheckWindowsHelloAvailable:
    @patch("locke.keystore.platform")
    def test_non_windows_returns_false(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        assert check_windows_hello_available() is False

    @patch("locke.keystore._run_async")
    @patch("locke.keystore._import_winrt")
    @patch("locke.keystore.platform")
    def test_available(self, mock_platform, mock_import, mock_run):
        mock_platform.system.return_value = "Windows"
        avail = MagicMock()
        avail.AVAILABLE = 1
        mock_import.return_value = (MagicMock(), MagicMock(), avail)
        mock_run.return_value = 1  # matches AVAILABLE
        assert check_windows_hello_available() is True

    @patch("locke.keystore._run_async")
    @patch("locke.keystore._import_winrt")
    @patch("locke.keystore.platform")
    def test_not_configured(self, mock_platform, mock_import, mock_run):
        mock_platform.system.return_value = "Windows"
        avail = MagicMock()
        avail.AVAILABLE = 1
        mock_import.return_value = (MagicMock(), MagicMock(), avail)
        mock_run.return_value = 0  # does NOT match AVAILABLE
        assert check_windows_hello_available() is False

    @patch("locke.keystore._run_async", side_effect=Exception("timeout"))
    @patch("locke.keystore._import_winrt")
    @patch("locke.keystore.platform")
    def test_timeout_returns_false(self, mock_platform, mock_import, mock_run):
        mock_platform.system.return_value = "Windows"
        mock_import.return_value = (MagicMock(), MagicMock(), MagicMock())
        assert check_windows_hello_available() is False


# ---------------------------------------------------------------------------
# Windows Hello verification
# ---------------------------------------------------------------------------


class TestVerifyWindowsHello:
    def setup_method(self):
        reset_bio_cache()

    @patch("locke.keystore._read_bio_session", return_value=False)
    @patch("locke.keystore.platform")
    def test_non_windows_passes(self, mock_platform, _sess):
        mock_platform.system.return_value = "Linux"
        assert verify_windows_hello() is True

    @patch("locke.keystore._is_interactive", return_value=True)
    @patch("locke.keystore._write_bio_session")
    @patch("locke.keystore._read_bio_session", return_value=False)
    @patch("locke.keystore._run_async")
    @patch("locke.keystore._import_winrt")
    @patch("locke.keystore.platform")
    def test_verified_sets_cache(self, mock_platform, mock_import, mock_run, _sess, _wr, _inter):
        mock_platform.system.return_value = "Windows"
        ucv = MagicMock()
        vr = MagicMock()
        vr.VERIFIED = 1
        avail = MagicMock()
        avail.AVAILABLE = 0
        mock_import.return_value = (ucv, vr, avail)
        # First call: check_availability_async, second: request_verification_async
        mock_run.side_effect = [0, 1]  # avail=AVAILABLE, result=VERIFIED
        assert verify_windows_hello() is True
        assert _bio_cache_valid() is True

    @patch("locke.keystore._is_interactive", return_value=True)
    @patch("locke.keystore._write_bio_session")
    @patch("locke.keystore._read_bio_session", return_value=False)
    @patch("locke.keystore._run_async")
    @patch("locke.keystore._import_winrt")
    @patch("locke.keystore.platform")
    def test_cached_skips_prompt(self, mock_platform, mock_import, mock_run, _sess, _wr, _inter):
        mock_platform.system.return_value = "Windows"
        ucv = MagicMock()
        vr = MagicMock()
        vr.VERIFIED = 1
        avail = MagicMock()
        avail.AVAILABLE = 0
        mock_import.return_value = (ucv, vr, avail)
        mock_run.side_effect = [0, 1]  # avail, verified
        verify_windows_hello()
        # Second call: should use cache, not call WinRT again
        mock_run.reset_mock()
        assert verify_windows_hello() is True
        mock_run.assert_not_called()

    @patch("locke.keystore._is_interactive", return_value=True)
    @patch("locke.keystore._read_bio_session", return_value=False)
    @patch("locke.keystore._run_async")
    @patch("locke.keystore._import_winrt")
    @patch("locke.keystore.platform")
    def test_denied_raises(self, mock_platform, mock_import, mock_run, _sess, _inter):
        mock_platform.system.return_value = "Windows"
        ucv = MagicMock()
        vr = MagicMock()
        vr.VERIFIED = 1
        vr.CANCELED = 2
        avail = MagicMock()
        avail.AVAILABLE = 0
        mock_import.return_value = (ucv, vr, avail)
        mock_run.side_effect = [0, 2]  # avail=AVAILABLE, result=CANCELED
        with pytest.raises(BiometricDeniedError, match="cancelled"):
            verify_windows_hello()

    @patch("locke.keystore._is_interactive", return_value=True)
    @patch("locke.keystore._read_bio_session", return_value=False)
    @patch("locke.keystore._import_winrt", side_effect=ImportError("no winrt"))
    @patch("locke.keystore.platform")
    def test_unavailable_raises(self, mock_platform, mock_import, _sess, _inter):
        mock_platform.system.return_value = "Windows"
        with pytest.raises(BiometricUnavailableError, match="winrt"):
            verify_windows_hello()

    @patch("locke.keystore._is_interactive", return_value=True)
    @patch("locke.keystore._read_bio_session", return_value=False)
    @patch("locke.keystore._run_async")
    @patch("locke.keystore._import_winrt")
    @patch("locke.keystore.platform")
    def test_timeout_raises_denied(self, mock_platform, mock_import, mock_run, _sess, _inter):
        mock_platform.system.return_value = "Windows"
        ucv = MagicMock()
        vr = MagicMock()
        avail = MagicMock()
        avail.AVAILABLE = 0
        mock_import.return_value = (ucv, vr, avail)
        # availability ok, then verification raises
        mock_run.side_effect = [0, Exception("verification failed")]
        with pytest.raises(BiometricDeniedError, match="verification failed"):
            verify_windows_hello()

    @patch("locke.keystore._is_interactive", return_value=False)
    @patch("locke.keystore._read_bio_session", return_value=False)
    @patch("locke.keystore.platform")
    def test_non_interactive_skips_prompt(self, mock_platform, _sess, _interactive):
        mock_platform.system.return_value = "Windows"
        # Should return True without attempting WinRT import or prompt
        assert verify_windows_hello() is True

    @patch("locke.keystore._is_interactive", return_value=True)
    @patch("locke.keystore._read_bio_session", return_value=False)
    @patch("locke.keystore._run_async")
    @patch("locke.keystore._import_winrt")
    @patch("locke.keystore.platform")
    def test_not_available_raises_unavailable(self, mock_platform, mock_import, mock_run, _sess, _inter):
        mock_platform.system.return_value = "Windows"
        ucv = MagicMock()
        vr = MagicMock()
        avail = MagicMock()
        avail.AVAILABLE = 0
        mock_import.return_value = (ucv, vr, avail)
        mock_run.return_value = 99  # does NOT match AVAILABLE
        with pytest.raises(BiometricUnavailableError, match="not available"):
            verify_windows_hello()


# ---------------------------------------------------------------------------
# _require_biometric integration
# ---------------------------------------------------------------------------


class TestRequireBiometric:
    def setup_method(self):
        reset_bio_cache()

    @patch("locke.keystore._biometric_enabled", return_value=False)
    def test_disabled_is_noop(self, _):
        _require_biometric()  # should not raise

    @patch("locke.keystore.platform")
    @patch("locke.keystore._biometric_enabled", return_value=True)
    def test_linux_is_noop(self, _, mock_platform):
        mock_platform.system.return_value = "Linux"
        _require_biometric()  # should not raise

    @patch("locke.keystore.verify_windows_hello")
    @patch("locke.keystore.platform")
    @patch("locke.keystore._biometric_enabled", return_value=True)
    def test_windows_calls_verify(self, _, mock_platform, mock_verify):
        mock_platform.system.return_value = "Windows"
        mock_verify.return_value = True
        _require_biometric()
        mock_verify.assert_called_once()


# ---------------------------------------------------------------------------
# Credential CRUD with biometric gating
# ---------------------------------------------------------------------------


class TestGetCredentialWithBiometric:
    def setup_method(self):
        reset_bio_cache()

    @patch("locke.keystore.keyring")
    @patch("locke.keystore._require_biometric")
    def test_calls_biometric_then_keyring(self, mock_bio, mock_kr):
        mock_kr.get_password.return_value = "secret"
        result = get_credential("MY_KEY")
        mock_bio.assert_called_once()
        mock_kr.get_password.assert_called_once_with("locke", "MY_KEY")
        assert result == "secret"

    @patch("locke.keystore._require_biometric", side_effect=BiometricDeniedError("denied"))
    def test_biometric_denied_propagates(self, _):
        with pytest.raises(BiometricDeniedError):
            get_credential("MY_KEY")


class TestSetCredentialWithBiometric:
    def setup_method(self):
        reset_bio_cache()

    @patch("locke.keystore.keyring")
    @patch("locke.keystore._require_biometric")
    def test_calls_biometric_then_keyring(self, mock_bio, mock_kr):
        set_credential("MY_KEY", "val")
        mock_bio.assert_called_once()
        mock_kr.set_password.assert_called_once_with("locke", "MY_KEY", "val")

    @patch("locke.keystore._require_biometric", side_effect=BiometricDeniedError("denied"))
    def test_biometric_denied_propagates(self, _):
        with pytest.raises(BiometricDeniedError):
            set_credential("MY_KEY", "val")


# ---------------------------------------------------------------------------
# Persistent biometric session
# ---------------------------------------------------------------------------


class TestBioSession:
    """Tests for the persistent biometric session file."""

    def setup_method(self):
        reset_bio_cache()

    @patch("locke.keystore._get_bio_session_dir")
    def test_no_file_returns_false(self, mock_dir, tmp_path):
        mock_dir.return_value = tmp_path
        assert _read_bio_session() is False

    @patch("locke.keystore._get_username", return_value="testuser")
    @patch("locke.keystore._get_machine_id", return_value="test-machine-guid")
    @patch("locke.keystore._get_bio_session_dir")
    def test_write_then_read(self, mock_dir, _mid, _usr, tmp_path):
        mock_dir.return_value = tmp_path
        _write_bio_session()
        assert (tmp_path / "bio_session.json").is_file()
        assert _read_bio_session() is True

    @patch("locke.keystore._get_username", return_value="testuser")
    @patch("locke.keystore._get_machine_id", return_value="test-machine-guid")
    @patch("locke.keystore._get_bio_session_dir")
    def test_expired_session(self, mock_dir, _mid, _usr, tmp_path):
        mock_dir.return_value = tmp_path
        _write_bio_session()
        # Patch the session file to have an old timestamp
        session_file = tmp_path / "bio_session.json"
        data = json.loads(session_file.read_text())
        data["verified_at"] = time.time() - 999999
        data["hmac"] = _compute_session_hmac(
            data["verified_at"], data["machine_id"], data["username"]
        )
        session_file.write_text(json.dumps(data))
        assert _read_bio_session() is False

    @patch("locke.keystore._get_username", return_value="testuser")
    @patch("locke.keystore._get_machine_id", return_value="test-machine-guid")
    @patch("locke.keystore._get_bio_session_dir")
    def test_wrong_machine_id(self, mock_dir, _mid, _usr, tmp_path):
        mock_dir.return_value = tmp_path
        _write_bio_session()
        # Now change the machine id that _get_machine_id returns
        _mid.return_value = "different-machine"
        assert _read_bio_session() is False

    @patch("locke.keystore._get_username", return_value="testuser")
    @patch("locke.keystore._get_machine_id", return_value="test-machine-guid")
    @patch("locke.keystore._get_bio_session_dir")
    def test_tampered_hmac(self, mock_dir, _mid, _usr, tmp_path):
        mock_dir.return_value = tmp_path
        _write_bio_session()
        session_file = tmp_path / "bio_session.json"
        data = json.loads(session_file.read_text())
        data["hmac"] = "deadbeef" * 8
        session_file.write_text(json.dumps(data))
        assert _read_bio_session() is False

    @patch("locke.keystore._get_username", return_value="testuser")
    @patch("locke.keystore._get_machine_id", return_value="test-machine-guid")
    @patch("locke.keystore._get_bio_session_dir")
    def test_wrong_username(self, mock_dir, _mid, _usr, tmp_path):
        mock_dir.return_value = tmp_path
        _write_bio_session()
        _usr.return_value = "otheruser"
        assert _read_bio_session() is False

    @patch("locke.keystore._get_username", return_value="testuser")
    @patch("locke.keystore._get_machine_id", return_value="test-machine-guid")
    @patch("locke.keystore._get_bio_session_dir")
    def test_invalidate_removes_file(self, mock_dir, _mid, _usr, tmp_path):
        mock_dir.return_value = tmp_path
        _write_bio_session()
        assert (tmp_path / "bio_session.json").is_file()
        result = invalidate_bio_session()
        assert result is True
        assert not (tmp_path / "bio_session.json").is_file()

    @patch("locke.keystore._get_bio_session_dir")
    def test_invalidate_no_file(self, mock_dir, tmp_path):
        mock_dir.return_value = tmp_path
        result = invalidate_bio_session()
        assert result is False

    @patch("locke.keystore._get_username", return_value="testuser")
    @patch("locke.keystore._get_machine_id", return_value="test-machine-guid")
    @patch("locke.keystore._get_bio_session_dir")
    def test_corrupt_json(self, mock_dir, _mid, _usr, tmp_path):
        mock_dir.return_value = tmp_path
        (tmp_path / "bio_session.json").write_text("not valid json{{{")
        assert _read_bio_session() is False

    def test_session_ttl_default(self):
        with patch.dict("os.environ", {}, clear=True):
            assert _bio_session_ttl() == 604800

    def test_session_ttl_override(self):
        with patch.dict("os.environ", {"LOCKE_BIO_SESSION_TTL": "86400"}):
            assert _bio_session_ttl() == 86400.0

    @patch("locke.keystore._write_bio_session")
    @patch("locke.keystore._read_bio_session", return_value=True)
    def test_verify_reads_session_and_skips_prompt(self, mock_read, mock_write):
        """verify_windows_hello() should check persistent session before prompting."""
        reset_bio_cache()
        assert verify_windows_hello() is True
        mock_read.assert_called_once()
        mock_write.assert_not_called()  # no new verification happened

    @patch("locke.keystore._is_interactive", return_value=True)
    @patch("locke.keystore._get_username", return_value="testuser")
    @patch("locke.keystore._get_machine_id", return_value="test-machine-guid")
    @patch("locke.keystore._get_bio_session_dir")
    @patch("locke.keystore._run_async")
    @patch("locke.keystore._import_winrt")
    @patch("locke.keystore.platform")
    def test_verify_writes_session_on_success(
        self, mock_platform, mock_import, mock_run, mock_dir, _mid, _usr, _inter, tmp_path
    ):
        """verify_windows_hello() should write a session file after successful verification."""
        mock_dir.return_value = tmp_path
        mock_platform.system.return_value = "Windows"
        ucv = MagicMock()
        vr = MagicMock()
        vr.VERIFIED = 1
        avail = MagicMock()
        avail.AVAILABLE = 0
        mock_import.return_value = (ucv, vr, avail)
        mock_run.side_effect = [0, 1]  # avail=AVAILABLE, result=VERIFIED
        verify_windows_hello()
        assert (tmp_path / "bio_session.json").is_file()
