"""OS keystore access with biometric gating.

Provides platform-native credential storage via the ``keyring`` library:
- Windows: Credential Manager + Windows Hello (UserConsentVerifier)
- macOS: Keychain (with optional Touch ID gating)
- Linux: Secret Service (D-Bus) — no biometric support

Biometric gating is controlled by ``LOCKE_USE_BIOMETRIC`` env var
(default ``true``).  When enabled on Windows, every credential read
triggers a Windows Hello prompt (fingerprint / face / PIN) through the
WinRT ``UserConsentVerifier`` API called directly via the ``winrt``
Python bindings (no PowerShell subprocess).  Verification is cached for
``LOCKE_BIO_CACHE_TTL`` seconds (default 300) to avoid repeated prompts
within a session.

A persistent session file in ``%LOCALAPPDATA%\\locke\\`` (Windows) or
``~/.locke/`` (other) extends the cache across process invocations.
Controlled by ``LOCKE_BIO_SESSION_TTL`` (default 7 days).

Set ``LOCKE_USE_BIOMETRIC=false`` to bypass biometric prompts entirely.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import platform
import tempfile
import time
from pathlib import Path

import keyring
from keyring.errors import KeyringError

from locke.errors import (
    BiometricDeniedError,
    BiometricUnavailableError,
    KeystoreUnavailableError,
)

logger = logging.getLogger(__name__)


SERVICE_NAME = "locke"


# ---------------------------------------------------------------------------
# Direct Windows Credential Manager access (bypasses keyring naming)
# ---------------------------------------------------------------------------
# The ``keyring`` library constructs target names as ``{service}/{username}``,
# but credentials stored by other tools (or earlier conventions) may use bare
# target names like ``{project}`` or ``config-encryption-key@{project}``.
# This helper reads credentials by their exact target name via the Win32
# CredRead API.

def _wincred_read_by_target(target: str) -> str | None:
    """Read a credential from Windows Credential Manager by exact target name.

    Bypasses keyring's ``{service}/{username}`` naming convention to access
    credentials stored under bare target names.

    Returns the credential password (CredentialBlob) as a string, or None.
    Windows-only; returns None on other platforms.
    """
    if platform.system() != "Windows":
        return None

    import ctypes
    import ctypes.wintypes

    CRED_TYPE_GENERIC = 1

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", ctypes.wintypes.DWORD),
                     ("dwHighDateTime", ctypes.wintypes.DWORD)]

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", ctypes.wintypes.DWORD),
            ("Type", ctypes.wintypes.DWORD),
            ("TargetName", ctypes.wintypes.LPWSTR),
            ("Comment", ctypes.wintypes.LPWSTR),
            ("LastWritten", FILETIME),
            ("CredentialBlobSize", ctypes.wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
            ("Persist", ctypes.wintypes.DWORD),
            ("AttributeCount", ctypes.wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", ctypes.wintypes.LPWSTR),
            ("UserName", ctypes.wintypes.LPWSTR),
        ]

    advapi32 = ctypes.windll.advapi32
    advapi32.CredReadW.argtypes = [
        ctypes.wintypes.LPCWSTR,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(CREDENTIAL)),
    ]
    advapi32.CredReadW.restype = ctypes.wintypes.BOOL
    advapi32.CredFree.argtypes = [ctypes.c_void_p]
    advapi32.CredFree.restype = None

    pcred = ctypes.POINTER(CREDENTIAL)()

    if not advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(pcred)):
        return None

    try:
        cred = pcred.contents
        if cred.CredentialBlobSize == 0:
            return None
        blob = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
        return blob.decode("utf-16-le")
    finally:
        advapi32.CredFree(pcred)


# ---------------------------------------------------------------------------
# Legacy credential naming (migration support)
# ---------------------------------------------------------------------------
# Older credential-management tools stored secrets using the project name as
# the service/target and a short credential name as the username. Locke
# unifies under service="locke" with UPPER_SNAKE_CASE names. The patterns
# below describe legacy naming conventions Locke can still read so users can
# migrate without losing credentials.
#
# Legacy patterns (target → username):
#   "{project}"                        → "config-encryption-key" | "config_encryption_key"
#   "config-encryption-key@{project}"  → "config-encryption-key"
#   "locke-bio"                        → "LOCKE_VAULT_PASSWORD"  (older locke versions)

_LEGACY_KEY_SUFFIX = "_CONFIG_ENCRYPTION_KEY"

_LEGACY_VAULT_PASSWORD_PATTERNS: list[tuple[str, str]] = [
    ("locke-bio", "LOCKE_VAULT_PASSWORD"),
]


def _legacy_lookups_for(name: str) -> list[tuple[str, str]]:
    """Return legacy (target, username) pairs to try for a Locke credential name."""
    candidates: list[tuple[str, str]] = []

    if name == "LOCKE_VAULT_PASSWORD":
        candidates.extend(_LEGACY_VAULT_PASSWORD_PATTERNS)
        return candidates

    if name.endswith(_LEGACY_KEY_SUFFIX):
        project = name[: -len(_LEGACY_KEY_SUFFIX)].lower()
        candidates.append((project, "config-encryption-key"))
        candidates.append((project, "config_encryption_key"))
        candidates.append((f"config-encryption-key@{project}", "config-encryption-key"))

    return candidates


# ---------------------------------------------------------------------------
# Biometric configuration
# ---------------------------------------------------------------------------

_BIO_CACHE_TTL_DEFAULT = 300  # seconds
_bio_verified_at: float | None = None


def _biometric_enabled() -> bool:
    """Check if biometric gating is enabled."""
    flag = os.environ.get("LOCKE_USE_BIOMETRIC", "true").lower().strip()
    return flag not in ("false", "0", "no")


def _bio_cache_ttl() -> float:
    """Return the biometric cache TTL in seconds."""
    try:
        return float(os.environ.get("LOCKE_BIO_CACHE_TTL", _BIO_CACHE_TTL_DEFAULT))
    except (ValueError, TypeError):
        return _BIO_CACHE_TTL_DEFAULT


def _bio_cache_valid() -> bool:
    """Return True if a recent biometric verification is still valid."""
    if _bio_verified_at is None:
        return False
    return (time.monotonic() - _bio_verified_at) < _bio_cache_ttl()


def reset_bio_cache() -> None:
    """Invalidate the biometric verification cache (useful for testing)."""
    global _bio_verified_at
    _bio_verified_at = None


# ---------------------------------------------------------------------------
# Persistent biometric session (survives across process invocations)
# ---------------------------------------------------------------------------

_BIO_SESSION_TTL_DEFAULT = 604800  # 7 days in seconds
_BIO_SESSION_FILE = "bio_session.json"


def _bio_session_ttl() -> float:
    """Return the persistent session TTL in seconds."""
    try:
        return float(os.environ.get("LOCKE_BIO_SESSION_TTL", _BIO_SESSION_TTL_DEFAULT))
    except (ValueError, TypeError):
        return _BIO_SESSION_TTL_DEFAULT


def _get_bio_session_dir() -> Path:
    """Return the directory for storing the biometric session file.

    Uses ``%LOCALAPPDATA%\\locke`` on Windows, ``~/.locke`` elsewhere.
    Creates the directory if it does not exist.
    """
    if platform.system() == "Windows":
        base = os.environ.get("LOCALAPPDATA", "")
        if base:
            d = Path(base) / "locke"
        else:
            d = Path.home() / ".locke"
    else:
        d = Path.home() / ".locke"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _get_machine_id() -> str:
    """Return a stable machine identifier.

    On Windows, reads ``MachineGuid`` from the registry.  Returns
    ``"unknown"`` on other platforms or on failure.
    """
    if platform.system() != "Windows":
        return "unknown"
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            return str(value)
    except Exception:  # noqa: BLE001 -- machine-id probe; any failure means "unidentified host"
        return "unknown"


def _get_username() -> str:
    """Return the current OS username."""
    try:
        return os.getlogin()
    except OSError:
        return os.environ.get("USERNAME", os.environ.get("USER", "unknown"))


def _compute_session_hmac(verified_at: float, machine_id: str, username: str) -> str:
    """Compute an HMAC-SHA256 over the session payload.

    The machine GUID is used as the HMAC key — this prevents casual
    tampering but is not a cryptographic secret.  The real security
    boundary is Windows Hello itself; the session file is a convenience
    cache (same threat model as ``sudo`` timestamp files).
    """
    msg = f"{verified_at}|{machine_id}|{username}".encode()
    return hmac.new(machine_id.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _write_bio_session() -> None:
    """Write a persistent biometric session file after successful verification."""
    try:
        session_dir = _get_bio_session_dir()
        machine_id = _get_machine_id()
        username = _get_username()
        verified_at = time.time()
        payload = {
            "verified_at": verified_at,
            "machine_id": machine_id,
            "username": username,
            "hmac": _compute_session_hmac(verified_at, machine_id, username),
        }
        target = session_dir / _BIO_SESSION_FILE
        # Atomic write: temp file in same directory, then replace
        fd, tmp = tempfile.mkstemp(dir=session_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f)
            os.replace(tmp, target)
        except BaseException:
            # Clean up temp file on any failure
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        logger.debug("Biometric session written to %s", target)
    except Exception as exc:  # noqa: BLE001 -- session cache is best-effort; never block auth on it
        logger.debug("Failed to write biometric session: %s", exc)


def _read_bio_session() -> bool:
    """Check the persistent biometric session file.

    Returns True if the session is valid (exists, not expired, matches
    current machine and user, HMAC intact).  Returns False on any error.
    """
    try:
        target = _get_bio_session_dir() / _BIO_SESSION_FILE
        if not target.is_file():
            return False
        with open(target) as f:
            data = json.load(f)

        verified_at = float(data["verified_at"])
        machine_id = str(data["machine_id"])
        username = str(data["username"])
        stored_hmac = str(data["hmac"])

        # Check machine binding
        if machine_id != _get_machine_id():
            logger.debug("Bio session machine_id mismatch")
            return False
        if username != _get_username():
            logger.debug("Bio session username mismatch")
            return False

        # Check HMAC integrity
        expected = _compute_session_hmac(verified_at, machine_id, username)
        if not hmac.compare_digest(stored_hmac, expected):
            logger.debug("Bio session HMAC mismatch")
            return False

        # Check TTL
        age = time.time() - verified_at
        if age < 0 or age >= _bio_session_ttl():
            logger.debug("Bio session expired (age=%.0fs, ttl=%.0fs)", age, _bio_session_ttl())
            return False

        logger.debug("Persistent bio session valid (age=%.0fs)", age)
        return True
    except Exception as exc:  # noqa: BLE001 -- unreadable cache must re-prompt, not crash
        logger.debug("Failed to read biometric session: %s", exc)
        return False


def invalidate_bio_session() -> bool:
    """Delete the persistent biometric session file and reset in-memory cache.

    Returns True if a session file was removed, False otherwise.
    """
    reset_bio_cache()
    try:
        target = _get_bio_session_dir() / _BIO_SESSION_FILE
        if target.is_file():
            target.unlink()
            logger.info("Biometric session invalidated")
            return True
    except Exception as exc:  # noqa: BLE001 -- invalidation is best-effort cleanup
        logger.debug("Failed to invalidate biometric session: %s", exc)
    return False


# ---------------------------------------------------------------------------
# Windows Hello verification (direct WinRT API via winrt bindings)
# ---------------------------------------------------------------------------

def _import_winrt():
    """Lazy-import WinRT types (Windows-only)."""
    from winrt.windows.security.credentials.ui import (
        UserConsentVerificationResult,
        UserConsentVerifier,
        UserConsentVerifierAvailability,
    )
    return UserConsentVerifier, UserConsentVerificationResult, UserConsentVerifierAvailability


_sta_initialized = False


def _ensure_sta():
    """Initialise a WinRT STA apartment if not already done.

    WinRT UI operations (e.g. Windows Hello) require a Single-Threaded
    Apartment with a message pump.
    """
    global _sta_initialized
    if _sta_initialized:
        return
    try:
        from winrt.runtime import STA, init_apartment
        init_apartment(STA)
        _sta_initialized = True
    except Exception:  # noqa: BLE001, S110 -- COM apartment init; non-UI calls work without STA
        pass


def _run_async(awaitable):
    """Run a WinRT IAsyncOperation from synchronous code.

    WinRT async operations implement ``__await__`` but are not native
    coroutines, so ``asyncio.run()`` cannot accept them directly.

    Ensures an STA apartment is initialised so that UI dialogs (like
    Windows Hello) can pump messages and remain visible.

    On Windows, pumps the Win32 message queue while waiting so that
    WinRT UI dialogs (e.g. Windows Hello) can render and respond to
    user input.
    """
    _ensure_sta()

    if platform.system() == "Windows":
        return _run_async_with_message_pump(awaitable)

    async def _wrapper():
        return await awaitable
    return asyncio.run(_wrapper())


def _run_async_with_message_pump(operation):
    """Run a WinRT IAsyncOperation while pumping the Win32 message queue.

    Polls ``operation.status`` directly instead of using asyncio, which
    avoids problems where the WinRT completion callback fires between
    ``run_until_complete`` calls and never resolves the asyncio future.

    Uses ``MsgWaitForMultipleObjectsEx`` to sleep efficiently until
    messages arrive, rather than busy-polling.
    """
    import ctypes
    import ctypes.wintypes

    from winrt.windows.foundation import AsyncStatus

    user32 = ctypes.windll.user32

    class MSG(ctypes.Structure):
        _fields_ = [
            ("hWnd", ctypes.wintypes.HWND),
            ("message", ctypes.c_uint),
            ("wParam", ctypes.wintypes.WPARAM),
            ("lParam", ctypes.wintypes.LPARAM),
            ("time", ctypes.wintypes.DWORD),
            ("pt", ctypes.wintypes.POINT),
        ]

    PM_REMOVE = 0x0001
    QS_ALLINPUT = 0x04FF
    MWMO_INPUTAVAILABLE = 0x0004
    TIMEOUT_MS = 50

    # Ensure the terminal window is in the foreground so the Windows
    # Hello dialog can attach to it.  GetConsoleWindow() returns 0 in
    # Windows Terminal; fall back to GetForegroundWindow().
    kernel32 = ctypes.windll.kernel32
    hwnd = kernel32.GetConsoleWindow() or user32.GetForegroundWindow()
    if hwnd:
        user32.SetForegroundWindow(hwnd)

    msg = MSG()
    deadline = time.monotonic() + 120  # 2-minute safety timeout

    while operation.status == AsyncStatus.STARTED:
        if time.monotonic() > deadline:
            operation.cancel()
            raise TimeoutError("Windows Hello dialog timed out after 120 s")

        # Wait efficiently for messages (or timeout after TIMEOUT_MS)
        user32.MsgWaitForMultipleObjectsEx(
            0, None, TIMEOUT_MS, QS_ALLINPUT, MWMO_INPUTAVAILABLE,
        )

        # Drain pending Win32 messages so UI dialogs stay responsive
        while user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, PM_REMOVE):
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    if operation.status == AsyncStatus.COMPLETED:
        return operation.get_results()
    if operation.status == AsyncStatus.CANCELED:
        raise asyncio.CancelledError("WinRT operation was cancelled")
    # AsyncStatus.ERROR
    raise RuntimeError(f"WinRT operation failed (error_code: {operation.error_code})")


def check_windows_hello_available() -> bool:
    """Return True if Windows Hello is configured and available."""
    if platform.system() != "Windows":
        return False
    try:
        UCV, _, Availability = _import_winrt()
        result = _run_async(UCV.check_availability_async())
        available = result == Availability.AVAILABLE
        if not available:
            logger.debug("Windows Hello not available: %s", result)
        return available
    except Exception as exc:  # noqa: BLE001 -- probe only; unknown failure means "not available"
        logger.debug("Windows Hello availability check failed: %s", exc)
        return False


def verify_windows_hello(
    message: str = "Locke: Verify your identity to access credentials",
) -> bool:
    """Trigger a Windows Hello prompt and return True if the user verified.

    Calls the WinRT ``UserConsentVerifier`` API directly via Python
    bindings — no PowerShell subprocess needed.

    Raises BiometricDeniedError if the user cancels or verification fails.
    Raises BiometricUnavailableError if Windows Hello is not set up.
    """
    global _bio_verified_at

    if _bio_cache_valid():
        logger.debug("Biometric cache still valid, skipping prompt")
        return True

    # Check persistent session file (survives across process invocations)
    if _read_bio_session():
        logger.debug("Persistent bio session valid, skipping prompt")
        _bio_verified_at = time.monotonic()  # warm the in-memory cache
        return True

    if platform.system() != "Windows":
        logger.debug("Not on Windows, skipping Windows Hello")
        return True

    # Non-interactive and MSYS/Git Bash hosts cannot reliably complete a
    # Windows Hello dialog. Allow keystore access ungated — the OS user session
    # is the remaining security boundary (same as Linux/macOS behaviour).
    if not _is_interactive():
        logger.warning(
            "Shell cannot present Windows Hello (non-interactive or MSYS/Git Bash) — "
            "skipping the prompt. Keystore access proceeds without biometric gate."
        )
        # Warm the process-local cache. Bulk/chunked operations call the gate
        # repeatedly and would otherwise emit this warning once per key.
        _bio_verified_at = time.monotonic()
        return True

    try:
        UCV, VerificationResult, Availability = _import_winrt()
    except ImportError as exc:
        raise BiometricUnavailableError(
            f"winrt packages not installed (pip install winrt-runtime "
            f"winrt-Windows.Security.Credentials.UI): {exc}"
        )

    # Check availability first
    try:
        avail = _run_async(UCV.check_availability_async())
    except Exception as exc:  # noqa: BLE001 -- converted to a typed BiometricUnavailableError below
        raise BiometricUnavailableError(f"availability check failed: {exc}")

    if avail != Availability.AVAILABLE:
        raise BiometricUnavailableError(f"Windows Hello not available (status: {avail})")

    # Request verification — shows the Windows Hello dialog
    try:
        result = _run_async(UCV.request_verification_async(message))
    except Exception as exc:  # noqa: BLE001 -- converted to a typed BiometricDeniedError below
        raise BiometricDeniedError(f"failed: {exc}")

    if result == VerificationResult.VERIFIED:
        _bio_verified_at = time.monotonic()
        _write_bio_session()
        logger.info("Windows Hello verification succeeded")
        return True

    if result == VerificationResult.CANCELED:
        raise BiometricDeniedError("cancelled by user")

    raise BiometricDeniedError(f"verification denied (result: {result})")


def _is_interactive() -> bool:
    """Detect whether the current process has an interactive console.

    Returns False in background services, CI runners, or shells where
    the Windows Hello dialog cannot be shown (no console window or
    stdin is not a TTY).
    """
    import sys

    if not sys.stdin.isatty():
        return False

    if platform.system() == "Windows":
        # Python launched from MSYS2/Git Bash can report both a TTY and a
        # console HWND even though WinRT's UserConsentVerifier dialog never
        # completes in that host. Classify it before starting a 120-second
        # prompt that can only time out. Native PowerShell/cmd/Windows Terminal
        # sessions do not set MSYSTEM and retain Windows Hello gating.
        if os.environ.get("MSYSTEM"):
            return False

        import ctypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if not hwnd:
            return False

    return True


def _require_biometric() -> None:
    """Gate access behind biometric verification when enabled.

    No-op when biometric is disabled, on Linux, or when the cache is valid.
    In shells that cannot host Windows Hello (no console window, non-TTY, or
    MSYS/Git Bash), skips the biometric prompt with a warning — keystore access
    proceeds ungated, relying on the OS user session for protection.
    """
    if not _biometric_enabled():
        return
    if platform.system() == "Linux":
        return
    if platform.system() == "Windows":
        verify_windows_hello()
    elif platform.system() == "Darwin":
        # macOS Touch ID — not yet implemented, log and pass through
        logger.debug("macOS Touch ID gating not yet implemented")


# ---------------------------------------------------------------------------
# Credential CRUD
# ---------------------------------------------------------------------------

def get_credential(name: str) -> str | None:
    """Retrieve a credential from the OS keystore.

    When biometric is enabled on Windows, triggers a Windows Hello prompt
    (cached for ``LOCKE_BIO_CACHE_TTL`` seconds after first verification).

    Tries the canonical ``locke`` service first, then falls back to legacy
    naming patterns from prior credential-management tools.

    Returns None if the credential is not found.
    Raises KeystoreUnavailableError if the keystore service is not accessible.
    Raises BiometricDeniedError if the user denies the biometric prompt.
    """
    _require_biometric()

    try:
        value = keyring.get_password(SERVICE_NAME, name)
        if value is not None:
            logger.debug("Credential '%s' found in OS keystore", name)
            return value
    except KeyringError as exc:
        logger.debug("Keystore access failed for '%s': %s", name, exc)
        raise KeystoreUnavailableError(
            platform=platform.system(),
            service=str(type(keyring.get_keyring()).__name__),
        ) from exc

    # Canonical lookup missed — try legacy patterns
    tried_wincred_targets: set[str] = set()
    for target, username in _legacy_lookups_for(name):
        try:
            value = keyring.get_password(target, username)
        except KeyringError:
            value = None

        # On Windows, keyring constructs target as "{service}/{username}" which
        # doesn't match credentials stored under bare target names. Fall back
        # to direct CredRead by exact target name.
        if value is None and target not in tried_wincred_targets:
            tried_wincred_targets.add(target)
            value = _wincred_read_by_target(target)

        if value is not None:
            logger.warning(
                "Credential '%s' found under legacy name (target=%r). "
                "Run 'locke keystore migrate' to update to the new naming.",
                name, target,
            )
            return value

    return None


def set_credential(name: str, value: str) -> None:
    """Store a credential in the OS keystore.

    When biometric is enabled on Windows, triggers a Windows Hello prompt
    before storing.

    Raises KeystoreUnavailableError if the keystore service is not accessible.
    Raises BiometricDeniedError if the user denies the biometric prompt.
    """
    _require_biometric()

    try:
        keyring.set_password(SERVICE_NAME, name, value)
        logger.debug("Credential '%s' stored in OS keystore", name)
    except KeyringError as exc:
        raise KeystoreUnavailableError(
            platform=platform.system(),
            service=str(type(keyring.get_keyring()).__name__),
        ) from exc


def delete_credential(name: str) -> None:
    """Remove a credential from the OS keystore.

    Raises KeystoreUnavailableError if the keystore service is not accessible.
    """
    _require_biometric()

    try:
        keyring.delete_password(SERVICE_NAME, name)
        logger.debug("Credential '%s' deleted from OS keystore", name)
    except keyring.errors.PasswordDeleteError:
        logger.debug("Credential '%s' not found in OS keystore for deletion", name)
    except KeyringError as exc:
        raise KeystoreUnavailableError(
            platform=platform.system(),
            service=str(type(keyring.get_keyring()).__name__),
        ) from exc


# ---------------------------------------------------------------------------
# Legacy credential migration
# ---------------------------------------------------------------------------

def find_legacy_credentials(names: list[str] | None = None) -> list[dict]:
    """Scan for credentials stored under legacy naming conventions.

    Args:
        names: Locke credential names to probe.  If ``None``, only
            ``LOCKE_VAULT_PASSWORD`` is checked, since project-specific
            ``*_CONFIG_ENCRYPTION_KEY`` names cannot be enumerated without
            the caller telling us what project slugs to look for.

    Returns:
        List of dicts with keys: ``locke_name``, ``legacy_target``,
        ``legacy_username``, ``already_migrated``.
    """
    candidates = names if names is not None else ["LOCKE_VAULT_PASSWORD"]

    found: list[dict] = []
    for name in candidates:
        tried_targets: set[str] = set()
        for target, username in _legacy_lookups_for(name):
            try:
                value = keyring.get_password(target, username)
            except KeyringError:
                value = None

            if value is None and target not in tried_targets:
                tried_targets.add(target)
                value = _wincred_read_by_target(target)

            if value is not None:
                try:
                    current = keyring.get_password(SERVICE_NAME, name)
                except KeyringError:
                    current = None
                found.append({
                    "locke_name": name,
                    "legacy_target": target,
                    "legacy_username": username,
                    "already_migrated": current is not None,
                })
    return found


def migrate_credential(name: str, *, delete_legacy: bool = False) -> str | None:
    """Copy a legacy credential into the Locke namespace.

    Returns the legacy source description (e.g.
    ``"target='myproject'"``) if migration succeeded, or ``None`` if no
    legacy credential was found.
    """
    _require_biometric()

    tried_targets: set[str] = set()
    for target, username in _legacy_lookups_for(name):
        try:
            value = keyring.get_password(target, username)
        except KeyringError:
            value = None

        if value is None and target not in tried_targets:
            tried_targets.add(target)
            value = _wincred_read_by_target(target)

        if value is not None:
            keyring.set_password(SERVICE_NAME, name, value)
            source = f"target={target!r}"
            logger.info(
                "Migrated credential '%s' from legacy %s to locke namespace",
                name, source,
            )
            if delete_legacy:
                try:
                    keyring.delete_password(target, username)
                    logger.info("Deleted legacy credential %s", source)
                except KeyringError:
                    logger.warning("Could not delete legacy credential %s", source)
            return source
    return None
