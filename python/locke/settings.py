"""Global (per-user) Locke settings.

Locke's Vaultwarden connection details (`LOCKE_VAULT_URL`,
`LOCKE_VAULT_USERNAME`) used to be reachable only through the process
environment or a `.env` file **in the current working directory**. That works
inside a project checkout and nowhere else: run the same command from a git
worktree, a scheduled task, or any other directory and the vault call fails
with "environment variable LOCKE_VAULT_URL is not set".

This module adds a user-level settings file — the same role `~/.gitconfig`
plays for git — so those settings resolve from any directory:

    # ~/.config/locke/config.toml  (%APPDATA%\\locke\\config.toml on Windows)
    vault_url = "https://vault.example.com"
    vault_email = "ops@example.com"

Resolution precedence for a connection setting is **environment variable >
`./.env` > this file**, so nothing that worked before changes behaviour.

Secrets never live here. The file is plaintext on disk, so it holds only
non-secret bootstrap settings; the Vaultwarden master password stays in the OS
keystore and is always read through :func:`locke.pipeline.resolve_credential`.
Writing a password key into the file is refused, and a password key found in an
existing file is ignored with a warning.
"""

import logging
import os
import sys
import tomllib
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: Points at an explicit settings file; overrides the search path entirely.
#: Mostly for tests and CI, where a stable path beats platform discovery.
SETTINGS_FILE_VAR = "LOCKE_SETTINGS_FILE"

SETTINGS_FILENAME = "config.toml"
SETTINGS_DIRNAME = "locke"

#: Connection-setting env var -> accepted file keys, first present wins.
_SETTING_KEYS: dict[str, tuple[str, ...]] = {
    "LOCKE_VAULT_URL": ("vault_url",),
    "LOCKE_VAULT_USERNAME": ("vault_email", "vault_username"),
}

#: Every key the file may define, in the order `set_setting` writes them.
KNOWN_KEYS: tuple[str, ...] = ("vault_url", "vault_email", "vault_username")

#: Keys that would put a secret in a plaintext file. Refused on write,
#: ignored on read.
_SECRET_KEYS = frozenset(
    {"vault_password", "password", "locke_vault_password", "openbao_token", "token"}
)

# (path, mtime_ns, size) -> parsed settings, so repeated lookups in one process
# do not re-read the file while still noticing edits made underneath us.
_cache: tuple[tuple[Path, int, int], dict[str, str]] | None = None


def clear_cache() -> None:
    """Drop the in-process settings cache (used by tests and `config set`)."""
    global _cache
    _cache = None


def _candidate_paths() -> list[Path]:
    """User-level settings locations, most-native first."""
    candidates: list[Path] = []

    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(Path(appdata) / SETTINGS_DIRNAME / SETTINGS_FILENAME)

    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        candidates.append(Path(xdg) / SETTINGS_DIRNAME / SETTINGS_FILENAME)

    candidates.append(Path.home() / ".config" / SETTINGS_DIRNAME / SETTINGS_FILENAME)

    # Preserve order while dropping duplicates (XDG_CONFIG_HOME may be ~/.config).
    seen: set[Path] = set()
    unique: list[Path] = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique


def settings_path() -> Path:
    """Return the settings file Locke reads and writes.

    ``LOCKE_SETTINGS_FILE`` wins outright. Otherwise the first *existing*
    candidate is used, so a file the operator already placed under
    ``~/.config`` keeps working on Windows; when none exists the platform-native
    location is returned for :func:`set_setting` to create.
    """
    explicit = os.environ.get(SETTINGS_FILE_VAR)
    if explicit:
        return Path(explicit).expanduser()

    candidates = _candidate_paths()
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def _coerce(path: Path, raw: dict[str, Any]) -> dict[str, str]:
    """Keep the string-valued, non-secret, top-level keys."""
    settings: dict[str, str] = {}
    for key, value in raw.items():
        if key in _SECRET_KEYS:
            logger.warning(
                "Ignoring '%s' in %s: the settings file is plaintext and must not "
                "hold secrets. Store it in the OS keystore instead "
                "(locke keystore set LOCKE_VAULT_PASSWORD).",
                key,
                path,
            )
            continue
        if not isinstance(value, str):
            logger.debug(
                "Ignoring '%s' in %s: expected a string, got %s",
                key,
                path,
                type(value).__name__,
            )
            continue
        settings[key] = value
    return settings


def load_settings() -> dict[str, str]:
    """Parse the settings file, or return ``{}`` when it is absent or broken.

    A missing or malformed file is never fatal — it only means the fallback has
    nothing to contribute, and the caller reports the original "not set" error.
    """
    global _cache

    path = settings_path()
    try:
        stat = path.stat()
    except OSError:
        return {}

    key = (path, stat.st_mtime_ns, stat.st_size)
    if _cache is not None and _cache[0] == key:
        return _cache[1]

    try:
        with open(path, "rb") as handle:
            raw = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        logger.warning("Locke settings file %s could not be parsed: %s", path, exc)
        return {}
    except OSError as exc:
        logger.debug("Failed to read Locke settings file %s: %s", path, exc)
        return {}

    settings = _coerce(path, raw)
    _cache = (key, settings)
    return settings


def get_setting(var_name: str) -> str | None:
    """Resolve a connection setting by its environment-variable name.

    Returns ``None`` for names the settings file does not cover, so callers can
    route every lookup through here without special-casing.
    """
    keys = _SETTING_KEYS.get(var_name)
    if not keys:
        return None

    settings = load_settings()
    for key in keys:
        value = settings.get(key)
        if value:
            logger.debug(
                "Setting %s resolved from %s (%s)", var_name, settings_path(), key
            )
            return value
    return None


def _toml_string(value: str) -> str:
    """Render a TOML basic string, escaping what the spec requires."""
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\b", "\\b")
        .replace("\t", "\\t")
        .replace("\n", "\\n")
        .replace("\f", "\\f")
        .replace("\r", "\\r")
    )
    return f'"{escaped}"'


def set_setting(key: str, value: str) -> Path:
    """Write one setting to the user-level file, creating it if needed.

    Returns the path written. Raises ``ValueError`` for unknown keys and for
    anything that belongs in the keystore.
    """
    if key in _SECRET_KEYS:
        raise ValueError(
            f"'{key}' is a secret and must not be written to a plaintext file: "
            "put it in the OS keystore (locke keystore set LOCKE_VAULT_PASSWORD)"
        )
    if key not in KNOWN_KEYS:
        known = ", ".join(KNOWN_KEYS)
        raise ValueError(f"'{key}' is not a known Locke setting (known: {known})")

    path = settings_path()
    current = dict(load_settings()) if path.is_file() else {}
    current[key] = value

    lines = [
        "# Locke user settings: non-secret bootstrap values, readable from any",
        "# directory. Secrets belong in the OS keystore, never in this file.",
    ]
    lines.extend(
        f"{name} = {_toml_string(current[name])}"
        for name in KNOWN_KEYS
        if name in current
    )
    body = "\n".join(lines) + "\n"

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    if sys.platform != "win32":
        path.chmod(0o600)

    clear_cache()
    logger.debug("Wrote setting '%s' to %s", key, path)
    return path
