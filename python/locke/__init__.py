"""Locke — Unified credentials framework."""

import json
import logging
import os
from pathlib import Path

from locke.crypto import decrypt_config, encrypt_config
from locke.flatten import flatten_config
from locke.pipeline import resolve_credential


def __getattr__(name: str):
    if name in {
        "get_vault_secret",
        "is_placeholder",
        "PLACEHOLDER_VALUE",
        "PLACEHOLDER_VALUES",
        "set_vault_secret",
        "VaultClient",
    }:
        import locke.vault as vault
        return getattr(vault, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__version__ = "0.6.1"
__all__ = [
    "VaultClient",
    "decrypt_config",
    "decrypt_config_file",
    "encrypt_config",
    "find_config",
    "flatten_config",
    "get_vault_secret",
    "inject_env",
    "is_placeholder",
    "load_config",
    "PLACEHOLDER_VALUE",
    "PLACEHOLDER_VALUES",
    "read_locke_config",
    "resolve_credential",
    "set_vault_secret",
]

logger = logging.getLogger(__name__)


def find_config(
    project_root: str | Path,
    env: str | None = None,
) -> Path | None:
    """Locate an encrypted config file using standard search order.

    Searches ``project_root``, ``project_root/.locke``, and ``project_root/src``
    for files matching ``config.encrypted.{env}.json``, then
    ``config.encrypted.development.json``, then ``config.encrypted.json``.

    Args:
        project_root: Project root directory.
        env: Environment name (e.g. ``"production"``).  Falls back to the
            ``LOCKE_ENV`` env var if not provided.

    Returns:
        Path to the first matching file, or ``None``.
    """
    project_root = Path(project_root)
    env = env or os.environ.get("LOCKE_ENV", "")

    search_dirs = [project_root, project_root / ".locke", project_root / "src"]
    for search_dir in search_dirs:
        if env:
            p = search_dir / f"config.encrypted.{env}.json"
            if p.is_file():
                return p
        for fallback in ("config.encrypted.development.json", "config.encrypted.json"):
            p = search_dir / fallback
            if p.is_file():
                return p
    return None


def decrypt_config_file(
    config_path: str | Path,
    key_name: str,
) -> dict:
    """Resolve key via pipeline, decrypt config file, return plaintext dict.

    Args:
        config_path: Path to config.encrypted.json.
        key_name: Credential name (e.g. ``MYAPP_CONFIG_ENCRYPTION_KEY``).
    """
    config_path = Path(config_path)
    with open(config_path) as f:
        encrypted = json.load(f)

    credential = resolve_credential(key_name)
    return decrypt_config(encrypted, credential.value)


def inject_env(
    config: dict,
    env_map: dict[tuple[str, ...], str],
) -> int:
    """Inject decrypted config values into ``os.environ``.

    Existing env vars are NOT overwritten.

    Args:
        config: Decrypted nested config dict.
        env_map: Mapping of ``(section, key)`` tuples to env var names.

    Returns:
        Number of variables set.
    """
    count = 0
    for path, env_var in env_map.items():
        value = config
        for segment in path:
            if isinstance(value, dict):
                value = value.get(segment)
            else:
                value = None
                break
        if value is None or value == "":
            continue
        if isinstance(value, list):
            value = ",".join(str(v) for v in value)
        elif isinstance(value, bool):
            value = str(value).lower()
        else:
            value = str(value)
        if os.environ.get(env_var):
            continue
        os.environ[env_var] = value
        count += 1
    return count


def read_locke_config(
    project_root: str | Path = ".",
) -> dict | None:
    """Read the ``.locke/locke.json`` config if it exists.

    Returns the parsed dict, or ``None`` if the file is missing.
    """
    locke_json = Path(project_root) / ".locke" / "locke.json"
    if not locke_json.is_file():
        return None
    try:
        with open(locke_json) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("Failed to read %s: %s", locke_json, exc)
        return None


def load_config(
    config_path: str | Path,
    key_name: str = "LOCKE_ENCRYPTION_KEY",
) -> dict[str, str]:
    """Resolve key, decrypt, and auto-flatten to SCREAMING_SNAKE_CASE.

    For projects that need a custom env mapping, use
    :func:`decrypt_config_file` + :func:`inject_env` instead.
    """
    plaintext = decrypt_config_file(config_path, key_name)
    return flatten_config(plaintext)
