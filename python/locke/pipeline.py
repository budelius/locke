"""Credential resolution pipeline.

Evaluates backends in priority order:
1. OS Keystore
2. Environment variable
3. GitLab CLI (glab)
4. .env file fallback (dev/staging only)

Production environments fail hard if no credential is found.
Dev/staging environments warn and attempt fallback.
"""

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from locke.env import detect_environment, is_production
from locke.errors import (
    BiometricDeniedError,
    BiometricUnavailableError,
    CredentialNotFoundError,
)
from locke.keystore import get_credential as keystore_get

logger = logging.getLogger(__name__)


@dataclass
class Credential:
    """A resolved credential with metadata."""

    name: str
    value: str
    source: str  # "keystore", "env_var", "gitlab_cli", "dotenv"
    resolved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _resolve_from_keystore(name: str) -> str | None:
    """Attempt to resolve credential from OS keystore.

    Biometric errors (denied / unavailable) are caught and treated as
    "keystore unavailable" so the pipeline can fall through to env var,
    GitLab CLI, and .env backends.  This enables graceful degradation in
    non-interactive shells where Windows Hello cannot prompt.
    """
    try:
        return keystore_get(name)
    except (BiometricDeniedError, BiometricUnavailableError) as exc:
        logger.warning(
            "Biometric gating prevented keystore access for '%s': %s — "
            "trying remaining backends.",
            name, exc,
        )
        return None
    except Exception:
        logger.debug("Keystore lookup failed for '%s'", name)
        return None


def _resolve_from_env(name: str) -> str | None:
    """Attempt to resolve credential from environment variable."""
    value = os.environ.get(name)
    if value:
        logger.debug("Credential '%s' found in environment variable", name)
    return value


def _resolve_from_glab(name: str) -> str | None:
    """Attempt to resolve credential from GitLab CLI (`glab`).

    Tries `glab auth token` for auth tokens, or `glab variable get` for
    CI/CD variables. Returns None if glab is not installed or not authenticated.
    """
    import shutil
    import subprocess

    if not shutil.which("glab"):
        logger.debug("glab CLI not found in PATH")
        return None

    # Try glab variable get first (for project-level variables)
    try:
        result = subprocess.run(
            ["glab", "variable", "get", name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            logger.debug("Credential '%s' found via glab variable get", name)
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # For auth-related tokens, try glab auth token
    if "TOKEN" in name.upper() or "GLAB" in name.upper():
        try:
            result = subprocess.run(
                ["glab", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                logger.debug("Credential '%s' found via glab auth token", name)
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return None


def _resolve_from_dotenv(name: str) -> str | None:
    """Attempt to resolve credential from .env file.

    Reads .env from the current directory. Only available in dev/staging.
    Logs a warning when a credential is resolved from .env.
    """
    dotenv_path = os.path.join(os.getcwd(), ".env")
    if not os.path.isfile(dotenv_path):
        return None

    try:
        with open(dotenv_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                # Remove surrounding quotes
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    value = value[1:-1]
                if key == name:
                    logger.warning(
                        "Credential '%s' resolved from .env file (fallback). "
                        "Consider storing in OS keystore instead.",
                        name,
                    )
                    return value
    except OSError:
        logger.debug("Failed to read .env file at '%s'", dotenv_path)

    return None


# Backend registry: ordered list of (name, resolver_function)
_BACKENDS: list[tuple[str, callable]] = [
    ("keystore", _resolve_from_keystore),
    ("env_var", _resolve_from_env),
    ("gitlab_cli", _resolve_from_glab),
    ("dotenv", _resolve_from_dotenv),
]


def resolve_credential(name: str) -> Credential:
    """Resolve a named credential through the priority pipeline.

    Evaluates backends in order, short-circuits on first success.

    In production: raises CredentialNotFoundError if all backends fail.
    In dev/staging: raises CredentialNotFoundError but logs a warning.
    """
    backends_searched: list[str] = []

    for backend_name, resolver in _BACKENDS:
        # .env fallback is only available in non-production
        if backend_name == "dotenv" and is_production():
            continue

        backends_searched.append(backend_name)
        value = resolver(name)

        if value is not None:
            logger.info(
                "Credential '%s' resolved from %s", name, backend_name
            )
            return Credential(name=name, value=value, source=backend_name)

    env = detect_environment()
    if is_production():
        raise CredentialNotFoundError(name, backends_searched)
    else:
        logger.warning(
            "Credential '%s' not found in any backend (env=%s). "
            "Backends searched: %s",
            name,
            env,
            ", ".join(backends_searched),
        )
        raise CredentialNotFoundError(name, backends_searched)
