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
import re
from contextvars import ContextVar
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

#: Opt-in for the cwd-scoped `glab variable get` lookup.
GLAB_VARIABLES_VAR = "LOCKE_GLAB_VARIABLES"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


@dataclass
class Credential:
    """A resolved credential with metadata."""

    name: str
    value: str
    source: str  # "keystore", "env_var", "gitlab_cli", "dotenv"
    resolved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _try_keystore(name: str) -> tuple[str | None, bool]:
    """Resolve from the OS keystore, reporting whether it could be consulted.

    Returns ``(value, unavailable)``. ``unavailable`` is True when the keystore
    could not answer for an *environmental* reason -- biometric gating, most
    often Windows Hello being unable to prompt while the workstation is locked.

    That distinction is the point. "The keystore does not have it" and "the
    keystore could not be asked" look identical to a caller, but only the first
    is evidence the credential is absent. Treating the second as a miss is what
    let weaker backends answer for a credential that was sitting right there.
    """
    try:
        return keystore_get(name), False
    except (BiometricDeniedError, BiometricUnavailableError) as exc:
        logger.warning(
            "Biometric gating prevented keystore access for '%s': %s - "
            "trying remaining name-addressed backends. Set "
            "LOCKE_USE_BIOMETRIC=false for unattended runs (the OS credential "
            "store stays readable while the workstation is locked; only the "
            "biometric prompt does not).",
            name, exc,
        )
        return None, True
    except Exception:
        logger.debug("Keystore lookup failed for '%s'", name)
        return None, False


#: Set by the keystore backend when it could not be consulted at all (as
#: opposed to being consulted and not having the credential). A ContextVar
#: rather than a module global so concurrent resolutions -- threads, asyncio
#: tasks -- cannot read each other's outcome.
_keystore_unavailable: ContextVar[bool] = ContextVar(
    "locke_keystore_unavailable", default=False
)


def _resolve_from_keystore(name: str) -> str | None:
    """Attempt to resolve credential from OS keystore.

    Biometric errors (denied / unavailable) are caught so the pipeline can fall
    through, and recorded in :data:`_keystore_unavailable` so
    :func:`resolve_credential` can tell "not stored" from "could not ask".
    """
    value, unavailable = _try_keystore(name)
    _keystore_unavailable.set(unavailable)
    return value


def _resolve_from_env(name: str) -> str | None:
    """Attempt to resolve credential from environment variable."""
    value = os.environ.get(name)
    if value:
        logger.debug("Credential '%s' found in environment variable", name)
    return value


# Words that mark a GitLab credential as something OTHER than the personal
# token `glab auth token` returns. GitLab issues many token kinds against the
# same host -- deploy, registry, runner, group, trigger, job, impersonation --
# and an admin token is a different identity with different rights.
_NON_PERSONAL_GITLAB_ROLES = frozenset(
    {
        "ADMIN",
        "BOT",
        "DEPLOY",
        "GROUP",
        "IMPERSONATION",
        "JOB",
        "PROJECT",
        "REGISTRY",
        "RUNNER",
        "TRIGGER",
        "WEBHOOK",
    }
)

# Words marking a name as not a token at all (an id, a URL, an account).
_NOT_A_TOKEN = frozenset({"ID", "URL", "HOST", "USER", "USERNAME", "EMAIL", "PASSWORD"})


def _is_glab_auth_token_name(name: str) -> bool:
    """True only if ``name`` denotes the personal token `glab auth token` returns.

    `glab auth token` is name-blind: it hands back whichever token the CLI
    authenticated with, no matter what was asked for. It may therefore answer
    only names that mean *that* token.

    Matching merely "mentions GitLab" is not enough. GitLab issues several
    kinds of credential against the same host, so `GITLAB_ADMIN_TOKEN` (used
    to rotate project access tokens) or `GITLAB_DEPLOY_TOKEN` would otherwise
    be answered with the personal token -- the same silent substitution that
    sent a GitLab token to api.hetzner.cloud, one blast radius smaller.

    Prefixed names still qualify (``OBACHAN_PROD_GITLAB_API_TOKEN``): callers
    namespace credentials per project and environment.
    """
    words = set(re.split(r"[^A-Z0-9]+", name.upper()))
    if not words & {"GITLAB", "GLAB"}:
        return False
    if "TOKEN" not in words:
        return False
    if words & _NON_PERSONAL_GITLAB_ROLES:
        return False
    return not words & _NOT_A_TOKEN


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

    # `glab variable get` resolves against whichever GitLab project the current
    # directory maps to, so the same name yields different values depending on
    # where the process happens to be running -- across environments, that is a
    # credential swap. It is name-addressed, so it is not the `auth token` bug,
    # but it is still an answer nobody asked this checkout for. Opt in.
    if os.environ.get(GLAB_VARIABLES_VAR, "").strip().lower() in _TRUTHY:
        try:
            result = subprocess.run(
                ["glab", "variable", "get", name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                logger.warning(
                    "Credential '%s' resolved from `glab variable get`, i.e. from "
                    "the GitLab project the current directory maps to. Verify it "
                    "is the right project and environment.",
                    name,
                )
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # `glab auth token` returns THE personal GitLab token regardless of what
    # was asked for, so it may only answer names that mean that token. Gating
    # on "TOKEN" made it answer every *_TOKEN name -- HCLOUD_TOKEN,
    # CLOUDFLARE_API_TOKEN, ... -- so any keystore miss silently handed the
    # caller a GitLab token and shipped it to an unrelated API.
    if _is_glab_auth_token_name(name):
        try:
            result = subprocess.run(
                ["glab", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                # Loud on purpose. This backend is not name-addressed, so an
                # answer here means a stronger source (keystore, env) missed --
                # exactly the condition that went unnoticed for ~10h during the
                # 2026-08-17 incident.
                logger.warning(
                    "Credential '%s' resolved from `glab auth token` -- the GitLab "
                    "CLI's own token, returned without regard to the name asked "
                    "for. A stronger backend (OS keystore, environment) did not "
                    "answer. Verify this is really the credential you want.",
                    name,
                )
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

# Backends that can return a value for a name they did not look up. They are
# acceptable as a last resort, but never as a stand-in for a keystore that was
# merely unreachable.
_NAME_BLIND_BACKENDS = frozenset({"gitlab_cli"})


def resolve_credential(name: str) -> Credential:
    """Resolve a named credential through the priority pipeline.

    Evaluates backends in order, short-circuits on first success.

    In production: raises CredentialNotFoundError if all backends fail.
    In dev/staging: raises CredentialNotFoundError but logs a warning.
    """
    backends_searched: list[str] = []
    keystore_unavailable = False
    _keystore_unavailable.set(False)

    for backend_name, resolver in _BACKENDS:
        # .env fallback is only available in non-production
        if backend_name == "dotenv" and is_production():
            continue

        if backend_name in _NAME_BLIND_BACKENDS and keystore_unavailable:
            # The authoritative, name-addressed source could not be consulted.
            # Letting a name-blind one answer in its place is how a GitLab
            # token ended up in Authorization headers to api.hetzner.cloud.
            logger.warning(
                "Skipping the %s backend for '%s': the OS keystore could not be "
                "consulted, and %s can return a value for a name it did not look "
                "up. Resolve the keystore problem rather than trusting this.",
                backend_name, name, backend_name,
            )
            continue

        backends_searched.append(backend_name)
        value = resolver(name)
        if backend_name == "keystore":
            keystore_unavailable = _keystore_unavailable.get()

        if value is not None:
            logger.info(
                "Credential '%s' resolved from %s", name, backend_name
            )
            return Credential(name=name, value=value, source=backend_name)

    env = detect_environment()
    if keystore_unavailable:
        # Do not let this read as "the credential was never stored" -- that
        # misreading cost ~10h of misdirected debugging on 2026-08-17.
        raise CredentialNotFoundError(
            name,
            backends_searched,
            detail=(
                "the OS keystore could not be consulted (biometric gating), so "
                "the credential may well be stored and simply unreachable. For "
                "unattended runs set LOCKE_USE_BIOMETRIC=false"
            ),
        )
    if not is_production():
        logger.warning(
            "Credential '%s' not found in any backend (env=%s). "
            "Backends searched: %s",
            name,
            env,
            ", ".join(backends_searched),
        )
    raise CredentialNotFoundError(name, backends_searched)
