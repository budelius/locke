"""1Password CLI-backed secret storage.

This backend deliberately delegates authentication and encryption to the
official ``op`` CLI.  Locke only builds and parses Login-item JSON.  Secret
values are supplied to ``op item create/edit`` over stdin so they never appear
in process arguments or shell history.

Each Locke path maps to the exact title of one Login item in an explicitly
configured 1Password account and vault.  Duplicate exact titles fail closed;
Locke never updates an arbitrary match.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from locke.env import is_production
from locke.errors import OnePasswordError, SecretNotFoundError
from locke.pipeline import _resolve_from_dotenv
from locke.settings import get_setting
from locke.vault import CredentialPair

ONEPASSWORD_ACCOUNT_VAR = "LOCKE_ONEPASSWORD_ACCOUNT"
ONEPASSWORD_VAULT_VAR = "LOCKE_ONEPASSWORD_VAULT"
_SETTINGS_SECTION_ID = "locke_settings"
_SETTINGS_SECTION_LABEL = "Connection settings"
_MANAGED_TAG = "locke-managed"
_FIELD_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_. -]{0,63}$")
_SESSION_CREDENTIAL_PREFIX = "LOCKE_ONEPASSWORD_SESSION_"
_OP_FIXED_AUTH_VARS = frozenset(
    {
        "OP_CONNECT_HOST",
        "OP_CONNECT_TOKEN",
        "OP_SERVICE_ACCOUNT_TOKEN",
        "OP_SESSION",
    }
)


def _session_credential_name(account: str) -> str:
    """Return a stable, account-scoped OS-keystore credential name."""
    digest = sha256(account.strip().casefold().encode("utf-8")).hexdigest()[:24]
    return f"{_SESSION_CREDENTIAL_PREFIX}{digest.upper()}"


def _has_ambient_auth(environment: dict[str, str]) -> bool:
    """Return whether ``op`` already has explicit non-terminal authentication."""
    if environment.get("OP_SERVICE_ACCOUNT_TOKEN") or environment.get("OP_SESSION"):
        return True
    if environment.get("OP_CONNECT_HOST") and environment.get("OP_CONNECT_TOKEN"):
        return True
    return any(
        name.startswith("OP_SESSION_") and bool(value)
        for name, value in environment.items()
    )


def _without_op_auth(environment: dict[str, str]) -> dict[str, str]:
    """Copy an environment without bearer credentials used by ``op``."""
    clean = dict(environment)
    for name in list(clean):
        if name in _OP_FIXED_AUTH_VARS or name.startswith("OP_SESSION_"):
            clean.pop(name, None)
    return clean


@dataclass(frozen=True)
class OnePasswordItem:
    """Decrypted fields from one Locke-managed 1Password Login item."""

    title: str
    username: str | None
    password: str
    url: str | None
    settings: dict[str, str]


class OnePasswordClient:
    """Idempotent Login-item client using the official ``op`` executable."""

    def __init__(self, account: str, vault: str) -> None:
        if not account:
            raise ValueError("1Password account must not be empty")
        if not vault:
            raise ValueError("1Password vault must not be empty")
        self.account = account
        self.vault = vault

    @staticmethod
    def _connection_setting(var_name: str) -> str | None:
        """Resolve environment > local .env > user settings."""
        value = os.environ.get(var_name)
        if value:
            return value
        if not is_production():
            value = _resolve_from_dotenv(var_name)
            if value:
                return value
        return get_setting(var_name)

    @classmethod
    def connect(
        cls,
        *,
        account: str | None = None,
        vault: str | None = None,
    ) -> OnePasswordClient:
        """Build a client with explicit, non-ambient account and vault scope."""
        resolved_account = account or cls._connection_setting(ONEPASSWORD_ACCOUNT_VAR)
        resolved_vault = vault or cls._connection_setting(ONEPASSWORD_VAULT_VAR)
        missing = [
            name
            for name, value in (
                (ONEPASSWORD_ACCOUNT_VAR, resolved_account),
                (ONEPASSWORD_VAULT_VAR, resolved_vault),
            )
            if not value
        ]
        if missing:
            settings = "onepassword_account / onepassword_vault"
            raise OnePasswordError(
                "configuration",
                f"missing {', '.join(missing)}; set environment variables or Locke settings "
                f"({settings})",
            )
        return cls(str(resolved_account), str(resolved_vault))

    @property
    def _session_credential(self) -> str:
        return _session_credential_name(self.account)

    def _stored_session_token(self) -> str | None:
        """Read this account's short-lived session from Locke's OS keystore."""
        from locke.errors import LockeError
        from locke.keystore import get_credential

        try:
            return get_credential(self._session_credential)
        except LockeError as exc:
            raise OnePasswordError(
                "authentication",
                "Locke could not read the cached 1Password session from the OS keystore",
            ) from exc
        except Exception as exc:
            # Omit backend text because it may contain secret data.
            raise OnePasswordError(
                "authentication",
                "unexpected failure while reading the cached 1Password session",
            ) from exc

    def _op_environment(
        self,
        *,
        session_token: str | None = None,
    ) -> tuple[dict[str, str], str]:
        """Build an isolated ``op`` environment and describe its auth source."""
        if session_token is not None:
            environment = _without_op_auth(os.environ)
            environment["OP_SESSION"] = session_token
            return environment, "explicit"

        environment = dict(os.environ)
        if _has_ambient_auth(environment):
            return environment, "ambient"

        # Interactive callers should keep using 1Password's desktop-app
        # integration. The keystore bridge exists specifically for child and
        # agent processes that cannot share that terminal-scoped authorization.
        if sys.stdin.isatty():
            return environment, "terminal"

        cached = self._stored_session_token()
        if cached:
            environment["OP_SESSION"] = cached
            return environment, "keystore"
        return environment, "none"

    def _run_json(
        self,
        operation: str,
        args: list[str],
        *,
        stdin_payload: dict[str, Any] | None = None,
        session_token: str | None = None,
    ) -> Any:
        """Run ``op`` and decode JSON without reflecting stderr or stdin."""
        executable = shutil.which("op")
        if not executable:
            raise OnePasswordError(operation, "the official 'op' CLI is not installed")

        command = [executable, *args, "--account", self.account, "--format=json"]
        stdin = None
        if stdin_payload is not None:
            stdin = json.dumps(stdin_payload, separators=(",", ":")) + "\n"
        environment, auth_source = self._op_environment(session_token=session_token)
        try:
            result = subprocess.run(
                command,
                input=stdin,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=120,
                check=False,
                env=environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise OnePasswordError(operation, "the op CLI timed out after 120 seconds") from exc
        except OSError as exc:
            raise OnePasswordError(operation, "the op CLI could not be started") from exc

        if result.returncode != 0:
            # `op` diagnostics can quote submitted field values. Do not include
            # stderr in an exception that an application may log.
            if auth_source == "keystore":
                detail = (
                    "the cached session was refused or has expired; run "
                    "'locke onepassword authorize' in an interactive terminal"
                )
            elif auth_source == "none":
                detail = (
                    "no reusable session is available; run "
                    "'locke onepassword authorize' in an interactive terminal"
                )
            else:
                detail = f"the op CLI exited with status {result.returncode}"
            raise OnePasswordError(operation, detail)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise OnePasswordError(operation, "the op CLI returned invalid JSON") from exc

    def _list_login_items(
        self,
        *,
        session_token: str | None = None,
    ) -> list[dict[str, Any]]:
        rows = self._run_json(
            "list items",
            ["item", "list", "--vault", self.vault, "--categories", "Login"],
            session_token=session_token,
        )
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise OnePasswordError("list items", "the op CLI returned an invalid item list")
        return rows

    def check(self) -> None:
        """Prove the configured account/vault is readable without revealing items."""
        self._list_login_items()

    def check_path(self, path: str) -> bool:
        """Preflight account/vault access and exact-title uniqueness."""
        return self._find_item_id(path) is not None

    def authorize(self) -> None:
        """Cache an interactive ``op signin`` session after verifying the vault.

        The short-lived token is captured in memory, verified against the
        configured account/vault, and stored only in Locke's OS keystore. It is
        never printed, passed on argv, or written to plaintext settings.
        """
        if not sys.stdin.isatty():
            raise OnePasswordError(
                "authorize",
                "this command must run directly in an interactive terminal",
            )

        executable = shutil.which("op")
        if not executable:
            raise OnePasswordError("authorize", "the official 'op' CLI is not installed")

        command = [executable, "signin", "--account", self.account, "--raw"]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=120,
                check=False,
                env=_without_op_auth(os.environ),
            )
        except subprocess.TimeoutExpired as exc:
            raise OnePasswordError(
                "authorize",
                "interactive sign-in timed out after 120 seconds",
            ) from exc
        except OSError as exc:
            raise OnePasswordError("authorize", "the op CLI could not be started") from exc

        if result.returncode != 0:
            raise OnePasswordError(
                "authorize",
                "interactive sign-in failed; run this command directly in an unlocked terminal",
            )
        token = result.stdout.strip()
        if not token or any(character.isspace() for character in token):
            raise OnePasswordError("authorize", "the op CLI returned an invalid session token")

        # Verify both account authentication and exact configured-vault access
        # before persisting the bearer token.
        self._list_login_items(session_token=token)

        from locke.errors import LockeError
        from locke.keystore import set_credential

        try:
            set_credential(self._session_credential, token)
        except LockeError as exc:
            raise OnePasswordError(
                "authorize",
                "Locke could not store the session in the OS keystore",
            ) from exc
        except Exception as exc:
            # Omit backend text because it may contain secret data.
            raise OnePasswordError(
                "authorize",
                "unexpected failure while storing the session",
            ) from exc

    def forget_session(self) -> None:
        """Delete this account's cached session from Locke's OS keystore."""
        from locke.errors import LockeError
        from locke.keystore import delete_credential

        try:
            delete_credential(self._session_credential)
        except LockeError as exc:
            raise OnePasswordError(
                "forget session",
                "Locke could not delete the cached session from the OS keystore",
            ) from exc
        except Exception as exc:
            # Keep backend diagnostics redaction-safe.
            raise OnePasswordError(
                "forget session",
                "unexpected failure while deleting the cached session",
            ) from exc

    def _find_item_id(self, path: str) -> str | None:
        rows = self._list_login_items()
        matches = [row for row in rows if row.get("title") == path]
        if len(matches) > 1:
            raise OnePasswordError(
                "find item",
                f"multiple Login items have the exact title {path!r} in vault {self.vault!r}",
            )
        if not matches:
            return None
        item_id = matches[0].get("id")
        if not isinstance(item_id, str) or not item_id:
            raise OnePasswordError("find item", "the matching item has no valid id")
        return item_id

    def _get_item_json(self, item_id: str) -> dict[str, Any]:
        payload = self._run_json(
            "get item",
            ["item", "get", item_id, "--vault", self.vault, "--reveal"],
        )
        if not isinstance(payload, dict):
            raise OnePasswordError("get item", "the op CLI returned an invalid item")
        return payload

    @staticmethod
    def _field_value(payload: dict[str, Any], *, field_id: str) -> str | None:
        for field in payload.get("fields", []):
            if isinstance(field, dict) and field.get("id") == field_id:
                value = field.get("value")
                return value if isinstance(value, str) else None
        return None

    @staticmethod
    def _item_from_json(payload: dict[str, Any]) -> OnePasswordItem:
        title = payload.get("title")
        if not isinstance(title, str) or not title:
            raise OnePasswordError("get item", "the op CLI item has no valid title")
        username = OnePasswordClient._field_value(payload, field_id="username")
        password = OnePasswordClient._field_value(payload, field_id="password") or ""
        settings: dict[str, str] = {}
        for field in payload.get("fields", []):
            if not isinstance(field, dict):
                continue
            section = field.get("section")
            if not isinstance(section, dict) or section.get("id") != _SETTINGS_SECTION_ID:
                continue
            label = field.get("label")
            value = field.get("value")
            if isinstance(label, str) and isinstance(value, str):
                settings[label] = value
        url = None
        for candidate in payload.get("urls", []):
            if isinstance(candidate, dict) and isinstance(candidate.get("href"), str):
                url = candidate["href"]
                if candidate.get("primary") is True:
                    break
        return OnePasswordItem(
            title=title,
            username=username,
            password=password,
            url=url,
            settings=settings,
        )

    @staticmethod
    def _settings_fields(settings: dict[str, str]) -> list[dict[str, Any]]:
        fields: list[dict[str, Any]] = []
        for label, value in sorted(settings.items()):
            if not _FIELD_KEY.fullmatch(label):
                raise ValueError(f"invalid 1Password setting field name: {label!r}")
            if not isinstance(value, str):
                raise TypeError(f"1Password setting {label!r} must be a string")
            field_id = f"locke_{sha256(label.encode('utf-8')).hexdigest()[:12]}"
            fields.append(
                {
                    "id": field_id,
                    "section": {"id": _SETTINGS_SECTION_ID},
                    "type": "STRING",
                    "label": label,
                    "value": value,
                }
            )
        return fields

    @classmethod
    def _login_payload(
        cls,
        path: str,
        username: str | None,
        password: str,
        *,
        url: str | None,
        settings: dict[str, str],
        tags: list[str] | None,
        otp: str | None = None,
    ) -> dict[str, Any]:
        if not path:
            raise ValueError("path must not be empty")
        if otp is not None and not otp.startswith("otpauth://totp/"):
            # Never echo the value: it carries the TOTP seed.
            raise ValueError("otp must be an otpauth://totp/ URL")
        fields: list[dict[str, Any]] = [
            {
                "id": "username",
                "type": "STRING",
                "purpose": "USERNAME",
                "label": "username",
                "value": username or "",
            },
            {
                "id": "password",
                "type": "CONCEALED",
                "purpose": "PASSWORD",
                "label": "password",
                "value": password,
            },
            {
                "id": "notesPlain",
                "type": "STRING",
                "purpose": "NOTES",
                "label": "notesPlain",
                "value": "Managed by Locke; update through the owning automation.",
            },
        ]
        fields.extend(cls._settings_fields(settings))
        if otp is not None:
            # 1Password generates codes from an OTP field holding the otpauth URL.
            fields.append(
                {"id": "locke_otp", "type": "OTP", "label": "one-time password", "value": otp}
            )
        payload: dict[str, Any] = {
            "title": path,
            "category": "LOGIN",
            "sections": [{"id": _SETTINGS_SECTION_ID, "label": _SETTINGS_SECTION_LABEL}],
            "fields": fields,
            "tags": sorted({_MANAGED_TAG, *(tags or [])}),
        }
        if url:
            payload["urls"] = [{"label": "website", "primary": True, "href": url}]
        return payload

    def get_item(self, path: str) -> OnePasswordItem:
        """Return one exact-title Login item with its structured settings."""
        item_id = self._find_item_id(path)
        if item_id is None:
            raise SecretNotFoundError(path)
        return self._item_from_json(self._get_item_json(item_id))

    def get_secret(self, path: str) -> str:
        """Return the password/value field for an exact Locke path."""
        return self.get_item(path).password

    def get_secret_pair(self, path: str) -> CredentialPair:
        """Return username and password from an exact Locke path."""
        item = self.get_item(path)
        return CredentialPair(username=item.username, password=item.password)

    def set_secret(
        self,
        path: str,
        value: str,
        *,
        username: str | None = None,
        url: str | None = None,
        settings: dict[str, str] | None = None,
        tags: list[str] | None = None,
        otp: str | None = None,
    ) -> str:
        """Create or replace one Login item, sending the secret over stdin.

        The write replaces every field, so callers that want a one-time-password
        field kept must pass ``otp`` on every write to the item.
        """
        payload = self._login_payload(
            path,
            username,
            value,
            url=url,
            settings=settings or {},
            tags=tags,
            otp=otp,
        )
        item_id = self._find_item_id(path)
        if item_id is None:
            self._run_json(
                "create item",
                ["item", "create", "--vault", self.vault, "-"],
                stdin_payload=payload,
            )
            return "created"
        self._run_json(
            "edit item",
            ["item", "edit", item_id, "--vault", self.vault],
            stdin_payload=payload,
        )
        return "updated"

    def set_secret_pair(
        self,
        path: str,
        username: str | None,
        password: str,
        *,
        url: str | None = None,
        settings: dict[str, str] | None = None,
        tags: list[str] | None = None,
        otp: str | None = None,
    ) -> str:
        """Create or replace one structured username/password Login item."""
        return self.set_secret(
            path,
            password,
            username=username,
            url=url,
            settings=settings,
            tags=tags,
            otp=otp,
        )


def get_onepassword_secret(path: str) -> str:
    """Retrieve a password/value from the configured 1Password vault."""
    return OnePasswordClient.connect().get_secret(path)


def get_onepassword_secret_pair(path: str) -> CredentialPair:
    """Retrieve a username/password pair from the configured 1Password vault."""
    return OnePasswordClient.connect().get_secret_pair(path)


def set_onepassword_secret(path: str, value: str, **kwargs: Any) -> str:
    """Create or update a Login item in the configured 1Password vault."""
    return OnePasswordClient.connect().set_secret(path, value, **kwargs)


def set_onepassword_secret_pair(
    path: str,
    username: str | None,
    password: str,
    **kwargs: Any,
) -> str:
    """Create or update a structured Login item in the configured 1Password vault."""
    return OnePasswordClient.connect().set_secret_pair(path, username, password, **kwargs)
