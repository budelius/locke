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

    def _run_json(
        self,
        operation: str,
        args: list[str],
        *,
        stdin_payload: dict[str, Any] | None = None,
    ) -> Any:
        """Run ``op`` and decode JSON without reflecting stderr or stdin."""
        executable = shutil.which("op")
        if not executable:
            raise OnePasswordError(operation, "the official 'op' CLI is not installed")

        command = [executable, *args, "--account", self.account, "--format=json"]
        stdin = None
        if stdin_payload is not None:
            stdin = json.dumps(stdin_payload, separators=(",", ":")) + "\n"
        try:
            result = subprocess.run(
                command,
                input=stdin,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise OnePasswordError(operation, "the op CLI timed out after 120 seconds") from exc
        except OSError as exc:
            raise OnePasswordError(operation, "the op CLI could not be started") from exc

        if result.returncode != 0:
            # `op` diagnostics can quote submitted field values. Do not include
            # stderr in an exception that an application may log.
            raise OnePasswordError(operation, f"the op CLI exited with status {result.returncode}")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise OnePasswordError(operation, "the op CLI returned invalid JSON") from exc

    def _list_login_items(self) -> list[dict[str, Any]]:
        rows = self._run_json(
            "list items",
            ["item", "list", "--vault", self.vault, "--categories", "Login"],
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
    ) -> dict[str, Any]:
        if not path:
            raise ValueError("path must not be empty")
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
        payload: dict[str, Any] = {
            "title": path,
            "category": "LOGIN",
            "sections": [{"id": _SETTINGS_SECTION_ID, "label": _SETTINGS_SECTION_LABEL}],
            "fields": fields,
            "tags": sorted(set([_MANAGED_TAG, *(tags or [])])),
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
    ) -> str:
        """Create or replace one Login item, sending the secret over stdin."""
        payload = self._login_payload(
            path,
            username,
            value,
            url=url,
            settings=settings or {},
            tags=tags,
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
    ) -> str:
        """Create or replace one structured username/password Login item."""
        return self.set_secret(
            path,
            password,
            username=username,
            url=url,
            settings=settings,
            tags=tags,
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
