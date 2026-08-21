"""OpenBao KV client.

Provides a small Locke-native interface over OpenBao's HTTP API. The client is
intentionally shaped like :mod:`locke.vault` so applications can migrate from
Vaultwarden to OpenBao without changing every call site.

Environment variables:
- ``LOCKE_OPENBAO_ADDR`` / ``OPENBAO_ADDR`` / ``VAULT_ADDR``: OpenBao base URL.
- ``LOCKE_OPENBAO_TOKEN`` / ``OPENBAO_TOKEN`` / ``VAULT_TOKEN``: token.
- ``LOCKE_OPENBAO_MOUNT``: KV mount name, default ``secret``.
- ``LOCKE_OPENBAO_KV_VERSION``: ``2`` (default) or ``1``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

from locke.errors import SecretNotFoundError, VaultAuthError
from locke.vault import PLACEHOLDER_VALUE, CredentialPair, is_placeholder


class OpenBaoError(RuntimeError):
    """Base OpenBao client error."""


@dataclass
class OpenBaoClient:
    """HTTP client for OpenBao KV secrets."""

    addr: str
    token: str
    mount: str = "secret"
    kv_version: int = 2
    timeout: float = 10.0

    @classmethod
    def connect(cls) -> OpenBaoClient:
        """Create a client from environment variables."""
        addr = _first_env("LOCKE_OPENBAO_ADDR", "OPENBAO_ADDR", "VAULT_ADDR")
        token = _first_env("LOCKE_OPENBAO_TOKEN", "OPENBAO_TOKEN", "VAULT_TOKEN")
        mount = os.environ.get("LOCKE_OPENBAO_MOUNT", "secret")
        kv_version_raw = os.environ.get("LOCKE_OPENBAO_KV_VERSION", "2")
        if not addr:
            raise VaultAuthError(
                "openbao", "LOCKE_OPENBAO_ADDR/OPENBAO_ADDR/VAULT_ADDR is not set"
            )
        if not token:
            raise VaultAuthError(
                addr, "LOCKE_OPENBAO_TOKEN/OPENBAO_TOKEN/VAULT_TOKEN is not set"
            )
        try:
            kv_version = int(kv_version_raw)
        except ValueError as exc:
            raise VaultAuthError(
                addr, "LOCKE_OPENBAO_KV_VERSION must be 1 or 2"
            ) from exc
        if kv_version not in {1, 2}:
            raise VaultAuthError(addr, "LOCKE_OPENBAO_KV_VERSION must be 1 or 2")
        return cls(
            addr=addr.rstrip("/"),
            token=token,
            mount=mount.strip("/"),
            kv_version=kv_version,
        )

    def get_secret(self, path: str) -> str:
        """Return the string secret at ``path``.

        KV v2 payloads may be either ``{"value": "..."}`` or a raw string-ish
        value. ``password`` is also accepted to ease pair migration.
        """
        data = self._read(path)
        value = data.get("value", data.get("password", ""))
        if value is None:
            value = ""
        value = str(value)
        if is_placeholder(value):
            # Keep behavior aligned with Vaultwarden: placeholders are returned
            # but callers can detect them with ``locke.is_placeholder``.
            pass
        return value

    def set_secret(self, path: str, value: str | None = None, **_: Any) -> str:
        """Create or update a string secret at ``path``."""
        self._write(path, {"value": value or PLACEHOLDER_VALUE})
        return "updated"

    def get_secret_pair(self, path: str) -> CredentialPair:
        """Return username + password stored at ``path``."""
        data = self._read(path)
        password = data.get("password", data.get("value", ""))
        return CredentialPair(
            username=str(data["username"])
            if data.get("username") is not None
            else None,
            password=str(password or ""),
        )

    def set_secret_pair(
        self, path: str, username: str, password: str | None = None, **_: Any
    ) -> str:
        """Create or update username + password at ``path``."""
        self._write(
            path, {"username": username, "password": password or PLACEHOLDER_VALUE}
        )
        return "updated"

    def list_secrets(self, prefix: str = "") -> dict[str, str]:
        """Best-effort recursive list of secrets under ``prefix``.

        Requires the token to have ``list`` capability on the KV metadata path.
        """
        out: dict[str, str] = {}
        for path in self._list_paths(prefix.strip("/")):
            try:
                out[path] = self.get_secret(path)
            except SecretNotFoundError:
                continue
        return out

    def _headers(self) -> dict[str, str]:
        return {"X-Vault-Token": self.token}

    def _secret_url(self, path: str) -> str:
        path = path.strip("/")
        if self.kv_version == 2:
            return f"{self.addr}/v1/{self.mount}/data/{path}"
        return f"{self.addr}/v1/{self.mount}/{path}"

    def _metadata_url(self, path: str) -> str:
        path = path.strip("/")
        if self.kv_version == 2:
            return f"{self.addr}/v1/{self.mount}/metadata/{path}"
        return f"{self.addr}/v1/{self.mount}/{path}"

    def _read(self, path: str) -> dict[str, Any]:
        response = httpx.get(
            self._secret_url(path), headers=self._headers(), timeout=self.timeout
        )
        if response.status_code == 404:
            raise SecretNotFoundError(path)
        if response.status_code in {401, 403}:
            raise VaultAuthError(
                self.addr, f"OpenBao denied secret read ({response.status_code})"
            )
        response.raise_for_status()
        payload = response.json().get("data", {})
        if self.kv_version == 2:
            payload = payload.get("data", {})
        if isinstance(payload, dict):
            return payload
        return {"value": payload}

    def _write(self, path: str, data: dict[str, Any]) -> None:
        payload = {"data": data} if self.kv_version == 2 else data
        response = httpx.post(
            self._secret_url(path),
            headers=self._headers(),
            json=payload,
            timeout=self.timeout,
        )
        if response.status_code in {401, 403}:
            raise VaultAuthError(
                self.addr, f"OpenBao denied secret write ({response.status_code})"
            )
        response.raise_for_status()

    def _list_paths(self, prefix: str) -> list[str]:
        url = self._metadata_url(prefix)
        response = httpx.request(
            "LIST", url, headers=self._headers(), timeout=self.timeout
        )
        if response.status_code == 404:
            return []
        if response.status_code in {401, 403}:
            raise VaultAuthError(
                self.addr, f"OpenBao denied secret list ({response.status_code})"
            )
        response.raise_for_status()
        keys = response.json().get("data", {}).get("keys", [])
        paths: list[str] = []
        for key in keys:
            key = str(key)
            child = f"{prefix.rstrip('/')}/{key}" if prefix else key
            if child.endswith("/"):
                paths.extend(self._list_paths(child.rstrip("/")))
            else:
                paths.append(child)
        return paths


def _first_env(*names: str) -> str:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return ""


def get_openbao_secret(path: str) -> str:
    """Retrieve an OpenBao KV secret by path."""
    return OpenBaoClient.connect().get_secret(path)


def set_openbao_secret(path: str, value: str | None = None, **kwargs: Any) -> str:
    """Create or update an OpenBao KV secret by path."""
    return OpenBaoClient.connect().set_secret(path, value, **kwargs)


def get_openbao_secret_pair(path: str) -> CredentialPair:
    """Retrieve username + password stored in one OpenBao secret."""
    return OpenBaoClient.connect().get_secret_pair(path)


def set_openbao_secret_pair(
    path: str, username: str, password: str | None = None, **kwargs: Any
) -> str:
    """Create or update username + password in one OpenBao secret."""
    return OpenBaoClient.connect().set_secret_pair(path, username, password, **kwargs)
