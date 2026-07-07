"""Tests for OpenBao KV support."""

from __future__ import annotations

import pytest

from locke.errors import SecretNotFoundError, VaultAuthError
from locke.openbao import OpenBaoClient


def test_connect_accepts_openbao_env_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENBAO_ADDR", "https://bao.example")
    monkeypatch.setenv("OPENBAO_TOKEN", "tok")
    monkeypatch.setenv("LOCKE_OPENBAO_MOUNT", "kv")

    client = OpenBaoClient.connect()

    assert client.addr == "https://bao.example"
    assert client.token == "tok"
    assert client.mount == "kv"
    assert client.kv_version == 2


def test_connect_requires_addr_and_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LOCKE_OPENBAO_ADDR", raising=False)
    monkeypatch.delenv("OPENBAO_ADDR", raising=False)
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("LOCKE_OPENBAO_TOKEN", raising=False)
    monkeypatch.delenv("OPENBAO_TOKEN", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)

    with pytest.raises(VaultAuthError):
        OpenBaoClient.connect()


def test_get_secret_reads_kv2_value(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    class Response:
        status_code = 200

        def raise_for_status(self) -> None: ...

        def json(self) -> dict:
            return {"data": {"data": {"value": "secret"}}}

    def fake_get(url: str, **kwargs: object) -> Response:
        seen["url"] = url
        seen["headers"] = kwargs["headers"]
        return Response()

    monkeypatch.setattr("locke.openbao.httpx.get", fake_get)
    client = OpenBaoClient("https://bao.example", "tok", mount="kv")

    assert client.get_secret("stoz3n/llm/openai/api-key") == "secret"
    assert seen["url"] == "https://bao.example/v1/kv/data/stoz3n/llm/openai/api-key"
    assert seen["headers"] == {"X-Vault-Token": "tok"}


def test_get_secret_404_raises_secret_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        status_code = 404

    monkeypatch.setattr("locke.openbao.httpx.get", lambda *_a, **_k: Response())
    client = OpenBaoClient("https://bao.example", "tok")

    with pytest.raises(SecretNotFoundError):
        client.get_secret("missing")


def test_set_secret_writes_kv2_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    class Response:
        status_code = 200

        def raise_for_status(self) -> None: ...

    def fake_post(url: str, **kwargs: object) -> Response:
        seen["url"] = url
        seen["json"] = kwargs["json"]
        return Response()

    monkeypatch.setattr("locke.openbao.httpx.post", fake_post)
    client = OpenBaoClient("https://bao.example", "tok", mount="kv")

    assert client.set_secret("path/to/secret", "value") == "updated"
    assert seen["url"] == "https://bao.example/v1/kv/data/path/to/secret"
    assert seen["json"] == {"data": {"value": "value"}}


def test_secret_pair_uses_username_and_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        status_code = 200

        def raise_for_status(self) -> None: ...

        def json(self) -> dict:
            return {"data": {"data": {"username": "u", "password": "p"}}}

    monkeypatch.setattr("locke.openbao.httpx.get", lambda *_a, **_k: Response())
    client = OpenBaoClient("https://bao.example", "tok")

    pair = client.get_secret_pair("login")

    assert pair.username == "u"
    assert pair.password == "p"
