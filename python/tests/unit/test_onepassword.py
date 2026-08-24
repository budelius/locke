"""Tests for the official-CLI-backed 1Password client."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import locke
from locke.errors import OnePasswordError, SecretNotFoundError
from locke.onepassword import OnePasswordClient


def _result(payload, *, returncode=0, stderr=""):
    stdout = payload if isinstance(payload, str) else json.dumps(payload)
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _install_op(monkeypatch, responses):
    calls = []
    queue = iter(responses)
    monkeypatch.setattr("locke.onepassword.shutil.which", lambda name: f"/bin/{name}")

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return next(queue)

    monkeypatch.setattr("locke.onepassword.subprocess.run", fake_run)
    return calls


def _item(path="obachan/prod/users/user@example.com", password="secret-value"):
    return {
        "id": "item-1",
        "title": path,
        "category": "LOGIN",
        "fields": [
            {"id": "username", "value": "user@example.com"},
            {"id": "password", "value": password},
            {
                "id": "mail-host-field",
                "section": {"id": "locke_settings"},
                "label": "host",
                "value": "mail.example.com",
            },
        ],
        "urls": [{"primary": True, "href": "https://mail.example.com"}],
    }


def test_onepassword_exports_are_lazy():
    assert locke.OnePasswordClient is OnePasswordClient
    assert locke.OnePasswordItem.__name__ == "OnePasswordItem"


def test_connect_requires_explicit_account_and_vault(monkeypatch):
    monkeypatch.delenv("LOCKE_ONEPASSWORD_ACCOUNT", raising=False)
    monkeypatch.delenv("LOCKE_ONEPASSWORD_VAULT", raising=False)
    monkeypatch.setattr("locke.onepassword._resolve_from_dotenv", lambda name: None)
    monkeypatch.setattr("locke.onepassword.get_setting", lambda name: None)

    with pytest.raises(OnePasswordError, match="onepassword_account"):
        OnePasswordClient.connect()


def test_connect_prefers_environment_over_user_settings(monkeypatch):
    monkeypatch.setenv("LOCKE_ONEPASSWORD_ACCOUNT", "account.example")
    monkeypatch.setenv("LOCKE_ONEPASSWORD_VAULT", "Mail")
    monkeypatch.setattr(
        "locke.onepassword.get_setting",
        lambda name: pytest.fail(f"settings must not be consulted for {name}"),
    )

    client = OnePasswordClient.connect()

    assert client.account == "account.example"
    assert client.vault == "Mail"


def test_get_item_returns_pair_url_and_structured_settings(monkeypatch):
    path = "obachan/prod/users/user@example.com"
    calls = _install_op(
        monkeypatch,
        [
            _result([{"id": "item-1", "title": path}]),
            _result(_item(path)),
        ],
    )
    client = OnePasswordClient("account.example", "Mail")

    item = client.get_item(path)

    assert item.username == "user@example.com"
    assert item.password == "secret-value"
    assert item.url == "https://mail.example.com"
    assert item.settings == {"host": "mail.example.com"}
    assert "--account" in calls[0][0]
    assert "account.example" in calls[0][0]
    assert "--vault" in calls[0][0]
    assert "Mail" in calls[0][0]
    assert "--reveal" in calls[1][0]


def test_check_path_preflights_scope_and_exact_title(monkeypatch):
    path = "obachan/prod/users/user@example.com"
    calls = _install_op(monkeypatch, [_result([{"id": "item-1", "title": path}])])

    assert OnePasswordClient("account.example", "Mail").check_path(path) is True

    assert len(calls) == 1
    assert calls[0][0][1:3] == ["item", "list"]


def test_get_missing_item_raises_without_get_call(monkeypatch):
    calls = _install_op(monkeypatch, [_result([])])

    with pytest.raises(SecretNotFoundError):
        OnePasswordClient("account.example", "Mail").get_secret("missing")

    assert len(calls) == 1


def test_duplicate_exact_titles_fail_closed(monkeypatch):
    path = "obachan/prod/users/user@example.com"
    _install_op(
        monkeypatch,
        [_result([{"id": "one", "title": path}, {"id": "two", "title": path}])],
    )

    with pytest.raises(OnePasswordError, match="multiple Login items"):
        OnePasswordClient("account.example", "Mail").set_secret(path, "secret")


def test_create_sends_password_only_over_stdin(monkeypatch):
    path = "obachan/prod/users/user@example.com"
    calls = _install_op(monkeypatch, [_result([]), _result({"id": "created"})])

    action = OnePasswordClient("account.example", "Mail").set_secret_pair(
        path,
        "user@example.com",
        "never-on-argv",
        url="https://mail.example.com",
        settings={"host": "mail.example.com", "imap_port": "993"},
        tags=["obachan", "mail"],
    )

    assert action == "created"
    create_command, create_kwargs = calls[1]
    assert "-" in create_command
    assert "never-on-argv" not in " ".join(create_command)
    payload = json.loads(create_kwargs["input"])
    password = next(field for field in payload["fields"] if field["id"] == "password")
    assert password["value"] == "never-on-argv"
    custom = {
        field["label"]: field["value"]
        for field in payload["fields"]
        if field.get("section", {}).get("id") == "locke_settings"
    }
    assert custom == {"host": "mail.example.com", "imap_port": "993"}
    assert payload["urls"][0]["href"] == "https://mail.example.com"
    assert payload["tags"] == ["locke-managed", "mail", "obachan"]


def test_update_targets_exact_item_id_and_uses_stdin(monkeypatch):
    path = "obachan/prod/users/user@example.com"
    calls = _install_op(
        monkeypatch,
        [_result([{"id": "existing-id", "title": path}]), _result({"id": "existing-id"})],
    )

    action = OnePasswordClient("account.example", "Mail").set_secret(path, "new-secret")

    assert action == "updated"
    command, kwargs = calls[1]
    assert command[1:4] == ["item", "edit", "existing-id"]
    assert "-" not in command
    assert "new-secret" not in " ".join(command)
    assert "new-secret" in kwargs["input"]


def test_op_failure_does_not_reflect_stderr_or_secret(monkeypatch):
    secret = "sensitive-value"
    _install_op(
        monkeypatch,
        [_result("", returncode=1, stderr=f"bad submitted value: {secret}")],
    )

    with pytest.raises(OnePasswordError) as caught:
        OnePasswordClient("account.example", "Mail").set_secret("path", secret)

    assert secret not in str(caught.value)
    assert "bad submitted" not in str(caught.value)


def test_op_timeout_is_wrapped_without_command_data(monkeypatch):
    monkeypatch.setattr("locke.onepassword.shutil.which", lambda name: f"/bin/{name}")
    run = Mock(side_effect=subprocess.TimeoutExpired(["op"], 30))
    monkeypatch.setattr("locke.onepassword.subprocess.run", run)

    with pytest.raises(OnePasswordError, match="timed out"):
        OnePasswordClient("account.example", "Mail").get_secret("path")


def test_setting_names_are_validated_before_op_write(monkeypatch):
    with pytest.raises(ValueError, match="field name"):
        OnePasswordClient._login_payload(
            "path",
            "user",
            "secret",
            url=None,
            settings={"bad/name": "value"},
            tags=None,
        )
