"""Tests for the official-CLI-backed 1Password client."""

from __future__ import annotations

import json
import os
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import locke
from locke.errors import OnePasswordError, SecretNotFoundError
from locke.onepassword import OnePasswordClient, _session_credential_name


@pytest.fixture(autouse=True)
def _disable_real_session_keystore(monkeypatch):
    """Unit tests must never consult the operator's real OS keystore."""
    monkeypatch.setattr(OnePasswordClient, "_stored_session_token", lambda self: None)


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


def test_get_reads_the_credential_of_an_api_credential_item(monkeypatch):
    path = "API Credentials"
    calls = _install_op(
        monkeypatch,
        [
            _result([{"id": "api-1", "title": path, "category": "API_CREDENTIAL"}]),
            _result(
                {
                    "id": "api-1",
                    "title": path,
                    "category": "API_CREDENTIAL",
                    "fields": [
                        {"id": "username", "value": "Kernity API KEY for notion"},
                        {"id": "credential", "value": "ntn_example"},
                        {"id": "hostname", "value": ""},
                    ],
                }
            ),
        ],
    )

    item = OnePasswordClient("account.example", "Private").get_item(path)

    assert item.password == "ntn_example"
    assert item.username == "Kernity API KEY for notion"
    list_command = calls[0][0]
    categories = list_command[list_command.index("--categories") + 1]
    assert categories == "Login,Password,API Credential"


def test_get_reads_the_password_of_a_password_item(monkeypatch):
    _install_op(
        monkeypatch,
        [
            _result([{"id": "pw-1", "title": "wifi", "category": "PASSWORD"}]),
            _result(
                {
                    "id": "pw-1",
                    "title": "wifi",
                    "category": "PASSWORD",
                    "fields": [{"id": "password", "value": "pw-secret"}],
                }
            ),
        ],
    )

    assert OnePasswordClient("account.example", "Private").get_secret("wifi") == "pw-secret"


def test_unknown_item_category_fails_closed(monkeypatch):
    _install_op(
        monkeypatch,
        [
            _result([{"id": "x", "title": "card"}]),
            _result({"id": "x", "title": "card", "category": "CREDIT_CARD", "fields": []}),
        ],
    )

    with pytest.raises(OnePasswordError, match="unsupported 1Password item category"):
        OnePasswordClient("account.example", "Private").get_secret("card")


def test_set_refuses_to_rewrite_a_non_login_item(monkeypatch):
    calls = _install_op(
        monkeypatch,
        [_result([{"id": "api-1", "title": "API Credentials", "category": "API_CREDENTIAL"}])],
    )

    with pytest.raises(OnePasswordError, match="only writes Login items"):
        OnePasswordClient("account.example", "Private").set_secret("API Credentials", "x")

    assert len(calls) == 1


def test_duplicate_titles_across_categories_fail_closed(monkeypatch):
    _install_op(
        monkeypatch,
        [
            _result(
                [
                    {"id": "one", "title": "dup", "category": "LOGIN"},
                    {"id": "two", "title": "dup", "category": "API_CREDENTIAL"},
                ]
            )
        ],
    )

    with pytest.raises(OnePasswordError, match="multiple items"):
        OnePasswordClient("account.example", "Private").get_secret("dup")


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

    with pytest.raises(OnePasswordError, match="multiple items"):
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


def _clear_op_auth(monkeypatch):
    for name in list(os.environ):
        if name in {
            "OP_CONNECT_HOST",
            "OP_CONNECT_TOKEN",
            "OP_SERVICE_ACCOUNT_TOKEN",
            "OP_SESSION",
        } or name.startswith("OP_SESSION_"):
            monkeypatch.delenv(name, raising=False)


def test_noninteractive_operation_injects_account_scoped_keystore_session(monkeypatch):
    _clear_op_auth(monkeypatch)
    monkeypatch.setattr(
        "locke.onepassword.sys.stdin",
        SimpleNamespace(isatty=lambda: False),
    )
    monkeypatch.setattr(
        OnePasswordClient,
        "_stored_session_token",
        lambda self: "cached-session-secret",
    )
    calls = _install_op(monkeypatch, [_result([])])

    OnePasswordClient("account.example", "Mail").check()

    command, kwargs = calls[0]
    assert "cached-session-secret" not in command
    assert kwargs["env"]["OP_SESSION"] == "cached-session-secret"
    assert "OP_SESSION" not in os.environ


def test_ambient_auth_takes_precedence_over_cached_session(monkeypatch):
    _clear_op_auth(monkeypatch)
    monkeypatch.setenv("OP_SESSION", "ambient-session")
    monkeypatch.setattr(
        OnePasswordClient,
        "_stored_session_token",
        lambda self: pytest.fail("keystore must not be read when ambient auth exists"),
    )
    calls = _install_op(monkeypatch, [_result([])])

    OnePasswordClient("account.example", "Mail").check()

    assert calls[0][1]["env"]["OP_SESSION"] == "ambient-session"


def test_session_keystore_keys_are_account_scoped():
    first = _session_credential_name("one.1password.com")
    second = _session_credential_name("two.1password.com")

    assert first.startswith("LOCKE_ONEPASSWORD_SESSION_")
    assert first != second
    assert first == _session_credential_name("ONE.1PASSWORD.COM")


def test_authorize_verifies_vault_then_stores_session_without_argv_disclosure(monkeypatch):
    _clear_op_auth(monkeypatch)
    monkeypatch.setattr(
        "locke.onepassword.sys.stdin",
        SimpleNamespace(isatty=lambda: True),
    )
    calls = _install_op(
        monkeypatch,
        [
            _result("short-lived-session-secret\n"),
            _result([]),
        ],
    )
    stored = []
    monkeypatch.setattr(
        "locke.keystore.set_credential",
        lambda name, value: stored.append((name, value)),
    )
    client = OnePasswordClient("account.example", "Mail")

    assert client.authorize() == "session-cached"

    signin_command, signin_kwargs = calls[0]
    assert signin_command[1:] == ["signin", "--account", "account.example", "--raw"]
    assert "short-lived-session-secret" not in signin_command
    assert "OP_SESSION" not in signin_kwargs["env"]

    verify_command, verify_kwargs = calls[1]
    assert verify_command[1:3] == ["item", "list"]
    assert "short-lived-session-secret" not in verify_command
    assert verify_kwargs["env"]["OP_SESSION"] == "short-lived-session-secret"
    assert stored == [(client._session_credential, "short-lived-session-secret")]


def test_authorize_with_app_integration_verifies_vault_and_stores_nothing(monkeypatch):
    _clear_op_auth(monkeypatch)
    monkeypatch.setattr(
        "locke.onepassword.sys.stdin",
        SimpleNamespace(isatty=lambda: True),
    )
    # The desktop app's CLI integration: sign-in succeeds with empty output.
    calls = _install_op(monkeypatch, [_result(""), _result([])])
    store = Mock(side_effect=AssertionError("no token exists to store"))
    monkeypatch.setattr("locke.keystore.set_credential", store)
    deleted = []
    monkeypatch.setattr("locke.keystore.delete_credential", deleted.append)
    client = OnePasswordClient("account.example", "Private")

    assert client.authorize() == "app-integration"

    verify_command, verify_kwargs = calls[1]
    assert verify_command[1:3] == ["item", "list"]
    assert "OP_SESSION" not in verify_kwargs["env"]
    store.assert_not_called()
    assert deleted == [client._session_credential]


def test_authorize_with_app_integration_fails_when_vault_is_unreadable(monkeypatch):
    _clear_op_auth(monkeypatch)
    monkeypatch.setattr(
        "locke.onepassword.sys.stdin",
        SimpleNamespace(isatty=lambda: True),
    )
    _install_op(monkeypatch, [_result(""), _result("", returncode=1)])
    deleted = []
    monkeypatch.setattr("locke.keystore.delete_credential", deleted.append)

    with pytest.raises(OnePasswordError):
        OnePasswordClient("account.example", "Private").authorize()

    assert deleted == []


def test_authorize_does_not_store_session_when_vault_preflight_fails(monkeypatch):
    _clear_op_auth(monkeypatch)
    monkeypatch.setattr(
        "locke.onepassword.sys.stdin",
        SimpleNamespace(isatty=lambda: True),
    )
    secret = "short-lived-session-secret"
    _install_op(
        monkeypatch,
        [
            _result(f"{secret}\n"),
            _result("", returncode=1, stderr=f"denied {secret}"),
        ],
    )
    store = Mock(side_effect=AssertionError("failed preflight must not persist a token"))
    monkeypatch.setattr("locke.keystore.set_credential", store)

    with pytest.raises(OnePasswordError) as caught:
        OnePasswordClient("account.example", "Mail").authorize()

    assert secret not in str(caught.value)
    store.assert_not_called()


def test_authorize_refuses_noninteractive_invocation_before_starting_op(monkeypatch):
    monkeypatch.setattr(
        "locke.onepassword.sys.stdin",
        SimpleNamespace(isatty=lambda: False),
    )
    run = Mock(side_effect=AssertionError("op must not start outside a human terminal"))
    monkeypatch.setattr("locke.onepassword.subprocess.run", run)

    with pytest.raises(OnePasswordError, match="interactive terminal"):
        OnePasswordClient("account.example", "Mail").authorize()

    run.assert_not_called()


def test_cached_session_failure_names_safe_reauthorization_command(monkeypatch):
    _clear_op_auth(monkeypatch)
    monkeypatch.setattr(
        "locke.onepassword.sys.stdin",
        SimpleNamespace(isatty=lambda: False),
    )
    monkeypatch.setattr(
        OnePasswordClient,
        "_stored_session_token",
        lambda self: "expired-session-secret",
    )
    _install_op(
        monkeypatch,
        [_result("", returncode=1, stderr="expired-session-secret was refused")],
    )

    with pytest.raises(OnePasswordError) as caught:
        OnePasswordClient("account.example", "Mail").check()

    message = str(caught.value)
    assert "expired-session-secret" not in message
    assert "locke onepassword authorize" in message


def test_forget_session_deletes_only_the_account_scoped_credential(monkeypatch):
    deleted = []
    monkeypatch.setattr("locke.keystore.delete_credential", deleted.append)
    client = OnePasswordClient("account.example", "Mail")

    client.forget_session()

    assert deleted == [client._session_credential]


_OTP_URL = "otpauth://totp/mail.example.com:user@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=mail.example.com"


def _otp_fields(payload):
    return [field for field in payload["fields"] if field.get("type") == "OTP"]


def test_login_payload_emits_one_otp_field_when_requested():
    payload = OnePasswordClient._login_payload(
        "path",
        "user",
        "secret",
        url=None,
        settings={},
        tags=None,
        otp=_OTP_URL,
    )

    assert _otp_fields(payload) == [
        {"id": "locke_otp", "type": "OTP", "label": "one-time password", "value": _OTP_URL}
    ]


def test_login_payload_has_no_otp_field_by_default():
    payload = OnePasswordClient._login_payload(
        "path", "user", "secret", url=None, settings={}, tags=None
    )

    assert _otp_fields(payload) == []


@pytest.mark.parametrize(
    "value",
    [
        "otpauth://hotp/issuer:user?secret=JBSWY3DPEHPK3PXP",
        "https://example.com/?secret=JBSWY3DPEHPK3PXP",
        "JBSWY3DPEHPK3PXP",
        "",
    ],
)
def test_login_payload_rejects_non_totp_values_without_echoing_them(value):
    with pytest.raises(ValueError) as caught:
        OnePasswordClient._login_payload(
            "path", "user", "secret", url=None, settings={}, tags=None, otp=value
        )

    assert "JBSWY3DPEHPK3PXP" not in str(caught.value)


def test_set_secret_pair_sends_otp_only_over_stdin(monkeypatch):
    path = "obachan/prod/users/user@example.com"
    calls = _install_op(monkeypatch, [_result([]), _result({"id": "created"})])

    OnePasswordClient("account.example", "Mail").set_secret_pair(
        path, "user@example.com", "never-on-argv", otp=_OTP_URL
    )

    command, kwargs = calls[1]
    assert _OTP_URL not in " ".join(command)
    assert _otp_fields(json.loads(kwargs["input"]))[0]["value"] == _OTP_URL


def test_module_level_pair_writer_forwards_otp(monkeypatch):
    client = Mock()
    monkeypatch.setattr(OnePasswordClient, "connect", classmethod(lambda cls: client))

    from locke.onepassword import set_onepassword_secret_pair

    set_onepassword_secret_pair("path", "user", "secret", otp=_OTP_URL)

    client.set_secret_pair.assert_called_once_with("path", "user", "secret", otp=_OTP_URL)
