"""Tests for validation helpers."""

from locke.cli.validate_cmd import _expand_vault_path, _is_placeholder_secret


def test_expand_vault_path_replaces_project_and_tenant():
    config = {"project": "myapp", "tenant": "dev"}

    assert _expand_vault_path("{project}/{tenant}/api_key", config) == "myapp/dev/api_key"


def test_is_placeholder_secret_detects_fill_me():
    assert _is_placeholder_secret("FILL_ME")
    assert _is_placeholder_secret("  FILL_ME  ")
    assert not _is_placeholder_secret("real-secret")
