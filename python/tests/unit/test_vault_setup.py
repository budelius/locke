"""Tests for the vault setup workflow."""

import json

from click.testing import CliRunner

import locke.cli.vault_setup as vault_setup_mod


def _write_locke_json(tmp_path, config):
    locke_dir = tmp_path / ".locke"
    locke_dir.mkdir()
    (locke_dir / "locke.json").write_text(json.dumps(config), encoding="utf-8")


def test_all_vault_entries_expands_registry_and_legacy_refs(tmp_path):
    config = {
        "project": "myapp",
        "tenant": "dev",
        "keys": {
            "vault": {
                "_comment": "ignored",
                "{project}/{tenant}/api_key": "API key -> API_KEY",
            },
        },
    }
    _write_locke_json(tmp_path, config)
    (tmp_path / ".locke" / "vault-references.json").write_text(
        json.dumps({
            "secrets": [
                {
                    "path": "{project}/{tenant}/token",
                    "original_key": "SERVICE_TOKEN",
                },
                {
                    "path": "{project}/{tenant}/api_key",
                    "original_key": "API_KEY",
                },
            ],
        }),
        encoding="utf-8",
    )

    entries = vault_setup_mod._all_vault_entries(str(tmp_path), config)

    assert [entry["actual_path"] for entry in entries] == [
        "myapp/dev/api_key",
        "myapp/dev/token",
    ]
    assert entries[1]["description"] == "Per-developer secret -> SERVICE_TOKEN"


def test_vault_setup_non_interactive_dry_run_creates_missing_only(tmp_path, monkeypatch):
    config = {
        "project": "myapp",
        "tenant": "dev",
        "keys": {
            "vault": {
                "{project}/{tenant}/api_key": "API key -> API_KEY",
                "{project}/{tenant}/token": "Token -> SERVICE_TOKEN",
            },
        },
    }
    _write_locke_json(tmp_path, config)
    client = object()
    monkeypatch.setattr(vault_setup_mod.VaultClient, "connect", staticmethod(lambda: client))
    monkeypatch.setattr(
        "locke.cli.vault_import._get_existing_ciphers",
        lambda _client: {
            "names": {"myapp/dev/token": "cipher-1"},
            "folders": {},
            "values": {"myapp/dev/token": "FILL_ME"},
        },
    )

    result = CliRunner().invoke(
        vault_setup_mod.vault_setup,
        ["--project-root", str(tmp_path), "--dry-run"],
    )

    assert result.exit_code == 0
    assert "[MISS] myapp/dev/api_key -- will create placeholder" in result.output
    assert "[TODO] myapp/dev/token -- placeholder already exists" in result.output
    assert "[NEW] myapp/dev/api_key" in result.output
    assert "[UPD] myapp/dev/token" not in result.output


def test_vault_setup_interactive_dry_run_updates_placeholders(tmp_path, monkeypatch):
    config = {
        "project": "myapp",
        "tenant": "dev",
        "keys": {
            "vault": {
                "{project}/{tenant}/api_key": "API key -> API_KEY",
                "{project}/{tenant}/token": "Token -> SERVICE_TOKEN",
            },
        },
    }
    _write_locke_json(tmp_path, config)
    client = object()
    monkeypatch.setattr(vault_setup_mod.VaultClient, "connect", staticmethod(lambda: client))
    monkeypatch.setattr(
        "locke.cli.vault_import._get_existing_ciphers",
        lambda _client: {
            "names": {"myapp/dev/token": "cipher-1"},
            "folders": {},
            "values": {"myapp/dev/token": "FILL_ME"},
        },
    )

    result = CliRunner().invoke(
        vault_setup_mod.vault_setup,
        ["--project-root", str(tmp_path), "--interactive", "--dry-run"],
        input="secret-api-key\nsecret-token\n",
    )

    assert result.exit_code == 0
    assert "[NEW] myapp/dev/api_key" in result.output
    assert "[UPD] myapp/dev/token" in result.output
    assert "1 would be created, 1 would be updated" in result.output
