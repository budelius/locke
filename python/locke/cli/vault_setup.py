"""locke vault setup -- initialize missing project vault secrets."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from locke.vault import PLACEHOLDER_VALUE, VaultClient


def _load_locke_json(project_root: str) -> dict:
    """Load locke.json from .locke/ or the project root."""
    root = Path(project_root)
    for candidate in [root / ".locke" / "locke.json", root / "locke.json"]:
        if candidate.exists():
            with open(candidate, encoding="utf-8") as f:
                return json.load(f)
    click.echo("Error: no locke.json found in .locke/ or project root.", err=True)
    sys.exit(1)


def _expand_path(path: str, config: dict) -> str:
    """Expand supported locke.json path placeholders."""
    replacements = {
        "{project}": str(config.get("project") or ""),
        "{tenant}": str(config.get("tenant") or "default"),
    }
    for token, value in replacements.items():
        path = path.replace(token, value)
    return path


def _folder_for_path(path: str) -> str:
    """Return the Vaultwarden folder path for a full secret path."""
    folder, _, _ = path.rpartition("/")
    return folder


def _description_text(value: object) -> str:
    """Convert registry descriptions to displayable text."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        description = value.get("description") or value.get("desc")
        env = value.get("env") or value.get("env_var")
        if description and env:
            return f"{description} -> {env}"
        if description:
            return str(description)
        if env:
            return f"Environment variable -> {env}"
    return str(value)


def _registry_entries(config: dict) -> list[dict[str, str]]:
    """Return vault entries documented under keys.vault."""
    vault_keys = config.get("keys", {}).get("vault", {})
    entries: list[dict[str, str]] = []
    for path, description in sorted(vault_keys.items()):
        if path.startswith("_"):
            continue
        actual_path = _expand_path(path, config)
        entries.append({
            "path": path,
            "actual_path": actual_path,
            "description": _description_text(description),
        })
    return entries


def _reference_entries(project_root: str, config: dict, known_paths: set[str]) -> list[dict[str, str]]:
    """Return legacy .locke/vault-references.json entries not in keys.vault."""
    root = Path(project_root)
    ref_path = root / ".locke" / "vault-references.json"
    if not ref_path.exists():
        return []

    try:
        with open(ref_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        click.echo(f"Warning: could not read {ref_path}: {exc}", err=True)
        return []

    entries: list[dict[str, str]] = []
    for item in data.get("secrets", []):
        path = item.get("path")
        if not path:
            continue
        actual_path = _expand_path(str(path), config)
        if actual_path in known_paths:
            continue
        known_paths.add(actual_path)
        description = item.get("description")
        original_key = item.get("original_key")
        if not description and original_key:
            description = f"Per-developer secret -> {original_key}"
        entries.append({
            "path": str(path),
            "actual_path": actual_path,
            "description": _description_text(description or "Per-developer secret"),
        })
    return entries


def _all_vault_entries(project_root: str, config: dict) -> list[dict[str, str]]:
    """Return registry and legacy reference entries, de-duplicated by path."""
    entries = _registry_entries(config)
    known_paths = {entry["actual_path"] for entry in entries}
    entries.extend(_reference_entries(project_root, config, known_paths))
    return sorted(entries, key=lambda item: item["actual_path"])


def _is_placeholder(value: str | None, placeholder: str) -> bool:
    """Return True when a vault value is a setup placeholder."""
    if value is None:
        return False
    return value.strip() == placeholder


def _prompt_value(entry: dict[str, str], placeholder: str) -> str:
    """Prompt for a secret value, using the placeholder when left blank."""
    click.echo()
    click.echo(entry["actual_path"])
    if entry.get("description"):
        click.echo(f"  {entry['description']}")
    return click.prompt(
        "  Value (leave blank for placeholder)",
        default=placeholder,
        hide_input=True,
        show_default=False,
    ).strip() or placeholder


def _setup_note(entry: dict[str, str], used_placeholder: bool) -> str:
    if used_placeholder:
        return f"Locke setup placeholder. Replace this value for {entry['actual_path']}."
    description = entry.get("description")
    if description:
        return f"Locke registry: {description}"
    return "Managed by Locke vault setup."


def _entry_payload(entry: dict[str, str], value: str, placeholder: str) -> dict:
    """Build an import payload for one setup entry."""
    return {
        "name": entry["actual_path"],
        "folder": _folder_for_path(entry["actual_path"]),
        "value": value,
        "notes": _setup_note(entry, used_placeholder=value == placeholder),
    }


def _write_setup_entries(
    client: VaultClient,
    existing: dict,
    secrets: list[dict],
    dry_run: bool,
) -> tuple[int, int]:
    """Create or update setup entries in the connected vault."""
    from locke.cli.vault_import import _create_cipher, _resolve_folder, _update_cipher

    created = 0
    updated = 0

    for secret in secrets:
        name = secret["name"]
        folder_name = secret["folder"]
        cipher_id = existing["names"].get(name)

        if dry_run:
            if cipher_id:
                click.echo(f"  [UPD] {name}")
                updated += 1
            else:
                click.echo(f"  [NEW] {name}")
                created += 1
            continue

        folder_id = _resolve_folder(client, folder_name, existing) if folder_name else None
        if cipher_id:
            current = existing.get("metadata", {}).get(name, {})
            _update_cipher(
                client,
                cipher_id,
                name,
                secret["value"],
                folder_id,
                username=secret.get("username") or current.get("username"),
                uri=secret.get("uri") or current.get("uri"),
                notes=secret.get("notes"),
            )
            click.echo(f"  [UPD] {name}")
            updated += 1
        else:
            _create_cipher(
                client,
                name,
                secret["value"],
                folder_id,
                notes=secret.get("notes"),
            )
            click.echo(f"  [NEW] {name}")
            created += 1

    return created, updated


@click.command("setup")
@click.option(
    "--project-root",
    default=".",
    help="Project root directory (default: current directory)",
)
@click.option(
    "--interactive",
    is_flag=True,
    help="Prompt for each missing or placeholder vault value",
)
@click.option(
    "--placeholder",
    default=PLACEHOLDER_VALUE,
    show_default=True,
    help="Placeholder value written for missing secrets in non-interactive mode",
)
@click.option("--dry-run", is_flag=True, help="Show planned vault changes without writing")
@click.option("--env-file", default=None, help="Path to .env file for vault connection vars")
def vault_setup(
    project_root: str,
    interactive: bool,
    placeholder: str,
    dry_run: bool,
    env_file: str | None,
) -> None:
    """Create or fill vault secrets listed in locke.json.

    Non-interactive mode creates missing vault entries with the placeholder
    value. Interactive mode asks for each missing value and for existing
    placeholder values, then writes the entered values back to Vaultwarden.
    """
    from locke.cli.vault_import import _get_existing_ciphers, _load_dotenv

    _load_dotenv(env_file or ".env")
    config = _load_locke_json(project_root)
    entries = _all_vault_entries(project_root, config)

    if not entries:
        click.echo("No vault secrets documented in locke.json.")
        return

    click.echo(
        f"Vault setup: {config.get('project', '?')} "
        f"(tenant: {config.get('tenant', 'default')})"
    )
    click.echo("Connecting to Vaultwarden...")
    try:
        client = VaultClient.connect()
    except Exception as exc:
        click.echo(f"Error connecting to vault: {exc}", err=True)
        sys.exit(1)

    click.echo("Syncing vault to check existing secrets...")
    try:
        existing = _get_existing_ciphers(client)
    except Exception as exc:
        click.echo(f"Error syncing vault: {exc}", err=True)
        sys.exit(1)

    existing_values = existing.get("values", {})
    secrets: list[dict] = []
    configured = 0
    placeholders = 0

    click.echo()
    for entry in entries:
        path = entry["actual_path"]
        value = existing_values.get(path)

        if value and not _is_placeholder(value, placeholder):
            click.echo(f"  [OK]   {path}")
            configured += 1
            continue

        if _is_placeholder(value, placeholder):
            placeholders += 1
            if not interactive:
                click.echo(f"  [TODO] {path} -- placeholder already exists")
                continue
            new_value = _prompt_value(entry, placeholder)
            secrets.append(_entry_payload(entry, new_value, placeholder))
            continue

        if interactive:
            new_value = _prompt_value(entry, placeholder)
        else:
            click.echo(f"  [MISS] {path} -- will create placeholder")
            new_value = placeholder
        secrets.append(_entry_payload(entry, new_value, placeholder))

    if not secrets:
        click.echo()
        click.echo(
            f"Vault setup complete: {configured} configured, "
            f"{placeholders} placeholder(s), 0 changed."
        )
        return

    click.echo()
    if dry_run:
        click.echo("Dry run -- no changes made. Planned changes:")
    else:
        click.echo("Writing vault entries:")

    created, updated = _write_setup_entries(client, existing, secrets, dry_run)
    verb = "would be " if dry_run else ""
    click.echo()
    click.echo(
        f"Done: {created} {verb}created, {updated} {verb}updated, "
        f"{configured} already configured."
    )
