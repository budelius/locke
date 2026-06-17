"""locke vault import — push secrets to Vaultwarden via API.

Replaces the old CSV-based workflow (legacy CSV scripts).
Uses the Bitwarden-compatible API to create or update secrets directly,
avoiding duplicates on repeated imports.

Modes:
  1. Azure tenant credentials:  locke vault import azure --tenant mycompany
  2. Generic key-value secrets:  locke vault import kv --folder myapp/infra --from-env BUNNY_API_KEY ...
     or from a JSON map file:   locke vault import kv --folder myapp/infra --from-file secrets.json
  3. GCP credential files:       locke vault import gcp sa-key.json --tenant mycompany
"""

import json
import os
import sys

import click

from locke.jsonc import load_jsonc
from locke.vault import VaultClient

# Azure credential field definitions
AZURE_FIELDS = [
    ("azure-tenant-id", "AZURE_TENANT_ID", "Azure AD tenant ID"),
    ("azure-client-id", "AZURE_CLIENT_ID", "Azure AD app client ID"),
    ("azure-client-secret", "AZURE_CLIENT_SECRET", "Azure AD app client secret"),
    ("azure-user-principal-name", "AZURE_USER_PRINCIPAL_NAME", "User principal name"),
]


def _azure_secret_names(index: int) -> list[str]:
    """Return Vaultwarden secret names for the given Azure account index.

    Index 1 (default):  azure-tenant-id, azure-client-id, ...
    Index 2+:           azure-2-tenant-id, azure-2-client-id, ...
    """
    base_names = [f[0] for f in AZURE_FIELDS]
    if index == 1:
        return base_names
    prefix = f"azure-{index}-"
    return [prefix + name.split("-", 1)[1] for name in base_names]


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}...{value[-4:]}"


# ── Shared options ──────────────────────────────────────────────────────────

def _common_options(fn):
    """Shared options for all import subcommands."""
    fn = click.option("--dry-run", is_flag=True, help="Show what would be imported without making changes")(fn)
    fn = click.option("--export-json", "export_path", default=None,
                       help="Export Bitwarden-compatible JSON to file instead of importing via API")(fn)
    fn = click.option("--env-file", default=None, help="Path to .env file to read values from")(fn)
    return fn


# ── Top-level group ─────────────────────────────────────────────────────────

@click.group("import")
def vault_import_cmd() -> None:
    """Import secrets into Vaultwarden (create or update, no duplicates)."""


# ── csv subcommand ──────────────────────────────────────────────────────────

@vault_import_cmd.command()
@click.argument("csv_file", type=click.Path(exists=True))
@click.option("--env-file", default=None, help="Path to .env file for vault connection vars")
@click.option("--dry-run", is_flag=True, help="Show what would be imported without making changes")
@click.option("--export-json", "export_path", default=None,
              help="Convert to Bitwarden JSON file instead of importing via API")
def csv(csv_file: str, env_file: str | None, dry_run: bool, export_path: str | None) -> None:
    """Import from a standard Bitwarden CSV file.

    Reads the CSV, deduplicates against existing vault entries, and
    creates new or updates existing secrets via API.

    \b
    Examples:
      locke vault import csv secrets.csv
      locke vault import csv secrets.csv --dry-run
      locke vault import csv secrets.csv --export-json secrets.json
    """
    _load_dotenv(env_file or ".env")

    import csv as csv_mod

    with open(csv_file, newline="", encoding="utf-8") as f:
        reader = csv_mod.DictReader(f)
        rows = list(reader)

    if not rows:
        click.echo("CSV file is empty.", err=True)
        sys.exit(1)

    click.echo(f"\nParsed {len(rows)} entry/entries from {csv_file}")
    click.echo("=" * 60)

    secrets: list[dict] = []
    for row in rows:
        name = row.get("name", "").strip()
        folder = row.get("folder", "").strip()
        password = row.get("login_password", "").strip()
        username = row.get("login_username", "").strip()
        uri = row.get("login_uri", "").strip()
        notes = row.get("notes", "").strip()
        item_type = row.get("type", "login").strip()

        if not name:
            click.echo("  [SKIP] row with empty name")
            continue

        display = _mask(password) if password else "(no password)"
        click.echo(f"  [OK]   {name} = {display}")

        secrets.append({
            "name": name,
            "folder": folder,
            "value": password,
            "username": username,
            "uri": uri,
            "notes": notes or None,
            "type": item_type,
        })

    click.echo()

    if not secrets:
        click.echo("No secrets to import.", err=True)
        sys.exit(1)

    if export_path:
        _export_bitwarden_json_full(secrets, export_path)
        return

    if dry_run:
        click.echo("Dry run — no changes made. Secrets that would be imported:")
        for s in secrets:
            action = "create/update"
            click.echo(f"  [{action}] {s['name']}")
        return

    _import_via_api_full(secrets)


# ── azure subcommand ────────────────────────────────────────────────────────

@vault_import_cmd.command()
@click.option("--tenant", required=True, help="Tenant slug (e.g. mycompany)")
@click.option("--project", default="myapp", help="Project prefix for vault folder (default: myapp)")
@click.option(
    "--account-index",
    type=int,
    default=1,
    help="Account index: 1=default, 2=second, ... (default: 1)",
)
@click.option("--azure-tenant-id", default=None, help="Azure AD tenant ID")
@click.option("--azure-client-id", default=None, help="Azure AD app client ID")
@click.option("--azure-client-secret", default=None, help="Azure AD app client secret")
@click.option("--azure-user-principal-name", default=None, help="User principal name")
@_common_options
def azure(
    tenant: str,
    project: str,
    account_index: int,
    azure_tenant_id: str | None,
    azure_client_id: str | None,
    azure_client_secret: str | None,
    azure_user_principal_name: str | None,
    dry_run: bool,
    export_path: str | None,
    env_file: str | None,
) -> None:
    """Import Azure tenant credentials into Vaultwarden.

    \b
    Examples:
      locke vault import azure --tenant mycompany
      locke vault import azure --tenant mycompany --account-index 2 \\
        --azure-tenant-id "..." --azure-client-id "..."
      locke vault import azure --tenant mycompany --dry-run
    """
    _load_dotenv(env_file or ".env")

    cli_overrides = {
        "AZURE_TENANT_ID": azure_tenant_id,
        "AZURE_CLIENT_ID": azure_client_id,
        "AZURE_CLIENT_SECRET": azure_client_secret,
        "AZURE_USER_PRINCIPAL_NAME": azure_user_principal_name,
    }

    secret_names = _azure_secret_names(account_index)
    folder = f"{project}/{tenant}"

    label = f"account #{account_index}" if account_index > 1 else "default account"
    click.echo(f"\nAzure credentials for tenant '{tenant}' ({label})")
    click.echo("=" * 60)

    secrets: list[dict] = []
    missing: list[str] = []

    for i, (_, env_var, _) in enumerate(AZURE_FIELDS):
        secret_name = secret_names[i]
        item_name = f"{project}/{tenant}/{secret_name}"

        value = cli_overrides.get(env_var)
        if not value and account_index <= 1:
            value = os.environ.get(env_var, "")

        if value:
            click.echo(f"  [OK]   {item_name} = {_mask(value)} ({len(value)} chars)")
            secrets.append({"name": item_name, "folder": folder, "value": value})
        else:
            click.echo(f"  [MISS] {item_name} (not set)")
            missing.append(secret_name)

    click.echo()

    if missing:
        click.echo(f"WARNING: {len(missing)} secret(s) missing: {', '.join(missing)}")
        if account_index > 1:
            click.echo("For additional accounts, pass values via --azure-* flags.")
        else:
            click.echo("Set them in your .env file or pass via --azure-* flags.")
        click.echo()

    _run_import(secrets, dry_run, export_path)


# ── kv subcommand ───────────────────────────────────────────────────────────

@vault_import_cmd.command()
@click.option("--folder", required=True, help="Vault folder path (e.g. myapp/infra)")
@click.option(
    "--from-env",
    "env_keys",
    multiple=True,
    help="Import an env var as a secret (repeatable). "
         "Secret name is derived from the env var (e.g. BUNNY_API_KEY -> bunny-api-key).",
)
@click.option(
    "--from-file",
    "secrets_file",
    default=None,
    type=click.Path(exists=True),
    help='JSON file mapping secret names to values: {"bunny-api-key": "...", ...}',
)
@click.option(
    "--secret",
    "inline_secrets",
    nargs=2,
    multiple=True,
    help="Inline secret: --secret <name> <value> (repeatable)",
)
@_common_options
def kv(
    folder: str,
    env_keys: tuple[str, ...],
    secrets_file: str | None,
    inline_secrets: tuple[tuple[str, str], ...],
    dry_run: bool,
    export_path: str | None,
    env_file: str | None,
) -> None:
    """Import arbitrary key-value secrets into Vaultwarden.

    \b
    Examples:
      # From env vars (secret name auto-derived):
      locke vault import kv --folder myapp/infra \\
        --from-env BUNNY_API_KEY --from-env HETZNER_S3_ACCESS_KEY

      # From a JSON map file:
      locke vault import kv --folder myapp/infra --from-file secrets.json

      # Inline:
      locke vault import kv --folder myapp/infra \\
        --secret bunny-api-key "sk_live_..."

      # Combine sources:
      locke vault import kv --folder myapp/infra \\
        --from-env BUNNY_API_KEY --secret custom-key "value"
    """
    _load_dotenv(env_file or ".env")

    click.echo(f"\nSecrets for folder '{folder}'")
    click.echo("=" * 60)

    secrets: list[dict] = []
    missing: list[str] = []

    # From env vars
    for env_key in env_keys:
        value = os.environ.get(env_key, "")
        secret_name = _env_to_secret_name(env_key)
        item_name = f"{folder}/{secret_name}"

        if value:
            click.echo(f"  [OK]   {item_name} = {_mask(value)} ({len(value)} chars)")
            secrets.append({"name": item_name, "folder": folder, "value": value})
        else:
            click.echo(f"  [MISS] {item_name} ({env_key} not set)")
            missing.append(env_key)

    # From JSON file
    if secrets_file:
        with open(secrets_file) as f:
            file_secrets = load_jsonc(f)
        for secret_name, value in file_secrets.items():
            item_name = f"{folder}/{secret_name}"
            if value:
                click.echo(f"  [OK]   {item_name} = {_mask(str(value))} ({len(str(value))} chars)")
                secrets.append({"name": item_name, "folder": folder, "value": str(value)})
            else:
                click.echo(f"  [MISS] {item_name} (empty value in file)")
                missing.append(secret_name)

    # Inline secrets
    for secret_name, value in inline_secrets:
        item_name = f"{folder}/{secret_name}"
        click.echo(f"  [OK]   {item_name} = {_mask(value)} ({len(value)} chars)")
        secrets.append({"name": item_name, "folder": folder, "value": value})

    click.echo()

    if missing:
        click.echo(f"WARNING: {len(missing)} secret(s) missing: {', '.join(missing)}")
        click.echo()

    _run_import(secrets, dry_run, export_path)


# ── gcp subcommand ─────────────────────────────────────────────────────────

# GCP credential file type indicators
_GCP_SA_TYPE = "service_account"
_GCP_OAUTH_KEYS = {"web", "installed"}


def _detect_gcp_type(data: dict) -> str | None:
    """Detect the type of GCP credential file from its content.

    Returns 'service_account', 'oauth_client', or None if unrecognised.
    """
    if data.get("type") == _GCP_SA_TYPE:
        return "service_account"
    if _GCP_OAUTH_KEYS & data.keys():
        return "oauth_client"
    return None


def _gcp_entry_from_sa(data: dict, project: str, tenant: str) -> dict:
    """Build a vault entry from a GCP service-account key file."""
    client_email = data.get("client_email", "")
    account_name = client_email.split("@")[0] if "@" in client_email else "unknown"
    gcp_project = data.get("project_id", "unknown")

    item_name = f"{project}/{tenant}/gcp-sa-{account_name}"
    return {
        "name": item_name,
        "folder": f"{project}/{tenant}",
        "value": json.dumps(data, indent=2),
        "username": client_email,
        "uri": data.get("token_uri"),
        "notes": f"GCP service account key for {client_email} (project: {gcp_project})",
    }


def _gcp_entry_from_oauth(data: dict, project: str, tenant: str) -> dict:
    """Build a vault entry from a GCP OAuth client-secret file."""
    # OAuth files nest under "web" or "installed"
    wrapper_key = next((k for k in _GCP_OAUTH_KEYS if k in data), None)
    inner = data[wrapper_key] if wrapper_key else data
    client_id = inner.get("client_id", "unknown")
    gcp_project = inner.get("project_id", "unknown")

    item_name = f"{project}/{tenant}/gcp-oauth-{gcp_project}"
    return {
        "name": item_name,
        "folder": f"{project}/{tenant}",
        "value": json.dumps(data, indent=2),
        "username": client_id,
        "uri": inner.get("token_uri"),
        "notes": f"GCP OAuth {wrapper_key or 'unknown'} client (project: {gcp_project})",
    }


@vault_import_cmd.command()
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--tenant", required=True, help="Tenant slug (e.g. mycompany)")
@click.option("--project", default="myapp", help="Project prefix for vault folder (default: myapp)")
@_common_options
def gcp(
    files: tuple[str, ...],
    tenant: str,
    project: str,
    dry_run: bool,
    export_path: str | None,
    env_file: str | None,
) -> None:
    """Import GCP credential JSON files into Vaultwarden.

    Supports service-account key files and OAuth client-secret files.
    The full JSON content is stored so consumers can reconstruct the file
    (e.g. for GOOGLE_APPLICATION_CREDENTIALS).

    \b
    Examples:
      locke vault import gcp sa-key.json --tenant mycompany
      locke vault import gcp sa-key.json oauth-secret.json --tenant mycompany
      locke vault import gcp *.json --tenant mycompany --project myapp --dry-run
    """
    _load_dotenv(env_file or ".env")

    click.echo(f"\nGCP credentials for tenant '{tenant}'")
    click.echo("=" * 60)

    secrets: list[dict] = []
    skipped: list[str] = []

    for filepath in files:
        try:
            with open(filepath, encoding="utf-8") as f:
                data = load_jsonc(f)
        except (json.JSONDecodeError, OSError) as exc:
            click.echo(f"  [SKIP] {filepath} — {exc}")
            skipped.append(filepath)
            continue

        gcp_type = _detect_gcp_type(data)
        if gcp_type is None:
            click.echo(f"  [SKIP] {filepath} — not a recognised GCP credential file")
            skipped.append(filepath)
            continue

        if gcp_type == "service_account":
            entry = _gcp_entry_from_sa(data, project, tenant)
            label = f"service-account ({data.get('client_email', '?')})"
        else:
            wrapper = next((k for k in _GCP_OAUTH_KEYS if k in data), "?")
            entry = _gcp_entry_from_oauth(data, project, tenant)
            label = f"oauth-{wrapper} ({data.get(wrapper, {}).get('project_id', '?')})"

        json_len = len(entry["value"])
        click.echo(f"  [OK]   {entry['name']} — {label} ({json_len} chars)")
        secrets.append(entry)

    click.echo()

    if skipped:
        click.echo(f"WARNING: {len(skipped)} file(s) skipped.")
        click.echo()

    _run_import(secrets, dry_run, export_path)


def _env_to_secret_name(env_key: str) -> str:
    """Convert SCREAMING_SNAKE_CASE env var to kebab-case secret name.

    BUNNY_API_KEY -> bunny-api-key
    HETZNER_S3_ACCESS_KEY -> hetzner-s3-access-key
    """
    return env_key.lower().replace("_", "-")


# ── Shared logic ────────────────────────────────────────────────────────────

def _run_import(secrets: list[dict], dry_run: bool, export_path: str | None) -> None:
    """Dispatch to export, dry-run, or API import."""
    if not secrets:
        click.echo("No secrets to import. Exiting.", err=True)
        sys.exit(1)

    if export_path:
        _export_bitwarden_json(secrets, export_path)
        return

    if dry_run:
        click.echo("Dry run — no changes made. Secrets that would be imported:")
        for s in secrets:
            click.echo(f"  {s['name']}")
        return

    _import_via_api(secrets)


def _load_dotenv(path: str) -> None:
    """Load a .env file into os.environ (best-effort, no override)."""
    if not os.path.isfile(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            os.environ.setdefault(key, value)


def _export_bitwarden_json(secrets: list[dict], path: str) -> None:
    """Export secrets as Bitwarden-compatible JSON for manual import."""
    items = []
    folders_seen: dict[str, int] = {}
    folders = []

    for s in secrets:
        folder = s["folder"]
        if folder not in folders_seen:
            folders_seen[folder] = len(folders)
            folders.append({"name": folder})

        uri = s.get("uri")
        uris = [{"match": None, "uri": uri}] if uri else []
        items.append({
            "type": 1,  # login
            "name": s["name"],
            "folderId": folders_seen[folder],
            "login": {
                "username": s.get("username", ""),
                "password": s["value"],
                "uris": uris,
            },
            "notes": s.get("notes"),
            "favorite": False,
            "reprompt": 0,
        })

    export = {
        "encrypted": False,
        "folders": [{"id": str(i + 1), "name": f["name"]} for i, f in enumerate(folders)],
        "items": items,
    }

    with open(path, "w") as f:
        json.dump(export, f, indent=2)
        f.write("\n")

    click.echo(f"Bitwarden JSON written to: {path}")
    click.echo(f"  {len(items)} secret(s)")
    click.echo()
    click.echo("To import manually:")
    click.echo("  1. Open Vaultwarden web UI")
    click.echo("  2. Tools -> Import Data")
    click.echo("  3. Format: Bitwarden (json)")
    click.echo(f"  4. Select: {path}")
    click.echo("  5. Import")
    click.echo(f"  6. DELETE the file: rm {path}")


def _import_via_api(secrets: list[dict]) -> None:
    """Import secrets via Vaultwarden API, creating or updating as needed."""
    click.echo("Connecting to Vaultwarden...")
    try:
        client = VaultClient.connect()
    except Exception as exc:
        click.echo(f"Error connecting to vault: {exc}", err=True)
        sys.exit(1)

    click.echo("Syncing vault to check for existing secrets...")
    existing = _get_existing_ciphers(client)

    created = 0
    updated = 0

    for s in secrets:
        name = s["name"]
        value = s["value"]
        folder_name = s["folder"]

        folder_id = _resolve_folder(client, folder_name, existing)
        cipher_id = existing["names"].get(name)

        extra = {
            "username": s.get("username"),
            "uri": s.get("uri"),
            "notes": s.get("notes"),
        }

        if cipher_id:
            _update_cipher(client, cipher_id, name, value, folder_id, **extra)
            click.echo(f"  [UPD] {name}")
            updated += 1
        else:
            _create_cipher(client, name, value, folder_id, **extra)
            click.echo(f"  [NEW] {name}")
            created += 1

    click.echo(f"\nDone: {created} created, {updated} updated.")


def _get_existing_ciphers(client: VaultClient) -> dict:
    """Sync vault and return lookup structures.

    Cipher names and folder names are stored encrypted on the server.
    We decrypt them here so callers can match by plaintext name.
    """
    import httpx

    response = httpx.get(
        f"{client._base_url}/api/sync",
        headers=client._headers,
        timeout=30,
    )
    response.raise_for_status()
    sync_data = response.json()

    names: dict[str, str] = {}
    values: dict[str, str] = {}
    metadata: dict[str, dict[str, str | None]] = {}
    for cipher in sync_data.get("ciphers", []):
        decrypted_name = client._decrypt(cipher.get("name"))
        if decrypted_name:
            names[decrypted_name] = cipher["id"]
            login = cipher.get("login") or {}
            decrypted_username = client._decrypt(login.get("username"))
            decrypted_uri = None
            uris = login.get("uris") or []
            if uris:
                decrypted_uri = client._decrypt(uris[0].get("uri"))
            decrypted_notes = client._decrypt(cipher.get("notes"))
            decrypted_value = client._decrypt(login.get("password"))
            if not decrypted_value:
                decrypted_value = decrypted_notes
            if decrypted_value is not None:
                values[decrypted_name] = decrypted_value
            metadata[decrypted_name] = {
                "username": decrypted_username,
                "uri": decrypted_uri,
                "notes": decrypted_notes,
            }

    folders: dict[str, str] = {}
    for folder in sync_data.get("folders", []):
        decrypted_name = client._decrypt(folder.get("name"))
        if decrypted_name:
            folders[decrypted_name] = folder["id"]

    return {
        "names": names,
        "folders": folders,
        "values": values,
        "metadata": metadata,
    }


def _resolve_folder(client: VaultClient, folder_name: str, existing: dict) -> str | None:
    """Get or create a vault folder, return its ID.

    Folder names must be encrypted before sending to the API.
    """
    import httpx

    folder_id = existing["folders"].get(folder_name)
    if folder_id:
        return folder_id

    encrypted_name = client._encrypt(folder_name)
    response = httpx.post(
        f"{client._base_url}/api/folders",
        headers=client._headers,
        json={"name": encrypted_name},
        timeout=30,
    )
    response.raise_for_status()
    folder_id = response.json()["id"]
    existing["folders"][folder_name] = folder_id
    return folder_id


def _build_cipher_payload(
    client: VaultClient,
    name: str,
    folder_id: str | None,
    password: str = "",
    username: str | None = None,
    uri: str | None = None,
    notes: str | None = None,
) -> dict:
    """Build a Bitwarden cipher payload with client-side encryption.

    All string fields (name, password, username, notes, URIs) must be
    encrypted in ``2.iv|ct|mac`` format before sending to the API.
    """
    return client._build_cipher_payload(name, password, folder_id, username, uri, notes)


def _create_cipher(
    client: VaultClient,
    name: str,
    value: str,
    folder_id: str | None,
    username: str | None = None,
    uri: str | None = None,
    notes: str | None = None,
) -> None:
    """Create a new login cipher in the vault."""
    import httpx

    response = httpx.post(
        f"{client._base_url}/api/ciphers",
        headers=client._headers,
        json=_build_cipher_payload(client, name, folder_id, value, username, uri, notes),
        timeout=30,
    )
    response.raise_for_status()


def _update_cipher(
    client: VaultClient,
    cipher_id: str,
    name: str,
    value: str,
    folder_id: str | None,
    username: str | None = None,
    uri: str | None = None,
    notes: str | None = None,
) -> None:
    """Update an existing login cipher."""
    import httpx

    response = httpx.put(
        f"{client._base_url}/api/ciphers/{cipher_id}",
        headers=client._headers,
        json=_build_cipher_payload(client, name, folder_id, value, username, uri, notes),
        timeout=30,
    )
    response.raise_for_status()


# ── CSV full-fidelity import (preserves username/uri/notes) ─────────────────

def _export_bitwarden_json_full(secrets: list[dict], path: str) -> None:
    """Export CSV-parsed secrets as Bitwarden-compatible JSON."""
    items = []
    folders_seen: dict[str, int] = {}
    folders = []

    for s in secrets:
        folder = s.get("folder", "")
        if folder and folder not in folders_seen:
            folders_seen[folder] = len(folders)
            folders.append({"name": folder})

        uris = [{"match": None, "uri": s["uri"]}] if s.get("uri") else []
        items.append({
            "type": 1,
            "name": s["name"],
            "folderId": folders_seen.get(folder),
            "login": {
                "username": s.get("username", ""),
                "password": s.get("value", ""),
                "uris": uris,
            },
            "notes": s.get("notes"),
            "favorite": False,
            "reprompt": 0,
        })

    export = {
        "encrypted": False,
        "folders": [{"id": str(i + 1), "name": f["name"]} for i, f in enumerate(folders)],
        "items": items,
    }

    with open(path, "w") as f:
        json.dump(export, f, indent=2)
        f.write("\n")

    click.echo(f"Bitwarden JSON written to: {path}")
    click.echo(f"  {len(items)} item(s), {len(folders)} folder(s)")
    click.echo(f"\n  DELETE this file after import: rm {path}")


def _import_via_api_full(secrets: list[dict]) -> None:
    """Import CSV-parsed secrets via API, preserving all fields."""
    click.echo("Connecting to Vaultwarden...")
    try:
        client = VaultClient.connect()
    except Exception as exc:
        click.echo(f"Error connecting to vault: {exc}", err=True)
        sys.exit(1)

    click.echo("Syncing vault to check for existing secrets...")
    existing = _get_existing_ciphers(client)

    created = 0
    updated = 0

    for s in secrets:
        name = s["name"]
        folder_name = s.get("folder", "")

        folder_id = _resolve_folder(client, folder_name, existing) if folder_name else None
        cipher_id = existing["names"].get(name)

        if cipher_id:
            _update_cipher(
                client, cipher_id, name, s.get("value", ""), folder_id,
                username=s.get("username"), uri=s.get("uri"), notes=s.get("notes"),
            )
            click.echo(f"  [UPD] {name}")
            updated += 1
        else:
            _create_cipher(
                client, name, s.get("value", ""), folder_id,
                username=s.get("username"), uri=s.get("uri"), notes=s.get("notes"),
            )
            click.echo(f"  [NEW] {name}")
            created += 1

    click.echo(f"\nDone: {created} created, {updated} updated.")
