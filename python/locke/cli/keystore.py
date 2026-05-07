"""locke keystore — manage OS keystore credentials."""

import secrets
import sys

import click

from locke.keystore import (
    delete_credential,
    find_legacy_credentials,
    get_credential,
    migrate_credential,
    set_credential,
)
from locke.errors import (
    BiometricDeniedError,
    BiometricUnavailableError,
    KeystoreUnavailableError,
)


@click.group()
def keystore() -> None:
    """Manage OS keystore credentials."""


@keystore.command("get")
@click.argument("name")
def keystore_get(name: str) -> None:
    """Read a credential from the OS keystore."""
    try:
        value = get_credential(name)
    except (BiometricDeniedError, BiometricUnavailableError) as exc:
        click.echo(f"Biometric error: {exc}", err=True)
        sys.exit(3)
    except KeystoreUnavailableError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)

    if value is None:
        click.echo(f"Credential '{name}' not found in keystore", err=True)
        sys.exit(1)

    click.echo(value)


@keystore.command("set")
@click.argument("name")
@click.option("--value", default=None, help="Credential value")
@click.option("--prompt", "use_prompt", is_flag=True, help="Prompt for value (no echo)")
def keystore_set(name: str, value: str | None, use_prompt: bool) -> None:
    """Write a credential to the OS keystore."""
    if use_prompt:
        value = click.prompt(f"Enter value for '{name}'", hide_input=True)
    elif value is None:
        click.echo("Error: Provide --value or --prompt", err=True)
        sys.exit(1)

    try:
        set_credential(name, value)
        click.echo(f"Credential '{name}' stored in keystore", err=True)
    except (BiometricDeniedError, BiometricUnavailableError) as exc:
        click.echo(f"Biometric error: {exc}", err=True)
        sys.exit(3)
    except KeystoreUnavailableError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@keystore.command("delete")
@click.argument("name")
def keystore_delete(name: str) -> None:
    """Remove a credential from the OS keystore."""
    try:
        delete_credential(name)
        click.echo(f"Credential '{name}' deleted from keystore", err=True)
    except (BiometricDeniedError, BiometricUnavailableError) as exc:
        click.echo(f"Biometric error: {exc}", err=True)
        sys.exit(3)
    except KeystoreUnavailableError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@keystore.command("generate")
@click.argument("name", required=False, default=None)
@click.option("--print", "print_key", is_flag=True, help="Print the key to stdout (even when storing)")
def keystore_generate(name: str | None, print_key: bool) -> None:
    """Generate a 32-byte random encryption key.

    If NAME is provided, the key is stored in the OS keystore under that name.
    Otherwise (or with --print), the key is printed to stdout.

    \b
    Examples:
        locke keystore generate                          # print a key
        locke keystore generate MYAPP_CONFIG_ENCRYPTION_KEY  # generate and store
        locke keystore generate MYAPP_CONFIG_ENCRYPTION_KEY --print  # store and print
    """
    key = secrets.token_hex(32)

    if name:
        try:
            set_credential(name, key)
            click.echo(f"Generated and stored '{name}' in keystore", err=True)
        except (BiometricDeniedError, BiometricUnavailableError) as exc:
            click.echo(f"Biometric error: {exc}", err=True)
            sys.exit(3)
        except KeystoreUnavailableError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

        if print_key:
            click.echo(key)
    else:
        click.echo(key)


@keystore.command("migrate")
@click.option(
    "--name",
    "names",
    multiple=True,
    help=(
        "Locke credential name to migrate (repeatable). "
        "Examples: --name LOCKE_VAULT_PASSWORD --name MYAPP_CONFIG_ENCRYPTION_KEY"
    ),
)
@click.option(
    "--delete-legacy", is_flag=True,
    help="Delete the legacy entry after migrating",
)
@click.option(
    "--dry-run", is_flag=True,
    help="Show what would be migrated without changing anything",
)
def keystore_migrate(names: tuple[str, ...], delete_legacy: bool, dry_run: bool) -> None:
    """Migrate credentials from legacy naming conventions to the Locke namespace.

    Locke unifies credentials under service="locke" with UPPER_SNAKE_CASE names.
    This command copies credentials stored under older naming conventions
    (project-name targets, ``locke-bio``) into the unified namespace.

    Pass ``--name`` once per credential to scan; repeatable.  If no names are
    given, only ``LOCKE_VAULT_PASSWORD`` is checked, since project-specific
    ``*_CONFIG_ENCRYPTION_KEY`` slugs are not enumerable.
    """
    name_list = list(names) if names else None

    if dry_run:
        try:
            legacy = find_legacy_credentials(name_list)
        except (BiometricDeniedError, BiometricUnavailableError) as exc:
            click.echo(f"Biometric error: {exc}", err=True)
            sys.exit(3)

        if not legacy:
            click.echo("No legacy credentials found.")
            return

        for entry in legacy:
            status = " (already in locke)" if entry["already_migrated"] else ""
            click.echo(
                f"  {entry['locke_name']} <- "
                f"target={entry['legacy_target']!r}, "
                f"user={entry['legacy_username']!r}{status}"
            )
        return

    if name_list:
        targets = name_list
    else:
        try:
            legacy = find_legacy_credentials(None)
        except (BiometricDeniedError, BiometricUnavailableError) as exc:
            click.echo(f"Biometric error: {exc}", err=True)
            sys.exit(3)
        targets = [e["locke_name"] for e in legacy if not e["already_migrated"]]

    if not targets:
        click.echo("Nothing to migrate.")
        return

    migrated = 0
    for cred_name in targets:
        try:
            source = migrate_credential(cred_name, delete_legacy=delete_legacy)
        except (BiometricDeniedError, BiometricUnavailableError) as exc:
            click.echo(f"Biometric error: {exc}", err=True)
            sys.exit(3)
        except KeystoreUnavailableError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

        if source:
            click.echo(f"  Migrated {cred_name} from {source}")
            migrated += 1
        else:
            click.echo(f"  No legacy credential found for {cred_name}", err=True)

    click.echo(f"\n{migrated} credential(s) migrated.")

