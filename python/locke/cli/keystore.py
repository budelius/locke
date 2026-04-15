"""locke keystore — manage OS keystore credentials."""

import secrets
import sys

import click

from locke.keystore import (
    delete_credential,
    get_credential,
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


