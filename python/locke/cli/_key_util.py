"""Shared key resolution helper for CLI commands."""

import os
import sys

import click

from locke.pipeline import resolve_credential


def get_key(key_source: str, key_name: str | None) -> str:
    """Resolve an encryption key from the given source.

    Args:
        key_source: One of "keystore", "env", "prompt".
        key_name: Credential name (required for keystore/env).

    Returns:
        The resolved key string.
    """
    if key_source == "prompt":
        return click.prompt("Encryption key", hide_input=True)

    if key_source == "env":
        if not key_name:
            click.echo("Error: --key-name required with --key-source=env", err=True)
            sys.exit(1)
        key = os.environ.get(key_name)
        if not key:
            click.echo(f"Error: {key_name} not set", err=True)
            sys.exit(1)
        return key

    # Default: keystore (uses full pipeline: keystore → env → glab → dotenv)
    if not key_name:
        click.echo(
            "Error: --key-name required (e.g. --key-name MYAPP_CONFIG_ENCRYPTION_KEY)",
            err=True,
        )
        sys.exit(1)
    cred = resolve_credential(key_name)
    return cred.value


KEY_NAME_OPTION = click.option(
    "--key-name",
    default=None,
    help="Credential name for the encryption key (e.g. MYAPP_CONFIG_ENCRYPTION_KEY)",
)

KEY_SOURCE_OPTION = click.option(
    "--key-source",
    type=click.Choice(["keystore", "env", "prompt"]),
    default="keystore",
    help="Where to get the encryption key",
)
