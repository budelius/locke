"""locke decrypt — decrypt an encrypted config file."""

import json
import sys
from pathlib import Path

import click

from locke.crypto import decrypt_config
from locke.cli._key_util import get_key


@click.command()
@click.argument("config_path", required=False, default=None)
@click.option(
    "--config",
    "config_opt",
    default=None,
    help="Path to encrypted config file (alternative to positional arg)",
)
@click.option(
    "--output", "-o",
    "output_path",
    default=None,
    help="Output file path (default: stdout)",
)
@click.option("--key-name", default=None, help="Credential name for the encryption key")
@click.option(
    "--key-source",
    type=click.Choice(["keystore", "env", "prompt"]),
    default="keystore",
    help="Where to get the encryption key",
)
@click.option(
    "--env",
    "env_name",
    default=None,
    help="Environment name for auto-discovery (e.g. development, staging, production)",
)
@click.option(
    "--project-root",
    default=".",
    help="Project root for auto-discovery (default: current directory)",
)
def decrypt(
    config_path: str | None,
    config_opt: str | None,
    output_path: str | None,
    key_name: str | None,
    key_source: str,
    env_name: str | None,
    project_root: str,
) -> None:
    """Decrypt an encrypted config file.

    \b
    Examples:
        locke decrypt config.encrypted.development.json --key-name MYAPP_CONFIG_ENCRYPTION_KEY
        locke decrypt --env production --key-name MYAPP_CONFIG_ENCRYPTION_KEY
        locke decrypt --key-name MYAPP_CONFIG_ENCRYPTION_KEY   # auto-discovers config
    """
    # Resolve input path: positional arg > --config > auto-discover
    path_str = config_path or config_opt
    if not path_str:
        from locke import find_config
        found = find_config(project_root, env=env_name)
        if found:
            path_str = str(found)
            click.echo(f"Auto-discovered: {path_str}", err=True)
        else:
            click.echo(
                "Error: no encrypted config file found. "
                "Provide a path or use --env / --project-root.",
                err=True,
            )
            sys.exit(1)

    try:
        with open(path_str) as f:
            encrypted = json.load(f)
    except FileNotFoundError:
        click.echo(f"Error: File not found: {path_str}", err=True)
        sys.exit(1)
    except json.JSONDecodeError:
        click.echo(f"Error: Invalid JSON in {path_str}", err=True)
        sys.exit(1)

    # Auto-resolve key_name from .locke/locke.json if not provided
    if not key_name:
        from locke import read_locke_config
        locke_cfg = read_locke_config(project_root)
        if locke_cfg and locke_cfg.get("keyName"):
            key_name = locke_cfg["keyName"]
            click.echo(f"Using key name from .locke/locke.json: {key_name}", err=True)

    try:
        key = get_key(key_source, key_name)
        plaintext = decrypt_config(encrypted, key)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    output = json.dumps(plaintext, indent=2, sort_keys=True)

    if output_path:
        with open(output_path, "w") as f:
            f.write(output)
            f.write("\n")
        click.echo(f"Decrypted config written to {output_path}", err=True)
    else:
        click.echo(output)
