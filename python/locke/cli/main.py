"""Locke CLI entrypoint.

Thin wrapper around library functions — no business logic here.
"""

import json
import shlex
import sys

import click

from locke import __version__


@click.group()
@click.version_option(__version__, prog_name="locke")
@click.option("--verbose", is_flag=True, help="Show resolution source and timing")
@click.option("--quiet", is_flag=True, help="Suppress warnings")
def cli(verbose: bool, quiet: bool) -> None:
    """Locke — Unified credentials framework."""
    import logging

    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")
    elif quiet:
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.WARNING)


@cli.command()
@click.argument("config_path", required=False, default=None)
@click.option(
    "--config",
    "config_opt",
    default=None,
    help="Path to encrypted config file (alternative to positional arg)",
)
@click.option(
    "--key-name",
    default=None,
    help="Credential name for the encryption key",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["shell", "json", "dotenv"]),
    default="shell",
    help="Output format",
)
@click.option(
    "--env",
    "env_name",
    default=None,
    help="Environment name for auto-discovery",
)
@click.option(
    "--project-root",
    default=".",
    help="Project root for auto-discovery (default: current directory)",
)
def env(
    config_path: str | None,
    config_opt: str | None,
    key_name: str | None,
    output_format: str,
    env_name: str | None,
    project_root: str,
) -> None:
    """Decrypt, flatten, and output config as environment variables.

    \b
    Examples:
        locke env --key-name MYAPP_CONFIG_ENCRYPTION_KEY
        locke env config.encrypted.production.json --key-name MYAPP_CONFIG_ENCRYPTION_KEY
        locke env --env staging --key-name MYAPP_CONFIG_ENCRYPTION_KEY --format dotenv
    """
    from locke import find_config, load_config

    # Resolve config path: positional > --config > auto-discover
    path_str = config_path or config_opt
    if not path_str:
        found = find_config(project_root, env=env_name)
        if found:
            path_str = str(found)
            click.echo(f"# Auto-discovered: {path_str}", err=True)
        else:
            click.echo(
                "Error: no encrypted config file found. "
                "Provide a path or use --env / --project-root.",
                err=True,
            )
            sys.exit(1)

    try:
        flat = load_config(path_str, key_name=key_name or "LOCKE_ENCRYPTION_KEY")
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if output_format == "json":
        click.echo(json.dumps(flat, indent=2, sort_keys=True))
    elif output_format == "dotenv":
        for key, value in sorted(flat.items()):
            click.echo(f"{key}={value}")
    else:  # shell
        for key, value in sorted(flat.items()):
            click.echo(f"export {key}={shlex.quote(value)}")


# Import and register subcommands
from locke.cli.config_cmd import config  # noqa: E402
from locke.cli.decrypt import decrypt  # noqa: E402
from locke.cli.encrypt import encrypt  # noqa: E402
from locke.cli.status import status  # noqa: E402

cli.add_command(config)
cli.add_command(decrypt)
cli.add_command(encrypt)
cli.add_command(status)


@cli.group()
def vault() -> None:
    """Manage Vaultwarden secrets."""


@vault.command("get")
@click.argument("path")
@click.option("--vault-url", default=None, help="Override vault URL")
def vault_get(path: str, vault_url: str | None) -> None:
    """Retrieve a secret from Vaultwarden by path."""
    import os
    if vault_url:
        os.environ["LOCKE_VAULT_URL"] = vault_url

    try:
        from locke.vault import get_vault_secret
        secret = get_vault_secret(path)
        click.echo(secret)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


def _register_optional_commands() -> None:
    """Register commands that may not exist yet (later phases)."""
    try:
        from locke.cli.keystore import keystore
        cli.add_command(keystore)
    except ImportError:
        pass
    try:
        from locke.cli.init_cmd import init
        cli.add_command(init)
    except ImportError:
        pass
    try:
        from locke.cli.registry import registry
        cli.add_command(registry)
    except ImportError:
        pass
    try:
        from locke.cli.validate_cmd import validate
        cli.add_command(validate)
    except ImportError:
        pass
    try:
        from locke.cli.vault_import import vault_import_cmd
        vault.add_command(vault_import_cmd)
    except ImportError:
        pass
    try:
        from locke.cli.vault_setup import vault_setup
        vault.add_command(vault_setup)
    except ImportError:
        pass
    try:
        from locke.cli.bio import bio
        cli.add_command(bio)
    except ImportError:
        pass


_register_optional_commands()

if __name__ == "__main__":
    cli()
