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
from locke.cli.config_cmd import config
from locke.cli.decrypt import decrypt
from locke.cli.encrypt import encrypt
from locke.cli.project_tools import genkeys, strip_jsonc_command
from locke.cli.status import status

cli.add_command(config)
cli.add_command(decrypt)
cli.add_command(encrypt)
cli.add_command(genkeys)
cli.add_command(status)
cli.add_command(strip_jsonc_command)


@cli.group()
def vault() -> None:
    """Manage Vaultwarden secrets."""


@vault.command("get")
@click.argument("path")
@click.option("--vault-url", default=None, help="Override vault URL")
@click.option(
    "--field",
    type=click.Choice(["password", "username", "both"]),
    default="password",
    help="Which field(s) of the entry to print (default: password)",
)
def vault_get(path: str, vault_url: str | None, field: str) -> None:
    """Retrieve a secret from Vaultwarden by path.

    \b
    Examples:
        locke vault get myapp/prod/api_key
        locke vault get myapp/prod/db_login --field username
        locke vault get myapp/prod/db_login --field both
    """
    import os

    if vault_url:
        os.environ["LOCKE_VAULT_URL"] = vault_url

    try:
        if field == "password":
            from locke.vault import get_vault_secret

            click.echo(get_vault_secret(path))
        else:
            from locke.vault import get_vault_secret_pair

            pair = get_vault_secret_pair(path)
            if field == "username":
                click.echo(pair.username or "")
            else:  # both
                click.echo(f"{pair.username or ''}:{pair.password}")
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@vault.command("set")
@click.argument("path")
@click.option("--vault-url", default=None, help="Override vault URL")
@click.option("--username", default=None, help="Username field of the entry")
@click.option(
    "--password",
    default=None,
    help="Password field of the entry (prompts if omitted and --username is set)",
)
@click.option(
    "--folder",
    default=None,
    help="Vault folder (default: derived from the path prefix)",
)
def vault_set(
    path: str,
    vault_url: str | None,
    username: str | None,
    password: str | None,
    folder: str | None,
) -> None:
    """Create or update a Vaultwarden entry.

    Pass ``--username`` together with ``--password`` to store both in one
    entry (the combined credential). Omit ``--username`` to store a plain
    single-value secret.

    \b
    Examples:
        locke vault set myapp/prod/api_key --password "sk_live_..."
        locke vault set myapp/prod/db_login --username admin --password "s3cr3t"
    """
    import os

    if vault_url:
        os.environ["LOCKE_VAULT_URL"] = vault_url

    if password is None and username is not None:
        password = click.prompt(
            "Password", hide_input=True, default="", show_default=False
        )

    try:
        if username is not None:
            from locke.vault import set_vault_secret_pair

            action = set_vault_secret_pair(path, username, password, folder=folder)
        else:
            from locke.vault import set_vault_secret

            action = set_vault_secret(path, password, folder=folder)
        click.echo(f"{action}: {path}", err=True)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@cli.group()
def openbao() -> None:
    """Manage OpenBao KV secrets."""


@openbao.command("get")
@click.argument("path")
@click.option("--addr", default=None, help="Override OpenBao address")
@click.option("--token", default=None, help="Override OpenBao token")
@click.option("--mount", default=None, help="Override KV mount")
@click.option(
    "--field",
    type=click.Choice(["password", "username", "both"]),
    default="password",
    help="Which field(s) of the entry to print (default: password/value)",
)
def openbao_get(
    path: str, addr: str | None, token: str | None, mount: str | None, field: str
) -> None:
    """Retrieve a secret from OpenBao KV by path."""
    import os

    if addr:
        os.environ["LOCKE_OPENBAO_ADDR"] = addr
    if token:
        os.environ["LOCKE_OPENBAO_TOKEN"] = token
    if mount:
        os.environ["LOCKE_OPENBAO_MOUNT"] = mount

    try:
        if field == "password":
            from locke.openbao import get_openbao_secret

            click.echo(get_openbao_secret(path))
        else:
            from locke.openbao import get_openbao_secret_pair

            pair = get_openbao_secret_pair(path)
            if field == "username":
                click.echo(pair.username or "")
            else:
                click.echo(f"{pair.username or ''}:{pair.password}")
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@openbao.command("set")
@click.argument("path")
@click.option("--addr", default=None, help="Override OpenBao address")
@click.option("--token", default=None, help="Override OpenBao token")
@click.option("--mount", default=None, help="Override KV mount")
@click.option("--username", default=None, help="Username field of the entry")
@click.option("--password", default=None, help="Password/value field")
def openbao_set(
    path: str,
    addr: str | None,
    token: str | None,
    mount: str | None,
    username: str | None,
    password: str | None,
) -> None:
    """Create or update an OpenBao KV secret."""
    import os

    if addr:
        os.environ["LOCKE_OPENBAO_ADDR"] = addr
    if token:
        os.environ["LOCKE_OPENBAO_TOKEN"] = token
    if mount:
        os.environ["LOCKE_OPENBAO_MOUNT"] = mount
    if password is None:
        password = click.prompt(
            "Password", hide_input=True, default="", show_default=False
        )

    try:
        if username is not None:
            from locke.openbao import set_openbao_secret_pair

            action = set_openbao_secret_pair(path, username, password)
        else:
            from locke.openbao import set_openbao_secret

            action = set_openbao_secret(path, password)
        click.echo(f"{action}: {path}", err=True)
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
