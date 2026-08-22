"""locke config — config file discovery and management."""

import sys

import click


@click.group()
def config() -> None:
    """Config file discovery and management."""


@config.command(name="find")
@click.option(
    "--env",
    "env_name",
    default=None,
    help="Environment name (e.g. development, staging, production)",
)
@click.option(
    "--project-root",
    default=".",
    type=click.Path(exists=True, file_okay=False),
    help="Project root directory (default: current directory)",
)
def config_find(env_name: str | None, project_root: str) -> None:
    """Find the encrypted config file for an environment.

    Prints the absolute path to stdout for use in shell scripts.
    Exits with code 1 if no config file is found.

    \b
    Examples:
        locke config find
        locke config find --env production
        locke config find --env staging --project-root /path/to/project

    \b
    Shell integration:
        CONFIG=$(locke config find --env production)
        docker run -v "$CONFIG:/app/config.encrypted.json:ro" ...
    """
    from locke import find_config

    path = find_config(project_root, env=env_name)
    if path:
        click.echo(str(path.resolve()))
    else:
        env_display = env_name or "any"
        click.echo(
            f"Error: no encrypted config found for env={env_display} "
            f"in {project_root}",
            err=True,
        )
        sys.exit(1)


@config.command(name="path")
def config_path_cmd() -> None:
    """Print the path of the user-level settings file.

    This is the file Locke reads for non-secret bootstrap settings
    (Vaultwarden URL/email and 1Password account/vault) from any working
    directory. The path is printed
    whether or not the file exists yet.

    \b
    Examples:
        locke config path
        cat "$(locke config path)"
    """
    from locke.settings import settings_path

    click.echo(str(settings_path()))


@config.command(name="show")
def config_show() -> None:
    """Show the effective user-level settings.

    \b
    Examples:
        locke config show
    """
    from locke.settings import load_settings, settings_path

    path = settings_path()
    settings = load_settings()

    if not path.is_file():
        click.echo(f"# no settings file at {path}", err=True)
    else:
        click.echo(f"# {path}", err=True)

    if not settings:
        click.echo("# (no settings)", err=True)
        return

    for key in sorted(settings):
        click.echo(f"{key} = {settings[key]}")


@config.command(name="set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str) -> None:
    """Set one user-level setting, creating the file if needed.

    Secrets are refused: the file is plaintext. Keep the Vaultwarden master
    password in the OS keystore (locke keystore set LOCKE_VAULT_PASSWORD).

    \b
    Examples:
        locke config set vault_url https://vault.example.com
        locke config set vault_email ops@example.com
        locke config set onepassword_account my.1password.com
        locke config set onepassword_vault Operations
    """
    from locke.settings import set_setting

    try:
        path = set_setting(key, value)
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(f"set {key} in {path}", err=True)
