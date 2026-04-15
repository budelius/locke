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
