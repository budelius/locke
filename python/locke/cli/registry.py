"""locke registry — authenticate with package registries via .netrc."""

import os
import sys
from pathlib import Path

import click


DEFAULT_HOST = "gitlab.com"
NETRC_LOGIN = "__token__"


def _netrc_path() -> Path:
    """Return the netrc path, preferring an existing file."""
    home = Path.home()
    # On Windows both .netrc and _netrc are common; prefer whichever exists
    for name in (".netrc", "_netrc"):
        candidate = home / name
        if candidate.exists():
            return candidate
    # Default: .netrc (works everywhere)
    return home / ".netrc"


def _parse_netrc_machines(path: Path) -> list[dict[str, str]]:
    """Parse .netrc into a list of machine entries."""
    if not path.exists():
        return []

    machines: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        tokens = stripped.split()
        i = 0
        while i < len(tokens):
            if tokens[i] == "machine" and i + 1 < len(tokens):
                current = {"machine": tokens[i + 1]}
                machines.append(current)
                i += 2
            elif tokens[i] in ("login", "password") and i + 1 < len(tokens) and current is not None:
                current[tokens[i]] = tokens[i + 1]
                i += 2
            else:
                i += 1

    return machines


def _write_netrc(path: Path, machines: list[dict[str, str]]) -> None:
    """Write machine entries back to .netrc."""
    lines: list[str] = []
    for m in machines:
        lines.append(f"machine {m['machine']}")
        if "login" in m:
            lines.append(f"  login {m['login']}")
        if "password" in m:
            lines.append(f"  password {m['password']}")
    path.write_text("\n".join(lines) + "\n")

    # Restrict permissions on Unix
    if os.name != "nt":
        path.chmod(0o600)


@click.group()
def registry() -> None:
    """Manage package registry authentication for consuming locke."""


@registry.command("login")
@click.option("--host", default=DEFAULT_HOST, show_default=True,
              help="Registry hostname (e.g. gitlab.com, gitlab.example.org)")
def registry_login(host: str) -> None:
    """Store a registry token in ~/.netrc for uv/pip authentication.

    Use a Personal Access Token with read access to the package registry
    (on GitLab: ``read_api`` scope).
    """
    token = click.prompt(f"{host} Personal Access Token (read_api scope)", hide_input=True)
    if not token.strip():
        click.echo("Error: token cannot be empty", err=True)
        sys.exit(1)

    path = _netrc_path()
    machines = _parse_netrc_machines(path)

    # Update existing or append
    updated = False
    for m in machines:
        if m["machine"] == host:
            m["login"] = NETRC_LOGIN
            m["password"] = token.strip()
            updated = True
            break

    if not updated:
        machines.append({
            "machine": host,
            "login": NETRC_LOGIN,
            "password": token.strip(),
        })

    _write_netrc(path, machines)
    click.echo(f"Credential stored in {path}", err=True)


@registry.command("check")
@click.option("--host", default=DEFAULT_HOST, show_default=True,
              help="Registry hostname to verify")
def registry_check(host: str) -> None:
    """Check if a registry credential is in ~/.netrc."""
    path = _netrc_path()
    machines = _parse_netrc_machines(path)

    for m in machines:
        if m["machine"] == host:
            click.echo(f"Credential found in {path} (login: {m.get('login', '?')})")
            return

    click.echo(f"No credential for {host} in {path}. Run: locke registry login", err=True)
    sys.exit(1)
