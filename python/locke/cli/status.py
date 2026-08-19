"""locke status — comprehensive credential and config status check.

Replaces per-project key-status scripts with a single unified command.
Shows key resolution, config file discovery, and environment detection.
"""

import os
from pathlib import Path

import click

from locke.env import detect_environment
from locke.errors import (
    BiometricDeniedError,
    BiometricUnavailableError,
    CredentialNotFoundError,
    KeystoreUnavailableError,
)

ENVIRONMENTS = ("development", "staging", "production")


@click.command()
@click.option(
    "--key-name",
    default=None,
    help="Credential name to check (e.g. MYAPP_CONFIG_ENCRYPTION_KEY)",
)
@click.option(
    "--project-root",
    default=".",
    type=click.Path(exists=True, file_okay=False),
    help="Project root for config discovery (default: current directory)",
)
def status(key_name: str | None, project_root: str) -> None:
    """Show credential resolution status and config file discovery.

    \b
    Examples:
        locke status --key-name MYAPP_CONFIG_ENCRYPTION_KEY
        locke status --key-name MYAPP_CONFIG_ENCRYPTION_KEY --project-root /path/to/project
    """
    root = Path(project_root).resolve()

    # ── Environment ──
    env = detect_environment()
    env_source = _detect_env_source()
    click.echo(f"\n  Environment: {env} ({env_source})")
    if key_name:
        click.echo(f"  Key name:    {key_name}")
    click.echo()

    # ── Key resolution chain ──
    if key_name:
        click.echo("  Key resolution:")
        _check_keystore(key_name)
        _check_env_var(key_name)
        _check_glab(key_name)
        _check_dotenv(key_name)

        # Overall resolution
        click.echo()
        try:
            from locke.pipeline import resolve_credential
            cred = resolve_credential(key_name)
            click.echo(
                f"  => Key resolved via {cred.source} ({len(cred.value)} chars)"
            )
        except CredentialNotFoundError:
            click.echo("  => NO key resolved. Options:")
            click.echo(f"     locke keystore generate {key_name}")
            click.echo(f"     locke keystore set {key_name} --prompt")
            click.echo(f"     export {key_name}=<64-char-hex-key>")
        click.echo()
    else:
        click.echo("  (use --key-name to check key resolution)")
        click.echo()

    # ── Config files ──
    click.echo("  Config files:")
    found_any = False
    search_dirs = [root, root / ".locke", root / "src"]
    seen_paths: set[Path] = set()

    for env_name in ENVIRONMENTS:
        fname = f"config.encrypted.{env_name}.json"
        found = False
        for d in search_dirs:
            p = d / fname
            if p.is_file() and p not in seen_paths:
                seen_paths.add(p)
                rel = _relative(p, root)
                marker = " <-- active" if env_name == env else ""
                click.echo(f"    [OK] {rel}{marker}")
                found = True
                found_any = True
                break
        if not found:
            click.echo(f"    [--] {fname}")

    # Check bare config.encrypted.json
    for d in search_dirs:
        p = d / "config.encrypted.json"
        if p.is_file() and p not in seen_paths:
            rel = _relative(p, root)
            click.echo(f"    [OK] {rel}")
            found_any = True

    if not found_any:
        click.echo()
        click.echo("  No encrypted configs found. Create one with:")
        click.echo("    1. cp config.example.json config.development.json")
        click.echo("    2. Edit config.development.json (fill in values)")
        if key_name:
            click.echo(
                f"    3. locke encrypt file config.development.json "
                f"--key-name {key_name}"
            )
        else:
            click.echo(
                "    3. locke encrypt file config.development.json "
                "--key-name <YOUR_KEY_NAME>"
            )
        click.echo("    4. rm config.development.json")

    # ── Plain config files (should NOT exist) ──
    plain_files = []
    for env_name in ENVIRONMENTS:
        for d in search_dirs:
            p = d / f"config.{env_name}.json"
            if p.is_file():
                plain_files.append(_relative(p, root))
    if plain_files:
        click.echo()
        click.echo("  WARNING: Plain config files found (should be encrypted + deleted):")
        for pf in plain_files:
            click.echo(f"    [!!] {pf}")

    click.echo()


def _relative(path: Path, root: Path) -> str:
    """Return path relative to root, or absolute if not under root."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _detect_env_source() -> str:
    """Identify which env var set the environment."""
    for var in ("LOCKE_ENV", "NODE_ENV", "PYTHON_ENV", "RAILS_ENV", "FLASK_ENV", "APP_ENV"):
        if os.environ.get(var):
            return f"from {var}"
    return "default"


def _check_keystore(key_name: str) -> None:
    """Check OS keystore for the credential."""
    try:
        from locke.keystore import SERVICE_NAME, get_credential
        value = get_credential(key_name)
        if value:
            click.echo(
                f"    [OK] OS keystore ({SERVICE_NAME}/{key_name}): "
                f"found ({len(value)} chars)"
            )
        else:
            click.echo(f"    [--] OS keystore ({SERVICE_NAME}/{key_name}): not found")
    except BiometricDeniedError:
        click.echo("    [!!] OS keystore: biometric verification denied")
    except BiometricUnavailableError:
        click.echo("    [!!] OS keystore: biometric not available")
    except KeystoreUnavailableError:
        click.echo("    [--] OS keystore: service unavailable")
    except Exception as exc:
        click.echo(f"    [--] OS keystore: error ({exc})")


def _check_env_var(key_name: str) -> None:
    """Check environment variable."""
    value = os.environ.get(key_name)
    if value:
        click.echo(f"    [OK] {key_name} env var: set ({len(value)} chars)")
    else:
        click.echo(f"    [--] {key_name} env var: not set")


def _check_glab(key_name: str) -> None:
    """Check GitLab CLI availability."""
    import shutil
    if shutil.which("glab"):
        click.echo("    [..] GitLab CLI (glab): available (not checked)")
    else:
        click.echo("    [--] GitLab CLI (glab): not in PATH")


def _check_dotenv(key_name: str) -> None:
    """Check .env file for the credential."""
    dotenv_path = Path.cwd() / ".env"
    if not dotenv_path.is_file():
        click.echo("    [--] .env file: not found")
        return

    try:
        with open(dotenv_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, _ = line.partition("=")
                if k.strip() == key_name:
                    click.echo(f"    [OK] .env file: {key_name} found")
                    return
        click.echo(f"    [--] .env file: {key_name} not found")
    except OSError:
        click.echo("    [--] .env file: read error")
