"""Project-level helpers replacing the legacy genkeys and strip_jsonc scripts."""

import json
import os
from pathlib import Path

import click

from locke.jsonc import strip_jsonc

_SETTING_NAMES = ("LOCKE_INPUT_DIR", "LOCKE_OUTPUT_DIR", "LOCKE_KEY_NAME")


def _find_project_root(project_root: Path | None = None) -> Path:
    """Return the explicit root or nearest ancestor containing a .env file."""
    if project_root is not None:
        return project_root.expanduser().resolve()

    current = Path.cwd().resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".env").is_file():
            return candidate
    raise click.ClickException(
        "no project-root .env found; run inside a project or pass --project-root"
    )


def _read_dotenv_settings(path: Path) -> dict[str, str]:
    """Read non-secret genkeys settings from a project-root .env file."""
    settings: dict[str, str] = {}
    if not path.is_file():
        return settings

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise click.ClickException(f"could not read {path}: {exc}") from exc

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        if name.startswith("export "):
            name = name[7:].strip()
        if name not in _SETTING_NAMES:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        settings[name] = value
    return settings


def _resolve_path(value: str, root: Path) -> Path:
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (root / path).resolve()


@click.command("genkeys")
@click.option(
    "--project-root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Project root. Defaults to the nearest ancestor containing .env.",
)
@click.option(
    "--input-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Plaintext config directory; overrides LOCKE_INPUT_DIR.",
)
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Encrypted config directory; overrides LOCKE_OUTPUT_DIR.",
)
@click.option("--key-name", default=None, help="Overrides LOCKE_KEY_NAME.")
@click.option(
    "--key-source",
    type=click.Choice(["keystore", "env", "prompt"]),
    default="keystore",
    help="Where to resolve the encryption key.",
)
@click.pass_context
def genkeys(
    ctx: click.Context,
    project_root: Path | None,
    input_dir: Path | None,
    output_dir: Path | None,
    key_name: str | None,
    key_source: str,
) -> None:
    """Encrypt all project configs using settings from the project-root .env.

    Settings use CLI option > process environment > project .env precedence.
    Relative directory values are resolved from the project root.
    """
    root = _find_project_root(project_root)
    settings = _read_dotenv_settings(root / ".env")

    input_value = input_dir or os.environ.get("LOCKE_INPUT_DIR") or settings.get(
        "LOCKE_INPUT_DIR"
    )
    output_value = output_dir or os.environ.get("LOCKE_OUTPUT_DIR") or settings.get(
        "LOCKE_OUTPUT_DIR"
    ) or ".locke"
    resolved_key_name = (
        key_name or os.environ.get("LOCKE_KEY_NAME") or settings.get("LOCKE_KEY_NAME")
    )

    if input_value is None:
        raise click.ClickException(
            "LOCKE_INPUT_DIR is not set in the project-root .env or environment"
        )
    if not resolved_key_name:
        raise click.ClickException(
            "LOCKE_KEY_NAME is not set in the project-root .env or environment"
        )

    resolved_input = _resolve_path(str(input_value), root)
    resolved_output = _resolve_path(str(output_value), root)
    if not resolved_input.is_dir():
        raise click.ClickException(f"input directory does not exist: {resolved_input}")

    # Encryption's credential pipeline and locke.json discovery are cwd-based.
    # Run it from the discovered root so key values may also fall back to that
    # project's .env file when allowed by the active environment.
    previous_cwd = Path.cwd()
    try:
        os.chdir(root)
        from locke.cli.encrypt import encrypt_all

        ctx.invoke(
            encrypt_all,
            input_dir=resolved_input,
            output_dir=resolved_output,
            key_name=resolved_key_name,
            key_source=key_source,
        )
    finally:
        os.chdir(previous_cwd)


@click.command("strip-jsonc")
@click.argument("input_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("output_path", required=False, type=click.Path(dir_okay=False, path_type=Path))
def strip_jsonc_command(input_path: Path, output_path: Path | None) -> None:
    """Convert JSONC INPUT_PATH to strict JSON on stdout or in OUTPUT_PATH."""
    try:
        cleaned = strip_jsonc(input_path.read_text(encoding="utf-8"))
        json.loads(cleaned)
    except (OSError, json.JSONDecodeError) as exc:
        raise click.ClickException(f"could not convert {input_path}: {exc}") from exc

    if output_path is None:
        click.echo(cleaned, nl=False)
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(cleaned, encoding="utf-8")
        click.echo(f"Converted: {input_path} -> {output_path}", err=True)
