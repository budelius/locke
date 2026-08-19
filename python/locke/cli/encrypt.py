"""locke encrypt — encrypt plaintext config files."""

import json
import sys
from pathlib import Path

import click

from locke.cli._key_util import get_key
from locke.crypto import encrypt_config
from locke.jsonc import parse_jsonc

ENVIRONMENTS = ("development", "staging", "production")


@click.group()
def encrypt() -> None:
    """Encrypt plaintext JSON config files."""


@encrypt.command(name="file")
@click.argument("config_path", required=False, default=None)
@click.option(
    "--config",
    "config_opt",
    default=None,
    help="Path to plaintext config file (alternative to positional arg)",
)
@click.option(
    "--output", "-o",
    "output_path",
    default=None,
    help="Output path (default: auto-generates config.encrypted.{env}.json)",
)
@click.option("--key-name", default=None, help="Credential name for the encryption key")
@click.option(
    "--key-source",
    type=click.Choice(["keystore", "env", "prompt"]),
    default="keystore",
    help="Where to get the encryption key",
)
def encrypt_file(
    config_path: str | None,
    config_opt: str | None,
    output_path: str | None,
    key_name: str | None,
    key_source: str,
) -> None:
    """Encrypt a single plaintext JSON config file.

    \b
    Examples:
        locke encrypt file config.development.json --key-name MYAPP_CONFIG_ENCRYPTION_KEY
        locke encrypt file config.production.json -o config.encrypted.production.json
    """
    # Resolve input path: positional arg > --config > error
    path_str = config_path or config_opt
    if not path_str:
        click.echo("Error: provide a config file path", err=True)
        sys.exit(1)

    path = Path(path_str)
    try:
        # parse_jsonc accepts plain JSON and JSONC (comments + trailing commas),
        # so annotated .json/.jsonc config files encrypt without pre-stripping.
        plaintext = parse_jsonc(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        click.echo(f"Error: File not found: {path}", err=True)
        sys.exit(1)
    except json.JSONDecodeError:
        click.echo(f"Error: Invalid JSON/JSONC in {path}", err=True)
        sys.exit(1)

    # Auto-resolve key_name from .locke/locke.json if not provided
    if not key_name:
        from locke import read_locke_config
        locke_cfg = read_locke_config(".")
        if locke_cfg and locke_cfg.get("keyName"):
            key_name = locke_cfg["keyName"]
            click.echo(f"Using key name from .locke/locke.json: {key_name}", err=True)

    try:
        key = get_key(key_source, key_name)
        encrypted = encrypt_config(plaintext, key)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    # Auto-generate output name: config.X.json → config.encrypted.X.json
    if output_path is None:
        stem = path.stem  # e.g. "config.development"
        if stem.startswith("config.") and not stem.startswith("config.encrypted."):
            out_name = stem.replace("config.", "config.encrypted.", 1) + ".json"
        else:
            out_name = path.stem + ".encrypted.json"
        out_path = path.parent / out_name
    else:
        out_path = Path(output_path)

    with open(out_path, "w") as f:
        json.dump(encrypted, f, indent=2)
        f.write("\n")

    click.echo(f"Encrypted: {path} -> {out_path}")


@encrypt.command(name="all")
@click.option(
    "-d",
    "--input-dir",
    "input_dir",
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Directory containing config.{env}.json files.",
)
@click.option(
    "-o",
    "--output-dir",
    "output_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Output directory for encrypted files. Defaults to input directory.",
)
@click.option("--key-name", default=None, help="Credential name for the encryption key")
@click.option(
    "--key-source",
    type=click.Choice(["keystore", "env", "prompt"]),
    default="keystore",
    help="Where to get the encryption key",
)
def encrypt_all(
    input_dir: Path,
    output_dir: Path | None,
    key_name: str | None,
    key_source: str,
) -> None:
    """Encrypt all environment configs (development, staging, production) in one run.

    Scans input-dir for config.{env}.json files and writes
    config.encrypted.{env}.json to output-dir.
    """
    # Auto-resolve key_name from .locke/locke.json if not provided
    if not key_name:
        from locke import read_locke_config
        locke_cfg = read_locke_config(".")
        if locke_cfg and locke_cfg.get("keyName"):
            key_name = locke_cfg["keyName"]
            click.echo(f"Using key name from .locke/locke.json: {key_name}", err=True)

    try:
        passphrase = get_key(key_source, key_name)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if output_dir is None:
        output_dir = input_dir
    else:
        output_dir.mkdir(parents=True, exist_ok=True)

    found = 0
    for env in ENVIRONMENTS:
        # Prefer an annotated .jsonc source, fall back to plain .json.
        input_file = input_dir / f"config.{env}.jsonc"
        if not input_file.exists():
            input_file = input_dir / f"config.{env}.json"
        if not input_file.exists():
            click.echo(f"  skip  {env:12s}  (no config.{env}.json[c])")
            continue

        config_data = parse_jsonc(input_file.read_text(encoding="utf-8"))

        encrypted = encrypt_config(config_data, passphrase)
        out_file = output_dir / f"config.encrypted.{env}.json"

        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(encrypted, f, indent=2)
            f.write("\n")

        click.echo(f"  OK    {env:12s}  {input_file} -> {out_file}")
        found += 1

    if found == 0:
        click.echo("No config.{env}.json files found.", err=True)
        sys.exit(1)
    else:
        click.echo(f"\nEncrypted {found} config(s).")
