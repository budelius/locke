"""locke validate -- check that all keys in locke.json are reachable."""

import json
import os
import sys
from pathlib import Path

import click

# ASCII-safe status markers (Windows cp1252 can't render Unicode checkmarks)
OK = "[OK]"
FAIL = "[!!]"
WARN = "[??]"
SKIP = "[--]"
PLACEHOLDER_VALUES = {"FILL_ME"}


def _load_locke_json(project_root: str) -> dict:
    """Load and return the locke.json config."""
    for candidate in [
        Path(project_root) / ".locke" / "locke.json",
        Path(project_root) / "locke.json",
    ]:
        if candidate.exists():
            with open(candidate) as f:
                return json.load(f)
    click.echo("Error: no locke.json found in .locke/ or project root.", err=True)
    sys.exit(1)


def _check_keystore(keys: dict) -> tuple[int, int]:
    """Check OS keystore credentials. Returns (passed, failed)."""
    if not keys:
        return 0, 0

    from locke.errors import BiometricDeniedError, BiometricUnavailableError
    from locke.keystore import get_credential

    passed = failed = 0
    click.echo("\nKeystore:")
    for name, desc in sorted(keys.items()):
        if name.startswith("_"):
            continue
        try:
            value = get_credential(name)
            if value:
                click.echo(click.style(f"  {OK} {name}", fg="green") + f" -- {desc}")
                passed += 1
            else:
                click.echo(click.style(f"  {FAIL} {name}", fg="red") + f" -- not found ({desc})")
                failed += 1
        except (BiometricDeniedError, BiometricUnavailableError) as exc:
            click.echo(click.style(f"  {WARN} {name}", fg="yellow") + f" -- biometric skipped: {exc}")
        except Exception as exc:
            click.echo(click.style(f"  {FAIL} {name}", fg="red") + f" -- error: {exc}")
            failed += 1
    return passed, failed


def _check_encrypted_config(config: dict) -> tuple[int, int]:
    """Check that encrypted config files exist and are decryptable."""
    keys = config.get("keys", {}).get("encryptedConfig", {})
    if not keys:
        return 0, 0

    passed = failed = 0
    click.echo("\nEncrypted Config:")

    # Find encrypted config files
    locke_dir = Path(".locke")
    config_path_pattern = config.get("encryptedConfigPath", "./config.encrypted.json")
    environments = config.get("environments", [])
    key_name = config.get("keyName")

    # Count documented keys (excluding _comment)
    doc_keys = [k for k in keys if not k.startswith("_")]
    click.echo(f"  Documented keys: {len(doc_keys)}")

    if not environments:
        # Single config file
        candidates = sorted(locke_dir.glob("config.encrypted*.json"))
    else:
        candidates = []
        for env_name in environments:
            expanded = config_path_pattern.replace("{env}", env_name)
            p = locke_dir / Path(expanded).name
            if p.exists():
                candidates.append(p)

    if not candidates:
        click.echo(click.style(f"  {FAIL} No encrypted config files found", fg="red"))
        return 0, 1

    for cfg_file in candidates:
        try:
            with open(cfg_file) as f:
                encrypted = json.load(f)
            # Check it has the right structure
            if encrypted.get("version") and encrypted.get("ciphertext"):
                click.echo(click.style(f"  {OK} {cfg_file.name}", fg="green") + " -- valid encrypted format")
                passed += 1
            else:
                click.echo(click.style(f"  {WARN} {cfg_file.name}", fg="yellow") + " -- not standard encrypted format")
                failed += 1
        except Exception as exc:
            click.echo(click.style(f"  {FAIL} {cfg_file.name}", fg="red") + f" -- {exc}")
            failed += 1

    # Attempt decryption of first file to verify key works
    if key_name and candidates:
        try:
            from locke.pipeline import resolve_credential
            cred = resolve_credential(key_name)
            from locke.crypto import decrypt_config
            with open(candidates[0]) as f:
                encrypted = json.load(f)
            plaintext = decrypt_config(encrypted, cred.value)
            actual_keys = set(_flatten_keys(plaintext))
            click.echo(click.style(f"  {OK} Decryption OK", fg="green") + f" -- {len(actual_keys)} keys in {candidates[0].name}")

            # Cross-reference documented vs actual
            for dk in doc_keys:
                if dk not in actual_keys:
                    click.echo(click.style(f"    {WARN} {dk}", fg="yellow") + " -- documented but not in config")
            for ak in sorted(actual_keys):
                if ak not in doc_keys:
                    click.echo(click.style(f"    {WARN} {ak}", fg="yellow") + " -- in config but not documented")

            passed += 1
        except Exception as exc:
            click.echo(click.style(f"  {FAIL} Decryption failed", fg="red") + f" -- {exc}")
            failed += 1

    return passed, failed


def _flatten_keys(obj: dict, prefix: str = "") -> list[str]:
    """Flatten a nested dict into dot-separated key paths."""
    keys = []
    for k, v in obj.items():
        if k.startswith("_"):
            continue
        full_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            keys.extend(_flatten_keys(v, full_key))
        else:
            keys.append(full_key)
    return keys


def _check_vault(keys: dict, config: dict) -> tuple[int, int]:
    """Check vault secrets are accessible."""
    if not keys:
        return 0, 0

    passed = failed = 0
    click.echo("\nVault:")

    vault_entries = {k: v for k, v in keys.items() if not k.startswith("_")}
    if not vault_entries:
        click.echo("  (no vault secrets documented)")
        return 0, 0

    # Check if vault is configured
    vault_url = os.environ.get("LOCKE_VAULT_URL")
    if not vault_url:
        click.echo(click.style(f"  {SKIP} Vault not configured", fg="yellow") + " -- LOCKE_VAULT_URL not set, checking env var fallbacks")
        # Fall back to checking if the target env vars are set
        for path, desc in sorted(vault_entries.items()):
            # Extract env var from description (format: "description → ENV_VAR")
            env_var = _extract_env_var(desc)
            if env_var and os.environ.get(env_var):
                click.echo(click.style(f"  {OK} {path}", fg="green") + f" -- {env_var} set via env")
                passed += 1
            else:
                click.echo(click.style(f"  {FAIL} {path}", fg="red") + f" -- not available ({desc})")
                failed += 1
        return passed, failed

    # Try actual vault lookup
    try:
        from locke.vault import get_vault_secret
        for path, desc in sorted(vault_entries.items()):
            # Replace {tenant} with actual tenant
            actual_path = _expand_vault_path(path, config)
            try:
                secret = get_vault_secret(actual_path)
                if _is_placeholder_secret(secret):
                    click.echo(click.style(f"  {FAIL} {path}", fg="red") + " -- placeholder value")
                    failed += 1
                elif secret:
                    click.echo(click.style(f"  {OK} {path}", fg="green") + " -- found")
                    passed += 1
                else:
                    click.echo(click.style(f"  {FAIL} {path}", fg="red") + f" -- empty ({desc})")
                    failed += 1
            except Exception:
                # Fall back: check if env var is set
                env_var = _extract_env_var(desc)
                if env_var and os.environ.get(env_var):
                    click.echo(click.style(f"  {WARN} {path}", fg="yellow") + f" -- vault miss, but {env_var} set via env")
                    passed += 1
                else:
                    click.echo(click.style(f"  {FAIL} {path}", fg="red") + f" -- not found ({desc})")
                    failed += 1
    except ImportError:
        click.echo(click.style(f"  {SKIP} Vault module not available", fg="yellow") + " -- install locke[vault]")
        failed += len(vault_entries)

    return passed, failed


def _expand_vault_path(path: str, config: dict) -> str:
    """Expand supported placeholders in a keys.vault path."""
    return (
        path
        .replace("{project}", str(config.get("project") or ""))
        .replace("{tenant}", str(config.get("tenant") or "default"))
    )


def _is_placeholder_secret(value: str | None) -> bool:
    """Return True when a vault secret is still a setup placeholder."""
    if value is None:
        return False
    return value.strip() in PLACEHOLDER_VALUES


def _extract_env_var(desc: str) -> str | None:
    """Extract env var name from description like 'Some desc → ENV_VAR'."""
    # Support multiple arrow styles in descriptions
    for sep in [" -> ", " => ", "\u2192 "]:
        if sep in desc:
            return desc.split(sep)[-1].strip()
    return None


def _check_env(keys: dict) -> tuple[int, int]:
    """Check environment variables."""
    if not keys:
        return 0, 0

    passed = failed = 0
    click.echo("\nEnvironment:")
    for name, desc in sorted(keys.items()):
        if name.startswith("_"):
            continue
        value = os.environ.get(name)
        if value:
            # Mask sensitive-looking values
            display = value if len(value) < 40 and "key" not in name.lower() and "secret" not in name.lower() and "password" not in name.lower() else "***"
            click.echo(click.style(f"  {OK} {name}", fg="green") + f" = {display}")
            passed += 1
        else:
            click.echo(click.style(f"  {SKIP} {name}", fg="yellow") + f" -- not set ({desc})")
            # Env vars are often optional, count as warning not failure
    return passed, failed


@click.command("validate")
@click.option(
    "--project-root",
    default=".",
    help="Project root directory (default: current directory)",
)
@click.option(
    "--skip-vault",
    is_flag=True,
    help="Skip vault checks (avoids vault auth)",
)
@click.option(
    "--skip-decrypt",
    is_flag=True,
    help="Skip decryption check (avoids biometric prompt)",
)
def validate(project_root: str, skip_vault: bool, skip_decrypt: bool) -> None:
    """Validate that all keys in locke.json are reachable.

    Checks keystore credentials, encrypted config files, vault secrets,
    and environment variables against the key registry in locke.json.

    \b
    Examples:
        locke validate
        locke validate --skip-vault
        locke validate --project-root /path/to/project
    """
    config = _load_locke_json(project_root)
    keys = config.get("keys", {})

    if not keys:
        click.echo("No keys section in locke.json -- nothing to validate.")
        click.echo("Run 'locke init' to create a key registry.")
        return

    click.echo(f"Validating: {config.get('project', '?')} (v{config.get('version', '?')})")

    total_passed = total_failed = 0

    # 1. Keystore
    p, f = _check_keystore(keys.get("keystore", {}))
    total_passed += p
    total_failed += f

    # 2. Encrypted config
    if not skip_decrypt:
        p, f = _check_encrypted_config(config)
        total_passed += p
        total_failed += f
    else:
        click.echo("\nEncrypted Config: (skipped)")

    # 3. Vault
    if not skip_vault:
        p, f = _check_vault(keys.get("vault", {}), config)
        total_passed += p
        total_failed += f
    else:
        click.echo("\nVault: (skipped)")

    # 4. Environment
    p, f = _check_env(keys.get("env", {}))
    total_passed += p
    total_failed += f

    # Summary
    click.echo(f"\n{'-' * 40}")
    click.echo(f"  {total_passed} passed, {total_failed} failed")

    if total_failed > 0:
        sys.exit(1)
