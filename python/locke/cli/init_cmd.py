"""locke init — initialize .locke directory and migrate .env."""

import fnmatch
import json
import os
import re
import shutil
import sys
from pathlib import Path

import click

TEMPLATES_DIR = Path(__file__).parent.parent.parent.parent / "templates"

# Default classification patterns: (glob_pattern, destination)
DEFAULT_PATTERNS = [
    ("*_URI", "config"),
    ("*_DSN", "config"),
    ("*_HOST", "config"),
    ("*_PORT", "config"),
    ("*_URL", "config"),
    ("*_DATABASE", "config"),
    ("*_DB", "config"),
    ("*_API_KEY", "vault"),
    ("*_TOKEN", "vault"),
    ("*_SECRET", "vault"),
    ("*_PASSWORD", "vault"),
    ("PERSONAL_*", "vault"),
    ("MY_*", "vault"),
]

_SAFE_VALUE_RE = re.compile(
    r"^("
    r"true|false|yes|no"               # booleans
    r"|[0-9]+"                         # integers
    r"|[0-9]+\.[0-9]+"                # floats
    r"|[a-z]{2,4}-[a-z]+-[0-9]+"     # AWS/cloud regions
    r"|[a-z]{2,4}[0-9]+"             # short region codes (nbg1, fsn1)
    r"|localhost"
    r"|0\.0\.0\.0"
    r"|https?://localhost[:/]?.*"
    r")$",
    re.IGNORECASE,
)


def _is_safe_value(value: str) -> bool:
    """Return True if a value looks non-secret (safe to keep in .env.example)."""
    value = value.strip().strip("'\"")
    if not value:
        return True
    return bool(_SAFE_VALUE_RE.match(value))


def _classify_key(key: str, rules: list[dict]) -> tuple[str, str]:
    """Classify a .env key as 'config' or 'vault'.

    Returns (destination, confidence) where confidence is 'confirmed' if
    a saved rule matched, or 'default' if pattern heuristic was used.
    """
    # Check saved rules first (confirmed rules take priority)
    for rule in rules:
        if fnmatch.fnmatch(key, rule["pattern"]):
            return rule["destination"], rule.get("confidence", "default")

    # Apply default patterns
    for pattern, dest in DEFAULT_PATTERNS:
        if fnmatch.fnmatch(key, pattern):
            return dest, "default"

    # Default fallback: shared config
    return "config", "default"


def _parse_env_file(env_path: Path) -> list[tuple[str, str]]:
    """Parse a .env file into (key, value) pairs."""
    entries = []
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            entries.append((key, value))
    return entries


def _generate_env_example(
    env_path: Path,
    classifications: dict[str, str],
    output_path: Path,
) -> None:
    """Generate .env.example with keys but placeholder values.

    Preserves comments and blank lines from the original .env file.
    Vault-classified keys get a vault placeholder; config keys keep safe
    values (digits, booleans, regions) or get a generic placeholder.
    """
    lines: list[str] = []
    with open(env_path) as f:
        for raw_line in f:
            raw = raw_line.rstrip("\n").rstrip("\r")
            stripped = raw.strip()

            # Preserve comments and blank lines
            if not stripped or stripped.startswith("#"):
                lines.append(raw)
                continue

            if "=" not in stripped:
                lines.append(raw)
                continue

            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip()

            dest = classifications.get(key, "config")

            if dest == "vault":
                lines.append(f"{key}=  # VAULT — retrieve via locke")
            elif _is_safe_value(value):
                lines.append(f"{key}={value}")
            else:
                placeholder = "your-" + key.lower().replace("_", "-") + "-here"
                lines.append(f"{key}={placeholder}")

    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")


@click.command("init")
@click.option("--env-file", default=".env", help="Path to .env file")
@click.option("--non-interactive", is_flag=True, help="Apply saved rules without prompting")
@click.option("--project", prompt="Project name", help="Project name for Vaultwarden paths")
@click.option("--tenant", default="default", help="Default tenant slug")
@click.option("--key-name", default=None, help="Encryption key credential name (e.g. MYAPP_CONFIG_ENCRYPTION_KEY)")
def init(env_file: str, non_interactive: bool, project: str, tenant: str, key_name: str | None) -> None:
    """Initialize a .locke directory and optionally migrate a .env file."""
    locke_dir = Path(".locke")
    locke_json_path = locke_dir / "locke.json"

    # Load existing config if re-initializing
    existing_config = None
    if locke_json_path.exists():
        with open(locke_json_path) as f:
            existing_config = json.load(f)
        click.echo("Existing .locke/ found — merging new entries.", err=True)

    # Create .locke directory
    locke_dir.mkdir(exist_ok=True)

    # Report existing encrypted configs
    encrypted_files = sorted(locke_dir.glob("config.encrypted.*.json"))
    if encrypted_files:
        example_files = [f for f in encrypted_files if "example" in f.name]
        stage_files = [f for f in encrypted_files if "example" not in f.name]
        if stage_files:
            click.echo(f"\n  Found {len(stage_files)} encrypted config(s):", err=True)
            for ef in stage_files:
                click.echo(f"    - {ef.name}", err=True)

    # Initialize locke.json from template or existing
    if existing_config:
        config = existing_config
    else:
        template_path = TEMPLATES_DIR / "locke.json"
        if template_path.exists():
            with open(template_path) as f:
                config = json.load(f)
        else:
            config = {
                "version": 2,
                "project": "",
                "tenant": "default",
                "keyName": "",
                "encryptedConfigPath": "./config.encrypted.json",
                "classificationRules": [],
                "keys": {
                    "keystore": {},
                    "encryptedConfig": {},
                    "vault": {},
                    "env": {},
                },
            }

    config["project"] = project
    config["tenant"] = tenant
    if key_name:
        config["keyName"] = key_name
    elif not config.get("keyName"):
        # Default convention: {PROJECT}_CONFIG_ENCRYPTION_KEY
        config["keyName"] = f"{project.upper()}_CONFIG_ENCRYPTION_KEY"

    # Ensure keys section exists (upgrade v1 → v2)
    if "keys" not in config:
        config["keys"] = {"keystore": {}, "encryptedConfig": {}, "vault": {}, "env": {}}
        config["version"] = 2
    # Auto-populate keystore entry for the encryption key
    ks = config["keys"].setdefault("keystore", {})
    if config["keyName"] and config["keyName"] not in ks:
        ks[config["keyName"]] = f"Decrypts config.encrypted.*.json for {project}"

    rules = config.get("classificationRules", [])

    # Template variable substitution map
    template_vars = {
        "{key_name}": config["keyName"],
        "{project}": config["project"],
        "{tenant}": config["tenant"],
    }

    # Copy templates (with variable substitution for text files)
    if not existing_config:
        for template_name in ["BOOTSTRAP.md", "config.example.json", "vault-references.example.json"]:
            src = TEMPLATES_DIR / template_name
            dst = locke_dir / template_name
            if src.exists() and not dst.exists():
                if src.suffix == ".md":
                    content = src.read_text(encoding="utf-8")
                    for var, val in template_vars.items():
                        content = content.replace(var, val)
                    dst.write_text(content, encoding="utf-8")
                else:
                    shutil.copy2(src, dst)

    # Move root .env.example into .locke/ if present
    root_env_example = Path(".env.example")
    locke_env_example = locke_dir / ".env.example"
    if root_env_example.exists() and not locke_env_example.exists():
        if non_interactive or click.confirm(
            "  Found .env.example at project root. Move into .locke/?", default=True
        ):
            shutil.move(str(root_env_example), str(locke_env_example))
            click.echo(f"  Moved .env.example → {locke_env_example}", err=True)

    # Migrate .env if it exists
    env_path = Path(env_file)
    shared_config: dict = {}
    vault_refs: list[dict] = []
    classifications: dict[str, str] = {}

    if env_path.exists():
        entries = _parse_env_file(env_path)
        click.echo(f"\nFound {len(entries)} entries in {env_file}", err=True)

        for key, value in entries:
            dest, confidence = _classify_key(key, rules)

            if non_interactive and confidence != "confirmed":
                # In non-interactive mode, only auto-apply confirmed rules
                # For unmatched entries, use default classification
                pass
            elif not non_interactive:
                # Interactive: show classification and ask for confirmation
                click.echo(f"\n  {key} → [{dest}] (confidence: {confidence})")
                choice = click.prompt(
                    "  Classify as",
                    type=click.Choice(["config", "vault", "skip"]),
                    default=dest,
                )
                if choice == "skip":
                    continue
                dest = choice
                confidence = "confirmed"

                # Save confirmed rule
                pattern = key  # Exact match for explicitly confirmed
                _update_rule(rules, pattern, dest, "confirmed")

            classifications[key] = dest

            if dest == "config":
                shared_config[key] = value
            else:
                vault_path = f"{project}/{tenant}/{key.lower()}"
                vault_refs.append({
                    "path": vault_path,
                    "original_key": key,
                    "description": f"Per-developer secret -> {key}",
                })
                vault_keys = config["keys"].setdefault("vault", {})
                vault_keys.setdefault(vault_path, f"Per-developer secret -> {key}")

        click.echo(
            f"\n  Classified: {len(shared_config)} shared config, {len(vault_refs)} vault secrets",
            err=True,
        )

        # Generate .env.example
        if not locke_env_example.exists():
            _generate_env_example(env_path, classifications, locke_env_example)
            click.echo(f"  .env.example written to {locke_env_example}", err=True)
    else:
        click.echo(f"No {env_file} found — skipping migration.", err=True)

    # Write shared config
    if shared_config:
        config_path = locke_dir / "config.json"
        if config_path.exists() and existing_config:
            # Merge with existing
            with open(config_path) as f:
                existing_shared = json.load(f)
            existing_shared.update(shared_config)
            shared_config = existing_shared
        with open(config_path, "w") as f:
            json.dump(shared_config, f, indent=2, sort_keys=True)
        click.echo(f"  Shared config written to {config_path}", err=True)

    # Write vault references
    if vault_refs:
        vault_ref_path = locke_dir / "vault-references.json"
        if vault_ref_path.exists():
            with open(vault_ref_path, encoding="utf-8") as f:
                existing_refs = json.load(f).get("secrets", [])
            by_path = {item.get("path"): item for item in existing_refs if item.get("path")}
            for item in vault_refs:
                by_path[item["path"]] = item
            vault_refs = list(by_path.values())
        with open(vault_ref_path, "w") as f:
            json.dump({"secrets": vault_refs}, f, indent=2)
        click.echo(f"  Vault references written to {vault_ref_path}", err=True)

    # Save locke.json with updated rules
    config["classificationRules"] = rules
    with open(locke_json_path, "w") as f:
        json.dump(config, f, indent=2)
    click.echo(f"  Config saved to {locke_json_path}", err=True)

    click.echo("\n.locke/ initialized successfully.", err=True)


def _update_rule(
    rules: list[dict], pattern: str, destination: str, confidence: str
) -> None:
    """Add or update a classification rule."""
    for rule in rules:
        if rule["pattern"] == pattern:
            rule["destination"] = destination
            rule["confidence"] = confidence
            return
    rules.append({
        "pattern": pattern,
        "destination": destination,
        "confidence": confidence,
    })
