"""CLI commands for biometric session management."""

from __future__ import annotations

import datetime
import time

import click


@click.group()
def bio() -> None:
    """Manage biometric session."""


@bio.command()
def logout() -> None:
    """Invalidate the persistent biometric session.

    After logout, the next keystore access will prompt Windows Hello again.
    """
    from locke.keystore import invalidate_bio_session

    if invalidate_bio_session():
        click.echo("Biometric session invalidated.")
    else:
        click.echo("No active biometric session.")


@bio.command()
def status() -> None:
    """Show biometric session status."""
    import json as json_mod

    from locke.keystore import (
        _BIO_SESSION_FILE,
        _bio_session_ttl,
        _biometric_enabled,
        _compute_session_hmac,
        _get_bio_session_dir,
        _get_machine_id,
        _get_username,
        _read_bio_session,
        check_windows_hello_available,
    )

    click.echo("Biometric status:")
    click.echo(f"  Enabled:          {_biometric_enabled()}")
    click.echo(f"  Windows Hello:    {check_windows_hello_available()}")
    click.echo(f"  Session TTL:      {_bio_session_ttl():.0f}s ({_bio_session_ttl() / 86400:.1f} days)")

    session_file = _get_bio_session_dir() / _BIO_SESSION_FILE
    if not session_file.is_file():
        click.echo("  Session:          none")
        return

    try:
        with open(session_file) as f:
            data = json_mod.load(f)
        verified_at = float(data["verified_at"])
        machine_id = str(data["machine_id"])
        username = str(data["username"])
        stored_hmac = str(data["hmac"])
    except Exception as exc:
        click.echo(f"  Session:          corrupt ({exc})")
        return

    ts = datetime.datetime.fromtimestamp(verified_at).strftime("%Y-%m-%d %H:%M:%S")
    age = time.time() - verified_at
    remaining = _bio_session_ttl() - age

    machine_ok = machine_id == _get_machine_id()
    user_ok = username == _get_username()
    expected_hmac = _compute_session_hmac(verified_at, machine_id, username)
    hmac_ok = stored_hmac == expected_hmac
    valid = _read_bio_session()

    click.echo(f"  Verified at:      {ts}")
    click.echo(f"  Age:              {age:.0f}s ({age / 3600:.1f}h)")
    if remaining > 0:
        click.echo(f"  Remaining:        {remaining:.0f}s ({remaining / 3600:.1f}h)")
    else:
        click.echo(f"  Remaining:        expired")
    click.echo(f"  Machine match:    {machine_ok}")
    click.echo(f"  User match:       {user_ok}")
    click.echo(f"  HMAC intact:      {hmac_ok}")
    click.echo(f"  Valid:            {valid}")
