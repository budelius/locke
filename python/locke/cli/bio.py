"""CLI commands for biometric session management."""

from __future__ import annotations

import datetime
import time

import click


@click.group()
def bio() -> None:
    """Manage biometric session."""


@click.command()
@click.option(
    "--force",
    is_flag=True,
    help="Re-verify even if a valid session already exists.",
)
def unlock(force: bool) -> None:
    """Refresh the biometric session via a Windows Hello prompt.

    Triggers Windows Hello now and, on success, writes a fresh persistent
    session so subsequent keystore/decrypt access won't prompt again until it
    expires. A no-op that reports the remaining time if the session is still
    valid, unless ``--force`` is given.

    Registered both as ``locke unlock`` and ``locke bio unlock``.
    """
    from locke.errors import BiometricDeniedError, BiometricUnavailableError
    from locke.keystore import (
        _biometric_enabled,
        _bio_session_ttl,
        _read_bio_session,
        _write_bio_session,
        invalidate_bio_session,
        reset_bio_cache,
        verify_windows_hello,
    )

    if not _biometric_enabled():
        click.echo("Biometric gating is disabled; nothing to unlock.")
        return

    if _read_bio_session() and not force:
        click.echo(
            f"Biometric session already valid ({_bio_session_ttl() / 3600:.1f}h TTL). "
            "Use --force to re-verify."
        )
        return

    if force:
        # Drop the in-memory cache and persistent session so verification
        # prompts fresh rather than short-circuiting on the existing session.
        reset_bio_cache()
        invalidate_bio_session()

    try:
        verified = verify_windows_hello("Locke: Unlock your credential session")
    except BiometricUnavailableError as exc:
        click.echo(f"Windows Hello unavailable: {exc}", err=True)
        raise SystemExit(1)
    except BiometricDeniedError as exc:
        click.echo(f"Unlock failed: {exc}", err=True)
        raise SystemExit(1)

    # On success verify_windows_hello() writes a session itself; but on a
    # non-interactive shell it returns True WITHOUT persisting one. Persist it
    # here so `unlock` reliably leaves a usable session behind.
    if verified and not _read_bio_session():
        _write_bio_session()

    if _read_bio_session():
        click.echo(f"Unlocked. Session valid for {_bio_session_ttl() / 3600:.1f}h.")
    else:
        click.echo(
            "Verification returned but no session was persisted "
            "(non-interactive shell without a console?).",
            err=True,
        )
        raise SystemExit(1)


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

    ts = (
        datetime.datetime.fromtimestamp(verified_at, tz=datetime.UTC)
        .astimezone()
        .strftime("%Y-%m-%d %H:%M:%S")
    )
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
        click.echo("  Remaining:        expired")
    click.echo(f"  Machine match:    {machine_ok}")
    click.echo(f"  User match:       {user_ok}")
    click.echo(f"  HMAC intact:      {hmac_ok}")
    click.echo(f"  Valid:            {valid}")


bio.add_command(unlock)
