# Plan: bridge interactive 1Password authorization to non-interactive Locke consumers

## Goal

Allow an operator to authorize Locke once from an interactive terminal and then run
Obachan/Locke 1Password operations from child or non-interactive processes that cannot
share 1Password CLI's terminal-scoped desktop-app session.

## Current state

- Locke 0.11 already has an explicit-account, explicit-vault 1Password Login-item backend.
- The backend delegates to the official `op` CLI and never sends secret values on argv.
- `op` desktop-app authorization is terminal-scoped. Agent subprocesses inherit no
  `OP_SESSION*` value, so `obachan mail ... provision-user` fails during the fail-closed
  1Password preflight before changing Stalwart or OpenBao.
- The target account is a human `my.1password.com` account. This plan does not assume a
  Business-only 1Password service account or Connect server.

## Design

1. Add `locke onepassword authorize`.
   - Resolve the already-explicit account and vault.
   - Run `op signin --account <account> --raw` with the operator's terminal attached.
   - Capture the short-lived session token in memory; never print it or place it on argv.
   - Verify read access to the configured vault with that token before persistence.
   - Store it under an account-scoped key in Locke's OS-keystore root of trust.
2. In non-interactive 1Password operations, when no explicit `OP_SESSION*`, Connect, or
   service-account environment authentication is present, read that account-scoped token
   and pass it only in the child `op` process environment as `OP_SESSION`.
3. Add `locke onepassword forget-session` to delete Locke's cached token.
4. Keep normal interactive/app-integrated and explicit environment authentication
   behavior unchanged. A stale cached token fails closed with a command naming
   `locke onepassword authorize`; no automatic account fallback or secret-bearing stderr.
5. Document the 30-minute-inactivity lifetime and the intended Obachan workflow.

## Security constraints

- Never persist the account password, Secret Key, or 1Password item secrets.
- Never write the session token to Locke's plaintext settings file.
- Never put the session token in command arguments, stdout, exceptions, logs, or tests.
- Scope cached tokens by configured account; verify the configured vault before storing.
- Do not fall back to a different 1Password account or ambient vault.
- Keep existing redaction-safe `op` error handling.

## Validation

- Unit tests for account isolation, non-interactive injection, ambient-auth precedence,
  authorize/vault-preflight ordering, failed-preflight no-store, token non-disclosure,
  forget-session, and CLI output.
- `python -m pytest tests/unit/test_onepassword.py tests/unit/test_onepassword_cli.py`
- Full Python test suite.
- Ruff on changed Python paths.
- Review docs/changelog diff.

## Non-goals

- No production mailbox, alias, OpenBao, DNS, or 1Password-item mutation in this change.
- No long-lived service-account token provisioning.
- No 1Password Connect server.
- No changes to TypeScript/Rust because this is Python's existing 1Password/Obachan path,
  not the cross-language encryption format or generic resolution pipeline.
