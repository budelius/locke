# Changelog

All notable changes to Locke are documented here. Versions are kept aligned
across the Python, TypeScript, and Rust packages.

## [Unreleased]

### Added

- Added `locke onepassword authorize` and `forget-session` to bridge an
  interactive, short-lived 1Password CLI session to non-interactive
  Locke/Obachan child processes through an account-scoped OS-keystore entry.
  Authorization verifies the explicitly configured vault before caching.
- Added a Python 1Password backend using the official `op` CLI. It provides
  exact-title, idempotent Login-item reads/writes, combined credentials,
  structured non-secret fields, access/uniqueness preflights, and
  `locke onepassword get/set` commands.
- Added `onepassword_account` and `onepassword_vault` user settings (overridden
  by `LOCKE_ONEPASSWORD_ACCOUNT` / `LOCKE_ONEPASSWORD_VAULT`) so every
  1Password operation has explicit account and vault scope.
- Added a Python user-level settings file (`~/.config/locke/config.toml`, or
  `%APPDATA%/locke/config.toml` on Windows) holding non-secret bootstrap
  settings, so Vaultwarden connection details resolve from **any** working
  directory instead of only from a project checkout that has a `.env`.
- Added `locke config path`, `locke config show`, and `locke config set` to
  inspect and edit that file.
- Added `LOCKE_SETTINGS_FILE` to override settings-file discovery with an
  explicit path.

### Changed

- `LOCKE_VAULT_URL` / `LOCKE_VAULT_USERNAME` now resolve as **environment
  variable > `./.env` (development and staging only) > the user-level settings
  file**. The new step is a fallback only, so existing setups are unaffected.
- The "not set" vault error now names every source that was consulted and the
  `locke config set` command that fixes it.

### Security

- Cached 1Password sessions never appear on stdout, argv, or in Locke's
  plaintext settings. Locke passes them only through an isolated child `op`
  environment, preserves explicit environment authentication precedence, and
  fails closed with a reauthorization command after session refusal/expiry.
- 1Password create/edit payloads are sent to `op` over stdin; Locke exposes no
  password command-line flag and does not include `op` stderr in exceptions,
  because either could disclose a submitted secret.
- The settings file is plaintext and refuses secrets: writing a password key
  raises, and a password key in an existing file is ignored with a warning. The
  Vaultwarden master password continues to resolve through the keystore-first
  credential pipeline.

- An unexpected OS-keystore failure (a broken keyring backend, a missing
  library, a permissions problem) is now treated as "the keystore could not be
  consulted" rather than "the credential is absent", the same as biometric
  gating already was. It previously fell through to weaker backends -- the
  identical silent degradation behind the 2026-08-17 credential substitution,
  reached by a different exception. Found by justifying each blind `except`
  individually while clearing the lint backlog.

### Fixed

- Interactive MSYS/Git Bash sessions on Windows no longer start a Windows Hello
  consent operation that cannot complete and then fail after 120 seconds. Locke
  detects that host up front, emits the OS-session-boundary warning once per
  process (including bulk/chunked operations), and leaves Windows Hello enabled
  for native shells.
- `publish:crates` installs its dependencies again: this runner cannot let apt
  drop privileges to `_apt`, and apt exited 0 anyway, so the v0.10.0 release
  failed later at `jq: command not found` with npm and crates.io unpublished.
- `publish:npm` now checks that an OIDC token was issued and that npm is new
  enough, instead of failing with a bare `ENEEDAUTH` that names neither.

### Changed

- Cleared the Python lint backlog (76 findings) and made the gate run: `lint`
  fired only on merge requests and on a `dev` branch that did not exist, while
  every commit went straight to `main`. It now also runs on the default branch,
  and a `dev` branch exists.
- Blind `except` clauses under `locke/` each carry a `# noqa: BLE001` with a
  reason; CLI entrypoints are exempted as a layer via `per-file-ignores`, since
  turning any failure into a clean message is the correct shape there.

## [0.10.0] - 2026-08-19

### Security

- An OS keystore that could not be *consulted* no longer licenses a name-blind
  backend to answer in its place. Biometric gating (Windows Hello cannot prompt
  while the workstation is locked) made "the keystore does not have it" and "the
  keystore could not be asked" indistinguishable, and the pipeline fell through
  to `glab auth token` for a credential that was sitting in the store. The glab
  backend is now skipped in that case, and the resulting
  `CredentialNotFoundError` says the keystore was unreachable and points at
  `LOCKE_USE_BIOMETRIC=false` — rather than reading as "never stored", the
  misreading that cost ~10h of misdirected debugging.
- `glab variable get` is now opt-in via `LOCKE_GLAB_VARIABLES=1` and warns when
  it answers. It resolves against whichever GitLab project the current directory
  maps to, so the same credential name yielded different values depending on
  where the process happened to run — across environments, a credential swap.
- `glab auth token` may no longer answer arbitrary credential names. It returns
  the GitLab CLI's own personal token regardless of what was requested, but was
  gated on `"TOKEN" in name`, so any `*_TOKEN` credential resolved to the GitLab
  token whenever the keystore stage missed — routine on Windows, where Hello
  cannot prompt while the workstation is locked. Callers saw a plausible
  credential and sent it to whichever API they were talking to; observed as 22
  Authorization headers to api.hetzner.cloud over ~10h on 2026-08-17.
- The same substitution inside the GitLab family is closed too: only names
  denoting the CLI's *own* token qualify. GitLab issues deploy, registry,
  runner, group, trigger, job, and impersonation tokens against the same host,
  and an admin token is a different identity — `GITLAB_ADMIN_TOKEN` (which
  rotates project access tokens) and `GITLAB_PROJECT_ACCESS_TOKEN_ID` are now
  refused rather than answered with the personal token. Prefixed names such as
  `OBACHAN_PROD_GITLAB_API_TOKEN` still resolve.
- Resolving a credential from `glab auth token` now logs a WARNING. This backend
  is not name-addressed, so an answer means a stronger source did not respond —
  the condition that went unnoticed for ~10h during that incident. `.env`
  already warned; glab now does too.

### Changed

- Route Python, npm, and crates.io publish jobs to the protected Obachan staging
  OSS runner.

### Added

- Added Python `locke genkeys` / `locke-genkeys` commands to replace
  project-local generation scripts. They discover the project-root `.env` and
  read `LOCKE_INPUT_DIR`, `LOCKE_OUTPUT_DIR`, and `LOCKE_KEY_NAME` from it.
- Added Python `locke strip-jsonc` / `locke-strip-jsonc` commands for converting
  JSONC files to strict JSON.

## [0.9.1] - 2026-07-21

### Fixed

- Python Vaultwarden connections now resolve `LOCKE_VAULT_URL` and
  `LOCKE_VAULT_USERNAME` from the process environment first, then from `./.env`
  in development and staging.
- Production continues to ignore `.env`, and the vault password remains behind
  the keystore-first credential pipeline.

### Documentation

- Documented vault connection-setting precedence and production behavior.

## [0.9.0] - 2026-07-12

### Added

- Python OpenBao KV v1/v2 support with secret and combined-credential APIs.
- `locke openbao get` and `locke openbao set` commands.

## [0.8.0] - 2026-05-07

### Added

- Cross-language Vaultwarden read/write and import support.
- Combined username/password credentials and placeholder handling.
- Windows Hello biometric gating.

## [0.7.0] - 2026-04-23

### Added

- JSONC support for all configuration reads in Python, TypeScript, and Rust.

[0.9.1]: https://gitlab.com/martin-wieser/locke/-/compare/v0.9.0...v0.9.1
[0.9.0]: https://gitlab.com/martin-wieser/locke/-/compare/v0.8.0...v0.9.0
[0.8.0]: https://gitlab.com/martin-wieser/locke/-/compare/v0.7.0...v0.8.0
[0.7.0]: https://gitlab.com/martin-wieser/locke/-/compare/v0.6.1...v0.7.0
