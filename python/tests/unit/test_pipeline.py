"""Tests for locke.pipeline — credential resolution priority."""

from contextlib import ExitStack
from unittest.mock import patch

import pytest

from locke.errors import (
    BiometricDeniedError,
    BiometricUnavailableError,
    CredentialNotFoundError,
)
from locke.pipeline import _resolve_from_keystore, resolve_credential
from tests.conftest import load_test_vectors

VECTORS = load_test_vectors("pipeline.json")["vectors"]


def _get_vector(name: str) -> dict:
    return next(v for v in VECTORS if v["name"] == name)


def _make_backends(vec):
    """Build a _BACKENDS-shaped list from the test vector's backends dict."""
    backends = vec["backends"]

    def _mk(value):
        return lambda name: value

    return [
        ("keystore", _mk(backends.get("keystore"))),
        ("env_var", _mk(backends.get("env_var"))),
        ("gitlab_cli", _mk(backends.get("gitlab_cli"))),
        ("dotenv", _mk(backends.get("dotenv"))),
    ]


def _run_with_mocked_backends(vec, fn):
    """Run fn() with all pipeline backends mocked according to the test vector."""
    with ExitStack() as stack:
        stack.enter_context(
            patch("locke.pipeline._BACKENDS", _make_backends(vec))
        )
        stack.enter_context(
            patch("locke.pipeline.detect_environment", return_value=vec["environment"])
        )
        stack.enter_context(
            patch("locke.pipeline.is_production", return_value=vec["environment"] == "production")
        )
        return fn()


class TestResolveCredential:
    def test_keystore_wins(self):
        vec = _get_vector("keystore-wins")
        cred = _run_with_mocked_backends(vec, lambda: resolve_credential(vec["credential_name"]))
        assert cred.value == vec["expected_value"]
        assert cred.source == vec["expected_source"]

    def test_env_fallback(self):
        vec = _get_vector("env-fallback")
        cred = _run_with_mocked_backends(vec, lambda: resolve_credential(vec["credential_name"]))
        assert cred.value == vec["expected_value"]
        assert cred.source == vec["expected_source"]

    def test_glab_fallback(self):
        vec = _get_vector("glab-fallback")
        cred = _run_with_mocked_backends(vec, lambda: resolve_credential(vec["credential_name"]))
        assert cred.value == vec["expected_value"]
        assert cred.source == vec["expected_source"]

    def test_dotenv_fallback_dev(self):
        vec = _get_vector("dotenv-fallback-dev")
        cred = _run_with_mocked_backends(vec, lambda: resolve_credential(vec["credential_name"]))
        assert cred.value == vec["expected_value"]
        assert cred.source == vec["expected_source"]

    def test_production_no_dotenv(self):
        vec = _get_vector("production-fail")

        def run():
            with pytest.raises(CredentialNotFoundError) as exc_info:
                resolve_credential(vec["credential_name"])
            return exc_info.value

        err = _run_with_mocked_backends(vec, run)
        assert err.backends_searched == vec["expected_backends_searched"]

    def test_dev_all_empty(self):
        vec = _get_vector("dev-all-empty")

        def run():
            with pytest.raises(CredentialNotFoundError) as exc_info:
                resolve_credential(vec["credential_name"])
            return exc_info.value

        err = _run_with_mocked_backends(vec, run)
        assert err.backends_searched == vec["expected_backends_searched"]


class TestBiometricFallback:
    """Biometric errors in _resolve_from_keystore should return None, not propagate."""

    @patch("locke.pipeline.keystore_get", side_effect=BiometricDeniedError("denied"))
    def test_denied_returns_none(self, _):
        assert _resolve_from_keystore("SOME_KEY") is None

    @patch("locke.pipeline.keystore_get", side_effect=BiometricUnavailableError("no hw"))
    def test_unavailable_returns_none(self, _):
        assert _resolve_from_keystore("SOME_KEY") is None

    @patch("locke.pipeline.keystore_get", side_effect=BiometricDeniedError("denied"))
    def test_falls_through_to_env_var(self, _):
        """When biometric blocks keystore, pipeline should find the env var."""
        with patch.dict("os.environ", {"MY_SECRET": "from_env"}):
            cred = resolve_credential("MY_SECRET")
            assert cred.value == "from_env"
            assert cred.source == "env_var"


class TestGlabAuthTokenScope:
    """`glab auth token` is name-blind — it must only answer GitLab names.

    Regression: gating on ``"TOKEN" in name`` made a keystore miss on any
    ``*_TOKEN`` credential return the GitLab token, which callers then sent
    to unrelated APIs (observed against api.hetzner.cloud, 2026-08-17).
    """

    @staticmethod
    def _glab_only_auth_token(name: str):
        """Patch set where `glab variable get` misses and `auth token` hits."""
        def run(cmd, **kwargs):
            from unittest.mock import Mock

            if cmd[:3] == ["glab", "variable", "get"]:
                return Mock(returncode=1, stdout="")
            if cmd[:3] == ["glab", "auth", "token"]:
                return Mock(returncode=0, stdout="glpat-THE-GITLAB-TOKEN\n")
            raise AssertionError(f"unexpected command: {cmd}")

        return run

    @pytest.mark.parametrize(
        "name",
        [
            "OBACHAN_STAGING_HCLOUD_TOKEN",
            "CLOUDFLARE_API_TOKEN",
            "INWX_TOKEN",
            "VAULT_TOKEN",
        ],
    )
    def test_non_gitlab_token_names_are_refused(self, name):
        from locke.pipeline import _resolve_from_glab

        with ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value="/usr/bin/glab"))
            stack.enter_context(
                patch("subprocess.run", side_effect=self._glab_only_auth_token(name))
            )
            assert _resolve_from_glab(name) is None

    @pytest.mark.parametrize(
        "name",
        ["GITLAB_TOKEN", "GLAB_TOKEN", "OBACHAN_PROD_GITLAB_API_TOKEN"],
    )
    def test_gitlab_names_still_resolve(self, name):
        from locke.pipeline import _resolve_from_glab

        with ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value="/usr/bin/glab"))
            stack.enter_context(
                patch("subprocess.run", side_effect=self._glab_only_auth_token(name))
            )
            assert _resolve_from_glab(name) == "glpat-THE-GITLAB-TOKEN"

    @pytest.mark.parametrize(
        "name",
        [
            # Real obachan credentials (src/obachan/cli/secrets.py). The admin
            # token rotates project access tokens through the GitLab API; the
            # personal token `glab auth token` returns is a different identity
            # with different rights.
            "GITLAB_ADMIN_TOKEN",
            "OBACHAN_PROD_GITLAB_ADMIN_TOKEN",
            "GITLAB_PROJECT_ACCESS_TOKEN_ID",
            # Other GitLab credentials that are not the CLI's own token.
            "GITLAB_DEPLOY_TOKEN",
            "GITLAB_REGISTRY_TOKEN",
            "GITLAB_RUNNER_TOKEN",
            "GITLAB_JOB_TOKEN",
            "GITLAB_TRIGGER_TOKEN",
            "GITLAB_GROUP_TOKEN",
            "GITLAB_WEBHOOK_TOKEN",
            "GITLAB_IMPERSONATION_TOKEN",
            "GITLAB_BOT_TOKEN",
        ],
    )
    def test_other_gitlab_credentials_are_refused(self, name):
        """Narrowing to GitLab names left the same bug inside the GitLab family.

        `glab auth token` returns the CLI's own personal token. Answering a
        deploy/registry/runner/admin credential with it is the same silent
        substitution, one blast radius smaller.
        """
        from locke.pipeline import _resolve_from_glab

        with ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value="/usr/bin/glab"))
            stack.enter_context(
                patch("subprocess.run", side_effect=self._glab_only_auth_token(name))
            )
            assert _resolve_from_glab(name) is None

    @pytest.mark.parametrize(
        "name",
        ["GITLAB_URL", "GITLAB_USERNAME", "GITLAB_PROJECT", "GITLAB_REGISTRY_PASSWORD"],
    )
    def test_gitlab_names_that_are_not_tokens_are_refused(self, name):
        """A URL, a username, or a password is never what `auth token` returns."""
        from locke.pipeline import _resolve_from_glab

        with ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value="/usr/bin/glab"))
            stack.enter_context(
                patch("subprocess.run", side_effect=self._glab_only_auth_token(name))
            )
            assert _resolve_from_glab(name) is None

    @pytest.mark.parametrize(
        "name",
        [
            "GITLAB_TOKEN",
            "GLAB_TOKEN",
            "OBACHAN_PROD_GITLAB_API_TOKEN",
            "GITLAB_ACCESS_TOKEN",
            "GITLAB_AUTH_TOKEN",
            "GITLAB_PERSONAL_ACCESS_TOKEN",
        ],
    )
    def test_the_clis_own_token_still_resolves(self, name):
        from locke.pipeline import _resolve_from_glab

        with ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value="/usr/bin/glab"))
            stack.enter_context(
                patch("subprocess.run", side_effect=self._glab_only_auth_token(name))
            )
            assert _resolve_from_glab(name) == "glpat-THE-GITLAB-TOKEN"

    def test_resolving_from_glab_is_warned_about(self, caplog):
        """The incident ran ~10h unseen because glab answered silently.

        `.env` already warns when it answers; glab is a weaker source still
        (it is not even name-addressed) and must be at least as loud.
        """
        import logging

        from locke.pipeline import _resolve_from_glab

        with ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value="/usr/bin/glab"))
            stack.enter_context(
                patch(
                    "subprocess.run",
                    side_effect=self._glab_only_auth_token("GITLAB_TOKEN"),
                )
            )
            with caplog.at_level(logging.WARNING, logger="locke.pipeline"):
                assert _resolve_from_glab("GITLAB_TOKEN") == "glpat-THE-GITLAB-TOKEN"

        assert "glab auth token" in caplog.text
        assert "GITLAB_TOKEN" in caplog.text


class TestKeystoreUnavailableSuppressesNameBlindBackends:
    """An environmental keystore failure is not evidence the credential is absent.

    Windows Hello cannot prompt while the workstation is locked, so the keystore
    stage returns nothing for a credential that is sitting right there. Falling
    through to a *name-addressed* backend (env, .env) is fine -- they answer the
    question asked. Falling through to `glab auth token`, which answers whatever
    it likes, is how the GitLab token reached api.hetzner.cloud on 2026-08-17.
    """

    @staticmethod
    def _glab_answers_everything():
        def run(cmd, **kwargs):
            from unittest.mock import Mock

            if cmd[:3] == ["glab", "variable", "get"]:
                return Mock(returncode=1, stdout="")
            if cmd[:3] == ["glab", "auth", "token"]:
                return Mock(returncode=0, stdout="glpat-THE-GITLAB-TOKEN\n")
            raise AssertionError(f"unexpected command: {cmd}")

        return run

    def test_glab_is_skipped_when_biometrics_blocked_the_keystore(self, monkeypatch):
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)
        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "locke.pipeline.keystore_get",
                    side_effect=BiometricUnavailableError("locked"),
                )
            )
            stack.enter_context(patch("shutil.which", return_value="/usr/bin/glab"))
            stack.enter_context(
                patch("subprocess.run", side_effect=self._glab_answers_everything())
            )
            with pytest.raises(CredentialNotFoundError):
                resolve_credential("GITLAB_TOKEN")

    def test_glab_still_answers_when_the_keystore_merely_lacks_the_name(
        self, monkeypatch
    ):
        """A real miss (credential absent) keeps the existing fallback behaviour."""
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)
        with ExitStack() as stack:
            stack.enter_context(patch("locke.pipeline.keystore_get", return_value=None))
            stack.enter_context(patch("shutil.which", return_value="/usr/bin/glab"))
            stack.enter_context(
                patch("subprocess.run", side_effect=self._glab_answers_everything())
            )
            cred = resolve_credential("GITLAB_TOKEN")

        assert cred.value == "glpat-THE-GITLAB-TOKEN"
        assert cred.source == "gitlab_cli"

    def test_name_addressed_backends_still_answer(self, monkeypatch):
        """env/.env look up the name they were given -- they stay in the chain."""
        monkeypatch.setenv("HCLOUD_TOKEN", "real-hetzner-token")
        with patch(
            "locke.pipeline.keystore_get",
            side_effect=BiometricDeniedError("denied"),
        ):
            cred = resolve_credential("HCLOUD_TOKEN")

        assert cred.value == "real-hetzner-token"
        assert cred.source == "env_var"

    def test_the_not_found_error_says_the_keystore_was_unreachable(self, monkeypatch):
        """'not found' read as 'never stored'. It must say what actually happened."""
        monkeypatch.delenv("HCLOUD_TOKEN", raising=False)
        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "locke.pipeline.keystore_get",
                    side_effect=BiometricUnavailableError("Hello cannot prompt"),
                )
            )
            stack.enter_context(patch("shutil.which", return_value=None))
            with pytest.raises(CredentialNotFoundError) as excinfo:
                resolve_credential("HCLOUD_TOKEN")

        message = str(excinfo.value)
        assert "keystore" in message.lower()
        assert "LOCKE_USE_BIOMETRIC" in message


class TestGlabVariableGetIsOptIn:
    """`glab variable get` resolves against whatever project cwd maps to.

    obachan manages staging and prod from one workstation, so a CI variable
    picked up from the wrong checkout is a cross-environment credential swap.
    It is name-addressed, so it is not the same bug as `auth token` -- but it
    is still an answer nobody asked this repository for.
    """

    @staticmethod
    def _variable_get_hits():
        def run(cmd, **kwargs):
            from unittest.mock import Mock

            if cmd[:3] == ["glab", "variable", "get"]:
                return Mock(returncode=0, stdout="value-from-some-project\n")
            return Mock(returncode=1, stdout="")

        return run

    def test_disabled_by_default(self, monkeypatch):
        from locke.pipeline import _resolve_from_glab

        monkeypatch.delenv("LOCKE_GLAB_VARIABLES", raising=False)
        with ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value="/usr/bin/glab"))
            stack.enter_context(
                patch("subprocess.run", side_effect=self._variable_get_hits())
            )
            assert _resolve_from_glab("HCLOUD_TOKEN") is None

    def test_enabled_by_opt_in(self, monkeypatch):
        from locke.pipeline import _resolve_from_glab

        monkeypatch.setenv("LOCKE_GLAB_VARIABLES", "1")
        with ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value="/usr/bin/glab"))
            stack.enter_context(
                patch("subprocess.run", side_effect=self._variable_get_hits())
            )
            assert _resolve_from_glab("HCLOUD_TOKEN") == "value-from-some-project"
